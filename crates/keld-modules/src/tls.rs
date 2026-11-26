//! TLS certificate / protocol audit for authorized targets.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keld_core::{
    EventSender, JobId, LogLevel, ModuleEvent, ModuleKind, RateLimiter, Scope, ScopeError,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::ports::{parse_ports, PortParseError};
use crate::Module;

/// Default connect / handshake / HTTP timeout.
pub const DEFAULT_TLS_TIMEOUT_MS: u64 = 5_000;
/// Default concurrent TLS workers.
pub const DEFAULT_TLS_CONCURRENCY: usize = 8;
/// Expiry window treated as high severity (days).
const EXPIRY_HIGH_DAYS: i64 = 14;
/// Expiry window treated as medium severity (days).
const EXPIRY_MEDIUM_DAYS: i64 = 30;

/// Configuration for one TLS audit job.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
    /// When set, trust this extra root (tests / private PKI).
    pub extra_root: Option<CertificateDer<'static>>,
}

impl TlsConfig {
    /// Build from CLI/TUI strings; ports default to `443` when empty.
    pub fn from_parts(
        target: impl Into<String>,
        ports_spec: &str,
        timeout_ms: u64,
        concurrency: usize,
        dry_run: bool,
        rate_per_sec: Option<u32>,
    ) -> Result<Self, PortParseError> {
        let spec = if ports_spec.trim().is_empty() {
            "443"
        } else {
            ports_spec
        };
        Ok(Self {
            target: target.into(),
            ports: parse_ports(spec)?,
            timeout: Duration::from_millis(timeout_ms.max(1)),
            concurrency: concurrency.max(1),
            dry_run,
            rate_per_sec,
            extra_root: None,
        })
    }

    /// Short parameters line for audit / status.
    pub fn parameters_summary(&self) -> String {
        format!(
            "ports={} timeout_ms={} concurrency={} dry_run={} rate={}",
            self.ports.len(),
            self.timeout.as_millis(),
            self.concurrency,
            self.dry_run,
            self.rate_per_sec
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into()),
        )
    }
}

/// Finding severity for TLS audit rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl TlsSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// One TLS finding (or dry-run plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFinding {
    pub host: String,
    pub port: u16,
    pub severity: TlsSeverity,
    pub kind: String,
    pub detail: String,
    pub planned: bool,
}

impl TlsFinding {
    /// Compact summary used on the event bus and in TUI parsing.
    pub fn summary_line(&self) -> String {
        if self.planned {
            return format!(
                "would audit {}:{} (chain+expiry+protocols+ciphers+hsts)",
                self.host, self.port
            );
        }
        format!(
            "sev={} {}:{} kind={} {}",
            self.severity.as_str(),
            self.host,
            self.port,
            self.kind,
            self.detail
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Ports(#[from] PortParseError),
    #[error("failed to resolve `{target}`: {message}")]
    Resolve { target: String, message: String },
    #[error("no addresses for `{target}`")]
    NoAddress { target: String },
}

/// TLS audit module.
#[derive(Debug, Clone)]
pub struct TlsModule {
    pub config: TlsConfig,
    pub scope: Scope,
}

impl TlsModule {
    pub fn new(config: TlsConfig, scope: Scope) -> Self {
        Self { config, scope }
    }

    /// Scope-check, then audit each port (or dry-run).
    pub async fn run_tls(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<TlsFinding>, TlsError> {
        self.scope.check(&self.config.target)?;

        if self.config.dry_run {
            return Ok(self.emit_dry_run(job_id, &events).await);
        }

        let addrs = resolve_addrs(&self.config.target).await?;
        if addrs.is_empty() {
            return Err(TlsError::NoAddress {
                target: self.config.target.clone(),
            });
        }

        let total = self.config.ports.len() as u64;
        let done = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let mut rate = RateLimiter::per_second(self.config.rate_per_sec);
        let mut findings = Vec::new();
        let mut handles = Vec::with_capacity(self.config.ports.len());
        let host = strip_port(&self.config.target).to_string();
        let extra_root = self.config.extra_root.clone();

        for port in self.config.ports.iter().copied() {
            rate.wait().await;
            let permit = sem.clone().acquire_owned().await.expect("semaphore open");
            let events = events.clone();
            let done = done.clone();
            let host = host.clone();
            let timeout_d = self.config.timeout;
            let extra_root = extra_root.clone();
            let addrs = addrs.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let port_findings =
                    audit_one(&host, port, &addrs, timeout_d, extra_root.as_ref()).await;
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                let message = format!("{host}:{port} {} finding(s)", port_findings.len());
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: n,
                    total,
                    message,
                });
                port_findings
            }));
        }

        for handle in handles {
            match handle.await {
                Ok(batch) => {
                    for finding in batch {
                        let summary = finding.summary_line();
                        let _ = events.publish(ModuleEvent::Result {
                            job_id,
                            summary: summary.clone(),
                        });
                        findings.push(finding);
                    }
                }
                Err(e) => {
                    let _ = events.publish(ModuleEvent::Log {
                        job_id,
                        level: LogLevel::Warn,
                        message: format!("worker join: {e}"),
                    });
                }
            }
        }

        let _ = events.publish(ModuleEvent::Done { job_id });
        Ok(findings)
    }

    async fn emit_dry_run(&self, job_id: JobId, events: &EventSender) -> Vec<TlsFinding> {
        let host = strip_port(&self.config.target).to_string();
        let total = self.config.ports.len() as u64;
        let mut planned = Vec::new();
        for (i, port) in self.config.ports.iter().copied().enumerate() {
            let finding = TlsFinding {
                host: host.clone(),
                port,
                severity: TlsSeverity::Info,
                kind: "planned".into(),
                detail: "chain+expiry+protocols+ciphers+hsts".into(),
                planned: true,
            };
            let done = (i as u64) + 1;
            let summary = finding.summary_line();
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done,
                total,
                message: summary.clone(),
            });
            let _ = events.publish(ModuleEvent::Result { job_id, summary });
            planned.push(finding);
        }
        let _ = events.publish(ModuleEvent::Done { job_id });
        planned
    }
}

impl Module for TlsModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Tls
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_tls(job_id, events.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    let _ = events.publish(ModuleEvent::Error {
                        job_id,
                        message: e.to_string(),
                    });
                }
            }
        })
    }
}

async fn audit_one(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    timeout_d: Duration,
    extra_root: Option<&CertificateDer<'static>>,
) -> Vec<TlsFinding> {
    let mut out = Vec::new();

    let inspect_cfg = match build_inspect_config(extra_root) {
        Ok(c) => c,
        Err(e) => {
            out.push(finding(
                host,
                port,
                TlsSeverity::High,
                "error",
                format!("tls config: {e}"),
            ));
            return out;
        }
    };

    let handshake = match handshake_inspect(host, port, addrs, timeout_d, inspect_cfg).await {
        Ok(h) => h,
        Err(e) => {
            out.push(finding(host, port, TlsSeverity::High, "connect", e));
            return out;
        }
    };

    out.push(finding(
        host,
        port,
        TlsSeverity::Info,
        "chain",
        format!(
            "depth={} leaf={} issuer={}",
            handshake.chain_depth, handshake.leaf_subject, handshake.leaf_issuer
        ),
    ));

    out.push(expiry_finding(host, port, handshake.not_after_unix));

    let cipher_strength = classify_cipher(&handshake.cipher);
    let cipher_sev = match cipher_strength {
        "weak" => TlsSeverity::High,
        "medium" => TlsSeverity::Medium,
        _ => TlsSeverity::Info,
    };
    out.push(finding(
        host,
        port,
        cipher_sev,
        "cipher",
        format!(
            "suite={} strength={} negotiated={}",
            handshake.cipher, cipher_strength, handshake.protocol
        ),
    ));

    let (tls13, tls12) = probe_versions(host, port, addrs, timeout_d, extra_root).await;
    let proto_sev = if tls13 {
        TlsSeverity::Info
    } else if tls12 {
        TlsSeverity::Low
    } else {
        TlsSeverity::Medium
    };
    out.push(finding(
        host,
        port,
        proto_sev,
        "protocol",
        format!(
            "tls13={} tls12={} note=tls10/11-not-offered-by-client",
            yes_no(tls13),
            yes_no(tls12)
        ),
    ));

    match verify_with_webpki(host, port, addrs, timeout_d, extra_root).await {
        Ok(()) => out.push(finding(
            host,
            port,
            TlsSeverity::Info,
            "verify",
            "ok".into(),
        )),
        Err(e) => out.push(finding(
            host,
            port,
            TlsSeverity::High,
            "verify",
            format!("failed: {e}"),
        )),
    }

    match check_hsts(host, port, addrs, timeout_d, extra_root).await {
        Ok(HstsResult::Present { header }) => {
            let sev = if hsts_max_age_ok(&header) {
                TlsSeverity::Info
            } else {
                TlsSeverity::Low
            };
            out.push(finding(
                host,
                port,
                sev,
                "hsts",
                format!("present {}", sanitize_header(&header)),
            ));
        }
        Ok(HstsResult::Missing) => out.push(finding(
            host,
            port,
            TlsSeverity::Medium,
            "hsts",
            "missing".into(),
        )),
        Ok(HstsResult::NotHttp) => out.push(finding(
            host,
            port,
            TlsSeverity::Info,
            "hsts",
            "skipped (non-HTTP response)".into(),
        )),
        Err(e) => out.push(finding(
            host,
            port,
            TlsSeverity::Low,
            "hsts",
            format!("error: {e}"),
        )),
    }

    out
}

struct HandshakeInfo {
    protocol: String,
    cipher: String,
    chain_depth: usize,
    leaf_subject: String,
    leaf_issuer: String,
    not_after_unix: i64,
}

async fn tcp_connect_any(
    addrs: &[SocketAddr],
    port: u16,
    timeout_d: Duration,
) -> Result<TcpStream, String> {
    let mut last = String::from("no addresses");
    for mut addr in addrs.iter().copied() {
        addr.set_port(port);
        match timeout(timeout_d, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = format!("tcp connect: {e}"),
            Err(_) => last = "tcp connect timeout".into(),
        }
    }
    Err(last)
}

async fn handshake_inspect(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    timeout_d: Duration,
    config: ClientConfig,
) -> Result<HandshakeInfo, String> {
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = server_name(host)?;
    let tcp = tcp_connect_any(addrs, port, timeout_d).await?;
    let _ = tcp.set_nodelay(true);
    let tls = timeout(timeout_d, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls handshake: {e}"))?;

    let (_, conn) = tls.get_ref();
    let protocol = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_else(|| "unknown".into());

    let certs = conn
        .peer_certificates()
        .ok_or_else(|| "no peer certificates".to_string())?;
    let leaf = certs
        .first()
        .ok_or_else(|| "empty certificate chain".to_string())?;
    let (_, parsed) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|e| format!("x509 parse: {e}"))?;
    let not_after_unix = parsed.validity().not_after.timestamp();

    Ok(HandshakeInfo {
        protocol,
        cipher,
        chain_depth: certs.len(),
        leaf_subject: parsed.subject().to_string(),
        leaf_issuer: parsed.issuer().to_string(),
        not_after_unix,
    })
}

async fn probe_versions(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    timeout_d: Duration,
    extra_root: Option<&CertificateDer<'static>>,
) -> (bool, bool) {
    let tls13 = try_version(
        host,
        port,
        addrs,
        timeout_d,
        extra_root,
        &[&rustls::version::TLS13],
    )
    .await;
    let tls12 = try_version(
        host,
        port,
        addrs,
        timeout_d,
        extra_root,
        &[&rustls::version::TLS12],
    )
    .await;
    (tls13, tls12)
}

async fn try_version(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    timeout_d: Duration,
    extra_root: Option<&CertificateDer<'static>>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> bool {
    let Ok(config) = build_version_config(extra_root, versions) else {
        return false;
    };
    handshake_inspect(host, port, addrs, timeout_d, config)
        .await
        .is_ok()
}

async fn verify_with_webpki(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    timeout_d: Duration,
    extra_root: Option<&CertificateDer<'static>>,
) -> Result<(), String> {
    let config = build_verify_config(extra_root).map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = server_name(host)?;
    let tcp = tcp_connect_any(addrs, port, timeout_d).await?;
    let _ = tcp.set_nodelay(true);
    timeout(timeout_d, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(())
}

enum HstsResult {
    Present { header: String },
    Missing,
    NotHttp,
}

async fn check_hsts(
    host: &str,
    port: u16,
    addrs: &[SocketAddr],
    timeout_d: Duration,
    extra_root: Option<&CertificateDer<'static>>,
) -> Result<HstsResult, String> {
    let config = build_inspect_config(extra_root).map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = server_name(host)?;
    let tcp = tcp_connect_any(addrs, port, timeout_d).await?;
    let _ = tcp.set_nodelay(true);
    let mut tls = timeout(timeout_d, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls handshake: {e}"))?;

    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: keld-tls/0.1\r\n\r\n"
    );
    timeout(timeout_d, tls.write_all(req.as_bytes()))
        .await
        .map_err(|_| "http write timeout".to_string())?
        .map_err(|e| format!("http write: {e}"))?;
    let _ = tls.flush().await;

    let mut buf = vec![0u8; 8192];
    let n = match timeout(timeout_d, tls.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(format!("http read: {e}")),
        Err(_) => return Err("http read timeout".into()),
    };
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf);
    if !text.starts_with("HTTP/") {
        return Ok(HstsResult::NotHttp);
    }
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line
            .strip_prefix("Strict-Transport-Security:")
            .or_else(|| line.strip_prefix("strict-transport-security:"))
        {
            return Ok(HstsResult::Present {
                header: rest.trim().to_string(),
            });
        }
    }
    Ok(HstsResult::Missing)
}

fn expiry_finding(host: &str, port: u16, not_after_unix: i64) -> TlsFinding {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = (not_after_unix - now).div_euclid(86_400);
    let (sev, detail) = if days < 0 {
        (
            TlsSeverity::Critical,
            format!("expired days_ago={} not_after_unix={not_after_unix}", -days),
        )
    } else if days <= EXPIRY_HIGH_DAYS {
        (
            TlsSeverity::High,
            format!("expires_in={days}d not_after_unix={not_after_unix}"),
        )
    } else if days <= EXPIRY_MEDIUM_DAYS {
        (
            TlsSeverity::Medium,
            format!("expires_in={days}d not_after_unix={not_after_unix}"),
        )
    } else {
        (
            TlsSeverity::Info,
            format!("expires_in={days}d not_after_unix={not_after_unix}"),
        )
    };
    finding(host, port, sev, "expiry", detail)
}

fn classify_cipher(suite: &str) -> &'static str {
    let s = suite.to_ascii_uppercase();
    if s.contains("RC4") || s.contains("DES") || s.contains("NULL") || s.contains("EXPORT") {
        return "weak";
    }
    if s.contains("CBC") && !s.contains("GCM") {
        return "medium";
    }
    if s.contains("RSA_WITH") && !s.contains("ECDHE") && !s.contains("DHE") {
        return "medium";
    }
    "strong"
}

fn hsts_max_age_ok(header: &str) -> bool {
    let lower = header.to_ascii_lowercase();
    let Some(rest) = lower.split("max-age=").nth(1) else {
        return false;
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse::<u64>()
        .map(|v| v >= 15_552_000) // ~180 days
        .unwrap_or(false)
}

fn sanitize_header(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(120)
        .collect()
}

fn finding(host: &str, port: u16, severity: TlsSeverity, kind: &str, detail: String) -> TlsFinding {
    TlsFinding {
        host: host.to_string(),
        port,
        severity,
        kind: kind.to_string(),
        detail,
        planned: false,
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn strip_port(target: &str) -> &str {
    // IPv6 in brackets: [::1]:443
    if let Some(rest) = target.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    target.split_once(':').map(|(h, _)| h).unwrap_or(target)
}

fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))
}

fn root_store(extra_root: Option<&CertificateDer<'static>>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(root) = extra_root {
        let _ = roots.add(root.clone());
    }
    roots
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn build_inspect_config(
    _extra_root: Option<&CertificateDer<'static>>,
) -> Result<ClientConfig, RustlsError> {
    ensure_crypto_provider();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    // Accept any chain so expired / private-PKI targets still yield cert metadata.
    Ok(ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier {
            provider: rustls::crypto::aws_lc_rs::default_provider(),
        }))
        .with_no_client_auth())
}

fn build_verify_config(
    extra_root: Option<&CertificateDer<'static>>,
) -> Result<ClientConfig, RustlsError> {
    ensure_crypto_provider();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    Ok(ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store(extra_root))
        .with_no_client_auth())
}

fn build_version_config(
    _extra_root: Option<&CertificateDer<'static>>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<ClientConfig, RustlsError> {
    ensure_crypto_provider();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    Ok(ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(versions)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier {
            provider: rustls::crypto::aws_lc_rs::default_provider(),
        }))
        .with_no_client_auth())
}

#[derive(Debug)]
struct AcceptAllVerifier {
    provider: rustls::crypto::CryptoProvider,
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn resolve_addrs(target: &str) -> Result<Vec<SocketAddr>, TlsError> {
    let host = strip_port(target);
    let lookup = format!("{host}:0");
    let resolved = tokio::net::lookup_host(lookup.as_str())
        .await
        .map_err(|e| TlsError::Resolve {
            target: target.into(),
            message: e.to_string(),
        })?;
    let v: Vec<_> = resolved.collect();
    if v.is_empty() {
        Err(TlsError::NoAddress {
            target: target.into(),
        })
    } else {
        Ok(v)
    }
}

/// Parse a Result summary back into a [`TlsFinding`] (TUI worker bridge).
pub fn parse_tls_summary(summary: &str) -> Option<TlsFinding> {
    if let Some(rest) = summary.strip_prefix("would audit ") {
        let (addr, _) = rest.split_once(" (")?;
        let (host, port_s) = split_host_port(addr)?;
        return Some(TlsFinding {
            host,
            port: port_s.parse().ok()?,
            severity: TlsSeverity::Info,
            kind: "planned".into(),
            detail: "chain+expiry+protocols+ciphers+hsts".into(),
            planned: true,
        });
    }
    // sev=X host:port kind=K detail...
    let rest = summary.strip_prefix("sev=")?;
    let (sev_s, rest) = rest.split_once(' ')?;
    let severity = TlsSeverity::parse(sev_s)?;
    let (addr, rest) = rest.split_once(' ')?;
    let (host, port_s) = split_host_port(addr)?;
    let port: u16 = port_s.parse().ok()?;
    let rest = rest.strip_prefix("kind=")?;
    let (kind, detail) = rest.split_once(' ').unwrap_or((rest, ""));
    Some(TlsFinding {
        host,
        port,
        severity,
        kind: kind.to_string(),
        detail: detail.to_string(),
        planned: false,
    })
}

fn split_host_port(addr: &str) -> Option<(String, String)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        return Some((host.to_string(), port.to_string()));
    }
    let (host, port) = addr.rsplit_once(':')?;
    Some((host.to_string(), port.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{EventBus, Job, JobState, Scope, ScopeEntry};
    use rustls::ServerConfig;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn loopback_scope() -> Scope {
        Scope {
            includes: vec![
                ScopeEntry::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ScopeEntry::Host("localhost".into()),
            ],
            excludes: Vec::new(),
            notes: None,
            source: None,
        }
    }

    fn test_cert_and_key() -> (
        CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".try_into().unwrap()),
            rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let cert = params.self_signed(&key).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        (cert_der, key_der)
    }

    async fn spawn_multi_accept_server(
        hsts: bool,
        accepts: usize,
    ) -> (
        SocketAddr,
        CertificateDer<'static>,
        tokio::task::JoinHandle<()>,
    ) {
        ensure_crypto_provider();
        let (cert, key) = test_cert_and_key();
        let root = cert.clone();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ServerConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for _ in 0..accepts {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let hsts = hsts;
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 1024];
                    let _ = timeout(Duration::from_millis(500), tls.read(&mut buf)).await;
                    let hsts_line = if hsts {
                        "Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n"
                    } else {
                        ""
                    };
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{hsts_line}\r\nOK");
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, root, handle)
    }

    #[tokio::test]
    async fn dry_run_plans_without_connect() {
        let bus = EventBus::new(256);
        let mut rx = bus.subscribe();
        let cfg = TlsConfig::from_parts("127.0.0.1", "443,8443", 200, 4, true, None).unwrap();
        let module = TlsModule::new(cfg, loopback_scope());
        let hits = module.run_tls(JobId::new(1), bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.planned));

        let mut results = 0;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, ModuleEvent::Result { .. }) {
                results += 1;
            }
        }
        assert_eq!(results, 2);
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let bus = EventBus::new(16);
        let cfg = TlsConfig::from_parts("8.8.8.8", "443", 200, 1, true, None).unwrap();
        let module = TlsModule::new(cfg, loopback_scope());
        let err = module
            .run_tls(JobId::new(2), bus.sender())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            TlsError::Scope(ScopeError::OutOfScope { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_handshake_ok() {
        let (addr, _root, server) = spawn_multi_accept_server(false, 4).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let cfg = build_inspect_config(None).unwrap();
        let info = handshake_inspect(
            "127.0.0.1",
            addr.port(),
            &[addr],
            Duration::from_millis(2_000),
            cfg,
        )
        .await
        .expect("handshake");
        assert!(info.chain_depth >= 1);
        assert!(info.not_after_unix > 0);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audits_local_tls_with_hsts() {
        let (addr, root, server) = spawn_multi_accept_server(true, 16).await;
        // Give the accept loop a moment to schedule.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let findings = audit_one(
            "127.0.0.1",
            addr.port(),
            &[addr],
            Duration::from_millis(2_000),
            Some(&root),
        )
        .await;
        assert!(
            findings.iter().any(|f| f.kind == "chain"),
            "findings={findings:?}"
        );
        assert!(findings.iter().any(|f| f.kind == "expiry"));
        assert!(findings.iter().any(|f| f.kind == "cipher"));
        assert!(findings.iter().any(|f| f.kind == "protocol"));
        assert!(findings
            .iter()
            .any(|f| f.kind == "hsts" && f.detail.starts_with("present")));
        assert!(findings
            .iter()
            .any(|f| f.kind == "verify" && f.detail == "ok"));
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reports_missing_hsts() {
        let (addr, root, server) = spawn_multi_accept_server(false, 16).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let findings = audit_one(
            "127.0.0.1",
            addr.port(),
            &[addr],
            Duration::from_millis(2_000),
            Some(&root),
        )
        .await;
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "hsts" && f.detail == "missing"),
            "findings={findings:?}"
        );
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_tls_job_completes() {
        let (addr, root, server) = spawn_multi_accept_server(true, 16).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bus = EventBus::new(256);
        let mut rx = bus.subscribe();
        let mut cfg =
            TlsConfig::from_parts("127.0.0.1", &addr.port().to_string(), 2_000, 2, false, None)
                .unwrap();
        cfg.extra_root = Some(root);
        let module = TlsModule::new(cfg, loopback_scope());
        let id = JobId::new(5);
        let mut job = Job::new(id, ModuleKind::Tls);
        job.start().unwrap();
        let findings = module.run_tls(id, bus.sender()).await.unwrap();
        assert!(!findings.is_empty());
        while let Ok(ev) = rx.try_recv() {
            let _ = job.apply_event(&ev);
        }
        assert_eq!(job.state, JobState::Completed);
        server.abort();
    }

    #[test]
    fn summary_roundtrip() {
        let planned =
            parse_tls_summary("would audit 10.0.0.5:443 (chain+expiry+protocols+ciphers+hsts)")
                .unwrap();
        assert!(planned.planned);
        assert_eq!(planned.port, 443);
        let real =
            parse_tls_summary("sev=high 10.0.0.5:443 kind=expiry expires_in=12d not_after_unix=1")
                .unwrap();
        assert_eq!(real.severity, TlsSeverity::High);
        assert_eq!(real.kind, "expiry");
        assert!(real.detail.contains("expires_in=12d"));
    }

    #[test]
    fn classify_cipher_strength() {
        assert_eq!(classify_cipher("TLS13_AES_256_GCM_SHA384"), "strong");
        assert_eq!(classify_cipher("TLS_RSA_WITH_AES_128_CBC_SHA"), "medium");
        assert_eq!(classify_cipher("TLS_RSA_WITH_RC4_128_SHA"), "weak");
    }
}
