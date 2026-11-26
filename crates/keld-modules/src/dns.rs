//! DNS record enumeration, AXFR check, wordlist and CT subdomain discovery.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use keld_core::{
    EventSender, JobId, LogLevel, ModuleEvent, ModuleKind, RateLimiter, Scope, ScopeError,
};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::Module;

/// Default lookup / HTTP timeout.
pub const DEFAULT_DNS_TIMEOUT_MS: u64 = 5_000;
/// Default concurrent subdomain probes.
pub const DEFAULT_DNS_CONCURRENCY: usize = 20;
/// Default crt.sh base URL (query string appended).
pub const DEFAULT_CT_BASE: &str = "https://crt.sh";

const RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::MX,
    RecordType::NS,
    RecordType::TXT,
    RecordType::CNAME,
    RecordType::SOA,
];

/// Kind of DNS finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsKind {
    Record,
    Axfr,
    Subdomain,
    Ct,
}

impl DnsKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Axfr => "axfr",
            Self::Subdomain => "subdomain",
            Self::Ct => "ct",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "record" | "rr" => Some(Self::Record),
            "axfr" | "zone" => Some(Self::Axfr),
            "subdomain" | "wordlist" | "brute" => Some(Self::Subdomain),
            "ct" | "crt" | "cert" => Some(Self::Ct),
            _ => None,
        }
    }
}

/// Severity for AXFR and notable DNS findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl DnsSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// One DNS finding (or dry-run plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHit {
    pub kind: DnsKind,
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub severity: DnsSeverity,
    pub planned: bool,
}

impl DnsHit {
    /// Compact summary used on the event bus and in TUI parsing.
    pub fn summary_line(&self) -> String {
        if self.planned {
            return format!(
                "would dns kind={} name={} type={} value={}",
                self.kind.as_str(),
                self.name,
                self.rtype,
                self.value
            );
        }
        format!(
            "kind={} sev={} name={} type={} value={}",
            self.kind.as_str(),
            self.severity.as_str(),
            self.name,
            self.rtype,
            self.value
        )
    }
}

/// Timeout, concurrency, dry-run, and rate for a DNS job.
#[derive(Debug, Clone)]
pub struct DnsRunOpts {
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
}

impl Default for DnsRunOpts {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_DNS_TIMEOUT_MS,
            concurrency: DEFAULT_DNS_CONCURRENCY,
            dry_run: false,
            rate_per_sec: None,
        }
    }
}

/// Configuration for one DNS job.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub domain: String,
    pub wordlist: Option<PathBuf>,
    pub ct: bool,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
    /// Optional custom resolvers (tests / operator override). Empty = system config.
    pub resolvers: Vec<SocketAddr>,
    /// crt.sh-compatible base URL (no query). Tests inject a local HTTP server.
    pub ct_base_url: String,
}

impl DnsConfig {
    /// Build from CLI/TUI parts.
    pub fn from_parts(
        domain: impl Into<String>,
        wordlist: Option<PathBuf>,
        ct: bool,
        run: DnsRunOpts,
    ) -> Result<Self, DnsError> {
        let domain = normalize_domain(&domain.into())?;
        Ok(Self {
            domain,
            wordlist,
            ct,
            timeout: Duration::from_millis(run.timeout_ms.max(1)),
            concurrency: run.concurrency.max(1),
            dry_run: run.dry_run,
            rate_per_sec: run.rate_per_sec,
            resolvers: Vec::new(),
            ct_base_url: DEFAULT_CT_BASE.into(),
        })
    }

    /// Short parameters line for audit / status.
    pub fn parameters_summary(&self) -> String {
        format!(
            "domain={} wordlist={} ct={} timeout_ms={} concurrency={} dry_run={} rate={}",
            self.domain,
            self.wordlist
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".into()),
            self.ct,
            self.timeout.as_millis(),
            self.concurrency,
            self.dry_run,
            self.rate_per_sec
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into()),
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error("invalid domain `{domain}`: {reason}")]
    InvalidDomain { domain: String, reason: String },
    #[error("wordlist: {0}")]
    Wordlist(String),
    #[error("resolver: {0}")]
    Resolver(String),
    #[error("http client: {0}")]
    Client(String),
}

/// DNS enumeration module.
#[derive(Debug, Clone)]
pub struct DnsModule {
    pub config: DnsConfig,
    pub scope: Scope,
}

impl DnsModule {
    pub fn new(config: DnsConfig, scope: Scope) -> Self {
        Self { config, scope }
    }

    /// Scope-check, then enumerate records / AXFR / wordlist / CT (or dry-run).
    pub async fn run_dns(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<DnsHit>, DnsError> {
        self.scope.check(&self.config.domain)?;

        if self.config.dry_run {
            return Ok(self.emit_dry_run(job_id, &events).await);
        }

        let resolver = build_resolver(&self.config)?;
        let mut hits = Vec::new();
        let mut steps_done = 0u64;
        // records + axfr + optional wordlist + optional ct
        let mut steps_total = 2u64;
        if self.config.wordlist.is_some() {
            steps_total += 1;
        }
        if self.config.ct {
            steps_total += 1;
        }

        let _ = events.publish(ModuleEvent::Progress {
            job_id,
            done: steps_done,
            total: steps_total,
            message: "enumerating records".into(),
        });

        let (record_hits, ns_hosts) = enumerate_records(&resolver, &self.config.domain).await;
        for hit in &record_hits {
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: hit.summary_line(),
            });
        }
        hits.extend(record_hits);
        steps_done += 1;
        let _ = events.publish(ModuleEvent::Progress {
            job_id,
            done: steps_done,
            total: steps_total,
            message: format!("records done; {} NS for AXFR", ns_hosts.len()),
        });

        let axfr_hits = check_axfr(&resolver, &self.config, &ns_hosts, &events, job_id).await;
        for hit in &axfr_hits {
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: hit.summary_line(),
            });
        }
        hits.extend(axfr_hits);
        steps_done += 1;
        let _ = events.publish(ModuleEvent::Progress {
            job_id,
            done: steps_done,
            total: steps_total,
            message: "axfr checks done".into(),
        });

        if let Some(path) = &self.config.wordlist {
            let words = load_wordlist(path)?;
            let sub_hits = brute_subdomains(
                &resolver,
                &self.config,
                &words,
                &events,
                job_id,
                steps_done,
                steps_total,
            )
            .await;
            for hit in &sub_hits {
                let _ = events.publish(ModuleEvent::Result {
                    job_id,
                    summary: hit.summary_line(),
                });
            }
            hits.extend(sub_hits);
            steps_done += 1;
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: steps_done,
                total: steps_total,
                message: "wordlist done".into(),
            });
        }

        if self.config.ct {
            match fetch_ct(&self.config).await {
                Ok(ct_hits) => {
                    for hit in &ct_hits {
                        let _ = events.publish(ModuleEvent::Result {
                            job_id,
                            summary: hit.summary_line(),
                        });
                    }
                    hits.extend(ct_hits);
                }
                Err(e) => {
                    let _ = events.publish(ModuleEvent::Log {
                        job_id,
                        level: LogLevel::Warn,
                        message: format!("ct: {e}"),
                    });
                }
            }
            steps_done += 1;
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: steps_done,
                total: steps_total,
                message: "ct done".into(),
            });
        }

        let _ = events.publish(ModuleEvent::Done { job_id });
        Ok(hits)
    }

    async fn emit_dry_run(&self, job_id: JobId, events: &EventSender) -> Vec<DnsHit> {
        let mut hits = Vec::new();
        let mut planned = Vec::new();
        for rt in RECORD_TYPES {
            planned.push(DnsHit {
                kind: DnsKind::Record,
                name: self.config.domain.clone(),
                rtype: format!("{rt}"),
                value: "lookup".into(),
                severity: DnsSeverity::Info,
                planned: true,
            });
        }
        planned.push(DnsHit {
            kind: DnsKind::Axfr,
            name: self.config.domain.clone(),
            rtype: "AXFR".into(),
            value: "check NS".into(),
            severity: DnsSeverity::Info,
            planned: true,
        });
        if let Some(path) = &self.config.wordlist {
            if let Ok(words) = load_wordlist(path) {
                for w in words.iter().take(50) {
                    planned.push(DnsHit {
                        kind: DnsKind::Subdomain,
                        name: format!("{w}.{}", self.config.domain),
                        rtype: "A".into(),
                        value: "lookup".into(),
                        severity: DnsSeverity::Info,
                        planned: true,
                    });
                }
                if words.len() > 50 {
                    planned.push(DnsHit {
                        kind: DnsKind::Subdomain,
                        name: self.config.domain.clone(),
                        rtype: "A".into(),
                        value: format!("... {} more words", words.len() - 50),
                        severity: DnsSeverity::Info,
                        planned: true,
                    });
                }
            }
        }
        if self.config.ct {
            planned.push(DnsHit {
                kind: DnsKind::Ct,
                name: self.config.domain.clone(),
                rtype: "CT".into(),
                value: format!(
                    "{}/?q=%25.{}&output=json",
                    self.config.ct_base_url, self.config.domain
                ),
                severity: DnsSeverity::Info,
                planned: true,
            });
        }

        let total = planned.len() as u64;
        for (i, hit) in planned.into_iter().enumerate() {
            let summary = hit.summary_line();
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: (i as u64) + 1,
                total,
                message: summary.clone(),
            });
            let _ = events.publish(ModuleEvent::Result { job_id, summary });
            hits.push(hit);
        }
        let _ = events.publish(ModuleEvent::Done { job_id });
        hits
    }
}

impl Module for DnsModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Dns
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_dns(job_id, events.clone()).await {
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

fn build_resolver(config: &DnsConfig) -> Result<TokioResolver, DnsError> {
    let mut opts = ResolverOpts::default();
    opts.timeout = config.timeout;
    opts.attempts = 1;

    let provider = TokioRuntimeProvider::default();
    let builder = if config.resolvers.is_empty() {
        Resolver::builder(provider).map_err(|e| DnsError::Resolver(e.to_string()))?
    } else {
        let mut servers = Vec::new();
        for addr in &config.resolvers {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            servers.push(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
        }
        let cfg = ResolverConfig::from_name_servers(servers);
        Resolver::builder_with_config(cfg, provider)
    };

    builder
        .with_options(opts)
        .build()
        .map_err(|e| DnsError::Resolver(e.to_string()))
}

async fn enumerate_records(resolver: &TokioResolver, domain: &str) -> (Vec<DnsHit>, Vec<String>) {
    let mut hits = Vec::new();
    let mut ns_hosts = BTreeSet::new();
    let fqdn = ensure_dot(domain);

    for rt in RECORD_TYPES {
        match resolver.lookup(fqdn.as_str(), *rt).await {
            Ok(lookup) => {
                for record in lookup.answers() {
                    let name = record.name.to_string().trim_end_matches('.').to_string();
                    let value = rdata_display(&record.data);
                    if *rt == RecordType::NS {
                        if let RData::NS(ns) = &record.data {
                            ns_hosts.insert(ns.0.to_string().trim_end_matches('.').to_string());
                        }
                    }
                    hits.push(DnsHit {
                        kind: DnsKind::Record,
                        name,
                        rtype: format!("{rt}"),
                        value,
                        severity: DnsSeverity::Info,
                        planned: false,
                    });
                }
            }
            Err(_) => {
                // NXDOMAIN / empty / timeout: skip quietly for that type.
            }
        }
    }
    (hits, ns_hosts.into_iter().collect())
}

async fn check_axfr(
    resolver: &TokioResolver,
    config: &DnsConfig,
    ns_hosts: &[String],
    events: &EventSender,
    job_id: JobId,
) -> Vec<DnsHit> {
    let mut hits = Vec::new();
    if ns_hosts.is_empty() {
        hits.push(DnsHit {
            kind: DnsKind::Axfr,
            name: config.domain.clone(),
            rtype: "AXFR".into(),
            value: "no NS records; skipped".into(),
            severity: DnsSeverity::Info,
            planned: false,
        });
        return hits;
    }

    let zone = match Name::from_str(&ensure_dot(&config.domain)) {
        Ok(n) => n,
        Err(e) => {
            hits.push(DnsHit {
                kind: DnsKind::Axfr,
                name: config.domain.clone(),
                rtype: "AXFR".into(),
                value: format!("invalid zone: {e}"),
                severity: DnsSeverity::Info,
                planned: false,
            });
            return hits;
        }
    };

    for ns_host in ns_hosts {
        let ips = resolve_host_ips(resolver, ns_host).await;
        if ips.is_empty() {
            let _ = events.publish(ModuleEvent::Log {
                job_id,
                level: LogLevel::Warn,
                message: format!("axfr: could not resolve NS {ns_host}"),
            });
            continue;
        }
        for ip in ips {
            let port = config.resolvers.first().map(|a| a.port()).unwrap_or(53);
            let addr = SocketAddr::new(ip, port);
            let outcome = axfr_probe(addr, &zone, config.timeout).await;
            hits.push(outcome_to_hit(&config.domain, ns_host, addr, outcome));
        }
    }
    hits
}

#[derive(Debug)]
enum AxfrOutcome {
    Open { records: usize },
    Denied { code: String },
    Error(String),
}

fn outcome_to_hit(domain: &str, ns_host: &str, addr: SocketAddr, outcome: AxfrOutcome) -> DnsHit {
    match outcome {
        AxfrOutcome::Open { records } => DnsHit {
            kind: DnsKind::Axfr,
            name: domain.to_string(),
            rtype: "AXFR".into(),
            value: format!("OPEN via {ns_host} ({addr}); {records} record(s)"),
            severity: DnsSeverity::High,
            planned: false,
        },
        AxfrOutcome::Denied { code } => DnsHit {
            kind: DnsKind::Axfr,
            name: domain.to_string(),
            rtype: "AXFR".into(),
            value: format!("denied via {ns_host} ({addr}); {code}"),
            severity: DnsSeverity::Info,
            planned: false,
        },
        AxfrOutcome::Error(e) => DnsHit {
            kind: DnsKind::Axfr,
            name: domain.to_string(),
            rtype: "AXFR".into(),
            value: format!("error via {ns_host} ({addr}): {e}"),
            severity: DnsSeverity::Low,
            planned: false,
        },
    }
}

async fn axfr_probe(addr: SocketAddr, zone: &Name, timeout: Duration) -> AxfrOutcome {
    let mut message = Message::new(0x4b4c, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = false;
    message.add_query(Query::query(zone.clone(), RecordType::AXFR));

    let payload = match message.to_vec() {
        Ok(b) => b,
        Err(e) => return AxfrOutcome::Error(e.to_string()),
    };

    let connect = TcpStream::connect(addr);
    let mut stream = match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return AxfrOutcome::Error(e.to_string()),
        Err(_) => return AxfrOutcome::Error("connect timeout".into()),
    };

    let mut framed = Vec::with_capacity(2 + payload.len());
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&payload);

    match tokio::time::timeout(timeout, stream.write_all(&framed)).await {
        Err(_) => return AxfrOutcome::Error("write timeout".into()),
        Ok(Err(e)) => return AxfrOutcome::Error(e.to_string()),
        Ok(Ok(())) => {}
    }

    let mut len_buf = [0u8; 2];
    match tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await {
        Err(_) => return AxfrOutcome::Error("read timeout".into()),
        Ok(Err(e)) => return AxfrOutcome::Error(e.to_string()),
        Ok(Ok(_)) => {}
    }
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 65_535 {
        return AxfrOutcome::Error(format!("invalid tcp length {resp_len}"));
    }
    let mut body = vec![0u8; resp_len];
    match tokio::time::timeout(timeout, stream.read_exact(&mut body)).await {
        Err(_) => return AxfrOutcome::Error("read body timeout".into()),
        Ok(Err(e)) => return AxfrOutcome::Error(e.to_string()),
        Ok(Ok(_)) => {}
    }

    let response = match Message::from_vec(&body) {
        Ok(m) => m,
        Err(e) => return AxfrOutcome::Error(e.to_string()),
    };

    match response.metadata.response_code {
        ResponseCode::NoError if !response.answers.is_empty() => AxfrOutcome::Open {
            records: response.answers.len(),
        },
        ResponseCode::NoError => AxfrOutcome::Denied {
            code: "NOERROR empty".into(),
        },
        ResponseCode::Refused => AxfrOutcome::Denied {
            code: "REFUSED".into(),
        },
        ResponseCode::NotAuth => AxfrOutcome::Denied {
            code: "NOTAUTH".into(),
        },
        ResponseCode::NXDomain => AxfrOutcome::Denied {
            code: "NXDOMAIN".into(),
        },
        other => AxfrOutcome::Denied {
            code: format!("{other}"),
        },
    }
}

async fn resolve_host_ips(resolver: &TokioResolver, host: &str) -> Vec<IpAddr> {
    let fqdn = ensure_dot(host);
    let mut ips = Vec::new();
    if let Ok(lookup) = resolver.lookup_ip(fqdn.as_str()).await {
        for ip in lookup.iter() {
            ips.push(ip);
        }
    }
    ips
}

async fn brute_subdomains(
    resolver: &TokioResolver,
    config: &DnsConfig,
    words: &[String],
    events: &EventSender,
    job_id: JobId,
    steps_done: u64,
    steps_total: u64,
) -> Vec<DnsHit> {
    let total_words = words.len() as u64;
    let done = Arc::new(AtomicU64::new(0));
    let sem = Arc::new(Semaphore::new(config.concurrency));
    let mut rate = RateLimiter::per_second(config.rate_per_sec);
    let mut handles = Vec::with_capacity(words.len());
    let domain = config.domain.clone();

    for word in words {
        rate.wait().await;
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let resolver = resolver.clone();
        let events = events.clone();
        let done = done.clone();
        let domain = domain.clone();
        let word = word.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let host = format!("{word}.{domain}");
            let fqdn = ensure_dot(&host);
            let outcome = resolver.lookup_ip(fqdn.as_str()).await;
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            let msg = match &outcome {
                Ok(lookup) => {
                    let ips: Vec<_> = lookup.iter().map(|ip| ip.to_string()).collect();
                    format!("sub {host} -> {}", ips.join(","))
                }
                Err(_) => format!("sub {host} nx"),
            };
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: steps_done,
                total: steps_total,
                message: format!("{msg} ({n}/{total_words})"),
            });
            (host, outcome)
        }));
    }

    let mut hits = Vec::new();
    for handle in handles {
        match handle.await {
            Ok((host, Ok(lookup))) => {
                let ips: Vec<_> = lookup.iter().map(|ip| ip.to_string()).collect();
                if ips.is_empty() {
                    continue;
                }
                hits.push(DnsHit {
                    kind: DnsKind::Subdomain,
                    name: host,
                    rtype: "A/AAAA".into(),
                    value: ips.join(","),
                    severity: DnsSeverity::Info,
                    planned: false,
                });
            }
            Ok((_, Err(_))) => {}
            Err(e) => {
                let _ = events.publish(ModuleEvent::Log {
                    job_id,
                    level: LogLevel::Warn,
                    message: format!("wordlist worker: {e}"),
                });
            }
        }
    }
    hits
}

async fn fetch_ct(config: &DnsConfig) -> Result<Vec<DnsHit>, String> {
    let client = Client::builder()
        .timeout(config.timeout)
        .connect_timeout(config.timeout)
        .user_agent("keld-dns/0.1")
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "{}/?q=%25.{}&output=json",
        config.ct_base_url.trim_end_matches('/'),
        config.domain
    );
    let body = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;

    let trimmed = body.trim_start();
    if !trimmed.starts_with('[') && !trimmed.starts_with('{') {
        return Err("ct response was not JSON".into());
    }

    let names = parse_ct_json(&body, &config.domain);
    Ok(names
        .into_iter()
        .map(|name| DnsHit {
            kind: DnsKind::Ct,
            name,
            rtype: "CT".into(),
            value: "certificate-transparency".into(),
            severity: DnsSeverity::Info,
            planned: false,
        })
        .collect())
}

/// Parse crt.sh JSON into unique hostnames under `domain`.
pub fn parse_ct_json(body: &str, domain: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let entries = match value {
        serde_json::Value::Array(a) => a,
        _ => return Vec::new(),
    };
    let domain_l = domain.to_ascii_lowercase();
    let mut set = BTreeSet::new();
    for entry in entries {
        for key in ["name_value", "common_name"] {
            let Some(raw) = entry.get(key).and_then(|v| v.as_str()) else {
                continue;
            };
            for line in raw.split(['\n', '\r']) {
                let name = line.trim().trim_start_matches("*.").to_ascii_lowercase();
                if name.is_empty() || name.contains(' ') {
                    continue;
                }
                if name == domain_l || name.ends_with(&format!(".{domain_l}")) {
                    set.insert(name);
                }
            }
        }
    }
    set.into_iter().collect()
}

fn rdata_display(data: &RData) -> String {
    data.to_string().trim_end_matches('.').to_string()
}

fn load_wordlist(path: &Path) -> Result<Vec<String>, DnsError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| DnsError::Wordlist(format!("{}: {e}", path.display())))?;
    let words: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    if words.is_empty() {
        return Err(DnsError::Wordlist("wordlist has no usable entries".into()));
    }
    Ok(words)
}

fn normalize_domain(raw: &str) -> Result<String, DnsError> {
    let trimmed = raw.trim().trim_end_matches('.');
    let host = if let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
    {
        rest.split(['/', ':', '?', '#'])
            .next()
            .unwrap_or(rest)
            .trim_matches(|c| c == '[' || c == ']')
    } else {
        trimmed
            .split(['/', ':', '?', '#'])
            .next()
            .unwrap_or(trimmed)
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(DnsError::InvalidDomain {
            domain: raw.to_string(),
            reason: "empty".into(),
        });
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err(DnsError::InvalidDomain {
            domain: raw.to_string(),
            reason: "expected a domain name, not an IP".into(),
        });
    }
    if Name::from_str(&ensure_dot(&host)).is_err() {
        return Err(DnsError::InvalidDomain {
            domain: raw.to_string(),
            reason: "invalid DNS name".into(),
        });
    }
    Ok(host)
}

fn ensure_dot(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// Parse a Result summary back into a [`DnsHit`] (TUI worker bridge).
pub fn parse_dns_summary(summary: &str) -> Option<DnsHit> {
    if let Some(rest) = summary.strip_prefix("would dns ") {
        let kind = DnsKind::parse(take_after(rest, "kind=")?)?;
        let after_kind = after_space(rest, "kind=")?;
        let name = take_after(after_kind, "name=")?.to_string();
        let after_name = after_space(after_kind, "name=")?;
        let rtype = take_after(after_name, "type=")?.to_string();
        let after_type = after_space(after_name, "type=")?;
        let value = after_type.strip_prefix("value=")?.to_string();
        return Some(DnsHit {
            kind,
            name,
            rtype,
            value,
            severity: DnsSeverity::Info,
            planned: true,
        });
    }

    let kind = DnsKind::parse(take_after(summary, "kind=")?)?;
    let after_kind = after_space(summary, "kind=")?;
    let severity = DnsSeverity::parse(take_after(after_kind, "sev=")?)?;
    let after_sev = after_space(after_kind, "sev=")?;
    let name = take_after(after_sev, "name=")?.to_string();
    let after_name = after_space(after_sev, "name=")?;
    let rtype = take_after(after_name, "type=")?.to_string();
    let after_type = after_space(after_name, "type=")?;
    let value = after_type.strip_prefix("value=")?.to_string();
    Some(DnsHit {
        kind,
        name,
        rtype,
        value,
        severity,
        planned: false,
    })
}

fn take_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let rest = s.find(key).map(|i| &s[i + key.len()..])?;
    Some(rest.split_once(' ').map_or(rest, |(a, _)| a))
}

fn after_space<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let rest = s.find(key).map(|i| &s[i + key.len()..])?;
    let val_end = rest.find(' ')?;
    Some(rest[val_end + 1..].trim_start())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{EventBus, Scope, ScopeEntry};
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    fn example_scope() -> Scope {
        Scope {
            includes: vec![ScopeEntry::Host("example.test".into())],
            excludes: Vec::new(),
            notes: None,
            source: None,
        }
    }

    fn write_wordlist(words: &[&str]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "keld-dns-words-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        for w in words {
            writeln!(f, "{w}").unwrap();
        }
        path
    }

    #[test]
    fn normalize_strips_url() {
        assert_eq!(
            normalize_domain("https://Example.TEST/path").unwrap(),
            "example.test"
        );
    }

    #[test]
    fn parse_ct_extracts_unique() {
        let json = r#"[{"name_value":"www.example.test\napi.example.test","common_name":"www.example.test"},{"name_value":"*.example.test"}]"#;
        let names = parse_ct_json(json, "example.test");
        assert!(names.contains(&"www.example.test".into()));
        assert!(names.contains(&"api.example.test".into()));
        assert!(names.contains(&"example.test".into()));
    }

    #[test]
    fn parse_roundtrip() {
        let hit = DnsHit {
            kind: DnsKind::Record,
            name: "example.test".into(),
            rtype: "A".into(),
            value: "127.0.0.1".into(),
            severity: DnsSeverity::Info,
            planned: false,
        };
        assert_eq!(parse_dns_summary(&hit.summary_line()).unwrap(), hit);
        let planned = DnsHit {
            kind: DnsKind::Ct,
            name: "example.test".into(),
            rtype: "CT".into(),
            value: "https://crt.sh/?q=%25.example.test&output=json".into(),
            severity: DnsSeverity::Info,
            planned: true,
        };
        assert_eq!(parse_dns_summary(&planned.summary_line()).unwrap(), planned);
    }

    #[tokio::test]
    async fn dry_run_plans_without_network() {
        let wl = write_wordlist(&["www", "mail"]);
        let bus = EventBus::new(64);
        let mut cfg = DnsConfig::from_parts(
            "example.test",
            Some(wl.clone()),
            true,
            DnsRunOpts {
                timeout_ms: 200,
                concurrency: 2,
                dry_run: true,
                rate_per_sec: None,
            },
        )
        .unwrap();
        cfg.ct_base_url = "http://127.0.0.1:9".into();
        let module = DnsModule::new(cfg, example_scope());
        let hits = module.run_dns(JobId::new(1), bus.sender()).await.unwrap();
        assert!(hits.iter().all(|h| h.planned));
        assert!(hits.iter().any(|h| h.kind == DnsKind::Record));
        assert!(hits.iter().any(|h| h.kind == DnsKind::Axfr));
        assert!(hits.iter().any(|h| h.kind == DnsKind::Subdomain));
        assert!(hits.iter().any(|h| h.kind == DnsKind::Ct));
        let _ = std::fs::remove_file(wl);
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let bus = EventBus::new(16);
        let cfg = DnsConfig::from_parts(
            "evil.test",
            None,
            false,
            DnsRunOpts {
                timeout_ms: 200,
                concurrency: 1,
                dry_run: true,
                rate_per_sec: None,
            },
        )
        .unwrap();
        let module = DnsModule::new(cfg, example_scope());
        let err = module
            .run_dns(JobId::new(2), bus.sender())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            DnsError::Scope(ScopeError::OutOfScope { .. })
        ));
    }

    /// Minimal UDP DNS: answers A for host.example.test and NS pointing at ns.example.test.
    async fn spawn_udp_dns() -> SocketAddr {
        let sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(req) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let mut resp = Message::response(req.metadata.id, OpCode::Query);
                resp.metadata.authoritative = true;
                for q in req.queries.clone() {
                    resp.add_query(q.clone());
                    let qname = q.name.to_string().to_ascii_lowercase();
                    let qname = qname.trim_end_matches('.').to_string();
                    match q.query_type() {
                        RecordType::A if qname == "example.test" || qname == "www.example.test" => {
                            let rec = hickory_proto::rr::Record::from_rdata(
                                q.name.clone(),
                                60,
                                RData::A(hickory_proto::rr::rdata::A::new(127, 0, 0, 1)),
                            );
                            resp.add_answer(rec);
                        }
                        RecordType::NS if qname == "example.test" => {
                            let ns = Name::from_str("ns.example.test.").unwrap();
                            let rec = hickory_proto::rr::Record::from_rdata(
                                q.name.clone(),
                                60,
                                RData::NS(hickory_proto::rr::rdata::NS(ns)),
                            );
                            resp.add_answer(rec);
                        }
                        RecordType::A if qname == "ns.example.test" => {
                            let rec = hickory_proto::rr::Record::from_rdata(
                                q.name.clone(),
                                60,
                                RData::A(hickory_proto::rr::rdata::A::new(127, 0, 0, 1)),
                            );
                            resp.add_answer(rec);
                        }
                        _ => {
                            resp.metadata.response_code = ResponseCode::NXDomain;
                        }
                    }
                }
                if let Ok(bytes) = resp.to_vec() {
                    let _ = sock.send_to(&bytes, peer).await;
                }
            }
        });
        addr
    }

    async fn spawn_tcp_axfr_refused(port_hint: u16) -> SocketAddr {
        // Bind TCP on same port as UDP when possible; else any port (AXFR uses config resolvers port).
        let listener = match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port_hint))).await
        {
            Ok(l) => l,
            Err(_) => TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap(),
        };
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if tcp.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len.min(4096)];
                    if tcp.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let Ok(req) = Message::from_vec(&body) else {
                        return;
                    };
                    let mut resp = Message::response(req.metadata.id, OpCode::Query);
                    resp.metadata.response_code = ResponseCode::Refused;
                    for q in req.queries {
                        resp.add_query(q);
                    }
                    let Ok(bytes) = resp.to_vec() else {
                        return;
                    };
                    let mut out = Vec::new();
                    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(&bytes);
                    let _ = tcp.write_all(&out).await;
                });
            }
        });
        addr
    }

    async fn spawn_ct_server(json: &str) -> String {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let body = json.to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = tcp.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tcp.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://{}", addr)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn records_axfr_wordlist_and_ct_against_local() {
        let dns_addr = spawn_udp_dns().await;
        let tcp_addr = spawn_tcp_axfr_refused(dns_addr.port()).await;
        // Prefer shared UDP/TCP port; if TCP landed elsewhere, point resolvers at UDP and AXFR at TCP via same IP:udp_port expectation.
        // Our axfr_probe uses resolvers[0].port(), so bind TCP on the UDP port when possible.
        let resolver_addr = if tcp_addr.port() == dns_addr.port() {
            dns_addr
        } else {
            // Fallback: only UDP port for lookups; AXFR will use that port (may fail connect -> error hit).
            dns_addr
        };
        let ct_base = spawn_ct_server(
            r#"[{"name_value":"www.example.test\nmail.example.test","common_name":"www.example.test"}]"#,
        )
        .await;

        let wl = write_wordlist(&["www", "ghost"]);
        let bus = EventBus::new(256);
        let mut cfg = DnsConfig::from_parts(
            "example.test",
            Some(wl.clone()),
            true,
            DnsRunOpts {
                timeout_ms: 2_000,
                concurrency: 4,
                dry_run: false,
                rate_per_sec: None,
            },
        )
        .unwrap();
        cfg.resolvers = vec![resolver_addr];
        cfg.ct_base_url = ct_base;

        let module = DnsModule::new(cfg, example_scope());
        let hits = module.run_dns(JobId::new(3), bus.sender()).await.unwrap();

        assert!(
            hits.iter()
                .any(|h| h.kind == DnsKind::Record && h.rtype == "A"),
            "expected A record, got {hits:?}"
        );
        assert!(
            hits.iter().any(|h| h.kind == DnsKind::Axfr),
            "expected AXFR result, got {hits:?}"
        );
        if tcp_addr.port() == dns_addr.port() {
            assert!(
                hits.iter()
                    .any(|h| h.kind == DnsKind::Axfr && h.value.contains("REFUSED")),
                "expected REFUSED AXFR, got {hits:?}"
            );
        }
        assert!(
            hits.iter()
                .any(|h| h.kind == DnsKind::Subdomain && h.name == "www.example.test"),
            "expected www subdomain, got {hits:?}"
        );
        assert!(
            hits.iter()
                .any(|h| h.kind == DnsKind::Ct && h.name == "mail.example.test"),
            "expected CT name, got {hits:?}"
        );
        let _ = std::fs::remove_file(wl);
        let _ = Ipv4Addr::LOCALHOST; // silence unused in some cfgs
    }
}
