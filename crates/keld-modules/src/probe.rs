//! Banner / service detection for authorized targets.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use keld_core::{
    EventSender, JobId, LogLevel, ModuleEvent, ModuleKind, RateLimiter, Scope, ScopeError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::ports::{parse_ports, PortParseError};
use crate::signatures::SignatureDb;
use crate::Module;

/// Default read/connect timeout.
pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 2_000;
/// Default concurrent probe workers.
pub const DEFAULT_PROBE_CONCURRENCY: usize = 32;
/// Max banner bytes kept per hit.
const BANNER_CAP: usize = 512;

/// Configuration for one probe job.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
}

impl ProbeConfig {
    /// Build from CLI/TUI strings; ports default to `top` when empty.
    pub fn from_parts(
        target: impl Into<String>,
        ports_spec: &str,
        timeout_ms: u64,
        concurrency: usize,
        dry_run: bool,
        rate_per_sec: Option<u32>,
    ) -> Result<Self, PortParseError> {
        let spec = if ports_spec.trim().is_empty() {
            "top"
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
        })
    }

    /// Short parameters line for audit / status.
    pub fn parameters_summary(&self) -> String {
        format!(
            "ports={} timeout_ms={} concurrency={} dry_run={} rate={} signatures={}",
            self.ports.len(),
            self.timeout.as_millis(),
            self.concurrency,
            self.dry_run,
            self.rate_per_sec
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into()),
            SignatureDb::embedded().probes.len()
        )
    }
}

/// One service/banner hit (or dry-run plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeHit {
    pub host: String,
    pub port: u16,
    pub service: String,
    pub product: String,
    pub banner: String,
    pub probe_name: String,
    pub planned: bool,
}

impl ProbeHit {
    /// Compact summary used on the event bus and in TUI parsing.
    pub fn summary_line(&self) -> String {
        if self.planned {
            return format!(
                "would probe {}:{} ({})",
                self.host, self.port, self.probe_name
            );
        }
        let banner = truncate_banner(&self.banner, 80);
        format!(
            "{}:{} {} {} [{}] {}",
            self.host, self.port, self.service, self.product, self.probe_name, banner
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Ports(#[from] PortParseError),
    #[error("failed to resolve `{target}`: {message}")]
    Resolve { target: String, message: String },
    #[error("no addresses for `{target}`")]
    NoAddress { target: String },
}

/// Banner / service probe module.
#[derive(Debug, Clone)]
pub struct ProbeModule {
    pub config: ProbeConfig,
    pub scope: Scope,
}

impl ProbeModule {
    pub fn new(config: ProbeConfig, scope: Scope) -> Self {
        Self { config, scope }
    }

    /// Resolve, scope-check, then probe (or dry-run).
    pub async fn run_probe(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<ProbeHit>, ProbeError> {
        self.scope.check(&self.config.target)?;

        if self.config.dry_run {
            return Ok(self.emit_dry_run(job_id, &events).await);
        }

        let addrs = resolve_addrs(&self.config.target).await?;
        let addr = *addrs.first().ok_or_else(|| ProbeError::NoAddress {
            target: self.config.target.clone(),
        })?;

        let db = SignatureDb::embedded();
        let total = self.config.ports.len() as u64;
        let done = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let mut rate = RateLimiter::per_second(self.config.rate_per_sec);
        let mut hits = Vec::new();
        let mut handles = Vec::with_capacity(self.config.ports.len());

        for port in self.config.ports.iter().copied() {
            rate.wait().await;
            let permit = sem.clone().acquire_owned().await.expect("semaphore open");
            let events = events.clone();
            let done = done.clone();
            let host = self.config.target.clone();
            let timeout_d = self.config.timeout;
            let mut sock = addr;
            sock.set_port(port);

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let hit = probe_one(db, &host, port, sock, timeout_d).await;
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                let message = match &hit {
                    Some(h) => h.summary_line(),
                    None => format!("{host}:{port} no-match"),
                };
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: n,
                    total,
                    message,
                });
                hit
            }));
        }

        for handle in handles {
            match handle.await {
                Ok(Some(hit)) => {
                    let summary = hit.summary_line();
                    let _ = events.publish(ModuleEvent::Result {
                        job_id,
                        summary: summary.clone(),
                    });
                    hits.push(hit);
                }
                Ok(None) => {}
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
        Ok(hits)
    }

    async fn emit_dry_run(&self, job_id: JobId, events: &EventSender) -> Vec<ProbeHit> {
        let db = SignatureDb::embedded();
        let total = self.config.ports.len() as u64;
        let mut planned = Vec::new();
        for (i, port) in self.config.ports.iter().copied().enumerate() {
            let probes = db.probes_for(port);
            let names: Vec<&str> = probes.iter().map(|p| p.name.as_str()).collect();
            let probe_name = if names.is_empty() {
                "none".into()
            } else {
                names.join("+")
            };
            let hit = ProbeHit {
                host: self.config.target.clone(),
                port,
                service: "planned".into(),
                product: "-".into(),
                banner: String::new(),
                probe_name,
                planned: true,
            };
            let done = (i as u64) + 1;
            let summary = hit.summary_line();
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done,
                total,
                message: summary.clone(),
            });
            let _ = events.publish(ModuleEvent::Result { job_id, summary });
            planned.push(hit);
        }
        let _ = events.publish(ModuleEvent::Done { job_id });
        planned
    }
}

impl Module for ProbeModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Probe
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_probe(job_id, events.clone()).await {
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

pub(crate) async fn probe_one(
    db: &SignatureDb,
    host: &str,
    port: u16,
    addr: SocketAddr,
    timeout_d: Duration,
) -> Option<ProbeHit> {
    let probes = db.probes_for(port);
    if probes.is_empty() {
        return None;
    }

    // One TCP session: listen for a banner, then send port-specific payloads.
    let stream = match timeout(timeout_d, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let mut stream = stream;
    let _ = stream.set_nodelay(true);

    for probe in probes {
        if !probe.payload.is_empty() {
            if timeout(timeout_d, stream.write_all(&probe.payload))
                .await
                .ok()
                .and_then(Result::ok)
                .is_none()
            {
                break;
            }
            let _ = stream.flush().await;
        }

        let mut buf = vec![0u8; BANNER_CAP];
        let n = match timeout(timeout_d, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
            Err(_) => {
                // No data for this probe; try next payload on same connection when possible.
                continue;
            }
        };
        if n == 0 {
            continue;
        }
        buf.truncate(n);
        if let Some(m) = db.match_response(probe, &buf) {
            return Some(ProbeHit {
                host: host.to_string(),
                port,
                service: m.service.clone(),
                product: m.product.clone(),
                banner: sanitize_banner(&buf),
                probe_name: probe.name.clone(),
                planned: false,
            });
        }
        // Unmatched banner still useful when this was the null listen.
        if probe.payload.is_empty() && !buf.is_empty() {
            return Some(ProbeHit {
                host: host.to_string(),
                port,
                service: "unknown".into(),
                product: "-".into(),
                banner: sanitize_banner(&buf),
                probe_name: probe.name.clone(),
                planned: false,
            });
        }
    }
    None
}

fn sanitize_banner(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else if c.is_control() {
                '.'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn truncate_banner(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

async fn resolve_addrs(target: &str) -> Result<Vec<SocketAddr>, ProbeError> {
    let host = target.split_once(':').map(|(h, _)| h).unwrap_or(target);
    let lookup = format!("{host}:0");
    let resolved = tokio::net::lookup_host(lookup.as_str())
        .await
        .map_err(|e| ProbeError::Resolve {
            target: target.into(),
            message: e.to_string(),
        })?;
    let v: Vec<_> = resolved.collect();
    if v.is_empty() {
        Err(ProbeError::NoAddress {
            target: target.into(),
        })
    } else {
        Ok(v)
    }
}

/// Parse a Result summary back into a [`ProbeHit`] (TUI worker bridge).
pub fn parse_probe_summary(summary: &str) -> Option<ProbeHit> {
    if let Some(rest) = summary.strip_prefix("would probe ") {
        // host:port (probe+names)
        let (addr, probes) = rest.rsplit_once(" (")?;
        let probes = probes.strip_suffix(')')?;
        let (host, port_s) = addr.rsplit_once(':')?;
        let port: u16 = port_s.parse().ok()?;
        return Some(ProbeHit {
            host: host.to_string(),
            port,
            service: "planned".into(),
            product: "-".into(),
            banner: String::new(),
            probe_name: probes.to_string(),
            planned: true,
        });
    }
    // host:port service product [probe] banner...
    let mut parts = summary.splitn(5, ' ');
    let addr = parts.next()?;
    let service = parts.next()?.to_string();
    let product = parts.next()?.to_string();
    let probe_bracket = parts.next()?;
    let banner = parts.next().unwrap_or("").to_string();
    let probe_name = probe_bracket
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))?
        .to_string();
    let (host, port_s) = addr.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    Some(ProbeHit {
        host: host.to_string(),
        port,
        service,
        product,
        banner,
        probe_name,
        planned: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{EventBus, Job, JobState, Scope, ScopeEntry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

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

    #[tokio::test]
    async fn dry_run_plans_without_connect() {
        let bus = EventBus::new(256);
        let mut rx = bus.subscribe();
        let cfg = ProbeConfig::from_parts("127.0.0.1", "22,80", 200, 4, true, None).unwrap();
        let module = ProbeModule::new(cfg, loopback_scope());
        let hits = module.run_probe(JobId::new(1), bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.planned));
        assert!(hits[0].probe_name.contains("null"));
        assert!(hits[1].probe_name.contains("httpget"));

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
        let cfg = ProbeConfig::from_parts("8.8.8.8", "53", 200, 1, true, None).unwrap();
        let module = ProbeModule::new(cfg, loopback_scope());
        let err = module
            .run_probe(JobId::new(2), bus.sender())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProbeError::Scope(ScopeError::OutOfScope { .. })
        ));
    }

    #[tokio::test]
    async fn detects_ssh_banner() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
            let mut buf = [0u8; 16];
            let _ = stream.read(&mut buf).await;
        });

        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg =
            ProbeConfig::from_parts("127.0.0.1", &port.to_string(), 500, 2, false, None).unwrap();
        let module = ProbeModule::new(cfg, loopback_scope());
        let id = JobId::new(3);
        let mut job = Job::new(id, ModuleKind::Probe);
        job.start().unwrap();

        let hits = module.run_probe(id, bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].service, "ssh");
        assert!(hits[0].banner.contains("SSH-2.0"));

        while let Ok(ev) = rx.try_recv() {
            let _ = job.apply_event(&ev);
        }
        assert_eq!(job.state, JobState::Completed);
        assert_eq!(job.results, 1);

        accept.await.unwrap();
    }

    #[tokio::test]
    async fn detects_http_via_get_probe() {
        let db = SignatureDb::parse(
            r#"
probe null ports=* payload=
probe httpget ports=* payload=GET / HTTP/1.0\r\n\r\n
match httpget http m/^HTTP\/1\.[01]/i product=http
"#,
        )
        .unwrap();

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut req = vec![0u8; 256];
            // Client null-reads first (times out), then sends GET.
            loop {
                match timeout(Duration::from_millis(400), stream.read(&mut req)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(_)) => {
                        stream
                            .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                        break;
                    }
                    Ok(Err(_)) => break,
                    Err(_) => continue,
                }
            }
        });

        let hit = probe_one(
            &db,
            "127.0.0.1",
            addr.port(),
            addr,
            Duration::from_millis(600),
        )
        .await
        .expect("http hit");
        assert_eq!(hit.service, "http");
        assert_eq!(hit.probe_name, "httpget");
        accept.await.unwrap();
    }

    #[test]
    fn summary_roundtrip() {
        let planned = parse_probe_summary("would probe 10.0.0.5:22 (null)").unwrap();
        assert!(planned.planned);
        assert_eq!(planned.port, 22);
        let real = parse_probe_summary("10.0.0.5:22 ssh ssh [null] SSH-2.0-OpenSSH").unwrap();
        assert_eq!(real.service, "ssh");
        assert_eq!(real.banner, "SSH-2.0-OpenSSH");
    }
}
