//! TCP connect port scanner (authorized targets only).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use keld_core::{
    EventSender, JobId, LogLevel, ModuleEvent, ModuleKind, RateLimiter, Scope, ScopeError,
};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::ports::{parse_ports, PortParseError};
use crate::Module;

/// Default connect timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 1_000;
/// Default concurrent connect attempts.
pub const DEFAULT_CONCURRENCY: usize = 100;

/// Configuration for one TCP connect scan job.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dry_run: bool,
    /// Optional max connect starts per second.
    pub rate_per_sec: Option<u32>,
}

impl ScanConfig {
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
            "ports={} timeout_ms={} concurrency={} dry_run={} rate={}",
            self.ports.len(),
            self.timeout.as_millis(),
            self.concurrency,
            self.dry_run,
            self.rate_per_sec
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into())
        )
    }
}

/// One open-port hit (also used as dry-run planned probe summary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortHit {
    pub host: String,
    pub port: u16,
    pub state: PortState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Planned,
}

impl PortState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Planned => "planned",
        }
    }
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Ports(#[from] PortParseError),
    #[error("failed to resolve `{target}`: {message}")]
    Resolve { target: String, message: String },
    #[error("no addresses for `{target}`")]
    NoAddress { target: String },
}

/// TCP connect scanner module.
#[derive(Debug, Clone)]
pub struct ScanModule {
    pub config: ScanConfig,
    pub scope: Scope,
}

impl ScanModule {
    pub fn new(config: ScanConfig, scope: Scope) -> Self {
        Self { config, scope }
    }

    /// Resolve, scope-check, then scan (or dry-run). Publishes events on `events`.
    pub async fn run_scan(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<PortHit>, ScanError> {
        self.scope.check(&self.config.target)?;

        if self.config.dry_run {
            return Ok(self.emit_dry_run(job_id, &events).await);
        }

        let addrs = resolve_addrs(&self.config.target).await?;
        let addr = *addrs.first().ok_or_else(|| ScanError::NoAddress {
            target: self.config.target.clone(),
        })?;

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
                let state = probe_tcp(sock, timeout_d).await;
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: n,
                    total,
                    message: format!("{host}:{port} {state}"),
                });
                (host, port, state)
            }));
        }

        for handle in handles {
            match handle.await {
                Ok((host, port, state)) => {
                    if state == PortState::Open {
                        let summary = format!("{host}:{port} open");
                        let _ = events.publish(ModuleEvent::Result {
                            job_id,
                            summary: summary.clone(),
                        });
                        hits.push(PortHit { host, port, state });
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
        Ok(hits)
    }

    async fn emit_dry_run(&self, job_id: JobId, events: &EventSender) -> Vec<PortHit> {
        let total = self.config.ports.len() as u64;
        let mut planned = Vec::with_capacity(self.config.ports.len());
        for (i, port) in self.config.ports.iter().copied().enumerate() {
            let done = (i as u64) + 1;
            let summary = format!("would connect {}:{}", self.config.target, port);
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done,
                total,
                message: summary.clone(),
            });
            let _ = events.publish(ModuleEvent::Result { job_id, summary });
            planned.push(PortHit {
                host: self.config.target.clone(),
                port,
                state: PortState::Planned,
            });
        }
        let _ = events.publish(ModuleEvent::Done { job_id });
        planned
    }
}

impl Module for ScanModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Scan
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_scan(job_id, events.clone()).await {
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

async fn resolve_addrs(target: &str) -> Result<Vec<SocketAddr>, ScanError> {
    // Allow host or host:ignored-port; we set ports ourselves.
    let host = target.split_once(':').map(|(h, _)| h).unwrap_or(target);
    let lookup = format!("{host}:0");
    let resolved = tokio::net::lookup_host(lookup.as_str())
        .await
        .map_err(|e| ScanError::Resolve {
            target: target.into(),
            message: e.to_string(),
        })?;
    let v: Vec<_> = resolved.collect();
    if v.is_empty() {
        Err(ScanError::NoAddress {
            target: target.into(),
        })
    } else {
        Ok(v)
    }
}

async fn probe_tcp(addr: SocketAddr, connect_timeout: Duration) -> PortState {
    match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        Ok(Err(_)) => PortState::Filtered,
        Err(_) => PortState::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{EventBus, Job, JobState, Scope, ScopeEntry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    async fn dry_run_emits_planned_without_connect() {
        let bus = EventBus::new(256);
        let mut rx = bus.subscribe();
        let cfg = ScanConfig::from_parts("127.0.0.1", "22,80", 200, 4, true, None).unwrap();
        let module = ScanModule::new(cfg, loopback_scope());
        let id = JobId::new(1);
        let hits = module.run_scan(id, bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.state == PortState::Planned));

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
        let cfg = ScanConfig::from_parts("8.8.8.8", "53", 200, 1, true, None).unwrap();
        let module = ScanModule::new(cfg, loopback_scope());
        let err = module
            .run_scan(JobId::new(2), bus.sender())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ScanError::Scope(ScopeError::OutOfScope { .. })
        ));
    }

    #[tokio::test]
    async fn finds_open_local_listener() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
        });

        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let cfg =
            ScanConfig::from_parts("127.0.0.1", &port.to_string(), 500, 2, false, None).unwrap();
        let module = ScanModule::new(cfg, loopback_scope());
        let id = JobId::new(3);
        let mut job = Job::new(id, ModuleKind::Scan);
        job.start().unwrap();

        let hits = module.run_scan(id, bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].port, port);
        assert_eq!(hits[0].state, PortState::Open);

        while let Ok(ev) = rx.try_recv() {
            let _ = job.apply_event(&ev);
        }
        assert_eq!(job.state, JobState::Completed);
        assert_eq!(job.results, 1);

        accept.await.unwrap();
    }

    #[tokio::test]
    async fn closed_port_not_reported_as_result() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let open = listener.local_addr().unwrap().port();
        // Pick a different high port unlikely to be open; connect should refuse/filter.
        let closed = if open == 65432 { 65431 } else { 65432 };

        let bus = EventBus::new(64);
        let ports = format!("{open},{closed}");
        let cfg = ScanConfig::from_parts("127.0.0.1", &ports, 200, 4, false, None).unwrap();
        let module = ScanModule::new(cfg, loopback_scope());
        // Keep listener alive without accepting (still "open" for connect on some OSes
        // until backlog fills; accepting once is safer).
        let accept = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
        });
        let hits = module.run_scan(JobId::new(4), bus.sender()).await.unwrap();
        assert!(hits.iter().all(|h| h.port == open));
        accept.await.unwrap();
    }
}
