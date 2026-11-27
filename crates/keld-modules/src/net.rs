//! Local interface listing and authorized subnet host discovery.
//!
//! Discovery cascade (Auto): ARP when a link-layer send path exists, else ICMP
//! when a raw ICMP socket opens, else TCP connect to probe ports. Windows does
//! not inject ARP frames (Npcap is reported only). Modules emit events only.

use std::future::Future;
use std::io::{self, ErrorKind};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use keld_core::{
    EventSender, JobId, LogLevel, ModuleEvent, ModuleKind, RateLimiter, Scope, ScopeError,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::Module;

/// Default connect / ICMP timeout.
pub const DEFAULT_NET_TIMEOUT_MS: u64 = 1_000;
/// Default concurrent host probes.
pub const DEFAULT_NET_CONCURRENCY: usize = 64;
/// Hard cap on hosts expanded from a CIDR (refuse larger ranges).
pub const MAX_DISCOVERY_HOSTS: usize = 1_024;
/// Default TCP probe ports when ICMP/ARP are unavailable.
pub const DEFAULT_PROBE_PORTS: &[u16] = &[80, 443, 22, 445];

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_HEADER_LEN: usize = 8;

/// How the operator asked to discover hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverTechnique {
    Auto,
    Arp,
    Icmp,
    Tcp,
}

impl DiscoverTechnique {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Arp => "arp",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "default" => Some(Self::Auto),
            "arp" => Some(Self::Arp),
            "icmp" | "ping" => Some(Self::Icmp),
            "tcp" | "connect" => Some(Self::Tcp),
            _ => None,
        }
    }
}

/// Which method actually marked a host up (or was planned in dry-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverMethod {
    Arp,
    Icmp,
    Tcp,
    Interface,
}

impl DiscoverMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Interface => "iface",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "arp" => Some(Self::Arp),
            "icmp" | "ping" => Some(Self::Icmp),
            "tcp" | "connect" => Some(Self::Tcp),
            "iface" | "interface" => Some(Self::Interface),
            _ => None,
        }
    }
}

/// Runtime facts for ARP / ICMP / TCP discovery (shared with doctor / TUI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverAvailability {
    pub arp_usable: bool,
    pub icmp_usable: bool,
    pub elevated: bool,
    pub npcap_present: bool,
    pub arp_detail: String,
    pub icmp_detail: String,
}

impl DiscoverAvailability {
    /// Probe elevation and whether privileged discovery sockets open.
    pub fn probe() -> Self {
        let elevated = is_elevated();
        let npcap_present = npcap_dll_present();
        let (arp_usable, arp_detail) = probe_arp(elevated, npcap_present);
        let (icmp_usable, icmp_detail) = probe_icmp();
        Self {
            arp_usable,
            icmp_usable,
            elevated,
            npcap_present,
            arp_detail,
            icmp_detail,
        }
    }
}

/// Chosen method after applying a request to probed capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverDecision {
    pub requested: DiscoverTechnique,
    pub primary: DiscoverMethod,
    pub fallback_note: Option<String>,
}

/// Resolve Auto/Arp/Icmp/Tcp against [`DiscoverAvailability`].
pub fn decide_discover(
    requested: DiscoverTechnique,
    avail: &DiscoverAvailability,
) -> DiscoverDecision {
    match requested {
        DiscoverTechnique::Tcp => DiscoverDecision {
            requested,
            primary: DiscoverMethod::Tcp,
            fallback_note: None,
        },
        DiscoverTechnique::Icmp => {
            if avail.icmp_usable {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Icmp,
                    fallback_note: None,
                }
            } else {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Tcp,
                    fallback_note: Some(format!(
                        "ICMP unavailable: {}. Using TCP connect.",
                        avail.icmp_detail
                    )),
                }
            }
        }
        DiscoverTechnique::Arp => {
            if avail.arp_usable {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Arp,
                    fallback_note: None,
                }
            } else if avail.icmp_usable {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Icmp,
                    fallback_note: Some(format!(
                        "ARP unavailable: {}. Using ICMP.",
                        avail.arp_detail
                    )),
                }
            } else {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Tcp,
                    fallback_note: Some(format!(
                        "ARP unavailable: {}. ICMP unavailable: {}. Using TCP connect.",
                        avail.arp_detail, avail.icmp_detail
                    )),
                }
            }
        }
        DiscoverTechnique::Auto => {
            if avail.arp_usable {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Arp,
                    fallback_note: None,
                }
            } else if avail.icmp_usable {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Icmp,
                    fallback_note: Some(format!(
                        "ARP unavailable: {}. Using ICMP.",
                        avail.arp_detail
                    )),
                }
            } else {
                DiscoverDecision {
                    requested,
                    primary: DiscoverMethod::Tcp,
                    fallback_note: Some(format!(
                        "ARP unavailable: {}. ICMP unavailable: {}. Using TCP connect.",
                        avail.arp_detail, avail.icmp_detail
                    )),
                }
            }
        }
    }
}

/// One local interface address row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub addr: IpAddr,
    pub prefix: Option<u8>,
    pub is_loopback: bool,
}

/// One discovery finding (or dry-run plan / interface row as hit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetHit {
    pub method: DiscoverMethod,
    pub target: String,
    pub detail: String,
    pub planned: bool,
}

impl NetHit {
    pub fn summary_line(&self) -> String {
        if self.planned {
            return format!(
                "would net method={} target={} detail={}",
                self.method.as_str(),
                self.target,
                self.detail
            );
        }
        format!(
            "method={} target={} detail={}",
            self.method.as_str(),
            self.target,
            self.detail
        )
    }
}

/// Timeout, concurrency, dry-run, and rate for a net job.
#[derive(Debug, Clone)]
pub struct NetRunOpts {
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
}

impl Default for NetRunOpts {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_NET_TIMEOUT_MS,
            concurrency: DEFAULT_NET_CONCURRENCY,
            dry_run: false,
            rate_per_sec: None,
        }
    }
}

/// Configuration for one net job (interfaces-only or discover).
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// CIDR or single IP for discovery. `None` = list interfaces only.
    pub target: Option<String>,
    pub technique: DiscoverTechnique,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
    /// Injected capability for tests (`None` = probe at run time).
    pub availability: Option<DiscoverAvailability>,
}

impl NetConfig {
    pub fn from_parts(
        target: Option<String>,
        technique: DiscoverTechnique,
        ports: impl AsRef<str>,
        run: NetRunOpts,
    ) -> Result<Self, NetError> {
        let target = match target {
            None => None,
            Some(t) => {
                let t = t.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(normalize_net_target(t)?)
                }
            }
        };
        let ports = parse_probe_ports(ports.as_ref())?;
        Ok(Self {
            target,
            technique,
            ports,
            timeout: Duration::from_millis(run.timeout_ms.max(1)),
            concurrency: run.concurrency.max(1),
            dry_run: run.dry_run,
            rate_per_sec: run.rate_per_sec,
            availability: None,
        })
    }

    pub fn parameters_summary(&self) -> String {
        format!(
            "target={} technique={} ports={} timeout_ms={} concurrency={} dry_run={} rate={}",
            self.target.as_deref().unwrap_or("(ifaces)"),
            self.technique.as_str(),
            ports_csv(&self.ports),
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
pub enum NetError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error("invalid target `{target}`: {reason}")]
    InvalidTarget { target: String, reason: String },
    #[error("invalid ports `{ports}`: {reason}")]
    InvalidPorts { ports: String, reason: String },
    #[error("discovery range too large ({count} hosts); max is {max}")]
    RangeTooLarge { count: usize, max: usize },
    #[error("interfaces: {0}")]
    Interfaces(String),
}

/// Net interfaces + discovery module.
#[derive(Debug, Clone)]
pub struct NetModule {
    pub config: NetConfig,
    pub scope: Scope,
}

impl NetModule {
    pub fn new(config: NetConfig, scope: Scope) -> Self {
        Self { config, scope }
    }

    /// List interfaces and/or discover hosts in scope (or dry-run).
    pub async fn run_net(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<NetHit>, NetError> {
        if let Some(target) = &self.config.target {
            self.scope.check(target)?;
        }

        if self.config.dry_run {
            return Ok(self.emit_dry_run(job_id, &events).await);
        }

        let mut hits = list_interface_hits()?;
        for hit in &hits {
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: hit.summary_line(),
            });
        }

        let Some(target) = &self.config.target else {
            let total = hits.len() as u64;
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: total,
                total,
                message: format!("{} interface(s)", hits.len()),
            });
            let _ = events.publish(ModuleEvent::Done { job_id });
            return Ok(hits);
        };

        let hosts = expand_targets(target)?;
        let avail = self
            .config
            .availability
            .clone()
            .unwrap_or_else(DiscoverAvailability::probe);
        let decision = decide_discover(self.config.technique, &avail);
        if let Some(note) = &decision.fallback_note {
            let _ = events.publish(ModuleEvent::Log {
                job_id,
                level: LogLevel::Warn,
                message: note.clone(),
            });
        }

        let total = hosts.len() as u64;
        let done = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let rate = Arc::new(tokio::sync::Mutex::new(RateLimiter::per_second(
            self.config.rate_per_sec,
        )));
        let mut tasks = Vec::with_capacity(hosts.len());

        for host in hosts {
            let host_str = host.to_string();
            if let Err(e) = self.scope.check(&host_str) {
                let _ = events.publish(ModuleEvent::Log {
                    job_id,
                    level: LogLevel::Info,
                    message: format!("skip {host_str}: {e}"),
                });
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: d,
                    total,
                    message: format!("skip {host_str}"),
                });
                continue;
            }

            let permit = sem.clone().acquire_owned().await;
            let Ok(permit) = permit else {
                break;
            };
            let events = events.clone();
            let done = Arc::clone(&done);
            let rate = Arc::clone(&rate);
            let timeout = self.config.timeout;
            let ports = self.config.ports.clone();
            let primary = decision.primary;
            let icmp_ok = avail.icmp_usable;
            let arp_ok = avail.arp_usable;

            tasks.push(tokio::spawn(async move {
                {
                    let mut guard = rate.lock().await;
                    guard.wait().await;
                }
                let result = probe_host(host, primary, arp_ok, icmp_ok, &ports, timeout).await;
                drop(permit);
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                let msg = match &result {
                    Some(h) => format!("{} up via {}", h.target, h.method.as_str()),
                    None => format!("{host} down"),
                };
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: d,
                    total,
                    message: msg,
                });
                if let Some(hit) = result {
                    let _ = events.publish(ModuleEvent::Result {
                        job_id,
                        summary: hit.summary_line(),
                    });
                    Some(hit)
                } else {
                    None
                }
            }));
        }

        for task in tasks {
            if let Ok(Some(hit)) = task.await {
                hits.push(hit);
            }
        }

        let _ = events.publish(ModuleEvent::Done { job_id });
        Ok(hits)
    }

    async fn emit_dry_run(&self, job_id: JobId, events: &EventSender) -> Vec<NetHit> {
        let mut planned = Vec::new();
        if let Ok(ifaces) = list_interfaces() {
            for iface in ifaces {
                let hit = NetHit {
                    method: DiscoverMethod::Interface,
                    target: format!("{}/{}", iface.addr, iface.prefix.unwrap_or(0)),
                    detail: format!("list interface {}", iface.name),
                    planned: true,
                };
                let _ = events.publish(ModuleEvent::Result {
                    job_id,
                    summary: hit.summary_line(),
                });
                planned.push(hit);
            }
        }

        if let Some(target) = &self.config.target {
            let avail = self
                .config
                .availability
                .clone()
                .unwrap_or_else(DiscoverAvailability::probe);
            let decision = decide_discover(self.config.technique, &avail);
            if let Some(note) = &decision.fallback_note {
                let _ = events.publish(ModuleEvent::Log {
                    job_id,
                    level: LogLevel::Warn,
                    message: note.clone(),
                });
            }
            let hosts = expand_targets(target).unwrap_or_default();
            let total = hosts.len() as u64;
            for (i, host) in hosts.into_iter().enumerate() {
                let hit = NetHit {
                    method: decision.primary,
                    target: host.to_string(),
                    detail: format!(
                        "probe via {} ports={}",
                        decision.primary.as_str(),
                        ports_csv(&self.config.ports)
                    ),
                    planned: true,
                };
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: (i as u64) + 1,
                    total,
                    message: format!("plan {}", hit.target),
                });
                let _ = events.publish(ModuleEvent::Result {
                    job_id,
                    summary: hit.summary_line(),
                });
                planned.push(hit);
            }
        }

        let _ = events.publish(ModuleEvent::Done { job_id });
        planned
    }
}

impl Module for NetModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Net
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_net(job_id, events.clone()).await {
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

/// Enumerate local interfaces (name, address, prefix).
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, NetError> {
    let raw = if_addrs::get_if_addrs().map_err(|e| NetError::Interfaces(e.to_string()))?;
    let mut out = Vec::with_capacity(raw.len());
    for iface in raw {
        let is_loopback = iface.is_loopback();
        let name = iface.name;
        let (addr, prefix) = match iface.addr {
            if_addrs::IfAddr::V4(v) => {
                let prefix = v
                    .netmask
                    .octets()
                    .iter()
                    .fold(0u8, |acc, b| acc + b.count_ones() as u8);
                (IpAddr::V4(v.ip), Some(prefix))
            }
            if_addrs::IfAddr::V6(v) => {
                let prefix = v
                    .netmask
                    .segments()
                    .iter()
                    .fold(0u8, |acc, s| acc + s.count_ones() as u8);
                (IpAddr::V6(v.ip), Some(prefix))
            }
        };
        out.push(InterfaceInfo {
            name,
            addr,
            prefix,
            is_loopback,
        });
    }
    out.sort_by(|a, b| (&a.name, &a.addr).cmp(&(&b.name, &b.addr)));
    Ok(out)
}

fn list_interface_hits() -> Result<Vec<NetHit>, NetError> {
    Ok(list_interfaces()?
        .into_iter()
        .map(|iface| {
            let prefix = iface.prefix.map(|p| format!("/{p}")).unwrap_or_default();
            let lo = if iface.is_loopback { " loopback" } else { "" };
            NetHit {
                method: DiscoverMethod::Interface,
                target: format!("{}{}", iface.addr, prefix),
                detail: format!("{}{}", iface.name, lo),
                planned: false,
            }
        })
        .collect())
}

/// Expand a single IP or CIDR into host addresses (network/broadcast skipped for IPv4).
pub fn expand_targets(target: &str) -> Result<Vec<IpAddr>, NetError> {
    let parsed = parse_net_target(target)?;
    match parsed {
        NetTarget::Ip(ip) => Ok(vec![ip]),
        NetTarget::Cidr { addr, prefix } => expand_cidr(addr, prefix),
    }
}

fn expand_cidr(network: IpAddr, prefix: u8) -> Result<Vec<IpAddr>, NetError> {
    match network {
        IpAddr::V4(n) => {
            let host_bits = 32u32.saturating_sub(u32::from(prefix));
            let count = if host_bits >= 32 {
                u64::from(u32::MAX) + 1
            } else {
                1u64 << host_bits
            };
            if count > MAX_DISCOVERY_HOSTS as u64 {
                return Err(NetError::RangeTooLarge {
                    count: count as usize,
                    max: MAX_DISCOVERY_HOSTS,
                });
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let base = u32::from(n) & mask;
            let mut hosts = Vec::new();
            for i in 0..count {
                let ip = Ipv4Addr::from(base.wrapping_add(i as u32));
                // Skip network and broadcast on prefixes < 31.
                if prefix < 31 && (i == 0 || i == count - 1) {
                    continue;
                }
                hosts.push(IpAddr::V4(ip));
                if hosts.len() > MAX_DISCOVERY_HOSTS {
                    return Err(NetError::RangeTooLarge {
                        count: hosts.len(),
                        max: MAX_DISCOVERY_HOSTS,
                    });
                }
            }
            if hosts.len() > MAX_DISCOVERY_HOSTS {
                return Err(NetError::RangeTooLarge {
                    count: hosts.len(),
                    max: MAX_DISCOVERY_HOSTS,
                });
            }
            Ok(hosts)
        }
        IpAddr::V6(n) => {
            let host_bits = 128u32.saturating_sub(u32::from(prefix));
            if host_bits > 16 {
                let count = 1u128 << host_bits.min(63);
                return Err(NetError::RangeTooLarge {
                    count: count.min(usize::MAX as u128) as usize,
                    max: MAX_DISCOVERY_HOSTS,
                });
            }
            let count = 1u32 << host_bits;
            if count as usize > MAX_DISCOVERY_HOSTS {
                return Err(NetError::RangeTooLarge {
                    count: count as usize,
                    max: MAX_DISCOVERY_HOSTS,
                });
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let base = u128::from(n) & mask;
            let mut hosts = Vec::with_capacity(count as usize);
            for i in 0..count {
                hosts.push(IpAddr::V6(std::net::Ipv6Addr::from(base + u128::from(i))));
            }
            Ok(hosts)
        }
    }
}

async fn probe_host(
    host: IpAddr,
    primary: DiscoverMethod,
    arp_ok: bool,
    icmp_ok: bool,
    ports: &[u16],
    timeout: Duration,
) -> Option<NetHit> {
    let order: &[DiscoverMethod] = match primary {
        DiscoverMethod::Arp => &[
            DiscoverMethod::Arp,
            DiscoverMethod::Icmp,
            DiscoverMethod::Tcp,
        ],
        DiscoverMethod::Icmp => &[DiscoverMethod::Icmp, DiscoverMethod::Tcp],
        DiscoverMethod::Tcp => &[DiscoverMethod::Tcp],
        DiscoverMethod::Interface => &[DiscoverMethod::Tcp],
    };

    for method in order {
        match method {
            DiscoverMethod::Arp if arp_ok => {
                if let Some(detail) = arp_probe(host, timeout) {
                    return Some(NetHit {
                        method: DiscoverMethod::Arp,
                        target: host.to_string(),
                        detail,
                        planned: false,
                    });
                }
            }
            DiscoverMethod::Icmp if icmp_ok => {
                if let Some(detail) = icmp_probe(host, timeout).await {
                    return Some(NetHit {
                        method: DiscoverMethod::Icmp,
                        target: host.to_string(),
                        detail,
                        planned: false,
                    });
                }
            }
            DiscoverMethod::Tcp => {
                if let Some(detail) = tcp_probe(host, ports, timeout).await {
                    return Some(NetHit {
                        method: DiscoverMethod::Tcp,
                        target: host.to_string(),
                        detail,
                        planned: false,
                    });
                }
            }
            _ => {}
        }
    }
    None
}

async fn tcp_probe(host: IpAddr, ports: &[u16], timeout: Duration) -> Option<String> {
    for &port in ports {
        let addr = SocketAddr::new(host, port);
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return Some(format!("tcp/{port} open")),
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    None
}

async fn icmp_probe(host: IpAddr, timeout: Duration) -> Option<String> {
    let IpAddr::V4(dst) = host else {
        return None;
    };
    tokio::task::spawn_blocking(move || icmp_echo_v4(dst, timeout))
        .await
        .ok()
        .flatten()
}

fn icmp_echo_v4(dst: Ipv4Addr, timeout: Duration) -> Option<String> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let id = (std::process::id() & 0xffff) as u16;
    let seq = 1u16;
    let mut packet = [0u8; ICMP_HEADER_LEN + 8];
    packet[0] = ICMP_ECHO_REQUEST;
    packet[1] = 0;
    packet[4] = (id >> 8) as u8;
    packet[5] = (id & 0xff) as u8;
    packet[6] = (seq >> 8) as u8;
    packet[7] = (seq & 0xff) as u8;
    packet[8..].copy_from_slice(b"keldping");
    let csum = icmp_checksum(&packet);
    packet[2] = (csum >> 8) as u8;
    packet[3] = (csum & 0xff) as u8;

    let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), 0));
    sock.send_to(&packet, &dest).ok()?;

    let deadline = Instant::now() + timeout;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let _ = sock.set_read_timeout(Some(remaining));
        match sock.recv(&mut buf) {
            Ok(0) => return None,
            Ok(n) => {
                // SAFETY: recv initializes the first n bytes.
                let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                if icmp_is_echo_reply(data, id, seq) {
                    return Some("icmp echo-reply".into());
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                return None;
            }
            Err(_) => return None,
        }
    }
}

fn icmp_is_echo_reply(packet: &[u8], id: u16, seq: u16) -> bool {
    // May include IPv4 header.
    let icmp = if packet.len() >= 28 && (packet[0] >> 4) == 4 {
        let ihl = (packet[0] & 0x0f) as usize * 4;
        if packet.len() < ihl + ICMP_HEADER_LEN {
            return false;
        }
        &packet[ihl..]
    } else if packet.len() >= ICMP_HEADER_LEN {
        packet
    } else {
        return false;
    };
    if icmp[0] != ICMP_ECHO_REPLY {
        return false;
    }
    let got_id = u16::from(icmp[4]) << 8 | u16::from(icmp[5]);
    let got_seq = u16::from(icmp[6]) << 8 | u16::from(icmp[7]);
    got_id == id && got_seq == seq
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        if i == 2 {
            i += 2;
            continue;
        }
        sum += u32::from(u16::from(data[i]) << 8 | u16::from(data[i + 1]));
        i += 2;
    }
    if i < data.len() && i != 2 {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ARP who-has is not injected in this build (needs a link-layer stack).
fn arp_probe(_host: IpAddr, _timeout: Duration) -> Option<String> {
    None
}

fn probe_arp(elevated: bool, npcap_present: bool) -> (bool, String) {
    #[cfg(windows)]
    {
        let _ = elevated;
        if npcap_present {
            (
                false,
                "Npcap is installed; Keld does not inject ARP frames".into(),
            )
        } else {
            (
                false,
                "ARP unavailable on Windows without a link-layer send path".into(),
            )
        }
    }
    #[cfg(unix)]
    {
        let _ = npcap_present;
        if elevated {
            (
                false,
                "elevated, but ARP who-has link-layer send is not enabled in this build".into(),
            )
        } else {
            (
                false,
                "ARP needs root or CAP_NET_RAW plus a link-layer send path".into(),
            )
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (elevated, npcap_present);
        (false, "ARP not supported on this platform".into())
    }
}

fn probe_icmp() -> (bool, String) {
    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(_) => (true, "raw ICMP socket opened".into()),
        Err(e) => (
            false,
            format!("raw ICMP unavailable: {}", socket_reason(&e)),
        ),
    }
}

fn socket_reason(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => format!("{} (os error {code})", err.kind()),
        None => err.kind().to_string(),
    }
}

fn npcap_dll_present() -> bool {
    #[cfg(windows)]
    {
        use std::path::Path;
        Path::new(r"C:\Windows\System32\Npcap\Packet.dll").exists()
            || Path::new(r"C:\Windows\System32\Packet.dll").exists()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid only reads this process's credential.
        unsafe { geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        windows_is_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

#[cfg(windows)]
fn windows_is_elevated() -> bool {
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: u32 = 20;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn CloseHandle(handle: isize) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
        fn GetTokenInformation(
            token: isize,
            class: u32,
            info: *mut core::ffi::c_void,
            len: u32,
            ret_len: *mut u32,
        ) -> i32;
    }

    // SAFETY: handles are opened for this process and closed before return.
    unsafe {
        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TokenElevation {
            token_is_elevated: 0,
        };
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            &mut elev as *mut TokenElevation as *mut core::ffi::c_void,
            u32::try_from(std::mem::size_of::<TokenElevation>()).unwrap_or(4),
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        ok != 0 && elev.token_is_elevated != 0
    }
}

enum NetTarget {
    Ip(IpAddr),
    Cidr { addr: IpAddr, prefix: u8 },
}

fn normalize_net_target(raw: &str) -> Result<String, NetError> {
    match parse_net_target(raw)? {
        NetTarget::Ip(ip) => Ok(ip.to_string()),
        NetTarget::Cidr { addr, prefix } => Ok(format!("{addr}/{prefix}")),
    }
}

fn parse_net_target(raw: &str) -> Result<NetTarget, NetError> {
    let s = raw.trim();
    if let Some((addr_part, prefix_part)) = s.split_once('/') {
        let addr = parse_ip(addr_part).map_err(|reason| NetError::InvalidTarget {
            target: raw.to_string(),
            reason,
        })?;
        let prefix: u8 = prefix_part.parse().map_err(|_| NetError::InvalidTarget {
            target: raw.to_string(),
            reason: format!("invalid prefix `{prefix_part}`"),
        })?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(NetError::InvalidTarget {
                target: raw.to_string(),
                reason: format!("prefix {prefix} exceeds {max}"),
            });
        }
        return Ok(NetTarget::Cidr { addr, prefix });
    }
    let ip = parse_ip(s).map_err(|reason| NetError::InvalidTarget {
        target: raw.to_string(),
        reason,
    })?;
    Ok(NetTarget::Ip(ip))
}

fn parse_ip(s: &str) -> Result<IpAddr, String> {
    let t = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    IpAddr::from_str(t).map_err(|_| format!("not an IP or CIDR: `{s}`"))
}

/// Parse comma-separated TCP probe ports (`80,443` or empty for defaults).
pub fn parse_probe_ports(raw: &str) -> Result<Vec<u16>, NetError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("default") {
        return Ok(DEFAULT_PROBE_PORTS.to_vec());
    }
    let mut ports = Vec::new();
    for part in trimmed.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let port: u16 = p.parse().map_err(|_| NetError::InvalidPorts {
            ports: raw.to_string(),
            reason: format!("invalid port `{p}`"),
        })?;
        if port == 0 {
            return Err(NetError::InvalidPorts {
                ports: raw.to_string(),
                reason: "port 0 is invalid".into(),
            });
        }
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    if ports.is_empty() {
        return Err(NetError::InvalidPorts {
            ports: raw.to_string(),
            reason: "no ports".into(),
        });
    }
    Ok(ports)
}

fn ports_csv(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse a Result summary back into a [`NetHit`] (TUI worker bridge).
pub fn parse_net_summary(summary: &str) -> Option<NetHit> {
    if let Some(rest) = summary.strip_prefix("would net ") {
        let method = DiscoverMethod::parse(take_after(rest, "method=")?)?;
        let after_method = after_space(rest, "method=")?;
        let target = take_after(after_method, "target=")?.to_string();
        let after_target = after_space(after_method, "target=")?;
        let detail = after_target.strip_prefix("detail=")?.to_string();
        return Some(NetHit {
            method,
            target,
            detail,
            planned: true,
        });
    }

    let method = DiscoverMethod::parse(take_after(summary, "method=")?)?;
    let after_method = after_space(summary, "method=")?;
    let target = take_after(after_method, "target=")?.to_string();
    let after_target = after_space(after_method, "target=")?;
    let detail = after_target.strip_prefix("detail=")?.to_string();
    Some(NetHit {
        method,
        target,
        detail,
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
    use tokio::net::TcpListener;

    fn lab_scope() -> Scope {
        Scope {
            includes: vec![ScopeEntry::Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                prefix: 8,
            }],
            excludes: Vec::new(),
            notes: None,
            source: None,
        }
    }

    fn forced_tcp_avail() -> DiscoverAvailability {
        DiscoverAvailability {
            arp_usable: false,
            icmp_usable: false,
            elevated: false,
            npcap_present: false,
            arp_detail: "test: arp off".into(),
            icmp_detail: "test: icmp off".into(),
        }
    }

    #[test]
    fn list_interfaces_returns_rows() {
        let ifaces = list_interfaces().unwrap();
        assert!(!ifaces.is_empty());
        assert!(ifaces.iter().any(|i| i.is_loopback));
    }

    #[test]
    fn expand_slash30_skips_network_and_broadcast() {
        let hosts = expand_targets("10.0.0.0/30").unwrap();
        assert_eq!(
            hosts,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ]
        );
    }

    #[test]
    fn refuse_huge_cidr() {
        let err = expand_targets("10.0.0.0/16").unwrap_err();
        assert!(matches!(err, NetError::RangeTooLarge { .. }));
    }

    #[test]
    fn decide_auto_falls_to_tcp() {
        let avail = forced_tcp_avail();
        let d = decide_discover(DiscoverTechnique::Auto, &avail);
        assert_eq!(d.primary, DiscoverMethod::Tcp);
        assert!(d.fallback_note.as_ref().unwrap().contains("TCP"));
    }

    #[test]
    fn parse_summary_roundtrip() {
        let hit = NetHit {
            method: DiscoverMethod::Tcp,
            target: "127.0.0.1".into(),
            detail: "tcp/80 open".into(),
            planned: false,
        };
        let parsed = parse_net_summary(&hit.summary_line()).unwrap();
        assert_eq!(parsed, hit);

        let plan = NetHit {
            method: DiscoverMethod::Icmp,
            target: "10.0.0.1".into(),
            detail: "probe via icmp".into(),
            planned: true,
        };
        assert_eq!(parse_net_summary(&plan.summary_line()).unwrap(), plan);
    }

    #[tokio::test]
    async fn dry_run_plans_hosts() {
        let mut config = NetConfig::from_parts(
            Some("127.0.0.1".into()),
            DiscoverTechnique::Tcp,
            "80",
            NetRunOpts {
                timeout_ms: 100,
                concurrency: 1,
                dry_run: true,
                rate_per_sec: None,
            },
        )
        .unwrap();
        config.availability = Some(forced_tcp_avail());
        let module = NetModule::new(config, lab_scope());
        let bus = EventBus::with_defaults();
        let hits = module.run_net(JobId::new(1), bus.sender()).await.unwrap();
        assert!(hits.iter().any(|h| h.planned && h.target == "127.0.0.1"));
    }

    #[tokio::test]
    async fn tcp_discovers_open_localhost_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut config = NetConfig::from_parts(
            Some("127.0.0.1".into()),
            DiscoverTechnique::Tcp,
            port.to_string(),
            NetRunOpts {
                timeout_ms: 2_000,
                concurrency: 1,
                dry_run: false,
                rate_per_sec: None,
            },
        )
        .unwrap();
        config.availability = Some(forced_tcp_avail());
        let module = NetModule::new(config, lab_scope());
        let bus = EventBus::with_defaults();
        let hits = module.run_net(JobId::new(2), bus.sender()).await.unwrap();
        let _ = accept.await;

        assert!(hits.iter().any(|h| {
            h.method == DiscoverMethod::Tcp
                && h.target == "127.0.0.1"
                && h.detail.contains(&format!("tcp/{port}"))
        }));
        assert!(hits.iter().any(|h| h.method == DiscoverMethod::Interface));
    }

    #[tokio::test]
    async fn out_of_scope_refused() {
        let scope = Scope {
            includes: vec![ScopeEntry::Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix: 8,
            }],
            excludes: Vec::new(),
            notes: None,
            source: None,
        };
        let config = NetConfig::from_parts(
            Some("127.0.0.1".into()),
            DiscoverTechnique::Tcp,
            "80",
            NetRunOpts {
                dry_run: true,
                ..NetRunOpts::default()
            },
        )
        .unwrap();
        let module = NetModule::new(config, scope);
        let bus = EventBus::with_defaults();
        let err = module
            .run_net(JobId::new(3), bus.sender())
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Scope(_)));
    }
}
