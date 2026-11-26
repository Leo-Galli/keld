//! Optional IPv4 SYN probes.
//!
//! Unix: a raw TCP socket (root or `CAP_NET_RAW`). Windows rejects TCP data on
//! raw sockets, so a failed open or a failed loopback send is not usable and
//! the caller falls back to TCP connect. Npcap is reported, not used to inject
//! frames (that needs a link-layer stack this path does not ship).

use std::io::{self, ErrorKind};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use keld_core::{EventSender, JobId, LogLevel, ModuleEvent, RateLimiter};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::scan::{PortHit, PortState};

/// Local port stamped on SYN probes. Replies are matched on this value.
const SYN_SOURCE_PORT: u16 = 48_521;
const IPPROTO_RAW: i32 = 255;
const SYN_FLAG: u8 = 0x02;
const SYN_ACK_MASK: u8 = 0x12;
const RST_FLAG: u8 = 0x04;

/// What the operator asked for, before privilege checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTechnique {
    Connect,
    Syn,
}

impl ScanTechnique {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Syn => "syn",
        }
    }
}

/// Runtime facts shared by `scan`, `doctor`, and the TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynAvailability {
    pub usable: bool,
    pub elevated: bool,
    pub npcap_present: bool,
    pub detail: String,
}

impl SynAvailability {
    /// Probe privileges and whether a raw IPv4 TCP socket can send.
    pub fn probe() -> Self {
        let elevated = is_elevated();
        let npcap_present = npcap_dll_present();
        match open_raw_sockets() {
            Ok((send, recv)) => {
                drop(recv);
                match confirm_send(&send) {
                    Ok(()) => Self {
                        usable: true,
                        elevated,
                        npcap_present,
                        detail: "raw IPv4 TCP socket opened".into(),
                    },
                    Err(detail) => Self {
                        usable: false,
                        elevated,
                        npcap_present,
                        detail,
                    },
                }
            }
            Err(e) => Self {
                usable: false,
                elevated,
                npcap_present,
                detail: format!(
                    "raw TCP socket unavailable: {}; {}",
                    socket_reason(&e),
                    npcap_note()
                ),
            },
        }
    }
}

/// Result of applying a request to a probed capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueDecision {
    pub requested: ScanTechnique,
    pub used: ScanTechnique,
    pub fallback: Option<String>,
}

/// `Connect` is unchanged. `Syn` is kept only when `avail` says the socket works.
pub fn decide(requested: ScanTechnique, avail: Option<&SynAvailability>) -> TechniqueDecision {
    if requested == ScanTechnique::Connect {
        return TechniqueDecision {
            requested,
            used: ScanTechnique::Connect,
            fallback: None,
        };
    }
    match avail {
        Some(a) if a.usable => TechniqueDecision {
            requested,
            used: ScanTechnique::Syn,
            fallback: None,
        },
        Some(a) => TechniqueDecision {
            requested,
            used: ScanTechnique::Connect,
            fallback: Some(format!("SYN unavailable: {}. Using TCP connect.", a.detail)),
        },
        None => TechniqueDecision {
            requested,
            used: ScanTechnique::Connect,
            fallback: Some("SYN unavailable: capability was not probed. Using TCP connect.".into()),
        },
    }
}

/// Inputs for one IPv4 SYN scan. Probes run one at a time on a shared socket.
pub struct SynScanRequest {
    pub job_id: JobId,
    pub host_label: String,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub rate_per_sec: Option<u32>,
}

/// Send SYNs and collect open ports. Returns `Err` only before the first probe
/// so the caller can fall back without scanning twice.
pub fn scan_ipv4(req: SynScanRequest, events: &EventSender) -> Result<Vec<PortHit>, String> {
    let (send, recv) =
        open_raw_sockets().map_err(|e| format!("raw socket: {}", socket_reason(&e)))?;
    confirm_send(&send)?;
    let total = req.ports.len() as u64;
    let mut rate = RateLimiter::per_second(req.rate_per_sec);
    let mut hits = Vec::new();

    for (index, port) in req.ports.iter().copied().enumerate() {
        rate.wait_blocking();
        let state = match probe_port(&send, &recv, req.src, req.dst, port, req.timeout) {
            Ok(state) => state,
            Err(e) if index == 0 => return Err(format!("send SYN: {}", socket_reason(&e))),
            Err(e) => {
                let _ = events.publish(ModuleEvent::Log {
                    job_id: req.job_id,
                    level: LogLevel::Warn,
                    message: format!(
                        "SYN {}:{} failed: {}",
                        req.host_label,
                        port,
                        socket_reason(&e)
                    ),
                });
                PortState::Filtered
            }
        };
        let done = (index as u64) + 1;
        let _ = events.publish(ModuleEvent::Progress {
            job_id: req.job_id,
            done,
            total,
            message: format!("{}:{port} {state} syn", req.host_label),
        });
        if state == PortState::Open {
            let summary = format!("{}:{port} open", req.host_label);
            let _ = events.publish(ModuleEvent::Result {
                job_id: req.job_id,
                summary,
            });
            hits.push(PortHit {
                host: req.host_label.clone(),
                port,
                state: PortState::Open,
            });
        }
    }

    let _ = events.publish(ModuleEvent::Done { job_id: req.job_id });
    Ok(hits)
}

fn probe_port(
    send: &Socket,
    recv: &Socket,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> io::Result<PortState> {
    let seq = 0x4B45_0000 | u32::from(port);
    let packet = build_ipv4_tcp(src, dst, SYN_SOURCE_PORT, port, seq, SYN_FLAG);
    let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(dst), port));
    let sent = send.send_to(&packet, &dest)?;
    if sent < packet.len() {
        return Err(io::Error::new(
            ErrorKind::WriteZero,
            "short send on raw socket",
        ));
    }

    let deadline = Instant::now() + timeout;
    let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(PortState::Filtered);
        }
        recv.set_read_timeout(Some(remaining))?;
        match recv.recv(&mut buf) {
            Ok(0) => return Ok(PortState::Filtered),
            Ok(n) => {
                // SAFETY: `Socket::recv` initializes the first `n` bytes.
                let received = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                if let Some(state) = parse_reply(received, src, dst, port) {
                    return Ok(state);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                return Ok(PortState::Filtered);
            }
            Err(e) => return Err(e),
        }
    }
}

fn open_raw_sockets() -> io::Result<(Socket, Socket)> {
    let send = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
    send.set_header_included_v4(true)?;
    let recv = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    Ok((send, recv))
}

/// Unix: an open raw socket is enough. Windows: one SYN to loopback port 1,
/// because `socket()` can succeed while TCP payloads are still rejected.
fn confirm_send(send: &Socket) -> Result<(), String> {
    #[cfg(windows)]
    {
        let packet = build_ipv4_tcp(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            SYN_SOURCE_PORT,
            1,
            1,
            SYN_FLAG,
        );
        let dest = SockAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1));
        send.send_to(&packet, &dest).map(|_| ()).map_err(|e| {
            format!(
                "Windows rejected raw TCP: {}. {}",
                socket_reason(&e),
                npcap_note()
            )
        })
    }
    #[cfg(not(windows))]
    {
        let _ = send;
        Ok(())
    }
}

fn socket_reason(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => format!("{} (os error {code})", err.kind()),
        None => err.kind().to_string(),
    }
}

fn npcap_note() -> &'static str {
    #[cfg(windows)]
    {
        if npcap_dll_present() {
            "Npcap is installed; Keld does not inject link-layer frames"
        } else {
            "Npcap is not installed"
        }
    }
    #[cfg(not(windows))]
    {
        "need root or CAP_NET_RAW"
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

/// IPv4 + TCP header. `flags` is the TCP flag byte (`0x02` = SYN).
pub fn build_ipv4_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
) -> [u8; 40] {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45;
    write_ip_len(&mut pkt[2..4], 40);
    pkt[4..6].copy_from_slice(&0x4B45u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_sum = nonzero_checksum(internet_checksum(&pkt[..20]));
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&1024u16.to_be_bytes());
    let tcp_sum = nonzero_checksum(tcp_checksum(src, dst, &pkt[20..]));
    pkt[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    pkt
}

fn parse_reply(
    buf: &[u8],
    local: Ipv4Addr,
    remote: Ipv4Addr,
    remote_port: u16,
) -> Option<PortState> {
    if buf.len() < 40 || (buf[0] >> 4) != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl + 20 || buf[9] != 6 {
        return None;
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    if src != remote || dst != local {
        return None;
    }
    let sport = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
    let dport = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
    if sport != remote_port || dport != SYN_SOURCE_PORT {
        return None;
    }
    let flags = buf[ihl + 13];
    if flags & SYN_ACK_MASK == SYN_ACK_MASK {
        Some(PortState::Open)
    } else if flags & RST_FLAG != 0 {
        Some(PortState::Closed)
    } else {
        None
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn write_ip_len(dst: &mut [u8], len: u16) {
    // BSD IP_HDRINCL expects ip_len in host byte order.
    dst.copy_from_slice(&len.to_ne_bytes());
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn write_ip_len(dst: &mut [u8], len: u16) {
    dst.copy_from_slice(&len.to_be_bytes());
}

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut v = Vec::with_capacity(12 + tcp.len());
    v.extend_from_slice(&src.octets());
    v.extend_from_slice(&dst.octets());
    v.push(0);
    v.push(6);
    let len = u16::try_from(tcp.len()).unwrap_or(20);
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(tcp);
    internet_checksum(&v)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn nonzero_checksum(sum: u16) -> u16 {
    if sum == 0 {
        0xffff
    } else {
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_never_falls_back() {
        let decision = decide(ScanTechnique::Connect, None);
        assert_eq!(decision.used, ScanTechnique::Connect);
        assert!(decision.fallback.is_none());
    }

    #[test]
    fn syn_falls_back_when_raw_socket_is_unusable() {
        let avail = SynAvailability {
            usable: false,
            elevated: false,
            npcap_present: true,
            detail: "raw TCP socket unavailable (permission denied)".into(),
        };
        let decision = decide(ScanTechnique::Syn, Some(&avail));
        assert_eq!(decision.used, ScanTechnique::Connect);
        let fallback = decision.fallback.expect("reason");
        assert!(fallback.contains("TCP connect"));
        assert!(fallback.contains("permission denied"));
    }

    #[test]
    fn syn_kept_when_socket_is_usable() {
        let avail = SynAvailability {
            usable: true,
            elevated: true,
            npcap_present: false,
            detail: "raw IPv4 TCP socket opened".into(),
        };
        let decision = decide(ScanTechnique::Syn, Some(&avail));
        assert_eq!(decision.used, ScanTechnique::Syn);
        assert!(decision.fallback.is_none());
    }

    #[test]
    fn syn_segment_checksums_and_flag() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 5);
        let pkt = build_ipv4_tcp(src, dst, SYN_SOURCE_PORT, 22, 0x4B45_0016, SYN_FLAG);
        assert_eq!(pkt[33], SYN_FLAG);
        assert_eq!(internet_checksum(&pkt[..20]), 0);
        assert_eq!(tcp_checksum(src, dst, &pkt[20..]), 0);
    }

    #[test]
    fn reply_parser_accepts_syn_ack_and_rst_only() {
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 5);
        let open = build_ipv4_tcp(remote, local, 22, SYN_SOURCE_PORT, 1, SYN_ACK_MASK);
        assert_eq!(parse_reply(&open, local, remote, 22), Some(PortState::Open));
        let closed = build_ipv4_tcp(remote, local, 22, SYN_SOURCE_PORT, 1, RST_FLAG);
        assert_eq!(
            parse_reply(&closed, local, remote, 22),
            Some(PortState::Closed)
        );
        let syn = build_ipv4_tcp(remote, local, 22, SYN_SOURCE_PORT, 1, SYN_FLAG);
        assert_eq!(parse_reply(&syn, local, remote, 22), None);
        assert_eq!(parse_reply(&open, local, remote, 80), None);
    }

    #[test]
    fn probe_detail_is_nonempty() {
        let avail = SynAvailability::probe();
        assert!(!avail.detail.is_empty());
        if !avail.usable {
            assert!(
                avail.detail.contains("TCP connect")
                    || avail.detail.contains("fallback")
                    || avail.detail.contains("root")
                    || avail.detail.contains("Npcap")
                    || avail.detail.contains("raw")
            );
        }
    }
}
