//! Authorized target scope (`scope.toml`).
//!
//! Active modules must call [`Scope::check`] before contacting a target.
//! Hostname matching is string-based (no DNS); IP and CIDR use network math.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default relative path discovered in the working directory.
pub const DEFAULT_SCOPE_FILE: &str = "scope.toml";

/// Parsed, validated authorization scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub includes: Vec<ScopeEntry>,
    pub excludes: Vec<ScopeEntry>,
    pub notes: Option<String>,
    /// Path the scope was loaded from, when known.
    pub source: Option<PathBuf>,
}

/// One include or exclude entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEntry {
    Ip(IpAddr),
    Cidr {
        addr: IpAddr,
        prefix: u8,
    },
    /// Lowercase hostname (no port, no scheme).
    Host(String),
}

impl std::fmt::Display for ScopeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr { addr, prefix } => write!(f, "{addr}/{prefix}"),
            Self::Host(h) => write!(f, "{h}"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
struct ScopeFile {
    includes: Vec<String>,
    excludes: Vec<String>,
    notes: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("no scope configured; provide scope.toml or --scope")]
    NoScope,
    #[error("target `{target}` is out of scope")]
    OutOfScope { target: String },
    #[error("target `{target}` is excluded by scope")]
    Excluded { target: String },
    #[error("invalid scope entry `{entry}`: {reason}")]
    InvalidEntry { entry: String, reason: String },
    #[error("scope must list at least one include")]
    EmptyIncludes,
    #[error("io error for {path}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("parse scope at {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("scope file not found: {path}")]
    NotFound { path: PathBuf },
    #[error("invalid target `{target}`: {reason}")]
    InvalidTarget { target: String, reason: String },
}

impl Scope {
    /// Empty scope: [`check`](Self::check) always returns [`ScopeError::NoScope`].
    pub fn empty() -> Self {
        Self {
            includes: Vec::new(),
            excludes: Vec::new(),
            notes: None,
            source: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.includes.is_empty()
    }

    /// Short line for TUI header / status bar.
    pub fn summary(&self) -> String {
        if self.includes.is_empty() {
            return "(no scope)".into();
        }
        let first = self.includes[0].to_string();
        let extra = self.includes.len().saturating_sub(1);
        let ex = self.excludes.len();
        match (extra, ex) {
            (0, 0) => first,
            (0, n) => format!("{first} (ex:{n})"),
            (e, 0) => format!("{first} (+{e})"),
            (e, n) => format!("{first} (+{e}, ex:{n})"),
        }
    }

    /// Refuse out-of-scope or excluded targets.
    pub fn check(&self, target: &str) -> Result<(), ScopeError> {
        if self.includes.is_empty() {
            return Err(ScopeError::NoScope);
        }
        let parsed = parse_target(target).map_err(|reason| ScopeError::InvalidTarget {
            target: target.to_string(),
            reason,
        })?;
        let label = parsed.to_string();
        if self.excludes.iter().any(|e| e.covers(&parsed)) {
            return Err(ScopeError::Excluded { target: label });
        }
        if self.includes.iter().any(|e| e.covers(&parsed)) {
            return Ok(());
        }
        Err(ScopeError::OutOfScope { target: label })
    }
}

impl ScopeEntry {
    /// Whether this entry authorizes (or excludes) `other`.
    pub fn covers(&self, other: &ScopeEntry) -> bool {
        match (self, other) {
            (Self::Ip(a), Self::Ip(b)) => a == b,
            (Self::Ip(a), Self::Cidr { addr, prefix }) => {
                is_host_prefix(*prefix, *addr) && a == addr
            }
            (Self::Cidr { addr, prefix }, Self::Ip(ip)) => cidr_contains(*addr, *prefix, *ip),
            (
                Self::Cidr {
                    addr: a,
                    prefix: pa,
                },
                Self::Cidr {
                    addr: b,
                    prefix: pb,
                },
            ) => cidr_contains_cidr(*a, *pa, *b, *pb),
            (Self::Host(a), Self::Host(b)) => host_matches(a, b),
            // No DNS: host and IP never match each other.
            (Self::Host(_), Self::Ip(_) | Self::Cidr { .. })
            | (Self::Ip(_) | Self::Cidr { .. }, Self::Host(_)) => false,
        }
    }
}

/// Load and validate a scope file. Missing path is an error.
pub fn load(path: &Path) -> Result<Scope, ScopeError> {
    if !path.exists() {
        return Err(ScopeError::NotFound {
            path: path.to_path_buf(),
        });
    }
    let text = fs::read_to_string(path).map_err(|e| ScopeError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let file: ScopeFile = toml::from_str(&text).map_err(|e| ScopeError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    parse_file(file, Some(path.to_path_buf()))
}

/// Resolve scope: explicit path, else `./scope.toml` if present, else empty.
pub fn load_optional(explicit: Option<&Path>) -> Result<Scope, ScopeError> {
    if let Some(path) = explicit {
        return load(path);
    }
    let discovered = PathBuf::from(DEFAULT_SCOPE_FILE);
    if discovered.is_file() {
        return load(&discovered);
    }
    Ok(Scope::empty())
}

fn parse_file(file: ScopeFile, source: Option<PathBuf>) -> Result<Scope, ScopeError> {
    if file.includes.is_empty() {
        return Err(ScopeError::EmptyIncludes);
    }
    let includes = file
        .includes
        .iter()
        .map(|s| parse_entry(s))
        .collect::<Result<Vec<_>, _>>()?;
    let excludes = file
        .excludes
        .iter()
        .map(|s| parse_entry(s))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Scope {
        includes,
        excludes,
        notes: file.notes.filter(|n| !n.trim().is_empty()),
        source,
    })
}

fn parse_entry(raw: &str) -> Result<ScopeEntry, ScopeError> {
    parse_target(raw).map_err(|reason| ScopeError::InvalidEntry {
        entry: raw.to_string(),
        reason,
    })
}

/// Parse an include/exclude line or a runtime target string.
fn parse_target(raw: &str) -> Result<ScopeEntry, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty".into());
    }

    if let Some(host) = host_from_url(s) {
        return parse_hostname(host);
    }

    if let Some((addr_part, prefix_part)) = s.split_once('/') {
        if let Ok(addr) = parse_ip_literal(addr_part) {
            let prefix: u8 = prefix_part
                .parse()
                .map_err(|_| format!("invalid prefix `{prefix_part}`"))?;
            validate_prefix(addr, prefix)?;
            return Ok(ScopeEntry::Cidr { addr, prefix });
        }
    }

    if let Ok(ip) = parse_ip_literal(s) {
        return Ok(ScopeEntry::Ip(ip));
    }

    parse_hostname(s)
}

fn parse_ip_literal(s: &str) -> Result<IpAddr, ()> {
    let t = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    IpAddr::from_str(t).map_err(|_| ())
}

fn validate_prefix(addr: IpAddr, prefix: u8) -> Result<(), String> {
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(format!("prefix {prefix} exceeds {max} for {addr}"));
    }
    Ok(())
}

fn host_from_url(s: &str) -> Option<&str> {
    let scheme_len = if s.len() >= 8 && s[..8].eq_ignore_ascii_case("https://") {
        8
    } else if s.len() >= 7 && s[..7].eq_ignore_ascii_case("http://") {
        7
    } else {
        return None;
    };
    let rest = &s[scheme_len..];
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or(inner)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn parse_hostname(s: &str) -> Result<ScopeEntry, String> {
    let host = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("empty hostname".into());
    }
    if host.len() > 253 {
        return Err("hostname too long".into());
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err("malformed hostname".into());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid hostname label".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("hostname label cannot start or end with '-'".into());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("hostname has invalid characters".into());
        }
    }
    Ok(ScopeEntry::Host(host))
}

fn is_host_prefix(prefix: u8, addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(_) => prefix == 32,
        IpAddr::V6(_) => prefix == 128,
    }
}

fn cidr_contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = ipv4_mask(prefix);
            (u32::from(n) & mask) == (u32::from(a) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = ipv6_mask(prefix);
            (u128::from(n) & mask) == (u128::from(a) & mask)
        }
        _ => false,
    }
}

/// True when `inner` is entirely inside `outer`.
fn cidr_contains_cidr(outer: IpAddr, outer_p: u8, inner: IpAddr, inner_p: u8) -> bool {
    if inner_p < outer_p {
        return false;
    }
    cidr_contains(outer, outer_p, inner)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// `pattern` covers `candidate` if equal or candidate is a subdomain of pattern.
fn host_matches(pattern: &str, candidate: &str) -> bool {
    candidate == pattern || candidate.ends_with(&format!(".{pattern}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_scope(body: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("keld-scope-{nanos}-{n}.toml"));
        fs::write(&path, body).unwrap();
        path
    }

    fn scope_from(includes: &[&str], excludes: &[&str]) -> Scope {
        let file = ScopeFile {
            includes: includes.iter().map(|s| (*s).to_string()).collect(),
            excludes: excludes.iter().map(|s| (*s).to_string()).collect(),
            notes: Some("lab".into()),
        };
        parse_file(file, None).unwrap()
    }

    #[test]
    fn include_ip_and_refuse_outside() {
        let s = scope_from(&["10.0.0.5"], &[]);
        s.check("10.0.0.5").unwrap();
        assert!(matches!(
            s.check("10.0.0.6"),
            Err(ScopeError::OutOfScope { .. })
        ));
    }

    #[test]
    fn include_cidr_exclude_host() {
        let s = scope_from(&["10.0.0.0/24"], &["10.0.0.1"]);
        s.check("10.0.0.50").unwrap();
        assert!(matches!(
            s.check("10.0.0.1"),
            Err(ScopeError::Excluded { .. })
        ));
        assert!(matches!(
            s.check("10.0.1.1"),
            Err(ScopeError::OutOfScope { .. })
        ));
    }

    #[test]
    fn exclude_cidr_wins() {
        let s = scope_from(&["10.0.0.0/16"], &["10.0.1.0/24"]);
        s.check("10.0.2.1").unwrap();
        assert!(matches!(
            s.check("10.0.1.9"),
            Err(ScopeError::Excluded { .. })
        ));
    }

    #[test]
    fn hostname_and_subdomain() {
        let s = scope_from(&["example.com"], &["evil.example.com"]);
        s.check("example.com").unwrap();
        s.check("www.example.com").unwrap();
        s.check("HTTPS://API.Example.COM/path").unwrap();
        assert!(matches!(
            s.check("evil.example.com"),
            Err(ScopeError::Excluded { .. })
        ));
        assert!(matches!(
            s.check("other.com"),
            Err(ScopeError::OutOfScope { .. })
        ));
    }

    #[test]
    fn empty_scope_refuses() {
        let s = Scope::empty();
        assert!(matches!(s.check("10.0.0.1"), Err(ScopeError::NoScope)));
        assert_eq!(s.summary(), "(no scope)");
    }

    #[test]
    fn summary_format() {
        let one = scope_from(&["10.0.0.0/24"], &[]);
        assert_eq!(one.summary(), "10.0.0.0/24");
        let with_ex = scope_from(&["10.0.0.0/24"], &["10.0.0.1", "10.0.0.2"]);
        assert_eq!(with_ex.summary(), "10.0.0.0/24 (ex:2)");
        let multi = scope_from(&["10.0.0.0/24", "app.example.com"], &["10.0.0.1"]);
        assert_eq!(multi.summary(), "10.0.0.0/24 (+1, ex:1)");
    }

    #[test]
    fn load_scope_toml() {
        let path = temp_scope(
            r#"
notes = "authorized lab"
includes = ["192.168.0.0/24", "lab.local"]
excludes = ["192.168.0.1"]
"#,
        );
        let s = load(&path).unwrap();
        assert_eq!(s.notes.as_deref(), Some("authorized lab"));
        s.check("192.168.0.10").unwrap();
        s.check("lab.local").unwrap();
        assert!(matches!(
            s.check("192.168.0.1"),
            Err(ScopeError::Excluded { .. })
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_includes_rejected() {
        let path = temp_scope("includes = []\nexcludes = []\n");
        assert!(matches!(load(&path), Err(ScopeError::EmptyIncludes)));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn invalid_entry_rejected() {
        let path = temp_scope("includes = [\"10.0.0.0/99\"]\n");
        assert!(matches!(load(&path), Err(ScopeError::InvalidEntry { .. })));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cidr_target_must_fit_include() {
        let s = scope_from(&["10.0.0.0/24"], &[]);
        s.check("10.0.0.0/28").unwrap();
        assert!(matches!(
            s.check("10.0.0.0/16"),
            Err(ScopeError::OutOfScope { .. })
        ));
    }

    #[test]
    fn ipv6_cidr() {
        let s = scope_from(&["2001:db8::/32"], &["2001:db8::1"]);
        s.check("2001:db8::2").unwrap();
        assert!(matches!(
            s.check("2001:db8::1"),
            Err(ScopeError::Excluded { .. })
        ));
    }
}
