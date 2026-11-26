//! Directory and virtual-host discovery from operator-supplied wordlists.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use keld_core::{
    EventSender, JobId, LogLevel, ModuleEvent, ModuleKind, RateLimiter, Scope, ScopeError,
};
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::{Client, Method, Url};
use tokio::sync::Semaphore;

use crate::Module;

/// Default request timeout.
pub const DEFAULT_FUZZ_TIMEOUT_MS: u64 = 5_000;
/// Default concurrent probes.
pub const DEFAULT_FUZZ_CONCURRENCY: usize = 20;
/// Default status codes to hide when match-status is empty.
pub const DEFAULT_FILTER_STATUS: &[u16] = &[404];

/// Discovery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzMode {
    /// Append wordlist entries to the URL path.
    Dir,
    /// Probe with `Host: {word}.{apex}` (or bare word when it already contains a dot).
    Vhost,
}

impl FuzzMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dir => "dir",
            Self::Vhost => "vhost",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dir" | "directory" | "path" => Some(Self::Dir),
            "vhost" | "vhosts" | "host" => Some(Self::Vhost),
            _ => None,
        }
    }
}

/// Status / size filters for discovery hits.
#[derive(Debug, Clone, Default)]
pub struct FuzzFilters {
    /// Hide these status codes when `match_status` is empty.
    pub filter_status: Vec<u16>,
    /// When non-empty, only keep these status codes.
    pub match_status: Vec<u16>,
    /// Hide responses with these body sizes (Content-Length or measured).
    pub filter_size: Vec<u64>,
}

impl FuzzFilters {
    pub fn default_status() -> Self {
        Self {
            filter_status: DEFAULT_FILTER_STATUS.to_vec(),
            match_status: Vec::new(),
            filter_size: Vec::new(),
        }
    }
}

/// Timeout, concurrency, dry-run, and rate for a fuzz job.
#[derive(Debug, Clone)]
pub struct FuzzRunOpts {
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
}

impl Default for FuzzRunOpts {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_FUZZ_TIMEOUT_MS,
            concurrency: DEFAULT_FUZZ_CONCURRENCY,
            dry_run: false,
            rate_per_sec: None,
        }
    }
}

/// Configuration for one fuzz job.
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub target: String,
    pub wordlist: PathBuf,
    pub mode: FuzzMode,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
    pub filters: FuzzFilters,
}

impl FuzzConfig {
    /// Build from CLI/TUI parts.
    pub fn from_parts(
        target: impl Into<String>,
        wordlist: impl Into<PathBuf>,
        mode: FuzzMode,
        run: FuzzRunOpts,
        filters: FuzzFilters,
    ) -> Result<Self, FuzzError> {
        let target = target.into();
        if target.trim().is_empty() {
            return Err(FuzzError::InvalidTarget {
                target,
                reason: "empty".into(),
            });
        }
        let wordlist = wordlist.into();
        if wordlist.as_os_str().is_empty() {
            return Err(FuzzError::Wordlist("wordlist path is empty".into()));
        }
        Ok(Self {
            target,
            wordlist,
            mode,
            timeout: Duration::from_millis(run.timeout_ms.max(1)),
            concurrency: run.concurrency.max(1),
            dry_run: run.dry_run,
            rate_per_sec: run.rate_per_sec,
            filters,
        })
    }

    /// Short parameters line for audit / status.
    pub fn parameters_summary(&self) -> String {
        format!(
            "mode={} wordlist={} timeout_ms={} concurrency={} dry_run={} rate={} filter_status={} match_status={} filter_size={}",
            self.mode.as_str(),
            self.wordlist.display(),
            self.timeout.as_millis(),
            self.concurrency,
            self.dry_run,
            self.rate_per_sec
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into()),
            join_u16(&self.filters.filter_status),
            join_u16(&self.filters.match_status),
            join_u64(&self.filters.filter_size),
        )
    }
}

/// One kept discovery hit (or dry-run plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzHit {
    pub mode: FuzzMode,
    pub word: String,
    pub url: String,
    pub host_header: Option<String>,
    pub status: u16,
    pub size: u64,
    pub planned: bool,
}

impl FuzzHit {
    /// Compact summary used on the event bus and in TUI parsing.
    pub fn summary_line(&self) -> String {
        if self.planned {
            return match &self.host_header {
                Some(h) => format!(
                    "would fuzz mode={} word={} host={} url={}",
                    self.mode.as_str(),
                    self.word,
                    h,
                    self.url
                ),
                None => format!(
                    "would fuzz mode={} word={} url={}",
                    self.mode.as_str(),
                    self.word,
                    self.url
                ),
            };
        }
        match &self.host_header {
            Some(h) => format!(
                "mode={} word={} status={} size={} host={} url={}",
                self.mode.as_str(),
                self.word,
                self.status,
                self.size,
                h,
                self.url
            ),
            None => format!(
                "mode={} word={} status={} size={} url={}",
                self.mode.as_str(),
                self.word,
                self.status,
                self.size,
                self.url
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FuzzError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error("invalid target `{target}`: {reason}")]
    InvalidTarget { target: String, reason: String },
    #[error("wordlist: {0}")]
    Wordlist(String),
    #[error("http client: {0}")]
    Client(String),
}

/// Directory / vhost discovery module.
#[derive(Debug, Clone)]
pub struct FuzzModule {
    pub config: FuzzConfig,
    pub scope: Scope,
}

impl FuzzModule {
    pub fn new(config: FuzzConfig, scope: Scope) -> Self {
        Self { config, scope }
    }

    /// Scope-check, load wordlist, then discover (or dry-run).
    pub async fn run_fuzz(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<FuzzHit>, FuzzError> {
        let url = normalize_url(&self.config.target)?;
        let host = url
            .host_str()
            .ok_or_else(|| FuzzError::InvalidTarget {
                target: self.config.target.clone(),
                reason: "missing host".into(),
            })?
            .to_string();
        self.scope.check(&host)?;

        let words = load_wordlist(&self.config.wordlist)?;
        if words.is_empty() {
            return Err(FuzzError::Wordlist("wordlist has no usable entries".into()));
        }

        if self.config.dry_run {
            return Ok(self
                .emit_dry_run(job_id, &events, &url, &host, &words)
                .await);
        }

        let client = build_client(self.config.timeout)?;
        let total = words.len() as u64;
        let done = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let mut rate = RateLimiter::per_second(self.config.rate_per_sec);
        let mut handles = Vec::with_capacity(words.len());
        let mode = self.config.mode;
        let filter_status = self.config.filters.filter_status.clone();
        let match_status = self.config.filters.match_status.clone();
        let filter_size = self.config.filters.filter_size.clone();

        for word in words {
            rate.wait().await;
            let permit = sem.clone().acquire_owned().await.expect("semaphore open");
            let client = client.clone();
            let base = url.clone();
            let apex = host.clone();
            let events = events.clone();
            let done = done.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let (probe_url, host_header) = build_probe(mode, &base, &apex, &word);
                let outcome = probe_one(&client, &probe_url, host_header.as_deref()).await;
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                let msg = match &outcome {
                    Ok((status, size)) => {
                        format!("{} {} status={status} size={size}", mode.as_str(), word)
                    }
                    Err(e) => format!("{} {} error={e}", mode.as_str(), word),
                };
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: n,
                    total,
                    message: msg,
                });
                (word, probe_url, host_header, outcome)
            }));
        }

        let mut hits = Vec::new();
        for handle in handles {
            match handle.await {
                Ok((word, probe_url, host_header, outcome)) => match outcome {
                    Ok((status, size)) => {
                        if !passes_filters(
                            status,
                            size,
                            &filter_status,
                            &match_status,
                            &filter_size,
                        ) {
                            continue;
                        }
                        let hit = FuzzHit {
                            mode,
                            word,
                            url: probe_url,
                            host_header,
                            status,
                            size,
                            planned: false,
                        };
                        let _ = events.publish(ModuleEvent::Result {
                            job_id,
                            summary: hit.summary_line(),
                        });
                        hits.push(hit);
                    }
                    Err(e) => {
                        let _ = events.publish(ModuleEvent::Log {
                            job_id,
                            level: LogLevel::Warn,
                            message: format!("probe {word}: {e}"),
                        });
                    }
                },
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

    async fn emit_dry_run(
        &self,
        job_id: JobId,
        events: &EventSender,
        url: &Url,
        apex: &str,
        words: &[String],
    ) -> Vec<FuzzHit> {
        let total = words.len() as u64;
        let mut hits = Vec::with_capacity(words.len());
        for (i, word) in words.iter().enumerate() {
            let (probe_url, host_header) = build_probe(self.config.mode, url, apex, word);
            let hit = FuzzHit {
                mode: self.config.mode,
                word: word.clone(),
                url: probe_url,
                host_header,
                status: 0,
                size: 0,
                planned: true,
            };
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

impl Module for FuzzModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Fuzz
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_fuzz(job_id, events.clone()).await {
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

fn build_client(timeout: Duration) -> Result<Client, FuzzError> {
    Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(RedirectPolicy::none())
        .user_agent("keld-fuzz/0.1")
        .build()
        .map_err(|e| FuzzError::Client(e.to_string()))
}

async fn probe_one(
    client: &Client,
    url: &str,
    host_header: Option<&str>,
) -> Result<(u16, u64), String> {
    let parsed = Url::parse(url).map_err(|e| e.to_string())?;
    let mut req = client.request(Method::GET, parsed);
    if let Some(host) = host_header {
        req = req.header("Host", host);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let size = match resp.content_length() {
        Some(n) => {
            // Drop body without buffering when length is known.
            let _ = resp.bytes().await;
            n
        }
        None => resp.bytes().await.map(|b| b.len() as u64).unwrap_or(0),
    };
    Ok((status, size))
}

fn build_probe(mode: FuzzMode, base: &Url, apex: &str, word: &str) -> (String, Option<String>) {
    match mode {
        FuzzMode::Dir => {
            let mut u = base.clone();
            let joined = join_word_path(u.path(), word);
            u.set_path(&joined);
            u.set_query(None);
            u.set_fragment(None);
            (u.to_string(), None)
        }
        FuzzMode::Vhost => {
            let host = if word.contains('.') {
                word.to_string()
            } else {
                format!("{word}.{apex}")
            };
            (base.to_string(), Some(host))
        }
    }
}

fn join_word_path(base_path: &str, word: &str) -> String {
    let word = word.trim_start_matches('/');
    if base_path.is_empty() || base_path == "/" {
        format!("/{word}")
    } else if base_path.ends_with('/') {
        format!("{base_path}{word}")
    } else {
        format!("{base_path}/{word}")
    }
}

fn passes_filters(
    status: u16,
    size: u64,
    filter_status: &[u16],
    match_status: &[u16],
    filter_size: &[u64],
) -> bool {
    if !match_status.is_empty() {
        if !match_status.contains(&status) {
            return false;
        }
    } else if filter_status.contains(&status) {
        return false;
    }
    !filter_size.contains(&size)
}

fn load_wordlist(path: &Path) -> Result<Vec<String>, FuzzError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| FuzzError::Wordlist(format!("{}: {e}", path.display())))?;
    let words: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    Ok(words)
}

fn normalize_url(raw: &str) -> Result<Url, FuzzError> {
    let trimmed = raw.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    Url::parse(&with_scheme).map_err(|e| FuzzError::InvalidTarget {
        target: raw.to_string(),
        reason: e.to_string(),
    })
}

fn join_u16(vals: &[u16]) -> String {
    if vals.is_empty() {
        return "none".into();
    }
    vals.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn join_u64(vals: &[u64]) -> String {
    if vals.is_empty() {
        return "none".into();
    }
    vals.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse comma-separated u16 list (`none` / `-` / empty => empty vec).
pub fn parse_u16_list(raw: &str) -> Result<Vec<u16>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") || trimmed == "-" {
        return Ok(Vec::new());
    }
    trimmed
        .split(',')
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid status code `{p}`"))
        })
        .collect()
}

/// Parse comma-separated u64 list (`none` / `-` / empty => empty vec).
pub fn parse_u64_list(raw: &str) -> Result<Vec<u64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") || trimmed == "-" {
        return Ok(Vec::new());
    }
    trimmed
        .split(',')
        .map(|p| {
            p.trim()
                .parse::<u64>()
                .map_err(|_| format!("invalid size `{p}`"))
        })
        .collect()
}

/// Parse a Result summary back into a [`FuzzHit`] (TUI worker bridge).
pub fn parse_fuzz_summary(summary: &str) -> Option<FuzzHit> {
    if let Some(rest) = summary.strip_prefix("would fuzz ") {
        let mode = take_kv(rest, "mode=")?.1;
        let mode = FuzzMode::parse(mode)?;
        let after_mode = rest.split_once("mode=")?.1;
        let after_mode = after_mode.split_once(' ')?.1;
        let word = take_kv(after_mode, "word=")?.1;
        let after_word = after_mode.split_once("word=")?.1;
        let after_word = after_word.split_once(' ')?.1;
        let (host_header, url) = if after_word.starts_with("host=") {
            let host = take_kv(after_word, "host=")?.1;
            let after_host = after_word.split_once("host=")?.1;
            let after_host = after_host.split_once(' ')?.1;
            let url = after_host.strip_prefix("url=")?;
            (Some(host.to_string()), url.to_string())
        } else {
            let url = after_word.strip_prefix("url=")?;
            (None, url.to_string())
        };
        return Some(FuzzHit {
            mode,
            word: word.to_string(),
            url,
            host_header,
            status: 0,
            size: 0,
            planned: true,
        });
    }

    let mode = take_kv(summary, "mode=")?.1;
    let mode = FuzzMode::parse(mode)?;
    let rest = summary.split_once("mode=")?.1;
    let rest = rest.split_once(' ')?.1;
    let word = take_kv(rest, "word=")?.1;
    let rest = rest.split_once("word=")?.1;
    let rest = rest.split_once(' ')?.1;
    let status: u16 = take_kv(rest, "status=")?.1.parse().ok()?;
    let rest = rest.split_once("status=")?.1;
    let rest = rest.split_once(' ')?.1;
    let size: u64 = take_kv(rest, "size=")?.1.parse().ok()?;
    let rest = rest.split_once("size=")?.1;
    let rest = rest.split_once(' ')?.1;
    let (host_header, url) = if rest.starts_with("host=") {
        let host = take_kv(rest, "host=")?.1;
        let after = rest.split_once("host=")?.1;
        let after = after.split_once(' ')?.1;
        let url = after.strip_prefix("url=")?;
        (Some(host.to_string()), url.to_string())
    } else {
        let url = rest.strip_prefix("url=")?;
        (None, url.to_string())
    };
    Some(FuzzHit {
        mode,
        word: word.to_string(),
        url,
        host_header,
        status,
        size,
        planned: false,
    })
}

fn take_kv<'a>(s: &'a str, key: &str) -> Option<(&'a str, &'a str)> {
    let rest = s.strip_prefix(key)?;
    let val = rest.split_once(' ').map_or(rest, |(a, _)| a);
    Some(("", val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{EventBus, Scope, ScopeEntry};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    fn write_wordlist(words: &[&str]) -> PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "keld-fuzz-words-{}-{}.txt",
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

    async fn spawn_fuzz_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ =
                        tokio::time::timeout(Duration::from_millis(500), tcp.read(&mut buf)).await;
                    let req = String::from_utf8_lossy(&buf);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let host = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                        .map(|l| l[5..].trim().to_string())
                        .unwrap_or_default();

                    let (status, body) = if path == "/admin" || path.ends_with("/admin") {
                        ("200 OK", "admin-ok")
                    } else if host.starts_with("staging.") {
                        ("200 OK", "vhost-ok")
                    } else {
                        ("404 Not Found", "missing")
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tcp.write_all(resp.as_bytes()).await;
                    let _ = tcp.shutdown().await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn dry_run_plans_without_connect() {
        let wl = write_wordlist(&["a", "b"]);
        let bus = EventBus::new(64);
        let cfg = FuzzConfig::from_parts(
            "http://127.0.0.1/",
            &wl,
            FuzzMode::Dir,
            FuzzRunOpts {
                timeout_ms: 200,
                concurrency: 2,
                dry_run: true,
                rate_per_sec: None,
            },
            FuzzFilters::default_status(),
        )
        .unwrap();
        let module = FuzzModule::new(cfg, loopback_scope());
        let hits = module.run_fuzz(JobId::new(1), bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.planned));
        let _ = std::fs::remove_file(wl);
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let wl = write_wordlist(&["x"]);
        let bus = EventBus::new(16);
        let cfg = FuzzConfig::from_parts(
            "http://8.8.8.8/",
            &wl,
            FuzzMode::Dir,
            FuzzRunOpts {
                timeout_ms: 200,
                concurrency: 1,
                dry_run: true,
                rate_per_sec: None,
            },
            FuzzFilters::default_status(),
        )
        .unwrap();
        let module = FuzzModule::new(cfg, loopback_scope());
        let err = module
            .run_fuzz(JobId::new(2), bus.sender())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FuzzError::Scope(ScopeError::OutOfScope { .. })
        ));
        let _ = std::fs::remove_file(wl);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dir_discovers_admin_filters_404() {
        let (addr, _server) = spawn_fuzz_server().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let wl = write_wordlist(&["admin", "missing", "nope"]);
        let url = format!("http://127.0.0.1:{}/", addr.port());
        let bus = EventBus::new(256);
        let cfg = FuzzConfig::from_parts(
            &url,
            &wl,
            FuzzMode::Dir,
            FuzzRunOpts {
                timeout_ms: 2_000,
                concurrency: 4,
                dry_run: false,
                rate_per_sec: None,
            },
            FuzzFilters::default_status(),
        )
        .unwrap();
        let module = FuzzModule::new(cfg, loopback_scope());
        let hits = module.run_fuzz(JobId::new(3), bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].word, "admin");
        assert_eq!(hits[0].status, 200);
        let _ = std::fs::remove_file(wl);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vhost_discovers_staging() {
        let (addr, _server) = spawn_fuzz_server().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let wl = write_wordlist(&["staging", "ghost"]);
        let url = format!("http://127.0.0.1:{}/", addr.port());
        let bus = EventBus::new(256);
        let cfg = FuzzConfig::from_parts(
            &url,
            &wl,
            FuzzMode::Vhost,
            FuzzRunOpts {
                timeout_ms: 2_000,
                concurrency: 4,
                dry_run: false,
                rate_per_sec: None,
            },
            FuzzFilters::default_status(),
        )
        .unwrap();
        let module = FuzzModule::new(cfg, loopback_scope());
        let hits = module.run_fuzz(JobId::new(4), bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].word, "staging");
        assert_eq!(hits[0].host_header.as_deref(), Some("staging.127.0.0.1"));
        let _ = std::fs::remove_file(wl);
    }

    #[test]
    fn parse_roundtrip_dir() {
        let f = FuzzHit {
            mode: FuzzMode::Dir,
            word: "admin".into(),
            url: "http://127.0.0.1/admin".into(),
            host_header: None,
            status: 200,
            size: 8,
            planned: false,
        };
        assert_eq!(parse_fuzz_summary(&f.summary_line()).unwrap(), f);
    }

    #[test]
    fn parse_roundtrip_vhost_planned() {
        let f = FuzzHit {
            mode: FuzzMode::Vhost,
            word: "staging".into(),
            url: "http://10.0.0.1/".into(),
            host_header: Some("staging.example.com".into()),
            status: 0,
            size: 0,
            planned: true,
        };
        assert_eq!(parse_fuzz_summary(&f.summary_line()).unwrap(), f);
    }

    #[test]
    fn filter_logic() {
        assert!(passes_filters(200, 10, &[404], &[], &[]));
        assert!(!passes_filters(404, 10, &[404], &[], &[]));
        assert!(passes_filters(404, 10, &[404], &[404], &[]));
        assert!(!passes_filters(200, 99, &[], &[200], &[99]));
    }

    #[test]
    fn parse_lists() {
        assert_eq!(parse_u16_list("404,403").unwrap(), vec![404, 403]);
        assert!(parse_u16_list("none").unwrap().is_empty());
        assert_eq!(parse_u64_list("0,123").unwrap(), vec![0, 123]);
    }
}
