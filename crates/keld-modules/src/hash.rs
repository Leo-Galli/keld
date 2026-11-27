//! Hash type identification and offline wordlist checks of operator-supplied hashes.
//!
//! No network I/O. Scope is not applied (hashes are not hosts). Modules emit events only.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use keld_core::{EventSender, JobId, ModuleEvent, ModuleKind, RateLimiter};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use tokio::sync::Semaphore;

use crate::Module;

/// Default concurrent wordlist digests.
pub const DEFAULT_HASH_CONCURRENCY: usize = 64;

/// Digest algorithms Keld can identify and (for hex digests) check offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    /// Identified only; wordlist check is not supported.
    Bcrypt,
    Md5Crypt,
    Sha256Crypt,
    Sha512Crypt,
    Unknown,
}

impl HashAlgo {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Bcrypt => "bcrypt",
            Self::Md5Crypt => "md5crypt",
            Self::Sha256Crypt => "sha256crypt",
            Self::Sha512Crypt => "sha512crypt",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "md5" => Some(Self::Md5),
            "sha1" | "sha-1" => Some(Self::Sha1),
            "sha256" | "sha-256" | "sha2-256" => Some(Self::Sha256),
            "sha384" | "sha-384" => Some(Self::Sha384),
            "sha512" | "sha-512" => Some(Self::Sha512),
            "bcrypt" | "2a" | "2b" | "2y" => Some(Self::Bcrypt),
            "md5crypt" => Some(Self::Md5Crypt),
            "sha256crypt" => Some(Self::Sha256Crypt),
            "sha512crypt" => Some(Self::Sha512Crypt),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// CLI/TUI "auto" means detect; returns `None` for auto.
    pub fn parse_force(s: &str) -> Result<Option<Self>, HashError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "detect" | "id" => Ok(None),
            other => Self::parse(other)
                .map(Some)
                .ok_or_else(|| HashError::InvalidHash(format!("unknown algo `{other}`"))),
        }
    }

    /// Hex digest length in characters when this algo is crackable offline.
    pub fn hex_len(self) -> Option<usize> {
        match self {
            Self::Md5 => Some(32),
            Self::Sha1 => Some(40),
            Self::Sha256 => Some(64),
            Self::Sha384 => Some(96),
            Self::Sha512 => Some(128),
            _ => None,
        }
    }

    pub fn crackable(self) -> bool {
        self.hex_len().is_some()
    }

    pub fn cycle(self) -> Self {
        match self {
            Self::Unknown => Self::Md5,
            Self::Md5 => Self::Sha1,
            Self::Sha1 => Self::Sha256,
            Self::Sha256 => Self::Sha384,
            Self::Sha384 => Self::Sha512,
            Self::Sha512 => Self::Unknown,
            // Forced non-hex types cycle back to auto (Unknown sentinel for UI).
            Self::Bcrypt | Self::Md5Crypt | Self::Sha256Crypt | Self::Sha512Crypt => Self::Unknown,
        }
    }
}

/// Kind of hash finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Identify,
    Match,
    Miss,
}

impl HashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identify => "identify",
            Self::Match => "match",
            Self::Miss => "miss",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "identify" | "id" | "type" => Some(Self::Identify),
            "match" | "hit" | "found" => Some(Self::Match),
            "miss" | "nomatch" | "none" => Some(Self::Miss),
            _ => None,
        }
    }
}

/// One hash finding (or dry-run plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashHit {
    pub kind: HashKind,
    pub algo: HashAlgo,
    pub detail: String,
    pub planned: bool,
}

impl HashHit {
    pub fn summary_line(&self) -> String {
        if self.planned {
            return format!(
                "would hash kind={} algo={} detail={}",
                self.kind.as_str(),
                self.algo.as_str(),
                self.detail
            );
        }
        format!(
            "kind={} algo={} detail={}",
            self.kind.as_str(),
            self.algo.as_str(),
            self.detail
        )
    }
}

/// Runtime options for a hash job.
#[derive(Debug, Clone)]
pub struct HashRunOpts {
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
}

impl Default for HashRunOpts {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_HASH_CONCURRENCY,
            dry_run: false,
            rate_per_sec: None,
        }
    }
}

/// Operator-supplied hash plus optional wordlist and algo override.
#[derive(Debug, Clone)]
pub struct HashConfig {
    pub hash: String,
    pub wordlist: Option<PathBuf>,
    /// `None` = auto-detect from the hash string.
    pub algo: Option<HashAlgo>,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
}

impl HashConfig {
    pub fn from_parts(
        hash: impl Into<String>,
        wordlist: Option<PathBuf>,
        algo: Option<HashAlgo>,
        run: HashRunOpts,
    ) -> Result<Self, HashError> {
        let hash = normalize_hash_input(&hash.into())?;
        if let Some(path) = &wordlist {
            if path.as_os_str().is_empty() {
                return Err(HashError::Wordlist("wordlist path is empty".into()));
            }
        }
        if let Some(forced) = algo {
            if !forced.crackable() && wordlist.is_some() {
                return Err(HashError::UnsupportedAlgo(forced.as_str().into()));
            }
        }
        Ok(Self {
            hash,
            wordlist,
            algo,
            concurrency: run.concurrency.max(1),
            dry_run: run.dry_run,
            rate_per_sec: run.rate_per_sec,
        })
    }

    pub fn parameters_summary(&self) -> String {
        format!(
            "hash={} algo={} wordlist={} concurrency={} dry_run={} rate={}",
            truncate_for_audit(&self.hash),
            self.algo.map(|a| a.as_str()).unwrap_or("auto"),
            self.wordlist
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".into()),
            self.concurrency,
            self.dry_run,
            self.rate_per_sec
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into()),
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("invalid hash: {0}")]
    InvalidHash(String),
    #[error("wordlist: {0}")]
    Wordlist(String),
    #[error("unsupported algo for wordlist check: {0}")]
    UnsupportedAlgo(String),
    #[error("algo `{algo}` does not match hash length {len}")]
    AlgoMismatch { algo: String, len: usize },
}

/// Offline hash identify / wordlist module.
#[derive(Debug, Clone)]
pub struct HashModule {
    pub config: HashConfig,
}

impl HashModule {
    pub fn new(config: HashConfig) -> Self {
        Self { config }
    }

    /// Identify the hash and optionally check a wordlist (or dry-run).
    pub async fn run_hash(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<HashHit>, HashError> {
        let candidates = identify_hash(&self.config.hash);
        if candidates.is_empty() {
            return Err(HashError::InvalidHash(
                "could not classify hash (empty candidates)".into(),
            ));
        }

        let algo = resolve_algo(self.config.algo, &candidates, &self.config.hash)?;

        if self.config.dry_run {
            return Ok(self.emit_dry_run(job_id, &events, &candidates, algo).await);
        }

        let mut hits = Vec::new();
        let id_total = candidates.len() as u64;
        for (i, c) in candidates.iter().enumerate() {
            let hit = HashHit {
                kind: HashKind::Identify,
                algo: *c,
                detail: identify_detail(*c, &self.config.hash),
                planned: false,
            };
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: (i as u64) + 1,
                total: id_total,
                message: format!("identify {}", c.as_str()),
            });
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: hit.summary_line(),
            });
            hits.push(hit);
        }

        let Some(wordlist) = &self.config.wordlist else {
            let _ = events.publish(ModuleEvent::Done { job_id });
            return Ok(hits);
        };

        if !algo.crackable() {
            let _ = events.publish(ModuleEvent::Error {
                job_id,
                message: format!(
                    "algo {} cannot be checked with a plain wordlist",
                    algo.as_str()
                ),
            });
            return Err(HashError::UnsupportedAlgo(algo.as_str().into()));
        }

        let words = load_wordlist(wordlist)?;
        if words.is_empty() {
            return Err(HashError::Wordlist("wordlist has no usable entries".into()));
        }

        let target = self.config.hash.to_ascii_lowercase();
        let total = words.len() as u64;
        let done = Arc::new(AtomicU64::new(0));
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let mut rate = RateLimiter::per_second(self.config.rate_per_sec);
        let mut handles = Vec::with_capacity(words.len());

        for word in words {
            rate.wait().await;
            let permit = sem.clone().acquire_owned().await.expect("semaphore open");
            let events = events.clone();
            let done = Arc::clone(&done);
            let target = target.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let digest = hash_hex(algo, word.as_bytes());
                let matched = digest == target;
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done: n,
                    total,
                    message: if matched {
                        format!("match {word}")
                    } else {
                        format!("checked {n}/{total}")
                    },
                });
                if matched {
                    Some(HashHit {
                        kind: HashKind::Match,
                        algo,
                        detail: word,
                        planned: false,
                    })
                } else {
                    None
                }
            }));
        }

        let mut matched = false;
        for handle in handles {
            if let Ok(Some(hit)) = handle.await {
                matched = true;
                let _ = events.publish(ModuleEvent::Result {
                    job_id,
                    summary: hit.summary_line(),
                });
                hits.push(hit);
            }
        }

        if !matched {
            let hit = HashHit {
                kind: HashKind::Miss,
                algo,
                detail: format!("no match in {total} word(s)"),
                planned: false,
            };
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: hit.summary_line(),
            });
            hits.push(hit);
        }

        let _ = events.publish(ModuleEvent::Done { job_id });
        Ok(hits)
    }

    async fn emit_dry_run(
        &self,
        job_id: JobId,
        events: &EventSender,
        candidates: &[HashAlgo],
        algo: HashAlgo,
    ) -> Vec<HashHit> {
        let mut planned = Vec::new();
        let word_count = self
            .config
            .wordlist
            .as_ref()
            .and_then(|p| load_wordlist(p).ok())
            .map(|w| w.len())
            .unwrap_or(0);
        let total = (candidates.len() + if word_count > 0 { 1 } else { 0 }) as u64;

        for (i, c) in candidates.iter().enumerate() {
            let hit = HashHit {
                kind: HashKind::Identify,
                algo: *c,
                detail: identify_detail(*c, &self.config.hash),
                planned: true,
            };
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: (i as u64) + 1,
                total,
                message: format!("plan identify {}", c.as_str()),
            });
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: hit.summary_line(),
            });
            planned.push(hit);
        }

        if word_count > 0 {
            let hit = HashHit {
                kind: HashKind::Match,
                algo,
                detail: format!("would check {word_count} word(s) as {}", algo.as_str()),
                planned: true,
            };
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: total,
                total,
                message: "plan wordlist".into(),
            });
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: hit.summary_line(),
            });
            planned.push(hit);
        }

        let _ = events.publish(ModuleEvent::Done { job_id });
        planned
    }
}

impl Module for HashModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Hash
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_hash(job_id, events.clone()).await {
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

/// Classify a hash string into candidate algorithms (best-first).
pub fn identify_hash(raw: &str) -> Vec<HashAlgo> {
    let s = raw.trim();
    if s.is_empty() {
        return Vec::new();
    }

    let lower = s.to_ascii_lowercase();
    if lower.starts_with("$2a$") || lower.starts_with("$2b$") || lower.starts_with("$2y$") {
        return vec![HashAlgo::Bcrypt];
    }
    if lower.starts_with("$1$") {
        return vec![HashAlgo::Md5Crypt];
    }
    if lower.starts_with("$5$") {
        return vec![HashAlgo::Sha256Crypt];
    }
    if lower.starts_with("$6$") {
        return vec![HashAlgo::Sha512Crypt];
    }

    let hex = strip_hex_prefix(&lower);
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return vec![HashAlgo::Unknown];
    }

    match hex.len() {
        32 => vec![HashAlgo::Md5],
        40 => vec![HashAlgo::Sha1],
        64 => vec![HashAlgo::Sha256],
        96 => vec![HashAlgo::Sha384],
        128 => vec![HashAlgo::Sha512],
        _ => vec![HashAlgo::Unknown],
    }
}

/// Parse a result summary emitted on the event bus.
pub fn parse_hash_summary(summary: &str) -> Option<HashHit> {
    let planned = summary.starts_with("would hash ");
    let body = summary.strip_prefix("would hash ").unwrap_or(summary);
    let kind = body
        .split_whitespace()
        .find_map(|p| p.strip_prefix("kind="))
        .and_then(HashKind::parse)?;
    let algo = body
        .split_whitespace()
        .find_map(|p| p.strip_prefix("algo="))
        .and_then(HashAlgo::parse)?;
    let detail = body
        .find("detail=")
        .map(|i| body[i + "detail=".len()..].to_string())?;
    Some(HashHit {
        kind,
        algo,
        detail,
        planned,
    })
}

fn resolve_algo(
    forced: Option<HashAlgo>,
    candidates: &[HashAlgo],
    hash: &str,
) -> Result<HashAlgo, HashError> {
    if let Some(algo) = forced {
        if let Some(expected) = algo.hex_len() {
            let lower = hash.to_ascii_lowercase();
            let hex = strip_hex_prefix(&lower);
            if hex.len() != expected {
                return Err(HashError::AlgoMismatch {
                    algo: algo.as_str().into(),
                    len: hex.len(),
                });
            }
        }
        return Ok(algo);
    }
    Ok(candidates[0])
}

fn identify_detail(algo: HashAlgo, hash: &str) -> String {
    match algo {
        HashAlgo::Md5 => format!("32-hex digest ({})", truncate_for_audit(hash)),
        HashAlgo::Sha1 => format!("40-hex digest ({})", truncate_for_audit(hash)),
        HashAlgo::Sha256 => format!("64-hex digest ({})", truncate_for_audit(hash)),
        HashAlgo::Sha384 => format!("96-hex digest ({})", truncate_for_audit(hash)),
        HashAlgo::Sha512 => format!("128-hex digest ({})", truncate_for_audit(hash)),
        HashAlgo::Bcrypt => "bcrypt modular crypt ($2a/$2b/$2y); wordlist check unsupported".into(),
        HashAlgo::Md5Crypt => "md5crypt ($1$); wordlist check unsupported".into(),
        HashAlgo::Sha256Crypt => "sha256crypt ($5$); wordlist check unsupported".into(),
        HashAlgo::Sha512Crypt => "sha512crypt ($6$); wordlist check unsupported".into(),
        HashAlgo::Unknown => format!("unrecognized ({})", truncate_for_audit(hash)),
    }
}

fn hash_hex(algo: HashAlgo, input: &[u8]) -> String {
    match algo {
        HashAlgo::Md5 => to_hex(Md5::digest(input)),
        HashAlgo::Sha1 => to_hex(Sha1::digest(input)),
        HashAlgo::Sha256 => to_hex(Sha256::digest(input)),
        HashAlgo::Sha384 => to_hex(Sha384::digest(input)),
        HashAlgo::Sha512 => to_hex(Sha512::digest(input)),
        _ => String::new(),
    }
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn normalize_hash_input(raw: &str) -> Result<String, HashError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(HashError::InvalidHash("hash is empty".into()));
    }
    if s.len() > 512 {
        return Err(HashError::InvalidHash("hash is too long".into()));
    }
    Ok(s.to_string())
}

fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn truncate_for_audit(hash: &str) -> String {
    let chars: String = hash.chars().take(16).collect();
    if hash.chars().count() > 16 {
        format!("{chars}...")
    } else {
        chars
    }
}

fn load_wordlist(path: &Path) -> Result<Vec<String>, HashError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| HashError::Wordlist(format!("{}: {e}", path.display())))?;
    let words: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::EventBus;
    use std::io::Write;

    fn write_wordlist(words: &[&str]) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "keld-hash-wl-{}-{}.txt",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        for w in words {
            writeln!(f, "{w}").unwrap();
        }
        path
    }

    #[test]
    fn identifies_common_hex_lengths() {
        assert_eq!(
            identify_hash("5eb63bbbe01eeed093cb22bb8f5acdc3"),
            vec![HashAlgo::Md5]
        );
        assert_eq!(
            identify_hash("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
            vec![HashAlgo::Sha1]
        );
        assert_eq!(
            identify_hash("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
            vec![HashAlgo::Sha256]
        );
    }

    #[test]
    fn identifies_modular_crypt_prefixes() {
        assert_eq!(
            identify_hash("$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUV"),
            vec![HashAlgo::Bcrypt]
        );
        assert_eq!(identify_hash("$1$salt$hash"), vec![HashAlgo::Md5Crypt]);
        assert_eq!(identify_hash("$5$salt$hash"), vec![HashAlgo::Sha256Crypt]);
        assert_eq!(identify_hash("$6$salt$hash"), vec![HashAlgo::Sha512Crypt]);
    }

    #[test]
    fn summary_roundtrip() {
        let hit = HashHit {
            kind: HashKind::Match,
            algo: HashAlgo::Md5,
            detail: "password".into(),
            planned: false,
        };
        assert_eq!(parse_hash_summary(&hit.summary_line()).unwrap(), hit);
        let plan = HashHit {
            kind: HashKind::Identify,
            algo: HashAlgo::Sha256,
            detail: "64-hex digest (abcd...)".into(),
            planned: true,
        };
        assert_eq!(parse_hash_summary(&plan.summary_line()).unwrap(), plan);
    }

    #[tokio::test]
    async fn identifies_md5_without_wordlist() {
        let bus = EventBus::with_defaults();
        let mut rx = bus.subscribe();
        let config = HashConfig::from_parts(
            "5eb63bbbe01eeed093cb22bb8f5acdc3",
            None,
            None,
            HashRunOpts::default(),
        )
        .unwrap();
        let hits = HashModule::new(config)
            .run_hash(JobId::new(1), bus.sender())
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, HashKind::Identify);
        assert_eq!(hits[0].algo, HashAlgo::Md5);
        let mut saw_done = false;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, ModuleEvent::Done { .. }) {
                saw_done = true;
            }
        }
        assert!(saw_done);
    }

    #[tokio::test]
    async fn wordlist_finds_md5_password() {
        // md5("hello world")
        let wl = write_wordlist(&["nope", "hello world", "other"]);
        let bus = EventBus::with_defaults();
        let config = HashConfig::from_parts(
            "5eb63bbbe01eeed093cb22bb8f5acdc3",
            Some(wl.clone()),
            None,
            HashRunOpts {
                concurrency: 4,
                dry_run: false,
                rate_per_sec: None,
            },
        )
        .unwrap();
        let hits = HashModule::new(config)
            .run_hash(JobId::new(2), bus.sender())
            .await
            .unwrap();
        let _ = std::fs::remove_file(wl);
        assert!(hits.iter().any(|h| {
            h.kind == HashKind::Match && h.detail == "hello world" && h.algo == HashAlgo::Md5
        }));
    }

    #[tokio::test]
    async fn wordlist_miss_emits_miss() {
        let wl = write_wordlist(&["aaa", "bbb"]);
        let bus = EventBus::with_defaults();
        let config = HashConfig::from_parts(
            "5eb63bbbe01eeed093cb22bb8f5acdc3",
            Some(wl.clone()),
            Some(HashAlgo::Md5),
            HashRunOpts::default(),
        )
        .unwrap();
        let hits = HashModule::new(config)
            .run_hash(JobId::new(3), bus.sender())
            .await
            .unwrap();
        let _ = std::fs::remove_file(wl);
        assert!(hits.iter().any(|h| h.kind == HashKind::Miss));
    }

    #[tokio::test]
    async fn dry_run_plans_identify_and_wordlist() {
        let wl = write_wordlist(&["a", "b"]);
        let bus = EventBus::with_defaults();
        let config = HashConfig::from_parts(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            Some(wl.clone()),
            None,
            HashRunOpts {
                concurrency: 1,
                dry_run: true,
                rate_per_sec: None,
            },
        )
        .unwrap();
        let hits = HashModule::new(config)
            .run_hash(JobId::new(4), bus.sender())
            .await
            .unwrap();
        let _ = std::fs::remove_file(wl);
        assert!(hits.iter().all(|h| h.planned));
        assert!(hits.iter().any(|h| h.kind == HashKind::Identify));
        assert!(hits.iter().any(|h| h.kind == HashKind::Match));
    }

    #[test]
    fn forced_algo_length_mismatch() {
        let err = HashConfig::from_parts(
            "5eb63bbbe01eeed093cb22bb8f5acdc3",
            None,
            Some(HashAlgo::Sha256),
            HashRunOpts::default(),
        );
        // from_parts does not check length; run_hash does via resolve_algo
        let config = err.unwrap();
        let bus = EventBus::with_defaults();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(HashModule::new(config).run_hash(JobId::new(5), bus.sender()));
        assert!(matches!(result, Err(HashError::AlgoMismatch { .. })));
    }

    #[test]
    fn bcrypt_rejects_wordlist_in_config() {
        let err = HashConfig::from_parts(
            "$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUV",
            Some(PathBuf::from("words.txt")),
            Some(HashAlgo::Bcrypt),
            HashRunOpts::default(),
        );
        assert!(matches!(err, Err(HashError::UnsupportedAlgo(_))));
    }
}
