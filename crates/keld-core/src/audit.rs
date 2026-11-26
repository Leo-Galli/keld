//! Append-only audit log (JSONL on disk).
//!
//! Every active action should record an [`AuditEntry`]. The file is never
//! rewritten in place; new lines are appended. Load reads the whole file for
//! the TUI viewer (read-only).

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default relative audit file in the working directory.
pub const DEFAULT_AUDIT_FILE: &str = "audit.jsonl";

/// Result of a recorded action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Ok,
    Error,
    Denied,
    Cancelled,
}

impl AuditOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
        }
    }
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One audited action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// UTC timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
    pub timestamp: String,
    /// Module or subsystem id (`scan`, `scope`, …).
    pub module: String,
    /// Target of the action (host, path, or `-` when none).
    pub target: String,
    /// Free-form parameters summary.
    pub parameters: String,
    pub outcome: AuditOutcome,
}

impl AuditEntry {
    /// Build an entry with the current UTC time.
    pub fn now(
        module: impl Into<String>,
        target: impl Into<String>,
        parameters: impl Into<String>,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            timestamp: utc_now_rfc3339(),
            module: module.into(),
            target: target.into(),
            parameters: parameters.into(),
            outcome,
        }
    }

    /// Case-insensitive substring match across fields.
    pub fn matches_filter(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_ascii_lowercase();
        self.timestamp.to_ascii_lowercase().contains(&q)
            || self.module.to_ascii_lowercase().contains(&q)
            || self.target.to_ascii_lowercase().contains(&q)
            || self.parameters.to_ascii_lowercase().contains(&q)
            || self.outcome.as_str().contains(q.as_str())
    }
}

/// Append-only audit log backed by a JSONL file.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    entries: Vec<AuditEntry>,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error for {path}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("parse audit line {line} in {path}: {message}")]
    Parse {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error("serialize audit entry: {0}")]
    Serialize(String),
}

impl AuditLog {
    /// Empty in-memory log with a path (file created on first append).
    pub fn empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            entries: Vec::new(),
        }
    }

    /// Load existing JSONL (missing file => empty log at that path).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(Self::empty(path));
        }
        let file = File::open(&path).map_err(|e| AuditError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| AuditError::Io {
                path: path.clone(),
                message: e.to_string(),
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let entry: AuditEntry =
                serde_json::from_str(trimmed).map_err(|e| AuditError::Parse {
                    path: path.clone(),
                    line: idx + 1,
                    message: e.to_string(),
                })?;
            entries.push(entry);
        }
        Ok(Self { path, entries })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries matching a filter query (empty query = all), oldest first.
    pub fn filtered(&self, query: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.matches_filter(query))
            .collect()
    }

    /// Append one entry to memory and to the file (creates parent dirs).
    pub fn append(&mut self, entry: AuditEntry) -> Result<(), AuditError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| AuditError::Io {
                    path: self.path.clone(),
                    message: e.to_string(),
                })?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io {
                path: self.path.clone(),
                message: e.to_string(),
            })?;
        let line =
            serde_json::to_string(&entry).map_err(|e| AuditError::Serialize(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| AuditError::Io {
            path: self.path.clone(),
            message: e.to_string(),
        })?;
        file.flush().map_err(|e| AuditError::Io {
            path: self.path.clone(),
            message: e.to_string(),
        })?;
        self.entries.push(entry);
        Ok(())
    }
}

/// Prefer `./audit.jsonl`, else user data dir `…/keld/audit.jsonl`.
pub fn default_audit_path() -> PathBuf {
    let local = PathBuf::from(DEFAULT_AUDIT_FILE);
    if local.is_file() {
        return local;
    }
    dirs::data_dir()
        .map(|d| d.join("keld").join(DEFAULT_AUDIT_FILE))
        .unwrap_or(local)
}

/// Format unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
pub fn format_rfc3339_utc(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_days(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339_utc(secs)
}

/// Howard Hinnant civil-from-days (UTC), plus time-of-day.
fn civil_from_days(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    // days since 1970-01-01 -> civil date
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("keld-audit-{tag}-{nanos}.jsonl"))
    }

    #[test]
    fn append_and_load_roundtrip() {
        let path = temp_path("round");
        let _ = fs::remove_file(&path);

        let mut log = AuditLog::empty(&path);
        log.append(AuditEntry {
            timestamp: "2026-11-26T10:00:00Z".into(),
            module: "scan".into(),
            target: "10.0.0.5".into(),
            parameters: "ports=1-1024".into(),
            outcome: AuditOutcome::Ok,
        })
        .unwrap();
        log.append(AuditEntry::now(
            "http",
            "https://app.example.com",
            "headers",
            AuditOutcome::Denied,
        ))
        .unwrap();

        assert_eq!(log.len(), 2);

        let loaded = AuditLog::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.entries()[0].module, "scan");
        assert_eq!(loaded.entries()[0].outcome, AuditOutcome::Ok);
        assert_eq!(loaded.entries()[1].module, "http");
        assert_eq!(loaded.entries()[1].outcome, AuditOutcome::Denied);

        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("\"module\":\"scan\""));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_missing_is_empty() {
        let path = temp_path("missing");
        let _ = fs::remove_file(&path);
        let log = AuditLog::load(&path).unwrap();
        assert!(log.is_empty());
        assert_eq!(log.path(), path.as_path());
    }

    #[test]
    fn filter_matches_fields() {
        let mut log = AuditLog::empty(temp_path("filter"));
        log.entries.push(AuditEntry {
            timestamp: "2026-11-26T10:00:00Z".into(),
            module: "scan".into(),
            target: "10.0.0.5".into(),
            parameters: "ports=22".into(),
            outcome: AuditOutcome::Ok,
        });
        log.entries.push(AuditEntry {
            timestamp: "2026-11-26T11:00:00Z".into(),
            module: "tls".into(),
            target: "app.example.com".into(),
            parameters: "sni".into(),
            outcome: AuditOutcome::Error,
        });
        assert_eq!(log.filtered("scan").len(), 1);
        assert_eq!(log.filtered("EXAMPLE").len(), 1);
        assert_eq!(log.filtered("error").len(), 1);
        assert_eq!(log.filtered("").len(), 2);
        assert!(log.filtered("nope").is_empty());
    }

    #[test]
    fn rfc3339_known_epoch() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // 2026-11-26T00:00:00Z
        assert_eq!(format_rfc3339_utc(1_795_651_200), "2026-11-26T00:00:00Z");
    }

    #[test]
    fn append_is_additive() {
        let path = temp_path("additive");
        let _ = fs::remove_file(&path);
        {
            let mut log = AuditLog::empty(&path);
            log.append(AuditEntry {
                timestamp: "2026-01-01T00:00:00Z".into(),
                module: "a".into(),
                target: "-".into(),
                parameters: String::new(),
                outcome: AuditOutcome::Ok,
            })
            .unwrap();
        }
        {
            let mut log = AuditLog::load(&path).unwrap();
            log.append(AuditEntry {
                timestamp: "2026-01-02T00:00:00Z".into(),
                module: "b".into(),
                target: "-".into(),
                parameters: String::new(),
                outcome: AuditOutcome::Cancelled,
            })
            .unwrap();
            assert_eq!(log.len(), 2);
        }
        let loaded = AuditLog::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.entries()[1].module, "b");
        let _ = fs::remove_file(&path);
    }
}
