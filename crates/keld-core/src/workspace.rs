//! Local SQLite workspaces: scope, findings, and audit entries per project.
//!
//! Layout: `{root}/<name>/workspace.sqlite` where root defaults to
//! `$XDG_DATA_HOME/keld/workspaces` (or the OS equivalent). Override with
//! `KELD_WORKSPACES_DIR` for tests and portable installs.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

use crate::audit::{format_rfc3339_utc, AuditEntry, AuditOutcome};
use crate::finding::{Finding, Severity};
use crate::scope::{self, Scope, ScopeError};

/// SQLite file name inside each workspace directory.
pub const WORKSPACE_DB_FILE: &str = "workspace.sqlite";

/// Env override for the workspaces root (tests / portable).
pub const WORKSPACES_DIR_ENV: &str = "KELD_WORKSPACES_DIR";

const SCHEMA_VERSION: i64 = 1;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    toml TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY NOT NULL,
    severity TEXT NOT NULL,
    module TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    module TEXT NOT NULL,
    target TEXT NOT NULL,
    parameters TEXT NOT NULL,
    outcome TEXT NOT NULL
);
"#;

/// Summary row for listing workspaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceInfo {
    pub name: String,
    pub path: PathBuf,
    pub findings: usize,
    pub audit_entries: usize,
    pub has_scope: bool,
}

/// Counts and scope summary for an open workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStats {
    pub findings: usize,
    pub audit_entries: usize,
    pub has_scope: bool,
    pub scope_summary: String,
}

/// Errors for workspace storage.
#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("invalid workspace name `{0}` (use letters, digits, `_`, `-`; 1-64 chars)")]
    InvalidName(String),
    #[error("workspace `{0}` already exists")]
    AlreadyExists(String),
    #[error("workspace `{0}` not found")]
    NotFound(String),
    #[error("no workspaces directory available")]
    NoRoot,
    #[error("io error for {path}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("scope: {0}")]
    Scope(#[from] ScopeError),
    #[error("invalid severity in workspace db: `{0}`")]
    InvalidSeverity(String),
    #[error("invalid audit outcome in workspace db: `{0}`")]
    InvalidOutcome(String),
}

impl From<rusqlite::Error> for WorkspaceError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value.to_string())
    }
}

/// Root directory that contains workspace folders.
#[derive(Debug, Clone)]
pub struct WorkspaceStore {
    root: PathBuf,
}

impl WorkspaceStore {
    /// Default root: `KELD_WORKSPACES_DIR`, else `{data_dir}/keld/workspaces`.
    pub fn default_root() -> Result<PathBuf, WorkspaceError> {
        if let Ok(override_dir) = std::env::var(WORKSPACES_DIR_ENV) {
            let p = PathBuf::from(override_dir);
            if !p.as_os_str().is_empty() {
                return Ok(p);
            }
        }
        dirs::data_dir()
            .map(|d| d.join("keld").join("workspaces"))
            .ok_or(WorkspaceError::NoRoot)
    }

    /// Open a store at the default root (creates the directory if needed).
    pub fn open_default() -> Result<Self, WorkspaceError> {
        Self::open(Self::default_root()?)
    }

    /// Open a store at an explicit root (creates the directory if needed).
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, WorkspaceError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| WorkspaceError::Io {
            path: root.clone(),
            message: e.to_string(),
        })?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// List workspace directories that contain a SQLite file.
    pub fn list(&self) -> Result<Vec<WorkspaceInfo>, WorkspaceError> {
        let mut out = Vec::new();
        let entries = fs::read_dir(&self.root).map_err(|e| WorkspaceError::Io {
            path: self.root.clone(),
            message: e.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| WorkspaceError::Io {
                path: self.root.clone(),
                message: e.to_string(),
            })?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if validate_name(&name).is_err() {
                continue;
            }
            let db = path.join(WORKSPACE_DB_FILE);
            if !db.is_file() {
                continue;
            }
            let ws = Workspace::open_at(&path, &name)?;
            let stats = ws.stats()?;
            drop(ws);
            out.push(WorkspaceInfo {
                name,
                path,
                findings: stats.findings,
                audit_entries: stats.audit_entries,
                has_scope: stats.has_scope,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Create a new empty workspace.
    pub fn create(&self, name: &str) -> Result<Workspace, WorkspaceError> {
        validate_name(name)?;
        let dir = self.root.join(name);
        if dir.exists() {
            return Err(WorkspaceError::AlreadyExists(name.into()));
        }
        fs::create_dir_all(&dir).map_err(|e| WorkspaceError::Io {
            path: dir.clone(),
            message: e.to_string(),
        })?;
        let db_path = dir.join(WORKSPACE_DB_FILE);
        let conn = Connection::open(&db_path)?;
        init_schema(&conn)?;
        Ok(Workspace {
            name: name.into(),
            dir,
            conn,
        })
    }

    /// Open an existing workspace by name.
    pub fn open_workspace(&self, name: &str) -> Result<Workspace, WorkspaceError> {
        validate_name(name)?;
        let dir = self.root.join(name);
        let db = dir.join(WORKSPACE_DB_FILE);
        if !db.is_file() {
            return Err(WorkspaceError::NotFound(name.into()));
        }
        Workspace::open_at(&dir, name)
    }

    /// Delete a workspace directory (must not be open elsewhere).
    pub fn delete(&self, name: &str) -> Result<(), WorkspaceError> {
        validate_name(name)?;
        let dir = self.root.join(name);
        if !dir.exists() {
            return Err(WorkspaceError::NotFound(name.into()));
        }
        fs::remove_dir_all(&dir).map_err(|e| WorkspaceError::Io {
            path: dir,
            message: e.to_string(),
        })
    }
}

/// Open SQLite-backed project.
#[derive(Debug)]
pub struct Workspace {
    name: String,
    dir: PathBuf,
    conn: Connection,
}

impl Workspace {
    fn open_at(dir: &Path, name: &str) -> Result<Self, WorkspaceError> {
        let db = dir.join(WORKSPACE_DB_FILE);
        let conn = Connection::open(&db)?;
        init_schema(&conn)?;
        Ok(Self {
            name: name.into(),
            dir: dir.to_path_buf(),
            conn,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.join(WORKSPACE_DB_FILE)
    }

    pub fn stats(&self) -> Result<WorkspaceStats, WorkspaceError> {
        let findings: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
        let audit_entries: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))?;
        let findings = findings.max(0) as usize;
        let audit_entries = audit_entries.max(0) as usize;
        let scope_toml = self.scope_toml()?;
        let (has_scope, scope_summary) = match scope_toml {
            Some(text) => match scope::parse_toml(&text) {
                Ok(s) => (true, s.summary()),
                Err(_) => (true, "(invalid scope)".into()),
            },
            None => (false, "(no scope)".into()),
        };
        Ok(WorkspaceStats {
            findings,
            audit_entries,
            has_scope,
            scope_summary,
        })
    }

    /// Raw scope.toml text, if set.
    pub fn scope_toml(&self) -> Result<Option<String>, WorkspaceError> {
        let row: Option<String> = self
            .conn
            .query_row("SELECT toml FROM scope WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        Ok(row)
    }

    /// Validate and store scope TOML text.
    pub fn set_scope_toml(&self, toml_text: &str) -> Result<Scope, WorkspaceError> {
        let scope = scope::parse_toml(toml_text)?;
        let updated = now_rfc3339();
        self.conn.execute(
            "INSERT INTO scope (id, toml, updated_at) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET toml = excluded.toml, updated_at = excluded.updated_at",
            params![toml_text, updated],
        )?;
        Ok(scope)
    }

    /// Load parsed scope (empty if unset).
    pub fn load_scope(&self) -> Result<Scope, WorkspaceError> {
        match self.scope_toml()? {
            Some(text) => Ok(scope::parse_toml(&text)?),
            None => Ok(Scope::empty()),
        }
    }

    pub fn list_findings(&self) -> Result<Vec<Finding>, WorkspaceError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, severity, module, target, title, evidence, timestamp
             FROM findings ORDER BY severity DESC, id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, sev, module, target, title, evidence, timestamp) = row?;
            let severity = Severity::parse(&sev).ok_or(WorkspaceError::InvalidSeverity(sev))?;
            out.push(
                Finding::new(id, severity, module, target, title)
                    .with_evidence(evidence)
                    .with_timestamp(timestamp),
            );
        }
        Ok(out)
    }

    /// Replace all findings with `findings`.
    pub fn replace_findings(&self, findings: &[Finding]) -> Result<(), WorkspaceError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM findings", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (id, severity, module, target, title, evidence, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for f in findings {
                stmt.execute(params![
                    f.id,
                    f.severity.as_str(),
                    f.module,
                    f.target,
                    f.title,
                    f.evidence,
                    f.timestamp,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Upsert findings by id (keeps other rows).
    pub fn upsert_findings(&self, findings: &[Finding]) -> Result<(), WorkspaceError> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (id, severity, module, target, title, evidence, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                   severity = excluded.severity,
                   module = excluded.module,
                   target = excluded.target,
                   title = excluded.title,
                   evidence = excluded.evidence,
                   timestamp = excluded.timestamp",
            )?;
            for f in findings {
                stmt.execute(params![
                    f.id,
                    f.severity.as_str(),
                    f.module,
                    f.target,
                    f.title,
                    f.evidence,
                    f.timestamp,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_audit(&self) -> Result<Vec<AuditEntry>, WorkspaceError> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, module, target, parameters, outcome
             FROM audit ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (timestamp, module, target, parameters, outcome_s) = row?;
            let outcome = parse_outcome(&outcome_s)?;
            out.push(AuditEntry {
                timestamp,
                module,
                target,
                parameters,
                outcome,
            });
        }
        Ok(out)
    }

    pub fn append_audit(&self, entry: &AuditEntry) -> Result<(), WorkspaceError> {
        self.conn.execute(
            "INSERT INTO audit (timestamp, module, target, parameters, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                entry.timestamp,
                entry.module,
                entry.target,
                entry.parameters,
                entry.outcome.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Append many audit entries (e.g. import from JSONL).
    pub fn append_audit_many(&self, entries: &[AuditEntry]) -> Result<(), WorkspaceError> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO audit (timestamp, module, target, parameters, outcome)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for entry in entries {
                stmt.execute(params![
                    entry.timestamp,
                    entry.module,
                    entry.target,
                    entry.parameters,
                    entry.outcome.as_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn init_schema(conn: &Connection) -> Result<(), WorkspaceError> {
    conn.execute_batch(SCHEMA_SQL)?;
    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if version.is_none() {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), WorkspaceError> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(WorkspaceError::InvalidName(name.into()));
    };
    if !first.is_ascii_alphanumeric() || name.len() > 64 {
        return Err(WorkspaceError::InvalidName(name.into()));
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        Ok(())
    } else {
        Err(WorkspaceError::InvalidName(name.into()))
    }
}

fn parse_outcome(s: &str) -> Result<AuditOutcome, WorkspaceError> {
    match s {
        "ok" => Ok(AuditOutcome::Ok),
        "error" => Ok(AuditOutcome::Error),
        "denied" => Ok(AuditOutcome::Denied),
        "cancelled" => Ok(AuditOutcome::Cancelled),
        other => Err(WorkspaceError::InvalidOutcome(other.into())),
    }
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339_utc(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static N: AtomicU64 = AtomicU64::new(0);

    fn temp_store() -> WorkspaceStore {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("keld-ws-{nanos}-{n}"));
        let _ = fs::remove_dir_all(&root);
        WorkspaceStore::open(root).unwrap()
    }

    #[test]
    fn rejects_bad_names() {
        assert!(validate_name("").is_err());
        assert!(validate_name("-bad").is_err());
        assert!(validate_name("_bad").is_err());
        assert!(validate_name("has/slash").is_err());
        assert!(validate_name("ok").is_ok());
        assert!(validate_name("lab-1").is_ok());
        assert!(validate_name("a_b").is_ok());
    }

    #[test]
    fn create_list_delete_roundtrip() {
        let store = temp_store();
        assert!(store.list().unwrap().is_empty());
        let ws = store.create("demo").unwrap();
        assert_eq!(ws.name(), "demo");
        assert!(ws.db_path().is_file());
        drop(ws);
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "demo");
        assert!(!listed[0].has_scope);
        store.delete("demo").unwrap();
        assert!(store.list().unwrap().is_empty());
        assert!(matches!(
            store.open_workspace("demo"),
            Err(WorkspaceError::NotFound(_))
        ));
    }

    #[test]
    fn scope_findings_audit_persist() {
        let store = temp_store();
        let ws = store.create("lab").unwrap();
        let scope = ws
            .set_scope_toml("includes = [\"192.0.2.0/24\", \"ex.com\"]\n")
            .unwrap();
        assert!(scope.summary().contains("192.0.2.0/24"));

        let findings = vec![
            Finding::new("t-1", Severity::High, "tls", "ex.com:443", "expired")
                .with_evidence("notAfter=2020"),
            Finding::new("h-1", Severity::Info, "http", "https://ex.com", "ok"),
        ];
        ws.replace_findings(&findings).unwrap();
        assert_eq!(ws.list_findings().unwrap().len(), 2);

        let entry = AuditEntry::now("workspace", "lab", "import findings=2", AuditOutcome::Ok);
        ws.append_audit(&entry).unwrap();
        assert_eq!(ws.list_audit().unwrap().len(), 1);

        let stats = ws.stats().unwrap();
        assert_eq!(stats.findings, 2);
        assert_eq!(stats.audit_entries, 1);
        assert!(stats.has_scope);

        drop(ws);
        let ws2 = store.open_workspace("lab").unwrap();
        assert_eq!(ws2.list_findings().unwrap().len(), 2);
        assert!(!ws2.load_scope().unwrap().is_empty());
    }

    #[test]
    fn upsert_keeps_other_findings() {
        let store = temp_store();
        let ws = store.create("up").unwrap();
        ws.replace_findings(&[Finding::new("a", Severity::Low, "scan", "1.1.1.1", "open")])
            .unwrap();
        ws.upsert_findings(&[Finding::new(
            "b",
            Severity::Medium,
            "probe",
            "1.1.1.1:22",
            "ssh",
        )])
        .unwrap();
        assert_eq!(ws.list_findings().unwrap().len(), 2);
    }

    #[test]
    fn duplicate_create_fails() {
        let store = temp_store();
        store.create("x").unwrap();
        assert!(matches!(
            store.create("x"),
            Err(WorkspaceError::AlreadyExists(_))
        ));
    }
}
