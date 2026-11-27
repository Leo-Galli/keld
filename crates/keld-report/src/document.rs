//! Report document load / merge.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use keld_core::{format_rfc3339_utc, Finding, VERSION};
use serde::{Deserialize, Serialize};
use thiserror::Error;

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339_utc(secs)
}

/// Canonical findings bundle for export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportDocument {
    pub keld_version: String,
    pub generated_at: String,
    #[serde(default)]
    pub title: String,
    pub findings: Vec<Finding>,
}

impl ReportDocument {
    /// Empty document stamped with the current crate version and UTC time.
    pub fn empty() -> Self {
        Self {
            keld_version: VERSION.into(),
            generated_at: now_rfc3339(),
            title: String::new(),
            findings: Vec::new(),
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }

    /// Refresh `generated_at` to now (UTC).
    pub fn touch(&mut self) {
        self.generated_at = now_rfc3339();
        if self.keld_version.is_empty() {
            self.keld_version = VERSION.into();
        }
    }
}

/// Flexible JSON envelope: either a full document or a bare findings array /
/// `{ "findings": [...] }` wrapper.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FindingsPayload {
    Document(ReportDocument),
    Wrapped { findings: Vec<Finding> },
    Array(Vec<Finding>),
}

/// Errors loading or writing reports.
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Message(String),
}

/// Parse a JSON findings document from bytes.
pub fn parse_document(bytes: &[u8]) -> Result<ReportDocument, ReportError> {
    let payload: FindingsPayload = serde_json::from_slice(bytes)?;
    Ok(match payload {
        FindingsPayload::Document(mut doc) => {
            if doc.keld_version.is_empty() {
                doc.keld_version = VERSION.into();
            }
            if doc.generated_at.is_empty() {
                doc.generated_at = now_rfc3339();
            }
            doc
        }
        FindingsPayload::Wrapped { findings } => ReportDocument::empty().with_findings(findings),
        FindingsPayload::Array(findings) => ReportDocument::empty().with_findings(findings),
    })
}

/// Load one JSON findings file.
pub fn load_document(path: &Path) -> Result<ReportDocument, ReportError> {
    let bytes = fs::read(path)?;
    parse_document(&bytes)
}

/// Load and merge several JSON findings files (order preserved).
pub fn load_paths(paths: &[impl AsRef<Path>]) -> Result<ReportDocument, ReportError> {
    if paths.is_empty() {
        return Err(ReportError::Message(
            "at least one input path is required".into(),
        ));
    }
    let mut docs = Vec::with_capacity(paths.len());
    for p in paths {
        docs.push(load_document(p.as_ref())?);
    }
    Ok(merge_documents(&docs))
}

/// Concatenate findings; keep first non-empty title; refresh timestamp.
pub fn merge_documents(docs: &[ReportDocument]) -> ReportDocument {
    let mut out = ReportDocument::empty();
    for doc in docs {
        if out.title.is_empty() && !doc.title.is_empty() {
            out.title = doc.title.clone();
        }
        out.findings.extend(doc.findings.iter().cloned());
    }
    out
}
