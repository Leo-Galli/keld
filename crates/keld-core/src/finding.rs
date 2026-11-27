//! Shared finding model for reports and (later) the cross-module Findings view.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Finding severity (info < low < medium < high < critical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parse a severity label (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One discrete finding from a module run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub module: String,
    pub target: String,
    pub title: String,
    #[serde(default)]
    pub evidence: String,
    /// RFC3339 UTC when known; empty if unknown.
    #[serde(default)]
    pub timestamp: String,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        module: impl Into<String>,
        target: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            module: module.into(),
            target: target.into(),
            title: title.into(),
            evidence: String::new(),
            timestamp: String::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = evidence.into();
        self
    }

    pub fn with_timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = timestamp.into();
        self
    }
}

/// Errors when parsing findings payloads.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FindingError {
    #[error("invalid severity `{0}`")]
    InvalidSeverity(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_roundtrip() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        assert_eq!(Severity::parse("CRIT"), Some(Severity::Critical));
        assert!(Severity::parse("nope").is_none());
    }

    #[test]
    fn finding_serde_json() {
        let f = Finding::new("t-1", Severity::High, "tls", "ex.com:443", "expired")
            .with_evidence("notAfter=2020");
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }
}
