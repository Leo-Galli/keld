//! Output format identifiers.

use std::fmt;
use std::path::Path;

/// Supported report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    Json,
    Markdown,
    Html,
    Csv,
    Sarif,
}

impl ReportFormat {
    pub const ALL: &'static [ReportFormat] = &[
        Self::Json,
        Self::Markdown,
        Self::Html,
        Self::Csv,
        Self::Sarif,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Html => "html",
            Self::Csv => "csv",
            Self::Sarif => "sarif",
        }
    }

    /// File extension without the dot.
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "md",
            Self::Html => "html",
            Self::Csv => "csv",
            Self::Sarif => "sarif",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "markdown" | "md" => Some(Self::Markdown),
            "html" | "htm" => Some(Self::Html),
            "csv" => Some(Self::Csv),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }

    pub fn cycle(self) -> Self {
        let idx = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    /// Guess format from a path extension.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|e| e.to_str())
            .and_then(Self::parse)
    }
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
