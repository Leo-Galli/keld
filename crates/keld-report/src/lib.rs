//! Report renderers for Keld findings.
//!
//! Formats: JSON (canonical), Markdown, self-contained HTML, CSV, SARIF 2.1.0.

mod document;
mod format;
mod render;

pub use document::{load_document, load_paths, merge_documents, ReportDocument, ReportError};
pub use format::ReportFormat;
pub use render::{render, write_report};

/// Splash logo lines embedded in the HTML report header (Unicode block art).
pub const HTML_LOGO_LINES: &[&str] = &[
    " ██╗  ██╗███████╗██╗     ██████╗ ",
    " ██║ ██╔╝██╔════╝██║     ██╔══██╗",
    " █████╔╝ █████╗  ██║     ██║  ██║",
    " ██╔═██╗ ██╔══╝  ██║     ██║  ██║",
    " ██║  ██╗███████╗███████╗██████╔╝",
    " ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝ ",
];

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{Finding, Severity, NAME, TAGLINE, VERSION};

    fn sample() -> ReportDocument {
        ReportDocument {
            keld_version: VERSION.into(),
            generated_at: "2026-11-27T12:00:00Z".into(),
            title: "sample".into(),
            findings: vec![
                Finding::new(
                    "tls-1",
                    Severity::High,
                    "tls",
                    "ex.com:443",
                    "cert expires soon",
                )
                .with_evidence("notAfter in 12 days")
                .with_timestamp("2026-11-27T11:00:00Z"),
                Finding::new(
                    "http-1",
                    Severity::Medium,
                    "http",
                    "https://ex.com",
                    "missing HSTS",
                )
                .with_evidence("Strict-Transport-Security absent"),
            ],
        }
    }

    #[test]
    fn json_roundtrip() {
        let doc = sample();
        let out = render(&doc, ReportFormat::Json).unwrap();
        let back: ReportDocument = serde_json::from_str(&out).unwrap();
        assert_eq!(back.findings.len(), 2);
        assert_eq!(back.findings[0].id, "tls-1");
    }

    #[test]
    fn markdown_contains_findings() {
        let md = render(&sample(), ReportFormat::Markdown).unwrap();
        assert!(md.contains("# sample") || md.contains("# Keld report"));
        assert!(md.contains("cert expires soon"));
        assert!(md.contains("| high |"));
    }

    #[test]
    fn html_embeds_logo_and_tagline() {
        let html = render(&sample(), ReportFormat::Html).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains(HTML_LOGO_LINES[0].trim()) || html.contains("███████╗"));
        assert!(html.contains(TAGLINE));
        assert!(html.contains(NAME) || html.contains("Keld"));
        assert!(html.contains("missing HSTS"));
        assert!(html.contains("self-contained") || html.contains("<style>"));
    }

    #[test]
    fn csv_has_header_and_rows() {
        let csv = render(&sample(), ReportFormat::Csv).unwrap();
        let lines: Vec<_> = csv.lines().collect();
        assert!(lines[0].contains("id"));
        assert!(lines[0].contains("severity"));
        assert_eq!(lines.len(), 3);
        assert!(csv.contains("tls-1"));
    }

    #[test]
    fn sarif_is_valid_shape() {
        let sarif = render(&sample(), ReportFormat::Sarif).unwrap();
        let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif"));
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "Keld");
    }

    #[test]
    fn format_parse() {
        assert_eq!(ReportFormat::parse("html"), Some(ReportFormat::Html));
        assert_eq!(ReportFormat::parse("md"), Some(ReportFormat::Markdown));
        assert_eq!(ReportFormat::parse("sarif"), Some(ReportFormat::Sarif));
        assert!(ReportFormat::parse("nope").is_none());
    }

    #[test]
    fn merge_concatenates_findings() {
        let a = sample();
        let mut b = sample();
        b.findings[0].id = "extra".into();
        let merged = merge_documents(&[a, b]);
        assert_eq!(merged.findings.len(), 4);
    }
}
