//! Reports screen: load findings JSON and export JSON/Markdown/HTML/CSV/SARIF.

use std::path::PathBuf;

use keld_core::{Finding, Severity};
use keld_report::{load_document, render, write_report, ReportDocument, ReportFormat};

/// Form field focus on the Reports screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportField {
    Input,
    Output,
    Title,
}

impl ReportField {
    pub fn next(self) -> Self {
        match self {
            Self::Input => Self::Output,
            Self::Output => Self::Title,
            Self::Title => Self::Input,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Input => Self::Title,
            Self::Output => Self::Input,
            Self::Title => Self::Output,
        }
    }
}

/// Export / load status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportRunState {
    Idle,
    Done,
    Failed,
}

/// TUI state for the Reports screen.
#[derive(Debug, Clone)]
pub struct ReportView {
    pub input: String,
    pub output: String,
    pub title: String,
    pub format: ReportFormat,
    pub field: ReportField,
    pub editing: bool,
    pub run_state: ReportRunState,
    pub message: String,
    pub findings: Vec<Finding>,
    pub selected: usize,
}

impl Default for ReportView {
    fn default() -> Self {
        Self {
            input: "findings.json".into(),
            output: "report.html".into(),
            title: String::new(),
            format: ReportFormat::Html,
            field: ReportField::Input,
            editing: false,
            run_state: ReportRunState::Idle,
            message: String::new(),
            findings: Vec::new(),
            selected: 0,
        }
    }
}

impl ReportView {
    /// Demo findings for snapshots and empty-state preview.
    pub fn placeholder_findings() -> Vec<Finding> {
        vec![
            Finding::new(
                "tls-1",
                Severity::High,
                "tls",
                "ex.com:443",
                "cert expires soon",
            )
            .with_evidence("notAfter in 12 days"),
            Finding::new(
                "http-1",
                Severity::Medium,
                "http",
                "https://ex.com",
                "missing HSTS",
            )
            .with_evidence("Strict-Transport-Security absent"),
        ]
    }

    pub fn ensure_preview(&mut self) {
        if self.findings.is_empty() {
            self.findings = Self::placeholder_findings();
            self.message = "preview (placeholder)".into();
        }
    }

    pub fn cycle_format(&mut self) {
        self.format = self.format.cycle();
        if let Some(ext) = PathBuf::from(&self.output).extension() {
            if ReportFormat::parse(&ext.to_string_lossy()).is_some() {
                let stem = PathBuf::from(&self.output)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "report".into());
                self.output = format!("{stem}.{}", self.format.extension());
            }
        }
    }

    pub fn active_value_mut(&mut self) -> &mut String {
        match self.field {
            ReportField::Input => &mut self.input,
            ReportField::Output => &mut self.output,
            ReportField::Title => &mut self.title,
        }
    }

    pub fn field_push(&mut self, c: char) {
        if !c.is_control() {
            self.active_value_mut().push(c);
        }
    }

    pub fn field_backspace(&mut self) {
        self.active_value_mut().pop();
    }

    pub fn select_next(&mut self) {
        if self.findings.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.findings.len();
    }

    pub fn select_prev(&mut self) {
        if self.findings.is_empty() {
            return;
        }
        self.selected = if self.selected == 0 {
            self.findings.len() - 1
        } else {
            self.selected - 1
        };
    }

    /// Load findings from the input path.
    pub fn load_input(&mut self) {
        match load_document(PathBuf::from(&self.input).as_path()) {
            Ok(doc) => {
                self.findings = doc.findings;
                if self.title.is_empty() && !doc.title.is_empty() {
                    self.title = doc.title;
                }
                self.selected = 0;
                self.run_state = ReportRunState::Done;
                self.message = format!("loaded {} finding(s)", self.findings.len());
            }
            Err(e) => {
                self.run_state = ReportRunState::Failed;
                self.message = e.to_string();
            }
        }
    }

    /// Export current findings to the output path.
    pub fn export(&mut self) {
        if self.findings.is_empty() {
            self.ensure_preview();
        }
        let mut doc = ReportDocument::empty()
            .with_title(self.title.clone())
            .with_findings(self.findings.clone());
        doc.touch();
        let path = PathBuf::from(&self.output);
        match write_report(&doc, self.format, &path) {
            Ok(()) => {
                self.run_state = ReportRunState::Done;
                self.message = format!(
                    "wrote {} ({} finding(s))",
                    self.format.as_str(),
                    self.findings.len()
                );
            }
            Err(e) => {
                self.run_state = ReportRunState::Failed;
                self.message = e.to_string();
            }
        }
    }

    /// Render to a string (for dry-run preview in message).
    pub fn preview_render(&self) -> Result<String, String> {
        let doc = ReportDocument::empty()
            .with_title(self.title.clone())
            .with_findings(self.findings.clone());
        render(&doc, self.format).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_format_updates_extension() {
        let mut v = ReportView {
            output: "out.html".into(),
            format: ReportFormat::Html,
            ..ReportView::default()
        };
        v.cycle_format();
        assert_eq!(v.format, ReportFormat::Csv);
        assert_eq!(v.output, "out.csv");
    }

    #[test]
    fn placeholder_has_two() {
        assert_eq!(ReportView::placeholder_findings().len(), 2);
    }
}
