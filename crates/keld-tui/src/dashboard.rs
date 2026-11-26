//! Dashboard and Jobs list view models (placeholder data until workspace/modules wire in).

use keld_core::{Job, JobId, JobState, ModuleKind};

use crate::theme::Severity;

/// One severity bucket for the findings bar chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeverityCount {
    pub severity: Severity,
    pub count: u64,
}

/// Open port summary row for the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
    pub proto: &'static str,
    pub note: String,
}

/// Job row shown on Dashboard (recent) and the Jobs screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
    pub job: Job,
    /// Elapsed wall time while non-terminal (advanced on tick).
    pub elapsed_secs: u64,
    /// Short results label (e.g. "12 open", "8 findings").
    pub results_label: String,
}

impl JobRow {
    pub fn new(job: Job, elapsed_secs: u64, results_label: impl Into<String>) -> Self {
        Self {
            job,
            elapsed_secs,
            results_label: results_label.into(),
        }
    }

    pub fn id_label(&self) -> String {
        format!("j-{:02}", self.job.id.get())
    }

    pub fn state_label(&self) -> &'static str {
        match self.job.state {
            JobState::Pending => "pending",
            JobState::Running => "running",
            JobState::Paused => "paused",
            JobState::Completed => "done",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }

    pub fn progress_pct(&self) -> Option<u8> {
        self.job
            .progress_fraction()
            .map(|f| (f * 100.0).round().clamp(0.0, 100.0) as u8)
    }

    pub fn duration_label(&self) -> String {
        let m = self.elapsed_secs / 60;
        let s = self.elapsed_secs % 60;
        format!("{m:02}:{s:02}")
    }

    /// Advance a running job one stub tick (progress + elapsed). Persists across screens.
    pub fn tick(&mut self) {
        if self.job.state != JobState::Running {
            return;
        }
        self.elapsed_secs = self.elapsed_secs.saturating_add(1);
        if self.job.total == 0 {
            self.job.total = 100;
        }
        if self.job.done < self.job.total {
            self.job.done = self.job.done.saturating_add(1);
        }
        if self.job.done >= self.job.total {
            self.job.state = JobState::Completed;
            if self.results_label.is_empty() {
                self.results_label = format!("{} results", self.job.results.max(1));
            }
        }
    }
}

/// Placeholder dashboard payload (stable for snapshots; tick mutates jobs/sparkline only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardState {
    pub findings: Vec<SeverityCount>,
    pub rps_samples: Vec<u64>,
    pub open_ports: Vec<OpenPort>,
    pub jobs: Vec<JobRow>,
}

impl DashboardState {
    /// Demo data matching DESIGN.md mockup numbers.
    pub fn placeholder() -> Self {
        let mut scan = Job::new(JobId::new(1), ModuleKind::Scan);
        scan.state = JobState::Completed;
        scan.done = 100;
        scan.total = 100;
        scan.results = 12;

        let mut http = Job::new(JobId::new(0), ModuleKind::Http);
        http.state = JobState::Running;
        http.done = 34;
        http.total = 100;
        http.results = 2;

        Self {
            findings: vec![
                SeverityCount {
                    severity: Severity::Critical,
                    count: 2,
                },
                SeverityCount {
                    severity: Severity::High,
                    count: 5,
                },
                SeverityCount {
                    severity: Severity::Medium,
                    count: 3,
                },
                SeverityCount {
                    severity: Severity::Low,
                    count: 2,
                },
                SeverityCount {
                    severity: Severity::Info,
                    count: 1,
                },
            ],
            rps_samples: vec![4, 8, 12, 18, 28, 22, 14, 10, 6, 9, 14, 20, 16, 11, 8],
            open_ports: vec![
                OpenPort {
                    port: 22,
                    proto: "tcp",
                    note: "ssh?".into(),
                },
                OpenPort {
                    port: 80,
                    proto: "tcp",
                    note: "http?".into(),
                },
                OpenPort {
                    port: 443,
                    proto: "tcp",
                    note: "https?".into(),
                },
            ],
            jobs: vec![
                JobRow::new(http, 12, "2 open"),
                JobRow::new(scan, 45, "12 open"),
            ],
        }
    }

    pub fn running_count(&self) -> usize {
        self.jobs
            .iter()
            .filter(|j| j.job.state == JobState::Running || j.job.state == JobState::Paused)
            .count()
    }

    pub fn error_count(&self) -> u64 {
        self.jobs.iter().map(|j| j.job.errors).sum()
    }

    pub fn current_rate(&self) -> u64 {
        self.rps_samples.last().copied().unwrap_or(0)
    }

    pub fn findings_total(&self) -> u64 {
        self.findings.iter().map(|f| f.count).sum()
    }

    /// Advance running jobs and nudge the RPS sparkline (screen-independent).
    pub fn tick(&mut self) {
        for job in &mut self.jobs {
            job.tick();
        }
        if let Some(last) = self.rps_samples.last().copied() {
            let next = match last % 5 {
                0 => last.saturating_add(3),
                1 => last.saturating_add(1),
                2 => last.saturating_sub(2).max(1),
                3 => last.saturating_add(2),
                _ => last.saturating_sub(1).max(1),
            };
            self.rps_samples.push(next.min(40));
            if self.rps_samples.len() > 24 {
                self.rps_samples.remove(0);
            }
        }
    }
}

/// Horizontal bar using filled/empty cells (`#`/`-` in ASCII).
pub fn bar(count: u64, max: u64, width: usize, ascii: bool) -> String {
    if width == 0 {
        return String::new();
    }
    let filled = if max == 0 {
        0
    } else {
        ((count as f64 / max as f64) * width as f64).round() as usize
    };
    let filled = filled.min(width);
    let on = if ascii { '#' } else { '█' };
    let off = if ascii { '-' } else { '░' };
    let mut s = String::with_capacity(width);
    for i in 0..width {
        s.push(if i < filled { on } else { off });
    }
    s
}

/// Compact sparkline from samples (`_.-=#` ASCII / block chars Unicode).
pub fn sparkline(samples: &[u64], width: usize, ascii: bool) -> String {
    if width == 0 || samples.is_empty() {
        return String::new();
    }
    let max = samples.iter().copied().max().unwrap_or(1).max(1);
    let start = samples.len().saturating_sub(width);
    let slice = &samples[start..];
    let levels: &[char] = if ascii {
        &['.', '_', '-', '=', '#']
    } else {
        &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']
    };
    let last = levels.len() - 1;
    slice
        .iter()
        .map(|v| {
            let idx = ((*v as f64 / max as f64) * last as f64).round() as usize;
            levels[idx.min(last)]
        })
        .collect()
}

pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_scales_to_width() {
        assert_eq!(bar(5, 5, 8, true), "########");
        assert_eq!(bar(0, 5, 8, true), "--------");
        assert_eq!(bar(1, 2, 4, true).chars().filter(|c| *c == '#').count(), 2);
    }

    #[test]
    fn sparkline_uses_recent_samples() {
        let s = sparkline(&[1, 2, 3, 4, 5], 3, true);
        assert_eq!(s.chars().count(), 3);
    }

    #[test]
    fn tick_advances_running_job_only() {
        let mut dash = DashboardState::placeholder();
        let before = dash.jobs[0].job.done;
        let done_before = dash.jobs[1].job.state;
        dash.tick();
        assert_eq!(dash.jobs[0].job.done, before + 1);
        assert_eq!(dash.jobs[1].job.state, done_before);
        assert_eq!(dash.running_count(), 1);
    }
}
