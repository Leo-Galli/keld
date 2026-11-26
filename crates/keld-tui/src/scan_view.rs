//! Scan module screen state (form + results). Live scans run on a worker thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    PortHit, PortState, ScanConfig, ScanModule, ScanTechnique, SynAvailability,
    DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanField {
    Target,
    Ports,
    Concurrency,
    Timeout,
}

impl ScanField {
    pub const fn next(self) -> Self {
        match self {
            Self::Target => Self::Ports,
            Self::Ports => Self::Concurrency,
            Self::Concurrency => Self::Timeout,
            Self::Timeout => Self::Target,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Target => Self::Timeout,
            Self::Ports => Self::Target,
            Self::Concurrency => Self::Ports,
            Self::Timeout => Self::Concurrency,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background scan worker.
#[derive(Debug, Clone)]
pub enum ScanUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Hit(PortHit),
    Notice(String),
    Done,
    Error(String),
}

/// TUI state for the Scan screen.
#[derive(Debug)]
pub struct ScanView {
    pub target: String,
    pub ports: String,
    pub concurrency: String,
    pub timeout_ms: String,
    pub dry_run: bool,
    /// Request SYN. Unavailable raw sockets fall back to TCP connect.
    pub syn: bool,
    /// Fallback or capability line shown on the Scan screen.
    pub notice: String,
    pub field: ScanField,
    pub editing: bool,
    pub run_state: ScanRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<PortHit>,
    pub selected: usize,
    pub error: Option<String>,
    inbox: Option<Receiver<ScanUiEvent>>,
}

impl Default for ScanView {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: "top".into(),
            concurrency: DEFAULT_CONCURRENCY.to_string(),
            timeout_ms: DEFAULT_TIMEOUT_MS.to_string(),
            dry_run: false,
            syn: false,
            notice: String::new(),
            field: ScanField::Target,
            editing: false,
            run_state: ScanRunState::Idle,
            done: 0,
            total: 0,
            message: String::new(),
            results: Vec::new(),
            selected: 0,
            error: None,
            inbox: None,
        }
    }
}

impl ScanView {
    pub fn progress_fraction(&self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        Some((self.done as f64 / self.total as f64).clamp(0.0, 1.0))
    }

    pub fn progress_label(&self) -> String {
        match self.progress_fraction() {
            Some(f) => format!("{:.0}%", f * 100.0),
            None => "--".into(),
        }
    }

    pub fn detail_line(&self) -> String {
        if let Some(err) = &self.error {
            return format!("Error: {err}");
        }
        if let Some(hit) = self.results.get(self.selected) {
            return format!(
                "{}:{} {} ({})",
                hit.host,
                hit.port,
                hit.state,
                self.mode_label()
            );
        }
        if !self.notice.is_empty() {
            return self.notice.clone();
        }
        if self.message.is_empty() {
            "Select a row for detail. s start  p dry-run  y syn".into()
        } else {
            self.message.clone()
        }
    }

    pub fn mode_label(&self) -> &'static str {
        if self.syn {
            "syn requested"
        } else {
            "tcp connect"
        }
    }

    /// Toggle a SYN request and explain whether it can run.
    pub fn toggle_syn(&mut self) {
        self.syn = !self.syn;
        if !self.syn {
            self.notice.clear();
            return;
        }
        let avail = SynAvailability::probe();
        self.notice = if avail.usable {
            format!("SYN available: {}", avail.detail)
        } else {
            format!("SYN unavailable: {}. Start uses TCP connect.", avail.detail)
        };
    }

    pub fn select_next(&mut self) {
        if self.results.is_empty() {
            self.selected = 0;
            return;
        }
        self.selected = (self.selected + 1).min(self.results.len() - 1);
    }

    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn field_push(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        self.field_buf().push(c);
    }

    pub fn field_backspace(&mut self) {
        self.field_buf().pop();
    }

    fn field_buf(&mut self) -> &mut String {
        match self.field {
            ScanField::Target => &mut self.target,
            ScanField::Ports => &mut self.ports,
            ScanField::Concurrency => &mut self.concurrency,
            ScanField::Timeout => &mut self.timeout_ms,
        }
    }

    pub fn field_value(&self) -> &str {
        match self.field {
            ScanField::Target => &self.target,
            ScanField::Ports => &self.ports,
            ScanField::Concurrency => &self.concurrency,
            ScanField::Timeout => &self.timeout_ms,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(ScanUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(ScanUiEvent::Hit(hit)) => {
                    self.results.push(hit);
                }
                Ok(ScanUiEvent::Notice(message)) => {
                    self.notice = message;
                }
                Ok(ScanUiEvent::Done) => {
                    self.run_state = ScanRunState::Done;
                    self.message = format!("done; {} hit(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(ScanUiEvent::Error(msg)) => {
                    self.run_state = ScanRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == ScanRunState::Running {
                        self.run_state = ScanRunState::Failed;
                        self.error = Some("scan worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start a scan against `scope` on a background thread.
    pub fn start(&mut self, scope: &Scope) -> Result<(), String> {
        if self.run_state == ScanRunState::Running {
            return Err("scan already running".into());
        }
        if self.target.trim().is_empty() {
            return Err("target is required".into());
        }

        let concurrency: usize = self
            .concurrency
            .trim()
            .parse()
            .unwrap_or(DEFAULT_CONCURRENCY);
        let timeout_ms: u64 = self.timeout_ms.trim().parse().unwrap_or(DEFAULT_TIMEOUT_MS);

        let mut config = ScanConfig::from_parts(
            self.target.trim(),
            &self.ports,
            timeout_ms,
            concurrency,
            self.dry_run,
            None,
        )
        .map_err(|e| e.to_string())?;
        if self.syn {
            config.technique = ScanTechnique::Syn;
        }

        scope.check(&config.target).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::channel();
        self.inbox = Some(rx);
        self.results.clear();
        self.selected = 0;
        self.done = 0;
        self.total = config.ports.len() as u64;
        self.error = None;
        self.message = "starting...".into();
        self.run_state = ScanRunState::Running;
        self.editing = false;

        let scope = scope.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(ScanUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = ScanModule::new(config, scope);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_scan(job_id, sender).await });
                let tx_fwd = tx.clone();

                let forward = tokio::spawn(async move {
                    loop {
                        match events.recv().await {
                            Ok(ModuleEvent::Progress {
                                done,
                                total,
                                message,
                                ..
                            }) => {
                                if tx_fwd
                                    .send(ScanUiEvent::Progress {
                                        done,
                                        total,
                                        message,
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Ok(ModuleEvent::Log { message, .. }) => {
                                if tx_fwd.send(ScanUiEvent::Notice(message)).is_err() {
                                    break;
                                }
                            }
                            Ok(ModuleEvent::Result { summary, .. }) => {
                                if let Some(hit) = parse_result_summary(&summary) {
                                    if tx_fwd.send(ScanUiEvent::Hit(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(ScanUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(ScanUiEvent::Error(message));
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                });

                match worker.await {
                    Ok(Ok(_)) => {
                        let _ = forward.await;
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(ScanUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(ScanUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                }
            });
        });

        Ok(())
    }
}

fn parse_result_summary(summary: &str) -> Option<PortHit> {
    // Formats: "host:port open" | "would connect host:port"
    if let Some(rest) = summary
        .strip_prefix("would connect ")
        .or_else(|| summary.strip_prefix("would syn "))
    {
        let (host, port_s) = rest.rsplit_once(':')?;
        let port: u16 = port_s.parse().ok()?;
        return Some(PortHit {
            host: host.to_string(),
            port,
            state: PortState::Planned,
        });
    }
    let mut parts = summary.split_whitespace();
    let addr = parts.next()?;
    let state_s = parts.next().unwrap_or("open");
    let (host, port_s) = addr.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    let state = match state_s {
        "open" => PortState::Open,
        "planned" => PortState::Planned,
        "closed" => PortState::Closed,
        "filtered" => PortState::Filtered,
        _ => PortState::Open,
    };
    Some(PortHit {
        host: host.to_string(),
        port,
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::ScopeEntry;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parse_open_and_planned() {
        let h = parse_result_summary("127.0.0.1:80 open").unwrap();
        assert_eq!(h.port, 80);
        assert_eq!(h.state, PortState::Open);
        let p = parse_result_summary("would connect 10.0.0.5:22").unwrap();
        assert_eq!(p.port, 22);
        assert_eq!(p.state, PortState::Planned);
        let syn = parse_result_summary("would syn 10.0.0.5:443").unwrap();
        assert_eq!(syn.port, 443);
        assert_eq!(syn.state, PortState::Planned);
    }

    #[test]
    fn syn_toggle_explains_availability() {
        let mut view = ScanView::default();
        assert!(!view.syn);
        view.toggle_syn();
        assert!(view.syn);
        assert!(!view.notice.is_empty());
        view.toggle_syn();
        assert!(!view.syn);
        assert!(view.notice.is_empty());
    }

    #[test]
    fn start_dry_run_against_scope() {
        let scope = Scope {
            includes: vec![ScopeEntry::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            excludes: Vec::new(),
            notes: None,
            source: None,
        };
        let mut view = ScanView {
            target: "127.0.0.1".into(),
            ports: "22,80".into(),
            dry_run: true,
            ..ScanView::default()
        };
        view.start(&scope).unwrap();
        assert_eq!(view.run_state, ScanRunState::Running);
        // Poll until done (worker is fast for dry-run).
        for _ in 0..200 {
            view.poll();
            if view.run_state != ScanRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, ScanRunState::Done);
        assert_eq!(view.results.len(), 2);
    }
}
