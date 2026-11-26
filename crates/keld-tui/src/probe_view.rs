//! Probe module screen state (form + results). Live probes run on a worker thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    parse_probe_summary, ProbeConfig, ProbeHit, ProbeModule, DEFAULT_PROBE_CONCURRENCY,
    DEFAULT_PROBE_TIMEOUT_MS,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeField {
    Target,
    Ports,
    Concurrency,
    Timeout,
}

impl ProbeField {
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
pub enum ProbeRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background probe worker.
#[derive(Debug, Clone)]
pub enum ProbeUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Hit(ProbeHit),
    Done,
    Error(String),
}

/// TUI state for the Probe screen.
#[derive(Debug)]
pub struct ProbeView {
    pub target: String,
    pub ports: String,
    pub concurrency: String,
    pub timeout_ms: String,
    pub dry_run: bool,
    pub field: ProbeField,
    pub editing: bool,
    pub run_state: ProbeRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<ProbeHit>,
    pub selected: usize,
    pub error: Option<String>,
    inbox: Option<Receiver<ProbeUiEvent>>,
}

impl Default for ProbeView {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: "top".into(),
            concurrency: DEFAULT_PROBE_CONCURRENCY.to_string(),
            timeout_ms: DEFAULT_PROBE_TIMEOUT_MS.to_string(),
            dry_run: false,
            field: ProbeField::Target,
            editing: false,
            run_state: ProbeRunState::Idle,
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

impl ProbeView {
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
            if hit.planned {
                return format!(
                    "{}:{} would run probes [{}]",
                    hit.host, hit.port, hit.probe_name
                );
            }
            let banner = if hit.banner.is_empty() {
                "(no banner)".into()
            } else {
                hit.banner.clone()
            };
            return format!(
                "{}:{} {} / {} via {} -- {}",
                hit.host, hit.port, hit.service, hit.product, hit.probe_name, banner
            );
        }
        if self.message.is_empty() {
            "Select a row for detail. s start  p dry-run".into()
        } else {
            self.message.clone()
        }
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
            ProbeField::Target => &mut self.target,
            ProbeField::Ports => &mut self.ports,
            ProbeField::Concurrency => &mut self.concurrency,
            ProbeField::Timeout => &mut self.timeout_ms,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(ProbeUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(ProbeUiEvent::Hit(hit)) => {
                    self.results.push(hit);
                }
                Ok(ProbeUiEvent::Done) => {
                    self.run_state = ProbeRunState::Done;
                    self.message = format!("done; {} hit(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(ProbeUiEvent::Error(msg)) => {
                    self.run_state = ProbeRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == ProbeRunState::Running {
                        self.run_state = ProbeRunState::Failed;
                        self.error = Some("probe worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start a probe job against `scope` on a background thread.
    pub fn start(&mut self, scope: &Scope) -> Result<(), String> {
        if self.run_state == ProbeRunState::Running {
            return Err("probe already running".into());
        }
        if self.target.trim().is_empty() {
            return Err("target is required".into());
        }

        let concurrency: usize = self
            .concurrency
            .trim()
            .parse()
            .unwrap_or(DEFAULT_PROBE_CONCURRENCY);
        let timeout_ms: u64 = self
            .timeout_ms
            .trim()
            .parse()
            .unwrap_or(DEFAULT_PROBE_TIMEOUT_MS);

        let config = ProbeConfig::from_parts(
            self.target.trim(),
            &self.ports,
            timeout_ms,
            concurrency,
            self.dry_run,
            None,
        )
        .map_err(|e| e.to_string())?;

        scope.check(&config.target).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::channel();
        self.inbox = Some(rx);
        self.results.clear();
        self.selected = 0;
        self.done = 0;
        self.total = config.ports.len() as u64;
        self.error = None;
        self.message = "starting...".into();
        self.run_state = ProbeRunState::Running;
        self.editing = false;

        let scope = scope.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(ProbeUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = ProbeModule::new(config, scope);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_probe(job_id, sender).await });
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
                                    .send(ProbeUiEvent::Progress {
                                        done,
                                        total,
                                        message,
                                    })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Ok(ModuleEvent::Result { summary, .. }) => {
                                if let Some(hit) = parse_probe_summary(&summary) {
                                    if tx_fwd.send(ProbeUiEvent::Hit(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(ProbeUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(ProbeUiEvent::Error(message));
                                break;
                            }
                            Ok(ModuleEvent::Log { .. }) => {}
                            Err(_) => break,
                        }
                    }
                });

                match worker.await {
                    Ok(Ok(_)) => {
                        let _ = forward.await;
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(ProbeUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(ProbeUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                }
            });
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::ScopeEntry;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn start_dry_run_against_scope() {
        let scope = Scope {
            includes: vec![ScopeEntry::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            excludes: Vec::new(),
            notes: None,
            source: None,
        };
        let mut view = ProbeView {
            target: "127.0.0.1".into(),
            ports: "22,80".into(),
            dry_run: true,
            ..ProbeView::default()
        };
        view.start(&scope).unwrap();
        assert_eq!(view.run_state, ProbeRunState::Running);
        for _ in 0..200 {
            view.poll();
            if view.run_state != ProbeRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, ProbeRunState::Done);
        assert_eq!(view.results.len(), 2);
    }
}
