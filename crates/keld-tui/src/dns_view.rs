//! DNS module screen state (form + findings). Live jobs run on a worker thread.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    parse_dns_summary, DnsConfig, DnsHit, DnsModule, DnsRunOpts, DEFAULT_DNS_CONCURRENCY,
    DEFAULT_DNS_TIMEOUT_MS,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsField {
    Domain,
    Wordlist,
    Concurrency,
    Timeout,
}

impl DnsField {
    pub const fn next(self) -> Self {
        match self {
            Self::Domain => Self::Wordlist,
            Self::Wordlist => Self::Concurrency,
            Self::Concurrency => Self::Timeout,
            Self::Timeout => Self::Domain,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Domain => Self::Timeout,
            Self::Wordlist => Self::Domain,
            Self::Concurrency => Self::Wordlist,
            Self::Timeout => Self::Concurrency,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background DNS worker.
#[derive(Debug, Clone)]
pub enum DnsUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Hit(DnsHit),
    Done,
    Error(String),
}

/// TUI state for the DNS screen.
#[derive(Debug)]
pub struct DnsView {
    pub domain: String,
    pub wordlist: String,
    pub concurrency: String,
    pub timeout_ms: String,
    pub dry_run: bool,
    pub ct: bool,
    pub field: DnsField,
    pub editing: bool,
    pub run_state: DnsRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<DnsHit>,
    pub selected: usize,
    pub error: Option<String>,
    inbox: Option<Receiver<DnsUiEvent>>,
}

impl Default for DnsView {
    fn default() -> Self {
        Self {
            domain: String::new(),
            wordlist: String::new(),
            concurrency: DEFAULT_DNS_CONCURRENCY.to_string(),
            timeout_ms: DEFAULT_DNS_TIMEOUT_MS.to_string(),
            dry_run: false,
            ct: true,
            field: DnsField::Domain,
            editing: false,
            run_state: DnsRunState::Idle,
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

impl DnsView {
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
                "[{}] {} {} {} = {}",
                hit.severity.as_str(),
                hit.kind.as_str(),
                hit.rtype,
                hit.name,
                hit.value
            );
        }
        if self.message.is_empty() {
            "Select a row for detail. s start  p dry-run  c ct".into()
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
            DnsField::Domain => &mut self.domain,
            DnsField::Wordlist => &mut self.wordlist,
            DnsField::Concurrency => &mut self.concurrency,
            DnsField::Timeout => &mut self.timeout_ms,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(DnsUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(DnsUiEvent::Hit(hit)) => {
                    self.results.push(hit);
                }
                Ok(DnsUiEvent::Done) => {
                    self.run_state = DnsRunState::Done;
                    self.message = format!("done; {} hit(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(DnsUiEvent::Error(msg)) => {
                    self.run_state = DnsRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == DnsRunState::Running {
                        self.run_state = DnsRunState::Failed;
                        self.error = Some("dns worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start enumeration against `scope` on a background thread.
    pub fn start(&mut self, scope: &Scope) -> Result<(), String> {
        if self.run_state == DnsRunState::Running {
            return Err("dns already running".into());
        }
        if self.domain.trim().is_empty() {
            return Err("domain is required".into());
        }

        let wordlist = {
            let w = self.wordlist.trim();
            if w.is_empty() {
                None
            } else {
                Some(PathBuf::from(w))
            }
        };
        let concurrency: usize = self
            .concurrency
            .trim()
            .parse()
            .unwrap_or(DEFAULT_DNS_CONCURRENCY);
        let timeout_ms: u64 = self
            .timeout_ms
            .trim()
            .parse()
            .unwrap_or(DEFAULT_DNS_TIMEOUT_MS);

        let config = DnsConfig::from_parts(
            self.domain.trim(),
            wordlist,
            self.ct,
            DnsRunOpts {
                timeout_ms,
                concurrency,
                dry_run: self.dry_run,
                rate_per_sec: None,
            },
        )
        .map_err(|e| e.to_string())?;

        scope.check(&config.domain).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::channel();
        self.inbox = Some(rx);
        self.results.clear();
        self.selected = 0;
        self.done = 0;
        self.total = 0;
        self.error = None;
        self.message = "starting...".into();
        self.run_state = DnsRunState::Running;
        self.editing = false;

        let scope = scope.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(DnsUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = DnsModule::new(config, scope);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_dns(job_id, sender).await });
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
                                    .send(DnsUiEvent::Progress {
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
                                if let Some(hit) = parse_dns_summary(&summary) {
                                    if tx_fwd.send(DnsUiEvent::Hit(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(DnsUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(DnsUiEvent::Error(message));
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
                        let _ = tx.send(DnsUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(DnsUiEvent::Error(e.to_string()));
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

    #[test]
    fn start_dry_run_against_scope() {
        let scope = Scope {
            includes: vec![ScopeEntry::Host("example.test".into())],
            excludes: Vec::new(),
            notes: None,
            source: None,
        };
        let mut view = DnsView {
            domain: "example.test".into(),
            dry_run: true,
            ct: false,
            ..DnsView::default()
        };
        view.start(&scope).unwrap();
        assert_eq!(view.run_state, DnsRunState::Running);
        for _ in 0..200 {
            view.poll();
            if view.run_state != DnsRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, DnsRunState::Done);
        assert!(!view.results.is_empty());
        assert!(view.results.iter().all(|h| h.planned));
    }
}
