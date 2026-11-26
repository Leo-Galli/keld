//! TLS module screen state (form + findings). Live audits run on a worker thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    parse_tls_summary, TlsConfig, TlsFinding, TlsModule, DEFAULT_TLS_CONCURRENCY,
    DEFAULT_TLS_TIMEOUT_MS,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsField {
    Target,
    Ports,
    Concurrency,
    Timeout,
}

impl TlsField {
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
pub enum TlsRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background TLS worker.
#[derive(Debug, Clone)]
pub enum TlsUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Finding(TlsFinding),
    Done,
    Error(String),
}

/// TUI state for the TLS screen.
#[derive(Debug)]
pub struct TlsView {
    pub target: String,
    pub ports: String,
    pub concurrency: String,
    pub timeout_ms: String,
    pub dry_run: bool,
    pub field: TlsField,
    pub editing: bool,
    pub run_state: TlsRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<TlsFinding>,
    pub selected: usize,
    pub error: Option<String>,
    inbox: Option<Receiver<TlsUiEvent>>,
}

impl Default for TlsView {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: "443".into(),
            concurrency: DEFAULT_TLS_CONCURRENCY.to_string(),
            timeout_ms: DEFAULT_TLS_TIMEOUT_MS.to_string(),
            dry_run: false,
            field: TlsField::Target,
            editing: false,
            run_state: TlsRunState::Idle,
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

impl TlsView {
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
                    "{}:{} would audit chain, expiry, protocols, ciphers, HSTS",
                    hit.host, hit.port
                );
            }
            return format!(
                "{}:{} [{}] {} -- {}",
                hit.host,
                hit.port,
                hit.severity.as_str(),
                hit.kind,
                hit.detail
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
            TlsField::Target => &mut self.target,
            TlsField::Ports => &mut self.ports,
            TlsField::Concurrency => &mut self.concurrency,
            TlsField::Timeout => &mut self.timeout_ms,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(TlsUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(TlsUiEvent::Finding(hit)) => {
                    self.results.push(hit);
                }
                Ok(TlsUiEvent::Done) => {
                    self.run_state = TlsRunState::Done;
                    self.message = format!("done; {} finding(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(TlsUiEvent::Error(msg)) => {
                    self.run_state = TlsRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == TlsRunState::Running {
                        self.run_state = TlsRunState::Failed;
                        self.error = Some("tls worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start a TLS audit against `scope` on a background thread.
    pub fn start(&mut self, scope: &Scope) -> Result<(), String> {
        if self.run_state == TlsRunState::Running {
            return Err("tls audit already running".into());
        }
        if self.target.trim().is_empty() {
            return Err("target is required".into());
        }

        let concurrency: usize = self
            .concurrency
            .trim()
            .parse()
            .unwrap_or(DEFAULT_TLS_CONCURRENCY);
        let timeout_ms: u64 = self
            .timeout_ms
            .trim()
            .parse()
            .unwrap_or(DEFAULT_TLS_TIMEOUT_MS);

        let config = TlsConfig::from_parts(
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
        self.run_state = TlsRunState::Running;
        self.editing = false;

        let scope = scope.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(TlsUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = TlsModule::new(config, scope);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_tls(job_id, sender).await });
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
                                    .send(TlsUiEvent::Progress {
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
                                if let Some(hit) = parse_tls_summary(&summary) {
                                    if tx_fwd.send(TlsUiEvent::Finding(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(TlsUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(TlsUiEvent::Error(message));
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
                        let _ = tx.send(TlsUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(TlsUiEvent::Error(e.to_string()));
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
        let mut view = TlsView {
            target: "127.0.0.1".into(),
            ports: "443,8443".into(),
            dry_run: true,
            ..TlsView::default()
        };
        view.start(&scope).unwrap();
        assert_eq!(view.run_state, TlsRunState::Running);
        for _ in 0..200 {
            view.poll();
            if view.run_state != TlsRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, TlsRunState::Done);
        assert_eq!(view.results.len(), 2);
    }
}
