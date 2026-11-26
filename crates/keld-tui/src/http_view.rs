//! HTTP module screen state (form + findings). Live audits run on a worker thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    parse_http_summary, HttpConfig, HttpFinding, HttpModule, DEFAULT_HTTP_CONCURRENCY,
    DEFAULT_HTTP_TIMEOUT_MS,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpField {
    Target,
    Concurrency,
    Timeout,
}

impl HttpField {
    pub const fn next(self) -> Self {
        match self {
            Self::Target => Self::Concurrency,
            Self::Concurrency => Self::Timeout,
            Self::Timeout => Self::Target,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Target => Self::Timeout,
            Self::Concurrency => Self::Target,
            Self::Timeout => Self::Concurrency,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background HTTP worker.
#[derive(Debug, Clone)]
pub enum HttpUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Finding(HttpFinding),
    Done,
    Error(String),
}

/// TUI state for the HTTP screen.
#[derive(Debug)]
pub struct HttpView {
    pub target: String,
    pub concurrency: String,
    pub timeout_ms: String,
    pub dry_run: bool,
    pub field: HttpField,
    pub editing: bool,
    pub run_state: HttpRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<HttpFinding>,
    pub selected: usize,
    pub error: Option<String>,
    inbox: Option<Receiver<HttpUiEvent>>,
}

impl Default for HttpView {
    fn default() -> Self {
        Self {
            target: String::new(),
            concurrency: DEFAULT_HTTP_CONCURRENCY.to_string(),
            timeout_ms: DEFAULT_HTTP_TIMEOUT_MS.to_string(),
            dry_run: false,
            field: HttpField::Target,
            editing: false,
            run_state: HttpRunState::Idle,
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

impl HttpView {
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
                    "{} would audit headers, cookies, CORS, fingerprint, robots, sitemap",
                    hit.url
                );
            }
            return format!(
                "{} [{}] {} -- {}",
                hit.url,
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
            HttpField::Target => &mut self.target,
            HttpField::Concurrency => &mut self.concurrency,
            HttpField::Timeout => &mut self.timeout_ms,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(HttpUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(HttpUiEvent::Finding(hit)) => {
                    self.results.push(hit);
                }
                Ok(HttpUiEvent::Done) => {
                    self.run_state = HttpRunState::Done;
                    self.message = format!("done; {} finding(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(HttpUiEvent::Error(msg)) => {
                    self.run_state = HttpRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == HttpRunState::Running {
                        self.run_state = HttpRunState::Failed;
                        self.error = Some("http worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start an HTTP audit against `scope` on a background thread.
    pub fn start(&mut self, scope: &Scope) -> Result<(), String> {
        if self.run_state == HttpRunState::Running {
            return Err("http audit already running".into());
        }
        if self.target.trim().is_empty() {
            return Err("target is required".into());
        }

        let concurrency: usize = self
            .concurrency
            .trim()
            .parse()
            .unwrap_or(DEFAULT_HTTP_CONCURRENCY);
        let timeout_ms: u64 = self
            .timeout_ms
            .trim()
            .parse()
            .unwrap_or(DEFAULT_HTTP_TIMEOUT_MS);

        let config = HttpConfig::from_parts(
            self.target.trim(),
            timeout_ms,
            concurrency,
            self.dry_run,
            None,
        )
        .map_err(|e| e.to_string())?;

        // Host-only gate (module also checks).
        let host = host_for_scope(&config.target);
        scope.check(&host).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::channel();
        self.inbox = Some(rx);
        self.results.clear();
        self.selected = 0;
        self.done = 0;
        self.total = 4;
        self.error = None;
        self.message = "starting...".into();
        self.run_state = HttpRunState::Running;
        self.editing = false;

        let scope = scope.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(HttpUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = HttpModule::new(config, scope);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_http(job_id, sender).await });
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
                                    .send(HttpUiEvent::Progress {
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
                                if let Some(hit) = parse_http_summary(&summary) {
                                    if tx_fwd.send(HttpUiEvent::Finding(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(HttpUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(HttpUiEvent::Error(message));
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
                        let _ = tx.send(HttpUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(HttpUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                }
            });
        });

        Ok(())
    }
}

fn host_for_scope(target: &str) -> String {
    let rest = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);
    rest.split(['/', ':', '?', '#'])
        .next()
        .unwrap_or(rest)
        .trim_matches(|c| c == '[' || c == ']')
        .to_string()
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
        let mut view = HttpView {
            target: "http://127.0.0.1/".into(),
            dry_run: true,
            ..HttpView::default()
        };
        view.start(&scope).unwrap();
        assert_eq!(view.run_state, HttpRunState::Running);
        for _ in 0..200 {
            view.poll();
            if view.run_state != HttpRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, HttpRunState::Done);
        assert_eq!(view.results.len(), 1);
        assert!(view.results[0].planned);
    }
}
