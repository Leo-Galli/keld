//! Fuzz module screen state (form + hits). Live discovery runs on a worker thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    parse_fuzz_summary, parse_u16_list, FuzzConfig, FuzzFilters, FuzzHit, FuzzMode, FuzzModule,
    FuzzRunOpts, DEFAULT_FILTER_STATUS, DEFAULT_FUZZ_CONCURRENCY, DEFAULT_FUZZ_TIMEOUT_MS,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzField {
    Target,
    Wordlist,
    Mode,
    FilterStatus,
    Concurrency,
    Timeout,
}

impl FuzzField {
    pub const fn next(self) -> Self {
        match self {
            Self::Target => Self::Wordlist,
            Self::Wordlist => Self::Mode,
            Self::Mode => Self::FilterStatus,
            Self::FilterStatus => Self::Concurrency,
            Self::Concurrency => Self::Timeout,
            Self::Timeout => Self::Target,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Target => Self::Timeout,
            Self::Wordlist => Self::Target,
            Self::Mode => Self::Wordlist,
            Self::FilterStatus => Self::Mode,
            Self::Concurrency => Self::FilterStatus,
            Self::Timeout => Self::Concurrency,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background fuzz worker.
#[derive(Debug, Clone)]
pub enum FuzzUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Hit(FuzzHit),
    Done,
    Error(String),
}

/// TUI state for the Fuzz screen.
#[derive(Debug)]
pub struct FuzzView {
    pub target: String,
    pub wordlist: String,
    pub mode: String,
    pub filter_status: String,
    pub concurrency: String,
    pub timeout_ms: String,
    pub dry_run: bool,
    pub field: FuzzField,
    pub editing: bool,
    pub run_state: FuzzRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<FuzzHit>,
    pub selected: usize,
    pub error: Option<String>,
    inbox: Option<Receiver<FuzzUiEvent>>,
}

impl Default for FuzzView {
    fn default() -> Self {
        Self {
            target: String::new(),
            wordlist: String::new(),
            mode: "dir".into(),
            filter_status: "404".into(),
            concurrency: DEFAULT_FUZZ_CONCURRENCY.to_string(),
            timeout_ms: DEFAULT_FUZZ_TIMEOUT_MS.to_string(),
            dry_run: false,
            field: FuzzField::Target,
            editing: false,
            run_state: FuzzRunState::Idle,
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

impl FuzzView {
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
                return match &hit.host_header {
                    Some(h) => format!("{} would probe Host:{h} {}", hit.word, hit.url),
                    None => format!("{} would probe {}", hit.word, hit.url),
                };
            }
            return match &hit.host_header {
                Some(h) => format!(
                    "{} status={} size={} Host:{} {}",
                    hit.word, hit.status, hit.size, h, hit.url
                ),
                None => format!(
                    "{} status={} size={} {}",
                    hit.word, hit.status, hit.size, hit.url
                ),
            };
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
            FuzzField::Target => &mut self.target,
            FuzzField::Wordlist => &mut self.wordlist,
            FuzzField::Mode => &mut self.mode,
            FuzzField::FilterStatus => &mut self.filter_status,
            FuzzField::Concurrency => &mut self.concurrency,
            FuzzField::Timeout => &mut self.timeout_ms,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(FuzzUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(FuzzUiEvent::Hit(hit)) => {
                    self.results.push(hit);
                }
                Ok(FuzzUiEvent::Done) => {
                    self.run_state = FuzzRunState::Done;
                    self.message = format!("done; {} hit(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(FuzzUiEvent::Error(msg)) => {
                    self.run_state = FuzzRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == FuzzRunState::Running {
                        self.run_state = FuzzRunState::Failed;
                        self.error = Some("fuzz worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start discovery against `scope` on a background thread.
    pub fn start(&mut self, scope: &Scope) -> Result<(), String> {
        if self.run_state == FuzzRunState::Running {
            return Err("fuzz already running".into());
        }
        if self.target.trim().is_empty() {
            return Err("target is required".into());
        }
        if self.wordlist.trim().is_empty() {
            return Err("wordlist path is required".into());
        }

        let mode = FuzzMode::parse(&self.mode)
            .ok_or_else(|| format!("invalid mode `{}` (dir or vhost)", self.mode.trim()))?;
        let filters = FuzzFilters {
            filter_status: if self.filter_status.trim().is_empty() {
                DEFAULT_FILTER_STATUS.to_vec()
            } else {
                parse_u16_list(&self.filter_status)?
            },
            match_status: Vec::new(),
            filter_size: Vec::new(),
        };
        let concurrency: usize = self
            .concurrency
            .trim()
            .parse()
            .unwrap_or(DEFAULT_FUZZ_CONCURRENCY);
        let timeout_ms: u64 = self
            .timeout_ms
            .trim()
            .parse()
            .unwrap_or(DEFAULT_FUZZ_TIMEOUT_MS);

        let config = FuzzConfig::from_parts(
            self.target.trim(),
            self.wordlist.trim(),
            mode,
            FuzzRunOpts {
                timeout_ms,
                concurrency,
                dry_run: self.dry_run,
                rate_per_sec: None,
            },
            filters,
        )
        .map_err(|e| e.to_string())?;

        let host = host_for_scope(&config.target);
        scope.check(&host).map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::channel();
        self.inbox = Some(rx);
        self.results.clear();
        self.selected = 0;
        self.done = 0;
        self.total = 0;
        self.error = None;
        self.message = "starting...".into();
        self.run_state = FuzzRunState::Running;
        self.editing = false;

        let scope = scope.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(FuzzUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = FuzzModule::new(config, scope);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_fuzz(job_id, sender).await });
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
                                    .send(FuzzUiEvent::Progress {
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
                                if let Some(hit) = parse_fuzz_summary(&summary) {
                                    if tx_fwd.send(FuzzUiEvent::Hit(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(FuzzUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(FuzzUiEvent::Error(message));
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
                        let _ = tx.send(FuzzUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(FuzzUiEvent::Error(e.to_string()));
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
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn write_wordlist(words: &[&str]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "keld-fuzz-tui-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        for w in words {
            writeln!(f, "{w}").unwrap();
        }
        path
    }

    #[test]
    fn start_dry_run_against_scope() {
        let wl = write_wordlist(&["a", "b"]);
        let scope = Scope {
            includes: vec![ScopeEntry::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            excludes: Vec::new(),
            notes: None,
            source: None,
        };
        let mut view = FuzzView {
            target: "http://127.0.0.1/".into(),
            wordlist: wl.to_string_lossy().into(),
            dry_run: true,
            ..FuzzView::default()
        };
        view.start(&scope).unwrap();
        assert_eq!(view.run_state, FuzzRunState::Running);
        for _ in 0..200 {
            view.poll();
            if view.run_state != FuzzRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, FuzzRunState::Done);
        assert_eq!(view.results.len(), 2);
        assert!(view.results.iter().all(|h| h.planned));
        let _ = std::fs::remove_file(wl);
    }
}
