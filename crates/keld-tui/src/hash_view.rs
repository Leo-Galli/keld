//! Hash module screen state (identify + offline wordlist). Live jobs run on a worker thread.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent};
use keld_modules::{
    parse_hash_summary, HashAlgo, HashConfig, HashHit, HashModule, HashRunOpts,
    DEFAULT_HASH_CONCURRENCY,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashField {
    Hash,
    Wordlist,
    Concurrency,
}

impl HashField {
    pub const fn next(self) -> Self {
        match self {
            Self::Hash => Self::Wordlist,
            Self::Wordlist => Self::Concurrency,
            Self::Concurrency => Self::Hash,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Hash => Self::Concurrency,
            Self::Wordlist => Self::Hash,
            Self::Concurrency => Self::Wordlist,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background hash worker.
#[derive(Debug, Clone)]
pub enum HashUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Hit(HashHit),
    Done,
    Error(String),
}

/// TUI state for the Hash screen.
#[derive(Debug)]
pub struct HashView {
    pub hash: String,
    pub wordlist: String,
    pub concurrency: String,
    pub dry_run: bool,
    /// `HashAlgo::Unknown` means auto-detect.
    pub algo: HashAlgo,
    pub field: HashField,
    pub editing: bool,
    pub run_state: HashRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<HashHit>,
    pub selected: usize,
    pub error: Option<String>,
    inbox: Option<Receiver<HashUiEvent>>,
}

impl Default for HashView {
    fn default() -> Self {
        Self {
            hash: String::new(),
            wordlist: String::new(),
            concurrency: DEFAULT_HASH_CONCURRENCY.to_string(),
            dry_run: false,
            algo: HashAlgo::Unknown,
            field: HashField::Hash,
            editing: false,
            run_state: HashRunState::Idle,
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

impl HashView {
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

    pub fn algo_label(&self) -> &'static str {
        if self.algo == HashAlgo::Unknown {
            "auto"
        } else {
            self.algo.as_str()
        }
    }

    pub fn detail_line(&self) -> String {
        if let Some(err) = &self.error {
            return format!("Error: {err}");
        }
        if let Some(hit) = self.results.get(self.selected) {
            return format!(
                "[{}] {} -- {}",
                hit.kind.as_str(),
                hit.algo.as_str(),
                hit.detail
            );
        }
        if self.message.is_empty() {
            "Select a row for detail. s start  p dry-run  a algo".into()
        } else {
            self.message.clone()
        }
    }

    pub fn cycle_algo(&mut self) {
        self.algo = self.algo.cycle();
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
            HashField::Hash => &mut self.hash,
            HashField::Wordlist => &mut self.wordlist,
            HashField::Concurrency => &mut self.concurrency,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(HashUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(HashUiEvent::Hit(hit)) => {
                    self.results.push(hit);
                }
                Ok(HashUiEvent::Done) => {
                    self.run_state = HashRunState::Done;
                    self.message = format!("done; {} hit(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(HashUiEvent::Error(msg)) => {
                    self.run_state = HashRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == HashRunState::Running {
                        self.run_state = HashRunState::Failed;
                        self.error = Some("hash worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start identify / wordlist check on a background thread.
    pub fn start(&mut self) -> Result<(), String> {
        if self.run_state == HashRunState::Running {
            return Err("hash already running".into());
        }

        let hash = self.hash.trim();
        if hash.is_empty() {
            return Err("hash is empty".into());
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
            .unwrap_or(DEFAULT_HASH_CONCURRENCY);
        let algo = if self.algo == HashAlgo::Unknown {
            None
        } else {
            Some(self.algo)
        };

        let config = HashConfig::from_parts(
            hash,
            wordlist,
            algo,
            HashRunOpts {
                concurrency,
                dry_run: self.dry_run,
                rate_per_sec: None,
            },
        )
        .map_err(|e| e.to_string())?;

        let (tx, rx) = mpsc::channel();
        self.inbox = Some(rx);
        self.results.clear();
        self.selected = 0;
        self.done = 0;
        self.total = 0;
        self.error = None;
        self.message = "starting...".into();
        self.run_state = HashRunState::Running;
        self.editing = false;

        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(HashUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = HashModule::new(config);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_hash(job_id, sender).await });
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
                                    .send(HashUiEvent::Progress {
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
                                if let Some(hit) = parse_hash_summary(&summary) {
                                    if tx_fwd.send(HashUiEvent::Hit(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(HashUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(HashUiEvent::Error(message));
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
                        let _ = tx.send(HashUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(HashUiEvent::Error(e.to_string()));
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
    use std::io::Write;

    #[test]
    fn start_dry_run_identify() {
        let mut view = HashView {
            hash: "5eb63bbbe01eeed093cb22bb8f5acdc3".into(),
            dry_run: true,
            ..HashView::default()
        };
        view.start().unwrap();
        assert_eq!(view.run_state, HashRunState::Running);
        for _ in 0..200 {
            view.poll();
            if view.run_state != HashRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, HashRunState::Done);
        assert!(!view.results.is_empty());
        assert!(view.results.iter().all(|h| h.planned));
    }

    #[test]
    fn cycle_algo_through_auto() {
        let mut view = HashView::default();
        assert_eq!(view.algo_label(), "auto");
        view.cycle_algo();
        assert_eq!(view.algo, HashAlgo::Md5);
        view.cycle_algo();
        assert_eq!(view.algo, HashAlgo::Sha1);
    }

    #[test]
    fn start_with_wordlist_match() {
        let path = std::env::temp_dir().join(format!("keld-hash-tui-{}.txt", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "hello world").unwrap();
        let mut view = HashView {
            hash: "5eb63bbbe01eeed093cb22bb8f5acdc3".into(),
            wordlist: path.display().to_string(),
            dry_run: false,
            ..HashView::default()
        };
        view.start().unwrap();
        for _ in 0..400 {
            view.poll();
            if view.run_state != HashRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_file(path);
        assert_eq!(view.run_state, HashRunState::Done);
        assert!(view
            .results
            .iter()
            .any(|h| h.kind == keld_modules::HashKind::Match && h.detail == "hello world"));
    }
}
