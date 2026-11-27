//! Net module screen state (interfaces + discovery). Live jobs run on a worker thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use keld_core::{EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    list_interfaces, parse_net_summary, DiscoverAvailability, DiscoverTechnique, InterfaceInfo,
    NetConfig, NetHit, NetModule, NetRunOpts, DEFAULT_NET_CONCURRENCY, DEFAULT_NET_TIMEOUT_MS,
};

/// Which form field owns text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetField {
    Target,
    Ports,
    Concurrency,
    Timeout,
}

impl NetField {
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
pub enum NetRunState {
    Idle,
    Running,
    Done,
    Failed,
}

/// Events from the background net worker.
#[derive(Debug, Clone)]
pub enum NetUiEvent {
    Progress {
        done: u64,
        total: u64,
        message: String,
    },
    Hit(NetHit),
    Done,
    Error(String),
}

/// TUI state for the Net screen.
#[derive(Debug)]
pub struct NetView {
    pub target: String,
    pub ports: String,
    pub concurrency: String,
    pub timeout_ms: String,
    pub dry_run: bool,
    pub technique: DiscoverTechnique,
    pub field: NetField,
    pub editing: bool,
    pub run_state: NetRunState,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub results: Vec<NetHit>,
    pub selected: usize,
    pub error: Option<String>,
    pub interfaces: Vec<InterfaceInfo>,
    pub fallback_note: Option<String>,
    inbox: Option<Receiver<NetUiEvent>>,
}

impl Default for NetView {
    fn default() -> Self {
        let interfaces = list_interfaces().unwrap_or_default();
        let avail = DiscoverAvailability::probe();
        let fallback_note = if avail.arp_usable && avail.icmp_usable {
            None
        } else {
            Some(format!(
                "ARP: {}. ICMP: {}",
                avail.arp_detail, avail.icmp_detail
            ))
        };
        Self {
            target: String::new(),
            ports: "80,443,22,445".into(),
            concurrency: DEFAULT_NET_CONCURRENCY.to_string(),
            timeout_ms: DEFAULT_NET_TIMEOUT_MS.to_string(),
            dry_run: false,
            technique: DiscoverTechnique::Auto,
            field: NetField::Target,
            editing: false,
            run_state: NetRunState::Idle,
            done: 0,
            total: 0,
            message: String::new(),
            results: Vec::new(),
            selected: 0,
            error: None,
            interfaces,
            fallback_note,
            inbox: None,
        }
    }
}

impl NetView {
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
            return format!("[{}] {} -- {}", hit.method.as_str(), hit.target, hit.detail);
        }
        if self.message.is_empty() {
            "Select a row for detail. s start  p dry-run  t technique  i refresh ifaces".into()
        } else {
            self.message.clone()
        }
    }

    pub fn cycle_technique(&mut self) {
        self.technique = match self.technique {
            DiscoverTechnique::Auto => DiscoverTechnique::Arp,
            DiscoverTechnique::Arp => DiscoverTechnique::Icmp,
            DiscoverTechnique::Icmp => DiscoverTechnique::Tcp,
            DiscoverTechnique::Tcp => DiscoverTechnique::Auto,
        };
    }

    pub fn refresh_interfaces(&mut self) {
        match list_interfaces() {
            Ok(list) => {
                self.interfaces = list;
                self.message = format!("{} interface(s)", self.interfaces.len());
                self.error = None;
            }
            Err(e) => {
                self.error = Some(e.to_string());
                self.message = e.to_string();
            }
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
            NetField::Target => &mut self.target,
            NetField::Ports => &mut self.ports,
            NetField::Concurrency => &mut self.concurrency,
            NetField::Timeout => &mut self.timeout_ms,
        }
    }

    /// Apply queued worker events (call from `on_tick`).
    pub fn poll(&mut self) {
        let Some(rx) = self.inbox.as_ref() else {
            return;
        };
        loop {
            match rx.try_recv() {
                Ok(NetUiEvent::Progress {
                    done,
                    total,
                    message,
                }) => {
                    self.done = done;
                    self.total = total;
                    self.message = message;
                }
                Ok(NetUiEvent::Hit(hit)) => {
                    self.results.push(hit);
                }
                Ok(NetUiEvent::Done) => {
                    self.run_state = NetRunState::Done;
                    self.message = format!("done; {} hit(s)", self.results.len());
                    self.inbox = None;
                    break;
                }
                Ok(NetUiEvent::Error(msg)) => {
                    self.run_state = NetRunState::Failed;
                    self.error = Some(msg.clone());
                    self.message = msg;
                    self.inbox = None;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.run_state == NetRunState::Running {
                        self.run_state = NetRunState::Failed;
                        self.error = Some("net worker disconnected".into());
                    }
                    self.inbox = None;
                    break;
                }
            }
        }
    }

    /// Start interface list and/or discovery against `scope` on a background thread.
    pub fn start(&mut self, scope: &Scope) -> Result<(), String> {
        if self.run_state == NetRunState::Running {
            return Err("net already running".into());
        }

        let target = {
            let t = self.target.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        };
        let concurrency: usize = self
            .concurrency
            .trim()
            .parse()
            .unwrap_or(DEFAULT_NET_CONCURRENCY);
        let timeout_ms: u64 = self
            .timeout_ms
            .trim()
            .parse()
            .unwrap_or(DEFAULT_NET_TIMEOUT_MS);

        let config = NetConfig::from_parts(
            target,
            self.technique,
            self.ports.trim(),
            NetRunOpts {
                timeout_ms,
                concurrency,
                dry_run: self.dry_run,
                rate_per_sec: None,
            },
        )
        .map_err(|e| e.to_string())?;

        if let Some(t) = &config.target {
            scope.check(t).map_err(|e| e.to_string())?;
        }

        let (tx, rx) = mpsc::channel();
        self.inbox = Some(rx);
        self.results.clear();
        self.selected = 0;
        self.done = 0;
        self.total = 0;
        self.error = None;
        self.message = "starting...".into();
        self.run_state = NetRunState::Running;
        self.editing = false;

        let scope = scope.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(NetUiEvent::Error(e.to_string()));
                    return;
                }
            };

            rt.block_on(async move {
                let bus = EventBus::with_defaults();
                let mut events = bus.subscribe();
                let sender = bus.sender();
                let module = NetModule::new(config, scope);
                let job_id = JobId::new(1);

                let worker = tokio::spawn(async move { module.run_net(job_id, sender).await });
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
                                    .send(NetUiEvent::Progress {
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
                                if let Some(hit) = parse_net_summary(&summary) {
                                    if tx_fwd.send(NetUiEvent::Hit(hit)).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(ModuleEvent::Done { .. }) => {
                                let _ = tx_fwd.send(NetUiEvent::Done);
                                break;
                            }
                            Ok(ModuleEvent::Error { message, .. }) => {
                                let _ = tx_fwd.send(NetUiEvent::Error(message));
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
                        let _ = tx.send(NetUiEvent::Error(e.to_string()));
                        let _ = forward.await;
                    }
                    Err(e) => {
                        let _ = tx.send(NetUiEvent::Error(e.to_string()));
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
            includes: vec![ScopeEntry::Cidr {
                addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                prefix: 8,
            }],
            excludes: Vec::new(),
            notes: None,
            source: None,
        };
        let mut view = NetView {
            target: "127.0.0.1".into(),
            dry_run: true,
            technique: DiscoverTechnique::Tcp,
            ..NetView::default()
        };
        view.start(&scope).unwrap();
        assert_eq!(view.run_state, NetRunState::Running);
        for _ in 0..200 {
            view.poll();
            if view.run_state != NetRunState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(view.run_state, NetRunState::Done);
        assert!(!view.results.is_empty());
        assert!(view.results.iter().all(|h| h.planned));
    }

    #[test]
    fn cycle_technique() {
        let mut view = NetView::default();
        assert_eq!(view.technique, DiscoverTechnique::Auto);
        view.cycle_technique();
        assert_eq!(view.technique, DiscoverTechnique::Arp);
        view.cycle_technique();
        assert_eq!(view.technique, DiscoverTechnique::Icmp);
        view.cycle_technique();
        assert_eq!(view.technique, DiscoverTechnique::Tcp);
        view.cycle_technique();
        assert_eq!(view.technique, DiscoverTechnique::Auto);
    }
}
