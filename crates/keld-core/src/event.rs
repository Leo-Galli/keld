//! Typed module events and an in-process broadcast bus.
//!
//! Modules publish; CLI and TUI (and later audit) subscribe. Slow subscribers
//! may lag; capacity is bounded so producers are never blocked.

use tokio::sync::broadcast;

use crate::job::JobId;

/// Default ring capacity for [`EventBus::new`].
pub const DEFAULT_BUS_CAPACITY: usize = 1024;

/// Severity for [`ModuleEvent::Log`] lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Events emitted by modules. Never printed by modules themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleEvent {
    /// Incremental progress for a job.
    Progress {
        job_id: JobId,
        done: u64,
        total: u64,
        message: String,
    },
    /// One discrete result row (finding or probe hit).
    Result { job_id: JobId, summary: String },
    /// Non-fatal log line for the UI / CLI pane.
    Log {
        job_id: JobId,
        level: LogLevel,
        message: String,
    },
    /// Job finished successfully (or with only non-fatal issues).
    Done { job_id: JobId },
    /// Job failed; message is operator-facing.
    Error { job_id: JobId, message: String },
}

impl ModuleEvent {
    /// Job this event belongs to.
    pub fn job_id(&self) -> JobId {
        match self {
            Self::Progress { job_id, .. }
            | Self::Result { job_id, .. }
            | Self::Log { job_id, .. }
            | Self::Done { job_id }
            | Self::Error { job_id, .. } => *job_id,
        }
    }
}

/// Cloneable publish handle for modules and job runners.
#[derive(Debug, Clone)]
pub struct EventSender {
    tx: broadcast::Sender<ModuleEvent>,
}

impl EventSender {
    /// Publish one event. Returns the subscriber count, or an error if nobody
    /// is subscribed (the event is still dropped).
    pub fn publish(
        &self,
        event: ModuleEvent,
    ) -> Result<usize, broadcast::error::SendError<ModuleEvent>> {
        self.tx.send(event)
    }
}

/// Multi-subscriber event bus (tokio broadcast).
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<ModuleEvent>,
}

impl EventBus {
    /// Create a bus with the given ring capacity (rounded up by tokio).
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// Bus with [`DEFAULT_BUS_CAPACITY`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_BUS_CAPACITY)
    }

    /// Publish handle for modules.
    pub fn sender(&self) -> EventSender {
        EventSender {
            tx: self.tx.clone(),
        }
    }

    /// Subscribe to future events. Misses anything published before this call.
    pub fn subscribe(&self) -> broadcast::Receiver<ModuleEvent> {
        self.tx.subscribe()
    }

    /// Publish one event (same as [`EventSender::publish`]).
    pub fn publish(
        &self,
        event: ModuleEvent,
    ) -> Result<usize, broadcast::error::SendError<ModuleEvent>> {
        self.tx.send(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JobId;

    #[tokio::test]
    async fn subscriber_receives_published_events() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        let id = JobId::new(1);

        bus.publish(ModuleEvent::Progress {
            job_id: id,
            done: 1,
            total: 2,
            message: "step".into(),
        })
        .unwrap();
        bus.publish(ModuleEvent::Done { job_id: id }).unwrap();

        match rx.recv().await.unwrap() {
            ModuleEvent::Progress {
                job_id,
                done,
                total,
                message,
            } => {
                assert_eq!(job_id, id);
                assert_eq!(done, 1);
                assert_eq!(total, 2);
                assert_eq!(message, "step");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            rx.recv().await.unwrap(),
            ModuleEvent::Done { job_id } if job_id == id
        ));
    }

    #[tokio::test]
    async fn multiple_subscribers_each_see_events() {
        let bus = EventBus::new(8);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        let id = JobId::new(7);

        bus.sender()
            .publish(ModuleEvent::Log {
                job_id: id,
                level: LogLevel::Info,
                message: "hi".into(),
            })
            .unwrap();

        for rx in [&mut a, &mut b] {
            match rx.recv().await.unwrap() {
                ModuleEvent::Log {
                    job_id,
                    level,
                    message,
                } => {
                    assert_eq!(job_id, id);
                    assert_eq!(level, LogLevel::Info);
                    assert_eq!(message, "hi");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn lagged_receiver_reports_skipped_count() {
        let bus = EventBus::new(2);
        let mut rx = bus.subscribe();
        let id = JobId::new(1);

        for n in 0..8 {
            let _ = bus.publish(ModuleEvent::Progress {
                job_id: id,
                done: n,
                total: 8,
                message: String::new(),
            });
        }

        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(skipped)) => assert!(skipped >= 1),
            other => panic!("expected Lagged, got {other:?}"),
        }
    }
}
