//! Deterministic stub module for wiring the event bus to CLI/TUI.

use std::future::Future;
use std::pin::Pin;

use keld_core::{EventSender, JobId, ModuleEvent, ModuleKind};

use crate::Module;

/// Emits a fixed number of progress ticks, one result, then Done.
#[derive(Debug, Clone)]
pub struct StubModule {
    steps: u64,
}

impl Default for StubModule {
    fn default() -> Self {
        Self::with_steps(5)
    }
}

impl StubModule {
    /// Create a stub that reports `steps` progress units (minimum 1).
    pub fn with_steps(steps: u64) -> Self {
        Self {
            steps: steps.max(1),
        }
    }

    /// Progress units this stub will emit.
    pub fn steps(&self) -> u64 {
        self.steps
    }
}

impl Module for StubModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Stub
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let total = self.steps;
            for done in 1..=total {
                let _ = events.publish(ModuleEvent::Progress {
                    job_id,
                    done,
                    total,
                    message: format!("stub step {done}/{total}"),
                });
            }
            let _ = events.publish(ModuleEvent::Result {
                job_id,
                summary: "stub complete".into(),
            });
            let _ = events.publish(ModuleEvent::Done { job_id });
        })
    }
}
