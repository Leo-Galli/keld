//! Feature modules for Keld.
//!
//! Each module implements [`Module`] and emits [`ModuleEvent`]s only.
//! They never write to stdout/stderr.

use std::future::Future;
use std::pin::Pin;

use keld_core::{EventSender, JobId, ModuleKind};

pub mod ports;
pub mod scan;
pub mod stub;

pub use ports::{parse_ports, PortParseError, MAX_PORTS, TOP_100};
pub use scan::{
    PortHit, PortState, ScanConfig, ScanError, ScanModule, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS,
};
pub use stub::StubModule;

/// Shared async contract for every recon/audit module.
pub trait Module: Send + Sync {
    /// Stable module identity.
    fn kind(&self) -> ModuleKind;

    /// Run the module for `job_id`, publishing progress/results on `events`.
    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Registered modules available to CLI/TUI wiring (stub + scan).
pub fn module_count() -> usize {
    2
}

/// Build the stub used for event-bus wiring tests and early UI demos.
pub fn stub_module() -> StubModule {
    StubModule::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{EventBus, Job, JobState, ModuleEvent};

    #[test]
    fn registry_lists_stub_and_scan() {
        assert_eq!(module_count(), 2);
        assert_eq!(stub_module().kind(), ModuleKind::Stub);
        assert_eq!(
            ScanModule::new(
                ScanConfig::from_parts("127.0.0.1", "22", 100, 1, true, None).unwrap(),
                keld_core::Scope::empty(),
            )
            .kind(),
            ModuleKind::Scan
        );
    }

    #[tokio::test]
    async fn stub_events_drive_job_to_completed() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        let id = JobId::new(42);
        let mut job = Job::new(id, ModuleKind::Stub);
        job.start().unwrap();

        let module = StubModule::with_steps(3);
        module.run(id, bus.sender()).await;

        while let Ok(event) = rx.try_recv() {
            job.apply_event(&event).unwrap();
        }

        assert_eq!(job.state, JobState::Completed);
        assert_eq!(job.done, 3);
        assert_eq!(job.total, 3);
        assert_eq!(job.results, 1);
    }

    #[tokio::test]
    async fn stub_publishes_ordered_progress_then_done() {
        let bus = EventBus::new(32);
        let mut rx = bus.subscribe();
        let id = JobId::new(1);

        StubModule::with_steps(2).run(id, bus.sender()).await;

        let mut got = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            got.push(ev);
        }

        assert!(matches!(
            &got[0],
            ModuleEvent::Progress {
                done: 1,
                total: 2,
                ..
            }
        ));
        assert!(matches!(
            &got[1],
            ModuleEvent::Progress {
                done: 2,
                total: 2,
                ..
            }
        ));
        assert!(matches!(&got[2], ModuleEvent::Result { .. }));
        assert!(matches!(&got[3], ModuleEvent::Done { job_id } if *job_id == id));
    }
}
