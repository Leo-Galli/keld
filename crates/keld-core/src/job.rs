//! Job identity, lifecycle state, and counters updated from [`ModuleEvent`]s.

use std::fmt;

use thiserror::Error;

use crate::event::ModuleEvent;

/// Opaque job identity (assigned by the runner / UI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(u64);

impl JobId {
    /// Construct from a raw counter value.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Raw numeric id.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which feature module owns the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleKind {
    /// KL-005 wiring stub; replaced by real modules later.
    Stub,
    Scan,
    Probe,
    Tls,
    Http,
    Fuzz,
    Dns,
    Net,
    Hash,
    Report,
    Workspace,
}

impl ModuleKind {
    /// Stable CLI / sidebar id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stub => "stub",
            Self::Scan => "scan",
            Self::Probe => "probe",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Fuzz => "fuzz",
            Self::Dns => "dns",
            Self::Net => "net",
            Self::Hash => "hash",
            Self::Report => "report",
            Self::Workspace => "workspace",
        }
    }
}

impl fmt::Display for ModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl JobState {
    /// Terminal states do not accept further progress.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Errors from illegal job transitions or mismatched events.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JobError {
    #[error("job {job_id} is {state:?}; cannot start")]
    CannotStart { job_id: JobId, state: JobState },
    #[error("job {job_id} is {state:?}; cannot pause")]
    CannotPause { job_id: JobId, state: JobState },
    #[error("job {job_id} is {state:?}; cannot resume")]
    CannotResume { job_id: JobId, state: JobState },
    #[error("job {job_id} is {state:?}; cannot cancel")]
    CannotCancel { job_id: JobId, state: JobState },
    #[error("event for job {event_id} does not match job {job_id}")]
    JobIdMismatch { job_id: JobId, event_id: JobId },
    #[error("job {job_id} is {state:?}; refusing event")]
    Terminal { job_id: JobId, state: JobState },
}

/// One runnable unit of work with progress counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: JobId,
    pub module: ModuleKind,
    pub state: JobState,
    /// Units completed (from the latest progress event).
    pub done: u64,
    /// Units expected (0 means unknown).
    pub total: u64,
    /// Count of [`ModuleEvent::Result`] applied.
    pub results: u64,
    /// Count of [`ModuleEvent::Error`] applied (job may still complete).
    pub errors: u64,
}

impl Job {
    /// New job in [`JobState::Pending`].
    pub fn new(id: JobId, module: ModuleKind) -> Self {
        Self {
            id,
            module,
            state: JobState::Pending,
            done: 0,
            total: 0,
            results: 0,
            errors: 0,
        }
    }

    /// Pending -> Running.
    pub fn start(&mut self) -> Result<(), JobError> {
        match self.state {
            JobState::Pending => {
                self.state = JobState::Running;
                Ok(())
            }
            state => Err(JobError::CannotStart {
                job_id: self.id,
                state,
            }),
        }
    }

    /// Running -> Paused.
    pub fn pause(&mut self) -> Result<(), JobError> {
        match self.state {
            JobState::Running => {
                self.state = JobState::Paused;
                Ok(())
            }
            state => Err(JobError::CannotPause {
                job_id: self.id,
                state,
            }),
        }
    }

    /// Paused -> Running.
    pub fn resume(&mut self) -> Result<(), JobError> {
        match self.state {
            JobState::Paused => {
                self.state = JobState::Running;
                Ok(())
            }
            state => Err(JobError::CannotResume {
                job_id: self.id,
                state,
            }),
        }
    }

    /// Non-terminal -> Cancelled.
    pub fn cancel(&mut self) -> Result<(), JobError> {
        if self.state.is_terminal() {
            return Err(JobError::CannotCancel {
                job_id: self.id,
                state: self.state,
            });
        }
        self.state = JobState::Cancelled;
        Ok(())
    }

    /// Apply a module event to counters and terminal state.
    pub fn apply_event(&mut self, event: &ModuleEvent) -> Result<(), JobError> {
        let event_id = event.job_id();
        if event_id != self.id {
            return Err(JobError::JobIdMismatch {
                job_id: self.id,
                event_id,
            });
        }
        if self.state.is_terminal() {
            return Err(JobError::Terminal {
                job_id: self.id,
                state: self.state,
            });
        }

        match event {
            ModuleEvent::Progress { done, total, .. } => {
                if self.state == JobState::Pending {
                    self.state = JobState::Running;
                }
                self.done = *done;
                self.total = *total;
            }
            ModuleEvent::Result { .. } => {
                if self.state == JobState::Pending {
                    self.state = JobState::Running;
                }
                self.results = self.results.saturating_add(1);
            }
            ModuleEvent::Log { .. } => {
                if self.state == JobState::Pending {
                    self.state = JobState::Running;
                }
            }
            ModuleEvent::Done { .. } => {
                self.state = JobState::Completed;
            }
            ModuleEvent::Error { .. } => {
                self.errors = self.errors.saturating_add(1);
                self.state = JobState::Failed;
            }
        }
        Ok(())
    }

    /// Fraction complete in `0.0..=1.0`, or `None` if total is unknown.
    pub fn progress_fraction(&self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        Some((self.done as f64 / self.total as f64).clamp(0.0, 1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::LogLevel;

    #[test]
    fn start_pause_resume_cancel() {
        let mut job = Job::new(JobId::new(1), ModuleKind::Stub);
        assert_eq!(job.state, JobState::Pending);
        job.start().unwrap();
        assert_eq!(job.state, JobState::Running);
        job.pause().unwrap();
        assert_eq!(job.state, JobState::Paused);
        job.resume().unwrap();
        assert_eq!(job.state, JobState::Running);
        job.cancel().unwrap();
        assert_eq!(job.state, JobState::Cancelled);
        assert!(job.start().is_err());
    }

    #[test]
    fn apply_progress_and_done() {
        let id = JobId::new(3);
        let mut job = Job::new(id, ModuleKind::Scan);
        job.apply_event(&ModuleEvent::Progress {
            job_id: id,
            done: 2,
            total: 10,
            message: "ports".into(),
        })
        .unwrap();
        assert_eq!(job.state, JobState::Running);
        assert_eq!(job.done, 2);
        assert_eq!(job.total, 10);
        assert!((job.progress_fraction().unwrap() - 0.2).abs() < f64::EPSILON);

        job.apply_event(&ModuleEvent::Result {
            job_id: id,
            summary: "open 80".into(),
        })
        .unwrap();
        assert_eq!(job.results, 1);

        job.apply_event(&ModuleEvent::Done { job_id: id }).unwrap();
        assert_eq!(job.state, JobState::Completed);
        assert!(job
            .apply_event(&ModuleEvent::Progress {
                job_id: id,
                done: 3,
                total: 10,
                message: String::new(),
            })
            .is_err());
    }

    #[test]
    fn apply_error_fails_job() {
        let id = JobId::new(9);
        let mut job = Job::new(id, ModuleKind::Stub);
        job.start().unwrap();
        job.apply_event(&ModuleEvent::Error {
            job_id: id,
            message: "boom".into(),
        })
        .unwrap();
        assert_eq!(job.state, JobState::Failed);
        assert_eq!(job.errors, 1);
    }

    #[test]
    fn rejects_mismatched_job_id() {
        let mut job = Job::new(JobId::new(1), ModuleKind::Stub);
        let err = job
            .apply_event(&ModuleEvent::Log {
                job_id: JobId::new(2),
                level: LogLevel::Warn,
                message: "x".into(),
            })
            .unwrap_err();
        assert!(matches!(err, JobError::JobIdMismatch { .. }));
    }

    #[test]
    fn illegal_transitions() {
        let mut job = Job::new(JobId::new(1), ModuleKind::Stub);
        assert!(matches!(
            job.pause().unwrap_err(),
            JobError::CannotPause { .. }
        ));
        job.start().unwrap();
        assert!(matches!(
            job.start().unwrap_err(),
            JobError::CannotStart { .. }
        ));
        assert!(matches!(
            job.resume().unwrap_err(),
            JobError::CannotResume { .. }
        ));
    }
}
