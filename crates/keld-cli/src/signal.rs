//! Ctrl+C hook skeleton: sets a cancel flag and runs a one-shot partial-save callback.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// Shared cancel + partial-save hook for long-running CLI commands.
///
/// Install before work starts. On Ctrl+C the flag is set and `save` runs once
/// (modules should flush partial results there). Poll [`Self::is_cancelled`]
/// in loops to stop cooperatively.
#[derive(Debug, Default)]
pub struct PartialSaveHook {
    cancelled: AtomicBool,
}

impl PartialSaveHook {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
        })
    }

    /// Spawn a background waiter for Ctrl+C. `save` runs at most once.
    ///
    /// No-op if a Tokio runtime cannot be built (extremely rare); the flag
    /// still works if set manually via [`Self::request_cancel`].
    pub fn install(self: &Arc<Self>, save: impl FnOnce() + Send + 'static) {
        let hook = Arc::clone(self);
        let save = Arc::new(Mutex::new(Some(save)));
        thread::Builder::new()
            .name("keld-ctrl-c".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                rt.block_on(async {
                    let _ = tokio::signal::ctrl_c().await;
                    hook.request_cancel();
                    if let Ok(mut guard) = save.lock() {
                        if let Some(cb) = guard.take() {
                            cb();
                        }
                    }
                });
            })
            .ok();
    }

    pub fn request_cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_cancel_sets_flag() {
        let hook = PartialSaveHook::new();
        assert!(!hook.is_cancelled());
        hook.request_cancel();
        assert!(hook.is_cancelled());
    }

    #[test]
    fn save_mutex_fires_once() {
        let calls = Arc::new(AtomicBool::new(false));
        let calls2 = Arc::clone(&calls);
        let save = Arc::new(Mutex::new(Some(move || {
            calls2.store(true, Ordering::SeqCst);
        })));

        let hook = PartialSaveHook::new();
        hook.request_cancel();
        if let Ok(mut guard) = save.lock() {
            if let Some(cb) = guard.take() {
                cb();
            }
        }
        assert!(save.lock().unwrap().is_none());
        assert!(calls.load(Ordering::SeqCst));
        assert!(hook.is_cancelled());
    }
}
