//! Global Ctrl+C cancellation mechanism.
//!
//! Provides a single shared cancel flag that any code can check, plus
//! an optional callback for sending cancel signals over RPC.
//!
//! The ctrlc crate only allows `set_handler` to be called once, so this
//! module installs one handler and exposes a composable API on top.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};

static CANCELLED: AtomicBool = AtomicBool::new(false);
static ON_CANCEL: Mutex<Option<Arc<dyn Fn() + Send + Sync>>> = Mutex::new(None);
static INIT: Once = Once::new();

fn ensure_init() {
    INIT.call_once(|| {
        let _ = ctrlc::set_handler(|| {
            CANCELLED.store(true, Ordering::Relaxed);
            if let Ok(guard) = ON_CANCEL.lock()
                && let Some(ref cb) = *guard
            {
                cb();
            }
        });
    });
}

/// Returns true if Ctrl+C has been pressed since the last [`clear`].
pub fn is_cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}

/// Clear the cancellation flag. Call before starting a cancellable operation.
pub fn clear() {
    ensure_init();
    CANCELLED.store(false, Ordering::Relaxed);
}

/// Register a callback to run on Ctrl+C (e.g., send RPC cancel signal).
///
/// Returns a guard that unregisters the callback when dropped. Only one
/// callback can be active at a time; registering a new one replaces the old.
pub fn on_cancel(f: impl Fn() + Send + Sync + 'static) -> CancelGuard {
    ensure_init();
    *ON_CANCEL.lock().unwrap() = Some(Arc::new(f));
    CancelGuard
}

/// RAII guard that unregisters the on-cancel callback when dropped.
pub struct CancelGuard;

impl Drop for CancelGuard {
    fn drop(&mut self) {
        *ON_CANCEL.lock().unwrap() = None;
    }
}
