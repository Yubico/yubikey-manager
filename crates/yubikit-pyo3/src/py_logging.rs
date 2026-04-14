//! Bridge from Rust `log` crate to Python `logging` module.
//!
//! When initialized, Rust log messages are forwarded to Python's logging system.
//! Calls into Python using `Python::with_gil`, and only forwards log records
//! from the Python main thread, with a thread-local flag used to prevent
//! reentrant logging.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use log::{Level, LevelFilter, Log, Metadata, Record};
use pyo3::prelude::*;

use yubikit::logging::TRAFFIC_TARGET_PREFIX;

/// Python logging levels
const PY_LOG_ERROR: u32 = 40;
const PY_LOG_WARNING: u32 = 30;
const PY_LOG_INFO: u32 = 20;
const PY_LOG_DEBUG: u32 = 10;
const PY_LOG_TRAFFIC: u32 = 5;

thread_local! {
    static IN_LOG: Cell<bool> = const { Cell::new(false) };
}

/// Thread ID of the Python main thread (set during init).
static PYTHON_THREAD_ID: AtomicU64 = AtomicU64::new(0);

fn current_thread_id() -> u64 {
    // Use a simple thread ID based on thread_local address
    thread_local! { static ID: Cell<u64> = const { Cell::new(0) }; }
    ID.with(|id| {
        let v = id.get();
        if v == 0 {
            let new_id = id as *const _ as u64;
            id.set(new_id);
            new_id
        } else {
            v
        }
    })
}

struct PyLogger;

impl Log for PyLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Only forward to Python from the Python main thread
        if current_thread_id() != PYTHON_THREAD_ID.load(Ordering::Relaxed) {
            return;
        }

        // Prevent reentrant logging
        if IN_LOG.with(|f| f.replace(true)) {
            return;
        }

        let is_traffic =
            record.level() == Level::Trace && record.target().starts_with(TRAFFIC_TARGET_PREFIX);

        let py_level = if is_traffic {
            PY_LOG_TRAFFIC
        } else {
            match record.level() {
                Level::Error => PY_LOG_ERROR,
                Level::Warn => PY_LOG_WARNING,
                Level::Info => PY_LOG_INFO,
                Level::Debug => PY_LOG_DEBUG,
                Level::Trace => {
                    IN_LOG.with(|f| f.set(false));
                    return;
                }
            }
        };

        let module = if let Some(stripped) = record.target().strip_prefix(TRAFFIC_TARGET_PREFIX) {
            stripped
        } else {
            record.target()
        };
        let module = module.replace("::", ".");

        let msg = format!("{}", record.args());

        // Safe: we verified we're on the Python thread
        let _ = Python::with_gil(|py| -> PyResult<()> {
            let logging = py.import("logging")?;
            let logger = logging.call_method1("getLogger", (&module,))?;
            logger.call_method1("log", (py_level, &msg))?;
            Ok(())
        });

        IN_LOG.with(|f| f.set(false));
    }

    fn flush(&self) {}
}

/// Initialize the Rust-to-Python logging bridge.
/// Call this once during module initialization.
pub fn init() {
    static LOGGER: PyLogger = PyLogger;
    PYTHON_THREAD_ID.store(current_thread_id(), Ordering::Relaxed);
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(LevelFilter::Trace);
    }
}
