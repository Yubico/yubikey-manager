//! Logging utilities for yubikit-rs.
//!
//! Defines a custom TRAFFIC log level below DEBUG for logging raw APDU/HID traffic.
//! Uses the standard `log` crate facade with target-based filtering.

/// The target prefix used for TRAFFIC-level log messages.
pub const TRAFFIC_TARGET_PREFIX: &str = "traffic::";

/// Log a TRAFFIC-level message (raw data sent/received).
#[macro_export]
macro_rules! log_traffic {
    ($($arg:tt)*) => {
        log::trace!(target: concat!("traffic::", module_path!()), $($arg)*)
    };
}

/// Format bytes as a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
