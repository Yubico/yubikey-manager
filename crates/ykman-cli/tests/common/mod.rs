#![allow(dead_code)]

use assert_cmd::Command;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Test device configuration, resolved from environment variables.
///
/// Set `YKMAN_TEST_SERIAL` for USB testing with a known serial.
/// Set `YKMAN_TEST_NO_SERIAL=1` for devices without a serial number.
/// If neither is set, all device tests abort.
struct TestDevice {
    serial: Option<String>,
    no_serial: bool,
}

fn test_device() -> &'static TestDevice {
    static DEVICE: OnceLock<TestDevice> = OnceLock::new();
    DEVICE.get_or_init(|| TestDevice {
        serial: env::var("YKMAN_TEST_SERIAL").ok(),
        no_serial: env::var("YKMAN_TEST_NO_SERIAL").is_ok(),
    })
}

/// Abort the test if no device is configured.
fn require_device() {
    let dev = test_device();
    if dev.serial.is_none() && !dev.no_serial {
        panic!(
            "No test device configured. Set YKMAN_TEST_SERIAL=<serial> \
             or YKMAN_TEST_NO_SERIAL=1 to run device tests."
        );
    }
}

/// Returns the configured serial number, if any.
pub fn device_serial() -> Option<&'static str> {
    test_device().serial.as_deref()
}

// PIV defaults
pub const DEFAULT_PIN: &str = "123456";
pub const NON_DEFAULT_PIN: &str = "12341235";
pub const DEFAULT_PUK: &str = "12345678";
pub const NON_DEFAULT_PUK: &str = "12341236";
pub const DEFAULT_MANAGEMENT_KEY: &str = "010203040506070801020304050607080102030405060708";
pub const NON_DEFAULT_MANAGEMENT_KEY: &str = "010103040506070801020304050607080102030405060708";

// OpenPGP defaults
pub const DEFAULT_OPENPGP_PIN: &str = "123456";
pub const NON_DEFAULT_OPENPGP_PIN: &str = "12345679";
pub const DEFAULT_OPENPGP_ADMIN_PIN: &str = "12345678";
pub const NON_DEFAULT_OPENPGP_ADMIN_PIN: &str = "12345670";

// OATH
pub const OATH_PASSWORD: &str = "aaaa";

// HSMAuth
pub const DEFAULT_HSMAUTH_MANAGEMENT_KEY: &str = "00000000000000000000000000000000";

// OTP access codes
pub const OTP_ACCESS_CODE_1: &str = "111111111111";

/// Return the path to the test fixtures directory.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Return the full path to a fixture file.
pub fn fixture_path(name: &str) -> PathBuf {
    let p = fixtures_dir().join(name);
    assert!(p.exists(), "fixture not found: {}", p.display());
    p
}

/// Build a base `ykman` command from the compiled binary.
pub fn ykman() -> Command {
    require_device();
    Command::cargo_bin("ykman").expect("binary 'ykman' not found")
}

/// Build a `ykman` command targeting the configured test device.
///
/// Uses `--device <serial>` when a serial is configured.
pub fn ykman_dev() -> Command {
    let mut cmd = ykman();
    let dev = test_device();
    if let Some(ref serial) = dev.serial {
        cmd.args(["--device", serial]);
    }
    cmd
}

/// Returns true if the device has the given USB interface enabled.
pub fn has_usb_interface(name: &str) -> bool {
    static INFO: OnceLock<String> = OnceLock::new();
    let stdout = INFO.get_or_init(|| {
        let output = ykman_dev()
            .args(["info"])
            .output()
            .expect("failed to run ykman info");
        String::from_utf8_lossy(&output.stdout).into_owned()
    });
    // Look for the interface name in the "Enabled USB interfaces:" line
    stdout
        .lines()
        .any(|line| line.starts_with("Enabled USB interfaces:") && line.contains(name))
}

/// Skip the test if the device does not have the given USB interface enabled.
#[macro_export]
macro_rules! require_interface {
    ($name:expr) => {
        if !common::has_usb_interface($name) {
            eprintln!("SKIP: {} not enabled on device", $name);
            return;
        }
    };
}

/// Reset PIV to factory defaults (force, no prompt).
pub fn piv_reset() {
    ykman_dev()
        .args(["piv", "reset", "-f"])
        .ok()
        .expect("PIV reset failed");
}

/// Reset OATH to factory defaults.
pub fn oath_reset() {
    ykman_dev()
        .args(["oath", "reset", "-f"])
        .ok()
        .expect("OATH reset failed");
}

/// Reset OpenPGP to factory defaults.
pub fn openpgp_reset() {
    ykman_dev()
        .args(["openpgp", "reset", "-f"])
        .ok()
        .expect("OpenPGP reset failed");
}

/// Reset HSMAuth to factory defaults.
pub fn hsmauth_reset() {
    ykman_dev()
        .args(["hsmauth", "reset", "-f"])
        .ok()
        .expect("HSMAuth reset failed");
}

/// Delete OTP slot 2 (ignore errors if empty).
pub fn otp_delete_slot2() {
    let _ = ykman_dev().args(["otp", "delete", "2", "-f"]).ok();
}

/// Reset Security Domain to factory defaults.
pub fn sd_reset() {
    ykman_dev()
        .args(["sd", "reset", "-f"])
        .ok()
        .expect("SD reset failed");
}

/// Default SCP03 key set (K-ENC:K-MAC:K-DEK) used after SD reset.
pub const DEFAULT_SCP03_KEYS: &str = "404142434445464748494a4b4c4d4e4f:404142434445464748494a4b4c4d4e4f:404142434445464748494a4b4c4d4e4f";

/// Like `ykman_dev()` but with default SCP03 authentication.
pub fn ykman_dev_scp() -> Command {
    let mut cmd = ykman_dev();
    cmd.args(["--scp", DEFAULT_SCP03_KEYS]);
    cmd
}
