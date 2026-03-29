#![allow(dead_code)]

use assert_cmd::Command;
use std::env;
use std::sync::OnceLock;

/// Test device configuration, resolved from environment variables.
///
/// Set `YKMAN_TEST_SERIAL` for USB testing, or `YKMAN_TEST_READER` for NFC.
/// If neither is set, all device tests abort.
struct TestDevice {
    serial: Option<String>,
    reader: Option<String>,
}

fn test_device() -> &'static TestDevice {
    static DEVICE: OnceLock<TestDevice> = OnceLock::new();
    DEVICE.get_or_init(|| TestDevice {
        serial: env::var("YKMAN_TEST_SERIAL").ok(),
        reader: env::var("YKMAN_TEST_READER").ok(),
    })
}

/// Abort the test if no device is configured.
fn require_device() {
    let dev = test_device();
    if dev.serial.is_none() && dev.reader.is_none() {
        panic!(
            "No test device configured. Set YKMAN_TEST_SERIAL=<serial> \
             or YKMAN_TEST_READER=<reader_substring> to run device tests."
        );
    }
}

/// Returns true when testing over NFC (YKMAN_TEST_READER is set).
pub fn is_nfc() -> bool {
    test_device().reader.is_some()
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

/// Build a base `ykman` command from the compiled binary.
pub fn ykman() -> Command {
    require_device();
    Command::cargo_bin("ykman").expect("binary 'ykman' not found")
}

/// Build a `ykman` command targeting the configured test device.
///
/// Uses `--reader <substring>` for NFC, or `--device <serial>` for USB.
pub fn ykman_dev() -> Command {
    let mut cmd = ykman();
    let dev = test_device();
    if let Some(ref reader) = dev.reader {
        cmd.args(["--reader", reader]);
    } else if let Some(ref serial) = dev.serial {
        cmd.args(["--device", serial]);
    }
    cmd
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
