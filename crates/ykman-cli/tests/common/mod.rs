#![allow(dead_code)]

use assert_cmd::Command;

pub const DEVICE_SERIAL: &str = "104";

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
    Command::cargo_bin("ykman").expect("binary 'ykman' not found")
}

/// Build a `ykman` command pre-configured with `--device 104`.
pub fn ykman_dev() -> Command {
    let mut cmd = ykman();
    cmd.args(["--device", DEVICE_SERIAL]);
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
    // Ignore failure – slot may already be empty
    let _ = ykman_dev().args(["otp", "delete", "2", "-f"]).ok();
}
