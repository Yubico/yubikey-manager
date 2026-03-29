mod common;

use common::{is_nfc, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;
use std::thread;
use std::time::Duration;

/// Wait for the YubiKey to re-enumerate after a USB config change.
/// Only needed over USB — NFC doesn't disconnect.
fn wait_for_reenumeration() {
    if !is_nfc() {
        thread::sleep(Duration::from_secs(3));
    }
}

#[test]
#[ignore]
#[serial]
fn test_config_usb_list() {
    ykman_dev()
        .args(["config", "usb", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
#[ignore]
#[serial]
fn test_config_nfc_list() {
    // NFC may not be present on all keys; accept success or a clear error
    let output = ykman_dev()
        .args(["config", "nfc", "--list"])
        .output()
        .expect("failed to run command");

    // If the key supports NFC the command succeeds, otherwise it may fail
    // with a descriptive error. Either outcome is acceptable for this test.
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.is_empty(), "Expected non-empty NFC capability list");
    }
}

#[test]
#[ignore]
#[serial]
fn test_config_usb_disable_enable_hsmauth() {
    // Ensure HSMAUTH is enabled first (ignore errors if already enabled)
    let _ = ykman_dev()
        .args(["config", "usb", "--enable", "hsmauth", "-f"])
        .ok();
    wait_for_reenumeration();

    // Disable HSMAUTH over USB
    ykman_dev()
        .args(["config", "usb", "--disable", "hsmauth", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    // Verify it is no longer listed as enabled
    ykman_dev()
        .args(["config", "usb", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YubiHSM Auth: Disabled"));

    // Re-enable HSMAUTH
    ykman_dev()
        .args(["config", "usb", "--enable", "hsmauth", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    // Verify it is listed again
    ykman_dev()
        .args(["config", "usb", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YubiHSM Auth: Enabled"));
}
