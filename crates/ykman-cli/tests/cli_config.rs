mod common;

use common::ykman_dev;
use predicates::prelude::*;
use serial_test::serial;
use std::thread;
use std::time::Duration;

/// Wait for the YubiKey to re-enumerate after a USB config change.
fn wait_for_reenumeration() {
    thread::sleep(Duration::from_secs(3));
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
    let output = ykman_dev()
        .args(["config", "nfc", "--list"])
        .output()
        .expect("failed to run command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.is_empty(), "Expected non-empty NFC capability list");
    }
}

#[test]
#[ignore]
#[serial]
fn test_config_usb_disable_enable_hsmauth() {
    require_interface!("CCID");
    let _ = ykman_dev()
        .args(["config", "usb", "--enable", "hsmauth", "-f"])
        .ok();
    wait_for_reenumeration();

    ykman_dev()
        .args(["config", "usb", "--disable", "hsmauth", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    ykman_dev()
        .args(["config", "usb", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YubiHSM Auth: Disabled"));

    ykman_dev()
        .args(["config", "usb", "--enable", "hsmauth", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    ykman_dev()
        .args(["config", "usb", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YubiHSM Auth: Enabled"));
}

#[test]
#[ignore]
#[serial]
fn test_config_nfc_enable_disable() {
    require_interface!("CCID");
    // Skip if key has no NFC support
    let output = ykman_dev()
        .args(["config", "nfc", "--list"])
        .output()
        .expect("failed to run command");
    if !output.status.success() {
        return;
    }

    // Ensure HSMAUTH is enabled over NFC first
    let _ = ykman_dev()
        .args(["config", "nfc", "--enable", "hsmauth", "-f"])
        .ok();

    // Disable HSMAUTH over NFC
    ykman_dev()
        .args(["config", "nfc", "--disable", "hsmauth", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["config", "nfc", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YubiHSM Auth: Disabled"));

    // Re-enable HSMAUTH over NFC
    ykman_dev()
        .args(["config", "nfc", "--enable", "hsmauth", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["config", "nfc", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YubiHSM Auth: Enabled"));
}

#[test]
#[ignore]
#[serial]
fn test_config_usb_enable_all() {
    require_interface!("CCID");
    // First disable an app so --enable-all has something to do
    let _ = ykman_dev()
        .args(["config", "usb", "--disable", "hsmauth", "-f"])
        .ok();
    wait_for_reenumeration();

    // Now enable-all should succeed
    ykman_dev()
        .args(["config", "usb", "--enable-all", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    // Verify everything is enabled
    ykman_dev()
        .args(["config", "usb", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("YubiHSM Auth: Enabled"));
}

#[test]
#[ignore]
#[serial]
fn test_config_nfc_disable_all_enable_all() {
    require_interface!("CCID");
    // NFC disable-all is safe — USB access can always recover.
    let output = ykman_dev()
        .args(["config", "nfc", "--list"])
        .output()
        .expect("failed to run command");
    if !output.status.success() {
        return; // NFC not supported on this key
    }

    ykman_dev()
        .args(["config", "nfc", "--disable-all", "-f"])
        .assert()
        .success();

    // Re-enable all NFC apps
    ykman_dev()
        .args(["config", "nfc", "--enable-all", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_config_set_lock_code() {
    require_interface!("CCID");
    let lock_code = "01020304050607080102030405060708";

    // Set a lock code
    ykman_dev()
        .args(["config", "set-lock-code", "-n", lock_code, "-f"])
        .assert()
        .success();

    // Clear the lock code (must supply current code)
    ykman_dev()
        .args(["config", "set-lock-code", "-l", lock_code, "--clear", "-f"])
        .assert()
        .success();
}
