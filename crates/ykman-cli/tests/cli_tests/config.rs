use super::common::{
    device_info, skip_before_version, skip_if_fips, skip_interactive_on_windows, ykman_dev,
    ykman_dev_tty,
};
use assert_cmd::Command;
use predicates::prelude::*;
use std::thread;
use std::time::Duration;

/// Wait for the YubiKey to re-enumerate after a USB config change.
fn wait_for_reenumeration() {
    thread::sleep(Duration::from_secs(3));
}

const TEST_LOCK_CODE: &str = "01020304050607080102030405060708";

struct LockCodeGuard {
    code: &'static str,
    armed: bool,
}

impl LockCodeGuard {
    fn set(code: &'static str) -> Self {
        ykman_dev()
            .args(["config", "set-lock-code", "-n", code, "-f"])
            .assert()
            .success();
        Self { code, armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for LockCodeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = ykman_dev()
                .args(["config", "set-lock-code", "-L", self.code, "--clear", "-f"])
                .ok();
        }
    }
}

fn configuration_is_locked() -> bool {
    let output = ykman_dev()
        .arg("info")
        .output()
        .expect("failed to run ykman info");
    String::from_utf8_lossy(&output.stdout)
        .contains("Configured capabilities are protected by a lock code")
}

fn fresh_info() -> String {
    let output = ykman_dev()
        .arg("info")
        .output()
        .expect("failed to run ykman info");
    assert!(
        output.status.success(),
        "ykman info failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn app_is_enabled(info: &str, app: &str, transport: &str) -> Option<bool> {
    let header = info.lines().find(|l| l.starts_with("Applications"))?;
    let col = header.find(transport)?;
    let app_line = info.lines().find(|l| l.starts_with(app))?;
    let field = app_line.get(col..)?.split_whitespace().next()?;
    Some(field == "Enabled")
}

fn has_nfc() -> bool {
    device_info().contains("NFC transport")
}

#[test]
fn test_config_set_lock_code_help() {
    Command::cargo_bin("ykman")
        .expect("binary 'ykman' not found")
        .args(["config", "set-lock-code", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "A lock code may be used to protect the application configuration.",
        ))
        .stdout(predicate::str::contains(
            "32 hexadecimal characters, representing 16 bytes",
        ))
        .stdout(predicate::str::contains("-L, --lock-code <HEX>"))
        .stdout(predicate::str::contains("-n, --new-lock-code <HEX>"));
}

#[test]
fn test_config_set_lock_code_conflicts() {
    Command::cargo_bin("ykman")
        .expect("binary 'ykman' not found")
        .args([
            "config",
            "set-lock-code",
            "--new-lock-code",
            "01020304050607080102030405060708",
            "--generate",
        ])
        .assert()
        .failure();

    Command::cargo_bin("ykman")
        .expect("binary 'ykman' not found")
        .args([
            "config",
            "set-lock-code",
            "--clear",
            "--new-lock-code",
            "01020304050607080102030405060708",
        ])
        .assert()
        .failure();
}

#[test]
fn test_config_usb_disable_enable_piv() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    if app_is_enabled(device_info(), "PIV", "USB") != Some(true) {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m PIV is not enabled over USB on this YubiKey");
        return;
    }

    ykman_dev()
        .args(["config", "usb", "--disable", "piv", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    assert_eq!(
        app_is_enabled(&fresh_info(), "PIV", "USB"),
        Some(false),
        "PIV should be disabled after config change"
    );

    ykman_dev()
        .args(["config", "usb", "--enable", "piv", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    assert_eq!(
        app_is_enabled(&fresh_info(), "PIV", "USB"),
        Some(true),
        "PIV should be enabled after config change"
    );
}

#[test]
fn test_config_nfc_enable_disable() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    if !has_nfc() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m NFC is not supported on this YubiKey");
        return;
    }

    // Ensure PIV is enabled over NFC first
    let _ = ykman_dev()
        .args(["config", "nfc", "--enable", "piv", "-f"])
        .ok();

    // Disable PIV over NFC
    ykman_dev()
        .args(["config", "nfc", "--disable", "piv", "-f"])
        .assert()
        .success();

    assert_eq!(
        app_is_enabled(&fresh_info(), "PIV", "NFC"),
        Some(false),
        "PIV should be disabled over NFC after config change"
    );

    // Re-enable PIV over NFC
    ykman_dev()
        .args(["config", "nfc", "--enable", "piv", "-f"])
        .assert()
        .success();

    assert_eq!(
        app_is_enabled(&fresh_info(), "PIV", "NFC"),
        Some(true),
        "PIV should be enabled over NFC after config change"
    );
}

#[test]
fn test_config_usb_enable_all() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    if app_is_enabled(device_info(), "PIV", "USB") != Some(true) {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m PIV is not enabled over USB on this YubiKey");
        return;
    }

    // First disable PIV so --enable-all has something to do
    ykman_dev()
        .args(["config", "usb", "--disable", "piv", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    // Now enable-all should succeed
    ykman_dev()
        .args(["config", "usb", "--enable-all", "-f"])
        .assert()
        .success();
    wait_for_reenumeration();

    // Verify PIV is enabled again
    assert_eq!(
        app_is_enabled(&fresh_info(), "PIV", "USB"),
        Some(true),
        "PIV should be enabled after --enable-all"
    );
}

#[test]
fn test_config_nfc_disable_all_enable_all() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    if !has_nfc() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m NFC is not supported on this YubiKey");
        return;
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
fn test_config_set_lock_code() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    let lock_code = TEST_LOCK_CODE;

    // Set a lock code
    ykman_dev()
        .args(["config", "set-lock-code", "-n", lock_code, "-f"])
        .assert()
        .success();

    // Clear the lock code (must supply current code)
    ykman_dev()
        .args(["config", "set-lock-code", "-L", lock_code, "--clear", "-f"])
        .assert()
        .success();
}

#[test]
fn test_config_set_lock_code_prompts_for_current_code() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    if skip_interactive_on_windows() {
        return;
    }
    if configuration_is_locked() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m configuration is already locked with an unknown code");
        return;
    }

    let guard = LockCodeGuard::set(TEST_LOCK_CODE);
    let output = ykman_dev_tty(
        &["config", "set-lock-code", "--clear", "-f"],
        &format!("{TEST_LOCK_CODE}\n"),
    );
    assert!(output.status.success(), "{output:?}");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("Current lock code"), "{combined}");
    guard.disarm();
}

#[test]
fn test_config_usb_lock_code_prompt_and_explicit_code() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    if skip_interactive_on_windows() {
        return;
    }
    if configuration_is_locked() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m configuration is already locked with an unknown code");
        return;
    }
    if app_is_enabled(device_info(), "PIV", "USB") != Some(true) {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m PIV is not enabled over USB on this YubiKey");
        return;
    }

    let guard = LockCodeGuard::set(TEST_LOCK_CODE);
    let output = ykman_dev_tty(
        &["config", "usb", "--disable", "piv", "-f"],
        &format!("{TEST_LOCK_CODE}\n"),
    );
    assert!(output.status.success(), "{output:?}");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("Enter lock code"), "{combined}");
    wait_for_reenumeration();

    ykman_dev()
        .args([
            "config",
            "usb",
            "--enable",
            "piv",
            "--lock-code",
            TEST_LOCK_CODE,
            "-f",
        ])
        .assert()
        .success();
    wait_for_reenumeration();

    ykman_dev()
        .args([
            "config",
            "set-lock-code",
            "-L",
            TEST_LOCK_CODE,
            "--clear",
            "-f",
        ])
        .assert()
        .success();
    guard.disarm();
}

#[test]
fn test_config_nfc_lock_code_prompt_and_explicit_code() {
    require_capability!("CCID");
    if skip_before_version((5, 0, 0), "device configuration") {
        return;
    }
    if skip_interactive_on_windows() {
        return;
    }
    if skip_if_fips("mutable NFC configuration lock-code prompt test") {
        return;
    }
    if configuration_is_locked() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m configuration is already locked with an unknown code");
        return;
    }
    if !has_nfc() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m NFC is not supported on this YubiKey");
        return;
    }

    let guard = LockCodeGuard::set(TEST_LOCK_CODE);
    let output = ykman_dev_tty(
        &["config", "nfc", "--disable", "piv", "-f"],
        &format!("{TEST_LOCK_CODE}\n"),
    );
    assert!(output.status.success(), "{output:?}");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("Enter lock code"), "{combined}");

    ykman_dev()
        .args([
            "config",
            "nfc",
            "--enable",
            "piv",
            "--lock-code",
            TEST_LOCK_CODE,
            "-f",
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "config",
            "set-lock-code",
            "-L",
            TEST_LOCK_CODE,
            "--clear",
            "-f",
        ])
        .assert()
        .success();
    guard.disarm();
}
