use super::common::{skip_if_fips, skip_interactive_on_windows, ykman_dev, ykman_dev_tty};
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
                .args(["config", "set-lock-code", "-l", self.code, "--clear", "-f"])
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

fn config_list_contains(args: &[&str], needle: &str) -> bool {
    let output = ykman_dev()
        .args(args)
        .output()
        .expect("failed to run command");
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains(needle)
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
        .stdout(predicate::str::contains("-l, --lock-code <HEX>"))
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
fn test_config_usb_list() {
    require_device_configured!();
    ykman_dev()
        .args(["config", "usb", "--list"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn test_config_nfc_list() {
    require_device_configured!();
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
fn test_config_usb_disable_enable_hsmauth() {
    require_capability!("CCID");
    if !config_list_contains(&["config", "usb", "--list"], "YubiHSM Auth:") {
        eprintln!("SKIP: YubiHSM Auth is not configurable over USB on this YubiKey");
        return;
    }

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
fn test_config_nfc_enable_disable() {
    require_capability!("CCID");
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
fn test_config_usb_enable_all() {
    require_capability!("CCID");
    if !config_list_contains(&["config", "usb", "--list"], "YubiHSM Auth:") {
        eprintln!("SKIP: YubiHSM Auth is not configurable over USB on this YubiKey");
        return;
    }

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
fn test_config_nfc_disable_all_enable_all() {
    require_capability!("CCID");
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
fn test_config_set_lock_code() {
    require_capability!("CCID");
    let lock_code = TEST_LOCK_CODE;

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

#[test]
fn test_config_set_lock_code_prompts_for_current_code() {
    require_capability!("CCID");
    if skip_interactive_on_windows() {
        return;
    }
    if configuration_is_locked() {
        eprintln!("SKIP: configuration is already locked with an unknown code");
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
    if skip_interactive_on_windows() {
        return;
    }
    if configuration_is_locked() {
        eprintln!("SKIP: configuration is already locked with an unknown code");
        return;
    }
    if !config_list_contains(&["config", "usb", "--list"], "YubiHSM Auth:") {
        eprintln!("SKIP: YubiHSM Auth is not configurable over USB on this YubiKey");
        return;
    }

    let guard = LockCodeGuard::set(TEST_LOCK_CODE);
    let output = ykman_dev_tty(
        &["config", "usb", "--disable", "hsmauth", "-f"],
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
            "hsmauth",
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
            "-l",
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
    if skip_interactive_on_windows() {
        return;
    }
    if skip_if_fips("mutable NFC configuration lock-code prompt test") {
        return;
    }
    if configuration_is_locked() {
        eprintln!("SKIP: configuration is already locked with an unknown code");
        return;
    }
    if !config_list_contains(&["config", "nfc", "--list"], "YubiHSM Auth:") {
        eprintln!("SKIP: YubiHSM Auth is not configurable over NFC on this YubiKey");
        return;
    }

    let guard = LockCodeGuard::set(TEST_LOCK_CODE);
    let output = ykman_dev_tty(
        &["config", "nfc", "--disable", "hsmauth", "-f"],
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
            "hsmauth",
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
            "-l",
            TEST_LOCK_CODE,
            "--clear",
            "-f",
        ])
        .assert()
        .success();
    guard.disarm();
}
