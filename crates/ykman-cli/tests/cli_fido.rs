mod common;

use common::ykman_dev;
use predicates::prelude::*;
use serial_test::serial;

// FIDO reset requires physical reinsert + touch, so we cannot automate it.
// Once a PIN is set it can only be changed, not removed.
// All tests that need a PIN call ensure_pin_set() first, so they can run
// in any order.

const FIDO_PIN: &str = "11234567";
const FIDO_PIN_2: &str = "22345678";

/// Ensure a PIN is set on the device (idempotent).
fn ensure_pin_set() {
    let output = ykman_dev()
        .args(["fido", "info"])
        .output()
        .expect("failed to run ykman fido info");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("Not set") {
        ykman_dev()
            .args(["fido", "access", "change-pin", "--new-pin", FIDO_PIN])
            .ok()
            .expect("Failed to set initial FIDO PIN");
    }
}

// ── info ──────────────────────────────────────────────────────────────

#[test]
#[ignore]
#[serial]
fn test_fido_info() {
    require_interface!("FIDO");
    ykman_dev()
        .args(["fido", "info"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("AAGUID:")
                .and(predicate::str::contains("PIN:"))
                .and(predicate::str::contains("Minimum PIN length:")),
        );
}

// ── access ────────────────────────────────────────────────────────────

#[test]
#[ignore]
#[serial]
fn test_fido_verify_pin() {
    require_interface!("FIDO");
    ensure_pin_set();
    ykman_dev()
        .args(["fido", "access", "verify-pin", "--pin", FIDO_PIN])
        .assert()
        .success()
        .stdout(predicate::str::contains("PIN verified."));
}

#[test]
#[ignore]
#[serial]
fn test_fido_verify_pin_wrong() {
    require_interface!("FIDO");
    ensure_pin_set();
    ykman_dev()
        .args(["fido", "access", "verify-pin", "--pin", "wrongpin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("PIN verification failed"));
}

#[test]
#[ignore]
#[serial]
fn test_fido_change_pin() {
    require_interface!("FIDO");
    ensure_pin_set();

    // Change PIN
    ykman_dev()
        .args([
            "fido",
            "access",
            "change-pin",
            "--pin",
            FIDO_PIN,
            "--new-pin",
            FIDO_PIN_2,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("PIN has been changed."));

    // Verify new PIN works
    ykman_dev()
        .args(["fido", "access", "verify-pin", "--pin", FIDO_PIN_2])
        .assert()
        .success();

    // Old PIN should fail
    ykman_dev()
        .args(["fido", "access", "verify-pin", "--pin", FIDO_PIN])
        .assert()
        .failure();

    // Change back
    ykman_dev()
        .args([
            "fido",
            "access",
            "change-pin",
            "--pin",
            FIDO_PIN_2,
            "--new-pin",
            FIDO_PIN,
        ])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_fido_set_pin_too_short() {
    require_interface!("FIDO");
    ensure_pin_set();
    ykman_dev()
        .args([
            "fido",
            "access",
            "change-pin",
            "--pin",
            FIDO_PIN,
            "--new-pin",
            "123",
        ])
        .assert()
        .failure();
}

// ── credentials ───────────────────────────────────────────────────────

#[test]
#[ignore]
#[serial]
fn test_fido_credentials_list_empty() {
    require_interface!("FIDO");
    ensure_pin_set();
    ykman_dev()
        .args(["fido", "credentials", "list", "--pin", FIDO_PIN])
        .assert()
        .success()
        .stdout(predicate::str::contains("No discoverable credentials."));
}

// ── config ────────────────────────────────────────────────────────────

#[test]
#[ignore]
#[serial]
fn test_fido_config_toggle_always_uv() {
    require_interface!("FIDO");
    ensure_pin_set();

    // Check initial state
    let output = ykman_dev()
        .args(["fido", "info"])
        .output()
        .expect("failed to run ykman fido info");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let initially_on = stdout.contains("Always Require UV: On");

    // Toggle
    ykman_dev()
        .args(["fido", "config", "toggle-always-uv", "--pin", FIDO_PIN])
        .assert()
        .success();

    // Verify it changed
    let expected = if initially_on {
        "Always Require UV: Off"
    } else {
        "Always Require UV: On"
    };
    ykman_dev()
        .args(["fido", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains(expected));

    // Toggle back
    ykman_dev()
        .args(["fido", "config", "toggle-always-uv", "--pin", FIDO_PIN])
        .assert()
        .success();

    // Verify restored
    let restored = if initially_on {
        "Always Require UV: On"
    } else {
        "Always Require UV: Off"
    };
    ykman_dev()
        .args(["fido", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains(restored));
}

// ── access (advanced, requires setMinPINLength) ───────────────────────

#[test]
#[ignore]
#[serial]
fn test_fido_access_set_min_pin_length() {
    require_interface!("FIDO");
    ensure_pin_set();

    // Read current minimum length
    let output = ykman_dev()
        .args(["fido", "info"])
        .output()
        .expect("failed to run ykman fido info");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let current_min: u32 = stdout
        .lines()
        .find(|l| l.starts_with("Minimum PIN length:"))
        .and_then(|l| l.split_whitespace().last())
        .and_then(|n| n.parse().ok())
        .unwrap_or(4);

    // Setting below current should fail
    if current_min > 4 {
        ykman_dev()
            .args([
                "fido",
                "access",
                "set-min-length",
                &(current_min - 1).to_string(),
                "--pin",
                FIDO_PIN,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Cannot set a minimum length shorter than",
            ));
    }

    // Setting to current value should succeed (no-op)
    ykman_dev()
        .args([
            "fido",
            "access",
            "set-min-length",
            &current_min.to_string(),
            "--pin",
            FIDO_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Minimum PIN length set."));
}

#[test]
#[ignore]
#[serial]
fn test_fido_access_force_change() {
    require_interface!("FIDO");
    ensure_pin_set();

    ykman_dev()
        .args(["fido", "access", "force-change", "--pin", FIDO_PIN])
        .assert()
        .success()
        .stdout(predicate::str::contains("Force PIN change set."));

    // PIN is now in force-change state; change to a new PIN to clear
    ykman_dev()
        .args([
            "fido",
            "access",
            "change-pin",
            "--pin",
            FIDO_PIN,
            "--new-pin",
            FIDO_PIN_2,
        ])
        .assert()
        .success();

    // Change back to original PIN
    ykman_dev()
        .args([
            "fido",
            "access",
            "change-pin",
            "--pin",
            FIDO_PIN_2,
            "--new-pin",
            FIDO_PIN,
        ])
        .assert()
        .success();
}
