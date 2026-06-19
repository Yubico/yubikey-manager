use super::common::{
    InputMode, app_is_fips_capable, device_serial, device_without_serial, ykman_dev, ykman_dev_tty,
};
use predicates::prelude::*;
use rstest::rstest;
use std::time::Duration;
use yubikit::core::Transport;
use yubikit::ctap::CtapSession;
use yubikit::ctap2::Ctap2Session;
use yubikit::management::{Capability, UsbInterface};
use yubikit::platform::device::{LocalYubiKeyDevice, list_devices};

// FIDO PIN-dependent tests reset the FIDO applet into a known state when a
// controller is configured. If the existing PIN is blocked or unknown and reset
// cannot be automated, those tests skip instead of consuming retries.

const FIDO_PIN: &str = "FidoPin1!";
const FIDO_PIN_2: &str = "FidoPin2!";

macro_rules! skip {
    ($($arg:tt)*) => {{
        eprintln!("SKIP: {}", format_args!($($arg)*));
        return;
    }};
}

/// Ensure a PIN is set on the device (idempotent).
fn ensure_pin_set() -> bool {
    use std::sync::OnceLock;
    static FIDO_PIN_READY: OnceLock<bool> = OnceLock::new();
    *FIDO_PIN_READY.get_or_init(setup_fido_pin)
}

fn setup_fido_pin() -> bool {
    let output = ykman_dev()
        .args(["fido", "info"])
        .output()
        .expect("failed to run ykman fido info");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("Not set") {
        return set_initial_pin();
    }

    if verify_pin(FIDO_PIN) {
        return true;
    }

    if !reset_fido_with_controller() {
        eprintln!("FIDO setup: existing PIN is unavailable and automated reset is unavailable");
        return false;
    }
    set_initial_pin()
}

fn verify_pin(pin: &str) -> bool {
    ykman_dev()
        .args(["fido", "access", "verify-pin", "--pin", pin])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn set_initial_pin() -> bool {
    let output = ykman_dev()
        .args(["fido", "access", "change-pin", "--new-pin", FIDO_PIN])
        .output()
        .expect("failed to set initial FIDO PIN");
    if output.status.success() {
        return true;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("policy") || stderr.contains("complexity") {
        eprintln!("SKIP: test FIDO PIN rejected by PIN policy: {stderr}");
        return false;
    }
    panic!("Failed to set initial FIDO PIN: {output:?}");
}

fn test_device() -> Option<LocalYubiKeyDevice> {
    let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO).ok()?;
    if device_without_serial() {
        let mut devices: Vec<_> = devices
            .into_iter()
            .filter(|device| device.info().serial.is_none())
            .collect();
        return (devices.len() == 1).then(|| devices.remove(0));
    }

    let serial = device_serial()?.parse::<u32>().ok()?;
    devices
        .into_iter()
        .find(|device| device.info().serial == Some(serial))
}

fn reset_fido_with_controller() -> bool {
    let Some(device) = test_device() else {
        eprintln!("FIDO setup: configured test device was not found");
        return false;
    };
    if device.transport() != Transport::Usb {
        eprintln!("FIDO setup: automated ykman FIDO reset currently requires USB");
        return false;
    }
    if device.info().reset_blocked.contains(Capability::FIDO2) {
        eprintln!("FIDO setup: FIDO reset is blocked by device configuration");
        return false;
    }

    let Ok(controller) = std::env::var("CONTROLLER") else {
        eprintln!("FIDO setup: set CONTROLLER to reset a key with an existing or blocked PIN");
        return false;
    };
    if controller.eq_ignore_ascii_case("interactive") {
        eprintln!("FIDO setup: interactive controller is not supported for automated reset");
        return false;
    }

    let base_url = controller.trim_end_matches('/').to_string();
    let port = std::env::var("PICO_PORT")
        .ok()
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(6);
    let get = |path: &str| {
        let url = format!("{base_url}/usb{port}/{path}");
        eprintln!("PicoController: GET {url}");
        ureq::get(&url)
            .call()
            .unwrap_or_else(|e| panic!("PicoController request failed: {url}: {e}"));
    };

    get("touch/off");
    get("power/off");
    get("power/on");
    std::thread::sleep(Duration::from_millis(2_000));

    let Some(device) = test_device() else {
        eprintln!("FIDO setup: device did not re-enumerate after reset power cycle");
        return false;
    };
    let conn = device.open_fido().expect("open FIDO HID after power cycle");
    let ctap = CtapSession::new_fido(conn)
        .map_err(|(e, _)| e)
        .expect("CtapSession::new_fido");
    let mut session = Ctap2Session::new(ctap)
        .map_err(|(e, _)| e)
        .expect("Ctap2Session::new");
    let info = session.get_info().expect("get_info");
    if !info.transports_for_reset.is_empty()
        && !info
            .transports_for_reset
            .iter()
            .any(|transport| transport.eq_ignore_ascii_case("usb"))
    {
        eprintln!(
            "FIDO setup: reset is not allowed over USB (transports_for_reset={:?})",
            info.transports_for_reset
        );
        return false;
    }

    if info.long_touch_for_reset {
        get("touch/on");
    }
    let result = session.reset(
        Some(&mut |status| {
            if status == 0x02 && !info.long_touch_for_reset {
                get("touch/off");
                std::thread::sleep(Duration::from_millis(200));
                get("touch/on");
            }
        }),
        None,
    );
    get("touch/off");

    match result {
        Ok(()) => true,
        Err(e) => {
            eprintln!("FIDO setup: reset failed: {e}");
            false
        }
    }
}

fn require_pin_set() {
    if !ensure_pin_set() {
        skip!("FIDO PIN setup unavailable");
    }
}

fn pin_retries() -> Option<u32> {
    let output = ykman_dev()
        .args(["fido", "info"])
        .output()
        .expect("failed to run ykman fido info");
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("PIN:"))
            .and_then(|status| status.split_whitespace().next())
            .and_then(|retries| retries.parse().ok());
    }
    None
}

fn restore_pin_if_needed() {
    let output = ykman_dev()
        .args(["fido", "access", "verify-pin", "--pin", FIDO_PIN])
        .output()
        .expect("failed to verify restored FIDO PIN");
    if output.status.success() {
        return;
    }

    let _ = ykman_dev()
        .args([
            "fido",
            "access",
            "change-pin",
            "--pin",
            FIDO_PIN_2,
            "--new-pin",
            FIDO_PIN,
        ])
        .ok();
}

struct FidoPinGuard;

impl Drop for FidoPinGuard {
    fn drop(&mut self) {
        restore_pin_if_needed();
    }
}

fn fido_pin_guard() -> FidoPinGuard {
    FidoPinGuard
}

// ── info ──────────────────────────────────────────────────────────────

#[test]
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

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_fido_verify_pin(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_interface!("FIDO");
    require_pin_set();
    if mode.is_interactive() {
        let output = ykman_dev_tty(&["fido", "access", "verify-pin"], &format!("{FIDO_PIN}\n"));
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("PIN verified."),
            "{output:?}"
        );
    } else {
        ykman_dev()
            .args(["fido", "access", "verify-pin", "--pin", FIDO_PIN])
            .assert()
            .success()
            .stdout(predicate::str::contains("PIN verified."));
    }
}

#[test]
fn test_fido_verify_pin_wrong() {
    require_interface!("FIDO");
    require_pin_set();
    if pin_retries().is_some_and(|retries| retries <= 1) {
        skip!("not enough FIDO PIN retries for wrong-PIN test");
    }
    ykman_dev()
        .args(["fido", "access", "verify-pin", "--pin", "wrongpin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Wrong PIN"));
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_fido_change_pin(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_interface!("FIDO");
    require_pin_set();
    let _guard = fido_pin_guard();

    // Change PIN
    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["fido", "access", "change-pin"],
            &format!("{FIDO_PIN}\n{FIDO_PIN_2}\n{FIDO_PIN_2}\n"),
        );
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("PIN has been changed."),
            "{output:?}"
        );
    } else {
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
    }

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
fn test_fido_set_pin_too_short() {
    require_interface!("FIDO");
    require_pin_set();
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

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_fido_credentials_list_empty(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_interface!("FIDO");
    require_pin_set();
    if mode.is_interactive() {
        let output = ykman_dev_tty(&["fido", "credentials", "list"], &format!("{FIDO_PIN}\n"));
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("No discoverable credentials."),
            "{output:?}"
        );
    } else {
        ykman_dev()
            .args(["fido", "credentials", "list", "--pin", FIDO_PIN])
            .assert()
            .success()
            .stdout(predicate::str::contains("No discoverable credentials."));
    }
}

// ── config ────────────────────────────────────────────────────────────

#[test]
fn test_fido_config_toggle_always_uv() {
    require_interface!("FIDO");
    require_pin_set();

    // Check initial state
    let output = ykman_dev()
        .args(["fido", "info"])
        .output()
        .expect("failed to run ykman fido info");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let initially_on = stdout.contains("Always Require UV: On");

    if app_is_fips_capable("FIDO2") && initially_on {
        ykman_dev()
            .args(["fido", "config", "toggle-always-uv", "--pin", FIDO_PIN])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Always Require UV cannot be disabled",
            ));
        return;
    }

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

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_fido_access_set_min_pin_length(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_interface!("FIDO");
    require_pin_set();

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
    if mode.is_interactive() {
        let min = current_min.to_string();
        let output = ykman_dev_tty(
            &["fido", "access", "set-min-length", &min],
            &format!("{FIDO_PIN}\n"),
        );
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Minimum PIN length set."),
            "{output:?}"
        );
    } else {
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
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_fido_access_force_change(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_interface!("FIDO");
    require_pin_set();
    let _guard = fido_pin_guard();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["fido", "access", "force-change"],
            &format!("{FIDO_PIN}\n"),
        );
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Force PIN change set."),
            "{output:?}"
        );
    } else {
        ykman_dev()
            .args(["fido", "access", "force-change", "--pin", FIDO_PIN])
            .assert()
            .success()
            .stdout(predicate::str::contains("Force PIN change set."));
    }

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
