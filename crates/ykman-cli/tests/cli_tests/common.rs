#![allow(dead_code)]

use assert_cmd::Command;
use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Output, Stdio};
use std::sync::{Mutex, Once, OnceLock};

static PICO_CLEANUP_TARGETS: OnceLock<Mutex<Vec<(String, u8)>>> = OnceLock::new();
static REGISTER_PICO_CLEANUP: Once = Once::new();

/// Test device configuration, resolved from environment variables.
///
/// Set `YUBIKEY_SERIAL` for testing with a known serial.
/// Set `YUBIKEY_NO_SERIAL=1` for devices without a serial number.
/// If neither is set, all device tests abort.
struct TestDevice {
    serial: Option<String>,
    no_serial: bool,
}

fn test_device() -> &'static TestDevice {
    static DEVICE: OnceLock<TestDevice> = OnceLock::new();
    DEVICE.get_or_init(|| {
        register_pico_cleanup_if_configured();
        TestDevice {
            serial: env::var("YUBIKEY_SERIAL")
                .or_else(|_| env::var("YKMAN_TEST_SERIAL"))
                .ok(),
            no_serial: env::var("YUBIKEY_NO_SERIAL").is_ok()
                || env::var("YKMAN_TEST_NO_SERIAL").is_ok(),
        }
    })
}

/// Abort the test if no device is configured.
fn require_device() {
    let dev = test_device();
    if dev.serial.is_none() && !dev.no_serial {
        panic!(
            "No test device configured. Set YUBIKEY_SERIAL=<serial> \
             or YUBIKEY_NO_SERIAL=1 to run device tests."
        );
    }
}

/// Returns the configured serial number, if any.
pub fn device_serial() -> Option<&'static str> {
    test_device().serial.as_deref()
}

/// Returns true if a test device is configured.
pub fn device_configured() -> bool {
    let dev = test_device();
    dev.serial.is_some() || dev.no_serial
}

/// Returns true if testing a device without a serial number.
pub fn device_without_serial() -> bool {
    test_device().no_serial
}

// PIV defaults
pub const DEFAULT_PIN: &str = "123456";
pub const NON_DEFAULT_PIN: &str = "12341235";
pub const DEFAULT_PUK: &str = "12345678";
pub const NON_DEFAULT_PUK: &str = "12341236";
pub const DEFAULT_MANAGEMENT_KEY: &str = "010203040506070801020304050607080102030405060708";
pub const NON_DEFAULT_MANAGEMENT_KEY: &str = "010103040506070801020304050607080102030405060708";
pub const FIPS_PIV_PIN: &str = "97463218";
pub const FIPS_PIV_PIN_2: &str = "68352749";
pub const FIPS_PIV_PUK: &str = "83726145";
pub const FIPS_PIV_PUK_2: &str = "58274936";
pub const FIPS_PIV_MANAGEMENT_KEY: &str = "0102030405060708090a0b0c0d0e0f10";
pub const FIPS_PIV_MANAGEMENT_KEY_2: &str = "100f0e0d0c0b0a090807060504030201";

// OpenPGP defaults
pub const DEFAULT_OPENPGP_PIN: &str = "123456";
pub const NON_DEFAULT_OPENPGP_PIN: &str = "12345679";
pub const DEFAULT_OPENPGP_ADMIN_PIN: &str = "12345678";
pub const NON_DEFAULT_OPENPGP_ADMIN_PIN: &str = "12345670";
pub const FIPS_OPENPGP_PIN: &str = "97463218";
pub const FIPS_OPENPGP_PIN_2: &str = "68352749";
pub const FIPS_OPENPGP_ADMIN_PIN: &str = "8372614597";
pub const FIPS_OPENPGP_ADMIN_PIN_2: &str = "9583726140";
pub const FIPS_OPENPGP_RESET_CODE: &str = "5839472618";

// OATH
pub const OATH_PASSWORD: &str = "N9!aR4#sT7$vX2%q";

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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Run ykman under a pseudo-terminal so rpassword-backed prompts can be tested.
///
/// This is intended for ignored hardware tests. It uses the POSIX `script`
/// command, which is available on the Linux hardware-test hosts.
pub fn ykman_dev_tty(args: &[&str], input: &str) -> Output {
    let bin = assert_cmd::cargo::cargo_bin("ykman");
    let mut command = shell_quote(&bin.display().to_string());
    let dev = test_device();
    if let Some(ref serial) = dev.serial {
        command.push_str(" --device ");
        command.push_str(&shell_quote(serial));
    }
    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }

    let mut child = StdCommand::new("script")
        .args(["-qfec", &command, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn script(1) for pseudo-terminal test");
    child
        .stdin
        .as_mut()
        .expect("script stdin must be piped")
        .write_all(input.as_bytes())
        .expect("failed to write prompt input");
    child
        .wait_with_output()
        .expect("failed to wait for pseudo-terminal test")
}

extern "C" fn cleanup_pico_touch() {
    if let Some(targets) = PICO_CLEANUP_TARGETS.get()
        && let Ok(targets) = targets.lock()
    {
        for (base_url, port) in targets.iter() {
            let url = format!("{base_url}/usb{port}/touch/off");
            eprintln!("PicoController cleanup: GET {url}");
            let _ = ureq::get(&url).call();
        }
    }
}

fn register_pico_cleanup_if_configured() {
    let Ok(controller) = env::var("CONTROLLER") else {
        return;
    };
    if controller.eq_ignore_ascii_case("interactive") {
        return;
    }

    let base_url = controller.trim_end_matches('/').to_string();
    let port = env::var("PICO_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);

    let targets = PICO_CLEANUP_TARGETS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut targets) = targets.lock() {
        let target = (base_url, port);
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    REGISTER_PICO_CLEANUP.call_once(|| unsafe {
        unsafe extern "C" {
            fn atexit(cb: extern "C" fn()) -> i32;
        }
        let _ = atexit(cleanup_pico_touch);
    });
}

/// Cached `ykman info` output for skip decisions.
pub fn device_info() -> &'static str {
    static INFO: OnceLock<String> = OnceLock::new();
    INFO.get_or_init(|| {
        let output = ykman_dev()
            .arg("info")
            .output()
            .expect("failed to run ykman info");
        if !output.status.success() {
            panic!(
                "failed to run ykman info: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        String::from_utf8_lossy(&output.stdout).into_owned()
    })
}

pub fn device_version() -> Option<(u8, u8, u8)> {
    device_info()
        .lines()
        .find_map(|line| line.strip_prefix("Firmware version:"))
        .and_then(|version| {
            let mut parts = version.trim().split('.').filter_map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u8>()
                    .ok()
            });
            Some((parts.next()?, parts.next()?, parts.next()?))
        })
}

pub fn is_fips() -> bool {
    device_info().contains("FIPS")
}

pub fn app_is_fips_capable(app: &str) -> bool {
    let marker = format!("  {app}:");
    device_info()
        .lines()
        .skip_while(|line| *line != "FIPS approved applications")
        .any(|line| line.starts_with(&marker))
}

pub fn piv_pin() -> &'static str {
    if app_is_fips_capable("PIV") {
        FIPS_PIV_PIN
    } else {
        DEFAULT_PIN
    }
}

pub fn piv_new_pin() -> &'static str {
    if app_is_fips_capable("PIV") {
        FIPS_PIV_PIN_2
    } else {
        NON_DEFAULT_PIN
    }
}

pub fn piv_puk() -> &'static str {
    if app_is_fips_capable("PIV") {
        FIPS_PIV_PUK
    } else {
        DEFAULT_PUK
    }
}

pub fn piv_new_puk() -> &'static str {
    if app_is_fips_capable("PIV") {
        FIPS_PIV_PUK_2
    } else {
        NON_DEFAULT_PUK
    }
}

pub fn piv_management_key() -> &'static str {
    if app_is_fips_capable("PIV") {
        FIPS_PIV_MANAGEMENT_KEY
    } else {
        DEFAULT_MANAGEMENT_KEY
    }
}

pub fn piv_new_management_key() -> &'static str {
    if app_is_fips_capable("PIV") {
        FIPS_PIV_MANAGEMENT_KEY_2
    } else {
        NON_DEFAULT_MANAGEMENT_KEY
    }
}

pub fn piv_management_key_algorithm() -> &'static str {
    if app_is_fips_capable("PIV") {
        "aes128"
    } else {
        "tdes"
    }
}

pub fn openpgp_pin() -> &'static str {
    if app_is_fips_capable("OpenPGP") {
        FIPS_OPENPGP_PIN
    } else {
        DEFAULT_OPENPGP_PIN
    }
}

pub fn openpgp_new_pin() -> &'static str {
    if app_is_fips_capable("OpenPGP") {
        FIPS_OPENPGP_PIN_2
    } else {
        NON_DEFAULT_OPENPGP_PIN
    }
}

pub fn openpgp_admin_pin() -> &'static str {
    if app_is_fips_capable("OpenPGP") {
        FIPS_OPENPGP_ADMIN_PIN
    } else {
        DEFAULT_OPENPGP_ADMIN_PIN
    }
}

pub fn openpgp_new_admin_pin() -> &'static str {
    if app_is_fips_capable("OpenPGP") {
        FIPS_OPENPGP_ADMIN_PIN_2
    } else {
        NON_DEFAULT_OPENPGP_ADMIN_PIN
    }
}

pub fn openpgp_reset_code() -> &'static str {
    if app_is_fips_capable("OpenPGP") {
        FIPS_OPENPGP_RESET_CODE
    } else {
        NON_DEFAULT_OPENPGP_PIN
    }
}

pub fn skip_if_fips(feature: &str) -> bool {
    if is_fips() {
        eprintln!("SKIP: {feature} is restricted or differs on FIPS YubiKeys");
        true
    } else {
        false
    }
}

pub fn skip_before_version(required: (u8, u8, u8), feature: &str) -> bool {
    let Some(version) = device_version() else {
        eprintln!("SKIP: could not determine firmware version for {feature}");
        return true;
    };
    if version < required {
        eprintln!("SKIP: {feature} requires {required:?}, device has {version:?}");
        true
    } else {
        false
    }
}

/// Returns true if the device has the given USB interface enabled.
pub fn has_usb_interface(name: &str) -> bool {
    let stdout = device_info();
    // Look for the interface name in the "Enabled USB interfaces:" line
    stdout
        .lines()
        .any(|line| line.starts_with("Enabled USB interfaces:") && line.contains(name))
        || (name == "CCID" && stdout.contains("Applications"))
}

/// Skip the test if the device does not have the given USB interface enabled.
#[macro_export]
macro_rules! require_interface {
    ($name:expr) => {
        if !$crate::common::device_configured() {
            eprintln!("SKIP: YUBIKEY_SERIAL or YUBIKEY_NO_SERIAL not set");
            return;
        }
        if !$crate::common::has_usb_interface($name) {
            eprintln!("SKIP: {} not enabled on device", $name);
            return;
        }
    };
}

/// Skip the test if no device is configured.
#[macro_export]
macro_rules! require_device_configured {
    () => {
        if !$crate::common::device_configured() {
            eprintln!("SKIP: YUBIKEY_SERIAL or YUBIKEY_NO_SERIAL not set");
            return;
        }
    };
}

/// Reset PIV to factory defaults (force, no prompt).
pub fn piv_reset_raw() {
    ykman_dev()
        .args(["piv", "reset", "-f"])
        .ok()
        .expect("PIV reset failed");
}

/// Reset PIV and, on FIPS-capable keys, perform the personalization required
/// to bring the application into FIPS approved mode.
pub fn piv_reset() {
    piv_reset_raw();
    if app_is_fips_capable("PIV") {
        ykman_dev()
            .args([
                "piv",
                "access",
                "change-pin",
                "--pin",
                DEFAULT_PIN,
                "--new-pin",
                FIPS_PIV_PIN,
            ])
            .assert()
            .success();
        ykman_dev()
            .args([
                "piv",
                "access",
                "change-puk",
                "--puk",
                DEFAULT_PUK,
                "--new-puk",
                FIPS_PIV_PUK,
            ])
            .assert()
            .success();
        ykman_dev()
            .args([
                "piv",
                "access",
                "change-management-key",
                "--management-key",
                DEFAULT_MANAGEMENT_KEY,
                "--new-management-key",
                FIPS_PIV_MANAGEMENT_KEY,
                "--algorithm",
                "aes128",
                "-f",
            ])
            .assert()
            .success();
    }
}

/// Reset OATH to factory defaults.
pub fn oath_reset_raw() {
    ykman_dev()
        .args(["oath", "reset", "-f"])
        .ok()
        .expect("OATH reset failed");
}

pub fn oath_reset() {
    oath_reset_raw();
}

/// Reset OpenPGP to factory defaults.
pub fn openpgp_reset_raw() {
    ykman_dev()
        .args(["openpgp", "reset", "-f"])
        .ok()
        .expect("OpenPGP reset failed");
}

pub fn openpgp_reset() {
    openpgp_reset_raw();
    if app_is_fips_capable("OpenPGP") {
        ykman_dev()
            .args([
                "openpgp",
                "access",
                "change-pin",
                "--pin",
                DEFAULT_OPENPGP_PIN,
                "--new-pin",
                FIPS_OPENPGP_PIN,
            ])
            .assert()
            .success();
        ykman_dev()
            .args([
                "openpgp",
                "access",
                "change-admin-pin",
                "--admin-pin",
                DEFAULT_OPENPGP_ADMIN_PIN,
                "--new-admin-pin",
                FIPS_OPENPGP_ADMIN_PIN,
            ])
            .assert()
            .success();
    }
}

/// Reset HSMAuth to factory defaults.
pub fn hsmauth_reset_raw() {
    ykman_dev()
        .args(["hsmauth", "reset", "-f"])
        .ok()
        .expect("HSMAuth reset failed");
}

pub fn hsmauth_reset() {
    hsmauth_reset_raw();
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
