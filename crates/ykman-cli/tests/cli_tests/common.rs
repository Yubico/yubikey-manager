#![allow(dead_code)]

use assert_cmd::Command;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};
use yubikit::management::UsbInterface;
use yubikit::platform::device::list_devices;

static SKIP_COUNT: AtomicUsize = AtomicUsize::new(0);
static PICO_CLEANUP_TARGETS: OnceLock<Mutex<Vec<(String, u8)>>> = OnceLock::new();
static REGISTER_PICO_CLEANUP: Once = Once::new();

extern "C" fn print_skip_summary() {
    let count = SKIP_COUNT.load(Ordering::Relaxed);
    if count > 0 {
        eprintln!("\x1b[1;33m{count} test(s) skipped\x1b[0m");
    }
}

pub fn record_skip() {
    static REGISTER: Once = Once::new();
    SKIP_COUNT.fetch_add(1, Ordering::Relaxed);
    REGISTER.call_once(|| unsafe {
        unsafe extern "C" {
            fn atexit(cb: extern "C" fn()) -> i32;
        }
        let _ = atexit(print_skip_summary);
    });
}

/// Test device configuration, resolved from environment variables.
///
/// Set `YUBIKEY_SERIAL` to the device serial number.
/// Set `YUBIKEY_SERIAL=-1` for devices without a serial number.
/// If not set, all device tests are skipped.
struct TestDevice {
    /// The serial string to pass to `--device`, or None for devices without a serial.
    serial: Option<String>,
    /// Whether a test device is configured (`YUBIKEY_SERIAL` is set).
    configured: bool,
}

fn test_device() -> &'static TestDevice {
    static DEVICE: OnceLock<TestDevice> = OnceLock::new();
    DEVICE.get_or_init(|| {
        register_pico_cleanup_if_configured();
        let raw = env::var("YUBIKEY_SERIAL")
            .or_else(|_| env::var("YKMAN_TEST_SERIAL"))
            .ok();
        let configured = raw.is_some();
        let serial = raw.and_then(resolve_device_serial);
        TestDevice { serial, configured }
    })
}

/// Validate the configured test device, if any, without requiring one.
pub fn validate_device_if_configured() {
    let _ = test_device();
}

fn resolve_device_serial(raw: String) -> Option<String> {
    if raw == "-1" {
        let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO)
            .expect("Failed to enumerate YubiKeys");
        let matching = devices
            .into_iter()
            .filter(|d| d.info().serial.is_none())
            .count();
        match matching {
            0 => panic!("No YubiKey without serial found"),
            1 => None,
            n => panic!("Multiple YubiKeys without serial found ({n}), cannot disambiguate"),
        }
    } else {
        let serial = raw
            .parse::<u32>()
            .expect("YUBIKEY_SERIAL must be a valid integer or -1");
        let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO)
            .expect("Failed to enumerate YubiKeys");
        if devices.into_iter().any(|d| d.info().serial == Some(serial)) {
            Some(raw)
        } else {
            panic!("No YubiKey found with serial {serial}")
        }
    }
}

/// Abort the test if no device is configured.
fn require_device() {
    if !test_device().configured {
        panic!(
            "No test device configured. Set YUBIKEY_SERIAL=<serial> \
             or YUBIKEY_SERIAL=-1 for devices without a serial."
        );
    }
}

/// Returns the configured serial number, if any.
pub fn device_serial() -> Option<&'static str> {
    test_device().serial.as_deref()
}

/// Returns true if a test device is configured.
pub fn device_configured() -> bool {
    test_device().configured
}

/// Returns true if testing a device without a serial number.
pub fn device_without_serial() -> bool {
    test_device().configured && test_device().serial.is_none()
}

fn wait_for_piv_info() {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if ykman_dev()
            .args(["piv", "info"])
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "YubiKey did not reappear after device reset"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub fn reset_blocked(capability: &str) -> bool {
    let args = match capability {
        "PIV" => ["piv", "info"],
        "FIDO" | "FIDO2" => ["fido", "info"],
        _ => return false,
    };
    ykman_dev().args(args).output().is_ok_and(|output| {
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("Factory reset is blocked")
    })
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

#[derive(Debug)]
pub struct TtyStatus {
    success: bool,
}

impl TtyStatus {
    pub fn success(&self) -> bool {
        self.success
    }
}

#[derive(Debug)]
pub struct TtyOutput {
    pub status: TtyStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run ykman under a pseudo-terminal so rpassword-backed prompts can be tested.
///
/// This is intended for hardware tests that need an interactive TTY.
pub fn ykman_dev_tty(args: &[&str], input: &str) -> TtyOutput {
    let bin = assert_cmd::cargo::cargo_bin("ykman");
    let mut command = CommandBuilder::new(bin);
    let dev = test_device();
    if let Some(ref serial) = dev.serial {
        command.arg("--device");
        command.arg(serial);
    }
    for arg in args {
        command.arg(arg);
    }

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("failed to open pseudo-terminal");
    let mut child = pair
        .slave
        .spawn_command(command)
        .expect("failed to spawn ykman in pseudo-terminal");
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .expect("failed to clone pseudo-terminal reader");
    let mut writer = pair
        .master
        .take_writer()
        .expect("failed to open pseudo-terminal writer");
    let reader_thread = std::thread::spawn(move || {
        let mut output = Vec::new();
        reader
            .read_to_end(&mut output)
            .expect("failed to read pseudo-terminal output");
        output
    });

    writer
        .write_all(input.as_bytes())
        .expect("failed to write prompt input");
    writer.flush().expect("failed to flush prompt input");
    drop(writer);

    let start = Instant::now();
    let exit_status = loop {
        if let Some(status) = child
            .try_wait()
            .expect("failed to wait for pseudo-terminal test")
        {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = reader_thread
                .join()
                .expect("failed to join pseudo-terminal reader thread");
            panic!("pseudo-terminal test timed out after 60s: {stdout:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    drop(pair.master);
    let stdout = reader_thread
        .join()
        .expect("failed to join pseudo-terminal reader thread");

    TtyOutput {
        status: TtyStatus {
            success: exit_status.success(),
        },
        stdout,
        stderr: Vec::new(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputMode {
    Arguments,
    Interactive,
}

impl InputMode {
    pub fn skip_if_windows(self) -> bool {
        if cfg!(windows) && self == Self::Interactive {
            record_skip();
            eprintln!("\x1b[1;33mSKIP:\x1b[0m interactive CLI tests are not supported on Windows");
            true
        } else {
            false
        }
    }

    pub fn is_interactive(self) -> bool {
        matches!(self, Self::Interactive)
    }
}

pub fn skip_interactive_on_windows() -> bool {
    if cfg!(windows) {
        record_skip();
        eprintln!("\x1b[1;33mSKIP:\x1b[0m interactive CLI tests are not supported on Windows");
        true
    } else {
        false
    }
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

pub fn piv_has_puk() -> bool {
    let output = ykman_dev()
        .args(["piv", "info"])
        .output()
        .expect("failed to run ykman piv info");
    if !output.status.success() {
        panic!(
            "failed to run ykman piv info: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("PUK tries remaining:"))
        .and_then(|tries| {
            let (_, total) = tries.trim().split_once('/')?;
            total.trim().parse::<u8>().ok()
        })
        .is_some_and(|total| total > 0)
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
    } else if device_version().is_some_and(|version| version >= (5, 4, 0)) {
        "aes192"
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
        record_skip();
        eprintln!("\x1b[1;33mSKIP:\x1b[0m {feature} is restricted or differs on FIPS YubiKeys");
        true
    } else {
        false
    }
}

pub fn skip_before_version(required: (u8, u8, u8), feature: &str) -> bool {
    let Some(version) = device_version() else {
        record_skip();
        eprintln!("\x1b[1;33mSKIP:\x1b[0m could not determine firmware version for {feature}");
        return true;
    };
    if version < required {
        record_skip();
        eprintln!("\x1b[1;33mSKIP:\x1b[0m {feature} requires {required:?}, device has {version:?}");
        true
    } else {
        false
    }
}

/// Returns true if the selected test device has the given capability enabled.
pub fn has_capability(name: &str) -> bool {
    let stdout = device_info();
    if stdout
        .lines()
        .any(|line| line.starts_with("Enabled USB interfaces:") && line.contains(name))
    {
        return true;
    }

    let app_name = match name {
        "FIDO" => "FIDO2",
        "OTP" => "Yubico OTP",
        other => other,
    };

    stdout
        .lines()
        .filter(|line| line.starts_with(app_name))
        .any(|line| line.split_whitespace().any(|field| field == "Enabled"))
}

/// Skip the current test with a formatted message.
#[macro_export]
macro_rules! skip {
    ($($arg:tt)*) => {{
        $crate::common::record_skip();
        eprintln!("\x1b[1;33mSKIP:\x1b[0m {}", format_args!($($arg)*));
        return;
    }};
}

/// Skip the test if the device does not have the given capability enabled.
#[macro_export]
macro_rules! require_capability {
    ($name:expr) => {
        if !$crate::common::device_configured() {
            skip!("YUBIKEY_SERIAL not set");
        }
        if !$crate::common::has_capability($name) {
            skip!("{} not enabled on device", $name);
        }
    };
}

/// Skip the test if no device is configured.
#[macro_export]
macro_rules! require_device_configured {
    () => {
        if !$crate::common::device_configured() {
            skip!("YUBIKEY_SERIAL not set");
        }
    };
}

/// Reset PIV to factory defaults (force, no prompt).
pub fn piv_reset_raw() {
    if reset_blocked("PIV") {
        ykman_dev()
            .args(["config", "reset", "-f"])
            .ok()
            .expect("YubiKey reset failed");
        wait_for_piv_info();
        return;
    }
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
        if piv_has_puk() {
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
        }
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
