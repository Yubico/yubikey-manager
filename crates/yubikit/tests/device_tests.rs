//! Integration tests that run against a real YubiKey.
//!
//! These tests require a YubiKey to be connected and the `YUBIKEY_SERIAL`
//! environment variable to be set to the device's serial number.
//! For devices without a serial, use `YUBIKEY_SERIAL=-1`.
//!
//! The device is found automatically whether it is connected over USB or NFC.
//!
//! ```sh
//! YUBIKEY_SERIAL=12345678 cargo test -p yubikit --test device_tests -- --test-threads=1
//! YUBIKEY_SERIAL=-1 cargo test -p yubikit --test device_tests -- --test-threads=1
//! ```
//!
//! **WARNING**: Some tests are destructive (they reset applications).
//! Only run against a test/development YubiKey.

#[path = "device_tests/arkg_p256.rs"]
mod arkg_p256;
#[path = "device_tests/controller.rs"]
mod controller;

use rstest::{fixture, rstest};
use std::sync::{Mutex, OnceLock, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};
use yubikit::core::Transport;
use yubikit::core::{Version, set_override_version};
use yubikit::device::ReinsertStatus;
use yubikit::management::{Capability, DeviceInfo, ManagementSession, ReleaseType, UsbInterface};
use yubikit::platform::device::{LocalYubiKeyDevice, list_devices};
use yubikit::platform::pcsc::PcscSmartCardConnection;
use yubikit::securitydomain::SecurityDomainSession;
use yubikit::smartcard::Aid;

/// Check if an error's Display contains an APDU status word.
/// Works across error wrappers (PivError, OathError, etc.) since they all
/// display the underlying SmartCardError::Apdu { sw } in their chain.
fn has_sw(e: &dyn std::fmt::Display, sw: u16) -> bool {
    e.to_string().contains(&format!("0x{sw:04X}"))
}

// ───────────────────────── Connection Parameterization ─────────────────────────

#[derive(Debug, Clone)]
enum TestConnection {
    /// SmartCard (CCID/NFC) — runs over whichever transport the device uses.
    SmartCard,
    /// SmartCard with SCP11b — skipped if SCP11b is not available on the device.
    SmartCardScp11b,
    /// USB HID — requires the device to be on USB with the OTP/FIDO HID interface.
    UsbHid,
}

macro_rules! skip_if_needed {
    ($tc:expr) => {
        if let Some(reason) = should_skip(&$tc) {
            skip!("{:?}: {}", $tc, reason);
        }
    };
}

/// Skip the current test with a printed reason.
macro_rules! skip {
    ($($arg:tt)*) => {{
        eprintln!("\x1b[1;33mSKIP:\x1b[0m {}", format_args!($($arg)*));
        return;
    }};
}

// ───────────────────────── Device ─────────────────────────

/// Cached device — resolved once and reused across all tests.
/// Uses RwLock to allow `reinsert` to update device state after power cycling.
static DEVICE: OnceLock<RwLock<LocalYubiKeyDevice>> = OnceLock::new();

/// Whether the device supports SCP11b (version >= 5.7.2).
static SCP11B_SUPPORTED: OnceLock<bool> = OnceLock::new();

/// Cached SCP11b parameters: (kid, kvn, pk_sd_ecka).
/// Uses Mutex so it can be invalidated after SD reset tests.
static SCP11B_PARAMS: Mutex<Option<Option<(u8, u8, Vec<u8>)>>> = Mutex::new(None);

fn required_serial() -> Option<u32> {
    let s = std::env::var("YUBIKEY_SERIAL").expect(
        "Set YUBIKEY_SERIAL to the device serial, or YUBIKEY_SERIAL=-1 for devices without one.\n\
         Example: YUBIKEY_SERIAL=12345678 cargo test -p yubikit --test device_tests",
    );
    match s.as_str() {
        "-1" => None,
        _ => Some(
            s.parse()
                .expect("YUBIKEY_SERIAL must be a valid integer or -1"),
        ),
    }
}

fn get_device() -> RwLockReadGuard<'static, LocalYubiKeyDevice> {
    DEVICE
        .get_or_init(|| {
            let serial = required_serial();
            let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO)
                .expect("Failed to enumerate YubiKeys");

            let dev = match serial {
                Some(s) => devices
                    .into_iter()
                    .find(|d| d.info().serial == Some(s))
                    .unwrap_or_else(|| panic!("No YubiKey found with serial {s}")),
                None => {
                    let mut devs: Vec<_> = devices
                        .into_iter()
                        .filter(|d| d.info().serial.is_none())
                        .collect();
                    match devs.len() {
                        0 => panic!("No YubiKey without serial found"),
                        1 => devs.remove(0),
                        n => {
                            panic!(
                                "Multiple YubiKeys without serial found ({n}), cannot disambiguate"
                            )
                        }
                    }
                }
            };

            if dev.info().version_qualifier.release_type != ReleaseType::Final {
                set_override_version(dev.info().version);
            }

            set_touch_threshold(&dev);

            RwLock::new(dev)
        })
        .read()
        .unwrap()
}

fn refresh_device_after_reset() {
    let serial = required_serial();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO)
            .unwrap_or_default();
        let found = match serial {
            Some(s) => devices.into_iter().find(|d| d.info().serial == Some(s)),
            None => {
                let mut devs: Vec<_> = devices
                    .into_iter()
                    .filter(|d| d.info().serial.is_none())
                    .collect();
                (devs.len() == 1).then(|| devs.remove(0))
            }
        };
        if let Some(dev) = found
            && dev.open_smartcard().is_ok()
        {
            if let Some(lock) = DEVICE.get() {
                *lock.write().unwrap() = dev;
            }
            invalidate_scp11b_params();
            return;
        }
        assert!(
            Instant::now() < deadline,
            "YubiKey did not reappear after device reset"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn set_touch_threshold(dev: &LocalYubiKeyDevice) {
    if let Ok(hex_str) = std::env::var("TOUCH") {
        match u8::from_str_radix(&hex_str, 16) {
            Ok(hex_val) => {
                let conn = dev.open_smartcard().expect("TOUCH needs CCID");
                let mut proto = yubikit::smartcard::SmartCardProtocol::new(conn);
                proto
                    .select(Aid::MANAGEMENT)
                    .expect("select management for TOUCH");
                proto
                    .send_apdu(0, 0x1c, 0, 0, &[0x03, 0x085, 0x01, hex_val])
                    .expect("send TOUCH APDU");
                eprintln!("Set touch level to: 0x{:02X}", hex_val);
            }
            Err(_) => {
                eprintln!("Error: '{}' is not a valid hex string.", hex_str);
            }
        }
    }
}

/// Extract an uncompressed P-256 public key (65 bytes) from a DER-encoded certificate.
fn extract_ec_p256_pubkey(cert_der: &[u8]) -> Option<Vec<u8>> {
    // BIT STRING containing uncompressed P-256 point: 03 42 00 04 <64 bytes>
    for i in 0..cert_der.len().saturating_sub(67) {
        if cert_der[i] == 0x03
            && cert_der[i + 1] == 0x42
            && cert_der[i + 2] == 0x00
            && cert_der[i + 3] == 0x04
        {
            return Some(cert_der[i + 3..i + 3 + 65].to_vec());
        }
    }
    None
}

fn detect_scp11b_params(conn: PcscSmartCardConnection) -> Option<(u8, u8, Vec<u8>)> {
    let mut sd = SecurityDomainSession::new(conn).ok()?;
    let key_info = sd.get_key_information().ok()?;
    let key_ref = *key_info.keys().find(|kr| kr.kid == 0x13)?;
    let certs = sd.get_certificate_bundle(key_ref).ok()?;
    let last_cert = certs.last()?;
    let pk = extract_ec_p256_pubkey(last_cert)?;
    Some((key_ref.kid, key_ref.kvn, pk))
}

fn scp11b_supported() -> bool {
    *SCP11B_SUPPORTED.get_or_init(|| get_device().info().version >= Version(5, 7, 2))
}

fn get_scp11b_params() -> Option<(u8, u8, Vec<u8>)> {
    let mut cached = SCP11B_PARAMS.lock().unwrap();
    if let Some(ref params) = *cached {
        return params.clone();
    }
    if !scp11b_supported() {
        *cached = Some(None);
        return None;
    }
    let conn = get_device()
        .open_smartcard()
        .expect("open smartcard for SCP11b detection");
    let result = detect_scp11b_params(conn);
    *cached = Some(result.clone());
    result
}

fn invalidate_scp11b_params() {
    *SCP11B_PARAMS.lock().unwrap() = None;
}

fn open_smartcard_connection(tc: &TestConnection) -> PcscSmartCardConnection {
    assert!(
        !matches!(tc, TestConnection::UsbHid),
        "UsbHid is not a smartcard connection"
    );
    get_device().open_smartcard().expect("open smartcard")
}

fn scp_params(tc: &TestConnection) -> Option<(u8, u8, Vec<u8>)> {
    match tc {
        TestConnection::SmartCardScp11b => get_scp11b_params(),
        _ => None,
    }
}

fn should_skip(tc: &TestConnection) -> Option<String> {
    if std::env::var("YUBIKEY_SERIAL").is_err() {
        return Some("YUBIKEY_SERIAL not set".into());
    }

    let dev = get_device();

    match tc {
        TestConnection::SmartCard => {
            // FIPS keys (FW >= 5.7) block sensitive operations over NFC without SCP
            if dev.info().is_fips && dev.transport() == Transport::Nfc {
                return Some("FIPS key requires SCP over NFC".into());
            }
            if dev.transport() == Transport::Usb {
                let enabled_usb = dev
                    .info()
                    .config
                    .enabled_capabilities
                    .get(&Transport::Usb)
                    .copied()
                    .unwrap_or(Capability::NONE);
                let ccid_apps =
                    Capability::PIV | Capability::OATH | Capability::OPENPGP | Capability::HSMAUTH;
                if (enabled_usb & ccid_apps).is_empty() {
                    return Some("CCID not enabled over USB".into());
                }
            }
            None
        }
        TestConnection::SmartCardScp11b => {
            if dev.transport() == Transport::Usb {
                let enabled_usb = dev
                    .info()
                    .config
                    .enabled_capabilities
                    .get(&Transport::Usb)
                    .copied()
                    .unwrap_or(Capability::NONE);
                let ccid_apps =
                    Capability::PIV | Capability::OATH | Capability::OPENPGP | Capability::HSMAUTH;
                if (enabled_usb & ccid_apps).is_empty() {
                    return Some("CCID not enabled over USB".into());
                }
            }
            if get_scp11b_params().is_none() {
                return Some("SCP11b not available on device".into());
            }
            None
        }
        TestConnection::UsbHid => {
            if dev.transport() != Transport::Usb {
                return Some("UsbHid requires USB transport".into());
            }
            let enabled_usb = dev
                .info()
                .config
                .enabled_capabilities
                .get(&Transport::Usb)
                .copied()
                .unwrap_or(Capability::NONE);
            if !enabled_usb.contains(Capability::OTP) {
                Some("OTP not enabled over USB".into())
            } else {
                None
            }
        }
    }
}

/// Returns the transport of the device under test.
fn device_transport() -> Transport {
    get_device().transport()
}

/// Fixture providing the device info (cached via OnceLock).
#[fixture]
fn device_info() -> &'static DeviceInfo {
    static INFO: OnceLock<DeviceInfo> = OnceLock::new();
    INFO.get_or_init(|| get_device().info().clone())
}

/// Fixture providing device capabilities for the active transport.
#[fixture]
fn capabilities(device_info: &DeviceInfo) -> Capability {
    device_info
        .config
        .enabled_capabilities
        .get(&device_transport())
        .copied()
        .unwrap_or(Capability::NONE)
}

fn device_capabilities() -> Capability {
    let dev = get_device();
    dev.info()
        .config
        .enabled_capabilities
        .get(&dev.transport())
        .copied()
        .unwrap_or(Capability::NONE)
}

fn device_version() -> Version {
    get_device().info().version
}

fn device_is_fips() -> bool {
    get_device().info().is_fips
}

fn device_is_fips_capable(capability: Capability) -> bool {
    get_device().info().fips_capable.contains(capability)
}

fn device_has_pin_complexity() -> bool {
    get_device().info().pin_complexity
}

macro_rules! require_capability {
    ($cap:expr) => {
        if !device_capabilities().contains($cap) {
            skip!("device does not support {:?}", stringify!($cap));
        }
    };
}

macro_rules! require_version {
    ($min:expr) => {
        if device_version() < $min {
            skip!("device version {:?} < {:?}", device_version(), $min);
        }
    };
}

macro_rules! require_transport {
    ($transport:expr) => {
        if std::env::var("YUBIKEY_SERIAL").is_err() {
            skip!("YUBIKEY_SERIAL not set");
        }
        if device_transport() != $transport {
            skip!("test requires {:?}", $transport);
        }
    };
}

/// Build SCP11b key params for test helper usage.
fn make_scp_key_params(kid: u8, kvn: u8, pk: &[u8]) -> yubikit::smartcard::ScpKeyParams {
    yubikit::smartcard::ScpKeyParams::Scp11b {
        kid,
        kvn,
        pk_sd_ecka: pk.to_vec(),
    }
}

// ───────────────────────── Device / Management ─────────────────────────

#[test]
fn test_list_devices_finds_key() {
    if std::env::var("YUBIKEY_SERIAL").is_err() {
        skip!("YUBIKEY_SERIAL not set");
    }
    require_transport!(Transport::Usb);
    let serial = required_serial();
    let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO)
        .expect("list_devices");
    match serial {
        Some(s) => assert!(
            devices.iter().any(|d| d.info().serial == Some(s)),
            "Expected YubiKey with serial {s} in device list"
        ),
        None => assert!(
            devices.iter().any(|d| d.info().serial.is_none()),
            "Expected YubiKey without serial in device list"
        ),
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_management_read_device_info(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 1, 0));
    match tc {
        TestConnection::UsbHid => {
            require_transport!(Transport::Usb);
            let conn = get_device().open_otp().expect("open OTP");
            let mut session = ManagementSession::new_otp(conn).expect("ManagementSession::new_otp");
            match session.read_device_info() {
                Ok(info) => assert_eq!(info.serial, required_serial()),
                Err(e) if e.to_string().contains("No data") => {
                    skip!("Management read_device_info not supported over OTP HID on this key");
                }
                Err(e) => panic!("read_device_info: {e}"),
            }
        }
        _ => {
            let conn = open_smartcard_connection(&tc);
            let mut session = if let Some((kid, kvn, ref pk)) = scp_params(&tc) {
                let params = make_scp_key_params(kid, kvn, pk);
                ManagementSession::new_with_scp(conn, &params).expect("ManagementSession with SCP")
            } else {
                ManagementSession::new(conn).expect("ManagementSession::new (CCID)")
            };
            let info = session.read_device_info().expect("read_device_info");
            assert_eq!(info.serial, required_serial());
        }
    }
}

#[test]
fn test_management_device_info_capabilities() {
    if std::env::var("YUBIKEY_SERIAL").is_err() {
        skip!("YUBIKEY_SERIAL not set");
    }
    let caps = device_capabilities();
    // Every YubiKey has at least one capability on its active transport
    assert!(
        !caps.is_empty(),
        "Expected at least one capability on active transport"
    );
}

#[path = "device_tests/fido.rs"]
mod fido;
#[path = "device_tests/hsmauth.rs"]
mod hsmauth;
#[path = "device_tests/oath.rs"]
mod oath;
#[path = "device_tests/openpgp.rs"]
mod openpgp;
#[path = "device_tests/piv.rs"]
mod piv;
#[path = "device_tests/securitydomain.rs"]
mod securitydomain;
#[path = "device_tests/yubiotp.rs"]
mod yubiotp;
