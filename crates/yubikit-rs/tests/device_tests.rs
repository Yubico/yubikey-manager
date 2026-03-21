//! Integration tests that run against a real YubiKey.
//!
//! These tests require a YubiKey to be connected and the `YUBIKEY_SERIAL`
//! environment variable to be set to the device's serial number.
//!
//! ```sh
//! YUBIKEY_SERIAL=12345678 cargo test -p yubikit-rs --test device_tests
//! ```
//!
//! **WARNING**: Some tests are destructive (they reset applications).
//! Only run against a test/development YubiKey.

use std::sync::OnceLock;
use yubikit_rs::device::{list_devices, YubiKeyDevice};
use yubikit_rs::iso7816::Transport;
use yubikit_rs::management::{Capability, DeviceInfo, ManagementSession};
use yubikit_rs::transport::pcsc::PcscConnection;

/// Cached device info so we only enumerate once.
static DEVICE_INFO: OnceLock<(YubiKeyDevice, DeviceInfo)> = OnceLock::new();

fn required_serial() -> u32 {
    std::env::var("YUBIKEY_SERIAL")
        .expect(
            "YUBIKEY_SERIAL env var must be set to the serial number of the test YubiKey.\n\
             Example: YUBIKEY_SERIAL=12345678 cargo test -p yubikit-rs --test device_tests",
        )
        .parse()
        .expect("YUBIKEY_SERIAL must be a valid integer")
}

fn get_device_and_info() -> &'static (YubiKeyDevice, DeviceInfo) {
    DEVICE_INFO.get_or_init(|| {
        let serial = required_serial();
        let devices = list_devices().expect("Failed to enumerate YubiKeys");
        let dev = devices
            .into_iter()
            .find(|d| d.serial() == Some(serial))
            .unwrap_or_else(|| panic!("No YubiKey found with serial {serial}"));

        let info = dev.info().clone();
        (dev, info)
    })
}

fn open_smartcard() -> PcscConnection {
    let (dev, _) = get_device_and_info();
    dev.open_smartcard().expect("Failed to open smartcard")
}

fn usb_capabilities() -> Capability {
    let (_, info) = get_device_and_info();
    info.supported_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE)
}

macro_rules! require_capability {
    ($cap:expr) => {
        if !usb_capabilities().contains($cap) {
            eprintln!(
                "SKIP: device does not support {:?}, skipping test",
                stringify!($cap)
            );
            return;
        }
    };
}

// ───────────────────────── Device / Management ─────────────────────────

#[test]
fn test_list_devices_finds_key() {
    let serial = required_serial();
    let devices = list_devices().expect("list_devices");
    assert!(
        devices.iter().any(|d| d.serial() == Some(serial)),
        "Expected YubiKey with serial {serial} in device list"
    );
}

#[test]
fn test_management_read_device_info() {
    let conn = open_smartcard();
    let mut session = ManagementSession::new(conn).expect("ManagementSession::new");
    let info = session
        .read_device_info_unchecked()
        .expect("read_device_info_unchecked");
    assert_eq!(info.serial, Some(required_serial()));
}

#[test]
fn test_management_device_info_capabilities() {
    let (_, info) = get_device_and_info();
    let caps = info
        .supported_capabilities
        .get(&Transport::Usb)
        .expect("USB capabilities should be present");
    // Every modern YubiKey has at least OTP
    assert!(
        !caps.is_empty(),
        "Expected at least one capability on USB"
    );
}

// ───────────────────────── OATH ─────────────────────────

mod oath {
    use super::*;
    use yubikit_rs::oath::{CredentialData, HashAlgorithm, OathSession, OathType};

    #[test]
    fn test_oath_session_version() {
        require_capability!(Capability::OATH);
        let conn = open_smartcard();
        let session = OathSession::new(conn).expect("OathSession::new");
        // Just verify we got a version
        let _v = session.version();
    }

    #[test]
    fn test_oath_reset_and_list() {
        require_capability!(Capability::OATH);
        let conn = open_smartcard();
        let mut session = OathSession::new(conn).expect("OathSession::new");
        session.reset().expect("reset");

        let creds = session.list_credentials().expect("list_credentials");
        assert!(creds.is_empty(), "Expected no credentials after reset");
    }

    #[test]
    fn test_oath_put_list_delete() {
        require_capability!(Capability::OATH);
        let conn = open_smartcard();
        let mut session = OathSession::new(conn).expect("OathSession::new");
        session.reset().expect("reset");

        let cred_data = CredentialData {
            name: "test@example.com".into(),
            oath_type: OathType::Totp,
            hash_algorithm: HashAlgorithm::Sha1,
            secret: b"12345678901234567890".to_vec(),
            digits: 6,
            period: 30,
            counter: 0,
            issuer: Some("TestIssuer".into()),
        };

        let cred = session
            .put_credential(&cred_data, false)
            .expect("put_credential");
        assert_eq!(cred.issuer.as_deref(), Some("TestIssuer"));

        let creds = session.list_credentials().expect("list_credentials");
        assert_eq!(creds.len(), 1);

        session
            .delete_credential(&cred_data.get_id())
            .expect("delete_credential");

        let creds = session.list_credentials().expect("list_credentials");
        assert!(creds.is_empty());
    }

    #[test]
    fn test_oath_calculate_all() {
        require_capability!(Capability::OATH);
        let conn = open_smartcard();
        let mut session = OathSession::new(conn).expect("OathSession::new");
        session.reset().expect("reset");

        let cred_data = CredentialData {
            name: "calc@test.com".into(),
            oath_type: OathType::Totp,
            hash_algorithm: HashAlgorithm::Sha1,
            secret: b"12345678901234567890".to_vec(),
            digits: 6,
            period: 30,
            counter: 0,
            issuer: None,
        };
        session
            .put_credential(&cred_data, false)
            .expect("put_credential");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let results = session.calculate_all(now).expect("calculate_all");
        assert_eq!(results.len(), 1);
        let (_, code) = &results[0];
        assert!(code.is_some(), "Expected a TOTP code");
    }
}

// ───────────────────────── PIV ─────────────────────────

mod piv {
    use super::*;
    use yubikit_rs::piv::PivSession;

    #[test]
    fn test_piv_session_version() {
        require_capability!(Capability::PIV);
        let conn = open_smartcard();
        let session = PivSession::new(conn).expect("PivSession::new");
        let _v = session.version();
    }

    #[test]
    fn test_piv_verify_default_pin() {
        require_capability!(Capability::PIV);
        let conn = open_smartcard();
        let mut session = PivSession::new(conn).expect("PivSession::new");
        session.reset().expect("reset");

        session.verify_pin("123456").expect("verify default PIN");
    }

    #[test]
    fn test_piv_pin_attempts() {
        require_capability!(Capability::PIV);
        let conn = open_smartcard();
        let mut session = PivSession::new(conn).expect("PivSession::new");
        session.reset().expect("reset");

        let attempts = session.get_pin_attempts().expect("get_pin_attempts");
        assert!(attempts > 0, "Expected positive PIN attempts");
    }
}

// ───────────────────────── OpenPGP ─────────────────────────

mod openpgp {
    use super::*;
    use yubikit_rs::openpgp::OpenPgpSession;

    #[test]
    fn test_openpgp_session_version() {
        require_capability!(Capability::OPENPGP);
        let conn = open_smartcard();
        let session = OpenPgpSession::new(conn).expect("OpenPgpSession::new");
        let _v = session.version();
    }

    #[test]
    fn test_openpgp_get_application_data() {
        require_capability!(Capability::OPENPGP);
        let conn = open_smartcard();
        let mut session = OpenPgpSession::new(conn).expect("OpenPgpSession::new");
        let app_data = session
            .get_application_related_data()
            .expect("get_application_related_data");
        let (major, minor) = app_data.aid.version();
        assert!(major >= 2, "Expected OpenPGP version >= 2.0, got {major}.{minor}");
    }

    #[test]
    fn test_openpgp_get_challenge() {
        require_capability!(Capability::OPENPGP);
        let conn = open_smartcard();
        let mut session = OpenPgpSession::new(conn).expect("OpenPgpSession::new");
        // get_challenge may fail on older versions
        match session.get_challenge(8) {
            Ok(challenge) => {
                assert_eq!(challenge.len(), 8);
                assert!(challenge.iter().any(|&b| b != 0));
            }
            Err(_) => {
                eprintln!("SKIP: get_challenge not supported on this device");
            }
        }
    }
}

// ───────────────────────── YubiOTP ─────────────────────────

mod yubiotp {
    use super::*;
    use yubikit_rs::yubiotp::YubiOtpSession;

    #[test]
    fn test_yubiotp_session_version() {
        require_capability!(Capability::OTP);
        let conn = open_smartcard();
        let session = YubiOtpSession::new(conn).expect("YubiOtpSession::new");
        let _v = session.version();
    }
}

// ───────────────────────── HSM Auth ─────────────────────────

mod hsmauth {
    use super::*;
    use yubikit_rs::hsmauth::HsmAuthSession;

    #[test]
    fn test_hsmauth_session_version() {
        require_capability!(Capability::HSMAUTH);
        let conn = open_smartcard();
        let session = HsmAuthSession::new(conn).expect("HsmAuthSession::new");
        let _v = session.version();
    }

    #[test]
    fn test_hsmauth_reset_and_list() {
        require_capability!(Capability::HSMAUTH);
        let conn = open_smartcard();
        let mut session = HsmAuthSession::new(conn).expect("HsmAuthSession::new");
        session.reset().expect("reset");

        let creds = session.list_credentials().expect("list_credentials");
        assert!(creds.is_empty(), "Expected no credentials after reset");
    }
}

// ───────────────────────── Security Domain ─────────────────────────

mod securitydomain {
    use super::*;
    use yubikit_rs::securitydomain::SecurityDomainSession;

    #[test]
    fn test_securitydomain_version() {
        let conn = open_smartcard();
        match SecurityDomainSession::new(conn) {
            Ok(session) => {
                let _v = session.version();
            }
            Err(_) => {
                eprintln!("SKIP: SecurityDomain not available on this device");
            }
        }
    }

    #[test]
    fn test_securitydomain_get_key_information() {
        let conn = open_smartcard();
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("SKIP: SecurityDomain not available on this device");
                return;
            }
        };
        let key_info = session.get_key_information().expect("get_key_information");
        // Default key set should always exist
        assert!(!key_info.is_empty(), "Expected at least one key entry");
    }
}
