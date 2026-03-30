//! Integration tests that run against a real YubiKey.
//!
//! These tests require a YubiKey to be connected and the `YUBIKEY_SERIAL`
//! environment variable to be set to the device's serial number.
//!
//! Optional: Set `YUBIKEY_READER` to a partial PC/SC reader name (case-insensitive)
//! and `YUBIKEY_NFC_SERIAL` to the NFC device's serial to also run tests over NFC.
//!
//! ```sh
//! YUBIKEY_SERIAL=12345678 cargo test -p yubikit --test device_tests -- --test-threads=1
//! YUBIKEY_SERIAL=12345678 YUBIKEY_READER=OMNIKEY YUBIKEY_NFC_SERIAL=19762577 cargo test ...
//! ```
//!
//! **WARNING**: Some tests are destructive (they reset applications).
//! Only run against a test/development YubiKey.

use rstest::{fixture, rstest};
use std::sync::OnceLock;
use yubikit::core::Transport;
use yubikit::core::{Version, set_override_version};
use yubikit::device::{
    YubiKeyDevice, list_devices, list_devices_ccid_all, list_devices_fido, list_devices_otp,
};
use yubikit::management::{
    Capability, DeviceInfo, ManagementCcidSession, ManagementSession, ReleaseType,
};
use yubikit::securitydomain::SecurityDomainSession;
use yubikit::transport::pcsc::{PcscSmartCardConnection, list_readers};

// ───────────────────────── Connection Parameterization ─────────────────────────

#[derive(Debug, Clone)]
enum TestConnection {
    UsbSmartCard,
    UsbSmartCardScp11b,
    UsbOtp,
    NfcSmartCard,
    NfcSmartCardScp11b,
}

macro_rules! skip_if_needed {
    ($tc:expr) => {
        if let Some(reason) = should_skip(&$tc) {
            eprintln!("  SKIP {:?}: {}", $tc, reason);
            return;
        }
    };
}

/// Cached device info so we only enumerate once.
static DEVICE_INFO: OnceLock<(YubiKeyDevice, DeviceInfo)> = OnceLock::new();

/// Cached SCP11b parameters for USB: (kid, kvn, pk_sd_ecka).
static SCP11B_PARAMS: OnceLock<Option<(u8, u8, Vec<u8>)>> = OnceLock::new();

/// Cached SCP11b parameters for NFC: (kid, kvn, pk_sd_ecka).
static NFC_SCP11B_PARAMS: OnceLock<Option<(u8, u8, Vec<u8>)>> = OnceLock::new();

/// Cached NFC device version.
static NFC_DEVICE_VERSION: OnceLock<Option<Version>> = OnceLock::new();

fn required_serial() -> u32 {
    std::env::var("YUBIKEY_SERIAL")
        .expect(
            "YUBIKEY_SERIAL env var must be set to the serial number of the test YubiKey.\n\
             Example: YUBIKEY_SERIAL=12345678 cargo test -p yubikit --test device_tests",
        )
        .parse()
        .expect("YUBIKEY_SERIAL must be a valid integer")
}

fn required_nfc_serial() -> Option<u32> {
    std::env::var("YUBIKEY_NFC_SERIAL").ok().map(|s| {
        s.parse()
            .expect("YUBIKEY_NFC_SERIAL must be a valid integer")
    })
}

fn get_device_and_info() -> &'static (YubiKeyDevice, DeviceInfo) {
    DEVICE_INFO.get_or_init(|| {
        let serial = required_serial();
        let devices = list_devices(&[list_devices_ccid_all, list_devices_otp, list_devices_fido])
            .expect("Failed to enumerate YubiKeys");
        let dev = devices
            .into_iter()
            .find(|d| d.serial() == Some(serial))
            .unwrap_or_else(|| panic!("No YubiKey found with serial {serial}"));

        let info = dev.info().clone();

        if info.version_qualifier.release_type != ReleaseType::Final {
            set_override_version(info.version);
        }

        (dev, info)
    })
}

fn open_usb_smartcard() -> PcscSmartCardConnection {
    let (dev, _) = get_device_and_info();
    dev.open_smartcard().expect("Failed to open USB smartcard")
}

fn nfc_reader() -> Option<String> {
    let filter = std::env::var("YUBIKEY_READER").ok()?;
    let readers = list_readers().ok()?;
    readers.into_iter().find(|r| {
        r.to_ascii_lowercase()
            .contains(&filter.to_ascii_lowercase())
    })
}

fn open_nfc_smartcard() -> Option<PcscSmartCardConnection> {
    let reader = nfc_reader()?;
    PcscSmartCardConnection::new(&reader, false).ok()
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

fn get_scp11b_params() -> &'static Option<(u8, u8, Vec<u8>)> {
    SCP11B_PARAMS.get_or_init(|| {
        let (_, info) = get_device_and_info();
        if info.version < Version(5, 7, 2) {
            return None;
        }
        let conn = open_usb_smartcard();
        detect_scp11b_params(conn)
    })
}

fn get_nfc_device_version() -> &'static Option<Version> {
    NFC_DEVICE_VERSION.get_or_init(|| {
        let conn = open_nfc_smartcard()?;
        let mut session = ManagementCcidSession::new(conn).ok()?;
        let info = session.read_device_info_unchecked().ok()?;
        Some(info.version)
    })
}

fn get_nfc_scp11b_params() -> &'static Option<(u8, u8, Vec<u8>)> {
    NFC_SCP11B_PARAMS.get_or_init(|| {
        let version = (*get_nfc_device_version())?;
        if version < Version(5, 7, 2) {
            return None;
        }
        let conn = open_nfc_smartcard()?;
        detect_scp11b_params(conn)
    })
}

fn open_smartcard_connection(tc: &TestConnection) -> PcscSmartCardConnection {
    match tc {
        TestConnection::UsbSmartCard | TestConnection::UsbSmartCardScp11b => open_usb_smartcard(),
        TestConnection::NfcSmartCard | TestConnection::NfcSmartCardScp11b => {
            open_nfc_smartcard().expect("NFC reader not available")
        }
        TestConnection::UsbOtp => panic!("UsbOtp is not a smartcard connection"),
    }
}

fn scp_params(tc: &TestConnection) -> Option<&'static (u8, u8, Vec<u8>)> {
    match tc {
        TestConnection::UsbSmartCardScp11b => get_scp11b_params().as_ref(),
        TestConnection::NfcSmartCardScp11b => get_nfc_scp11b_params().as_ref(),
        _ => None,
    }
}

fn should_skip(tc: &TestConnection) -> Option<String> {
    if std::env::var("YUBIKEY_SERIAL").is_err() {
        return Some("YUBIKEY_SERIAL not set".into());
    }

    match tc {
        TestConnection::UsbSmartCard | TestConnection::UsbOtp => None,
        TestConnection::UsbSmartCardScp11b => {
            if get_scp11b_params().is_none() {
                Some("SCP11b not available on USB device".into())
            } else {
                None
            }
        }
        TestConnection::NfcSmartCard => {
            if nfc_reader().is_none() {
                Some("YUBIKEY_READER not set or reader not found".into())
            } else if required_nfc_serial().is_none() {
                Some("YUBIKEY_NFC_SERIAL not set".into())
            } else {
                None
            }
        }
        TestConnection::NfcSmartCardScp11b => {
            if nfc_reader().is_none() {
                Some("YUBIKEY_READER not set or reader not found".into())
            } else if required_nfc_serial().is_none() {
                Some("YUBIKEY_NFC_SERIAL not set".into())
            } else if get_nfc_scp11b_params().is_none() {
                Some("SCP11b not available on NFC device".into())
            } else {
                None
            }
        }
    }
}

/// Fixture providing the USB device info (cached via OnceLock).
#[fixture]
fn device_info() -> &'static DeviceInfo {
    &get_device_and_info().1
}

/// Fixture providing USB device capabilities.
#[fixture]
fn capabilities(device_info: &DeviceInfo) -> Capability {
    device_info
        .supported_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE)
}

fn usb_capabilities() -> Capability {
    let (_, info) = get_device_and_info();
    info.supported_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE)
}

fn device_version() -> Version {
    let (_, info) = get_device_and_info();
    info.version
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

macro_rules! require_version {
    ($min:expr) => {
        if device_version() < $min {
            eprintln!(
                "SKIP: device version {:?} < {:?}, skipping test",
                device_version(),
                $min
            );
            return;
        }
    };
}

/// Build SCP11b key params for test helper usage.
fn make_scp_key_params(kid: u8, kvn: u8, pk: &[u8]) -> yubikit::scp::ScpKeyParams {
    yubikit::scp::ScpKeyParams::Scp11b {
        kid,
        kvn,
        pk_sd_ecka: pk.to_vec(),
    }
}

// ───────────────────────── Device / Management ─────────────────────────

#[test]
fn test_list_devices_finds_key() {
    if std::env::var("YUBIKEY_SERIAL").is_err() {
        eprintln!("  SKIP: YUBIKEY_SERIAL not set");
        return;
    }
    let serial = required_serial();
    let devices = list_devices(&[list_devices_ccid_all, list_devices_otp, list_devices_fido])
        .expect("list_devices");
    assert!(
        devices.iter().any(|d| d.serial() == Some(serial)),
        "Expected YubiKey with serial {serial} in device list"
    );
}

#[rstest]
#[case(TestConnection::UsbSmartCard)]
#[case(TestConnection::UsbSmartCardScp11b)]
#[case(TestConnection::UsbOtp)]
#[case(TestConnection::NfcSmartCard)]
#[case(TestConnection::NfcSmartCardScp11b)]
fn test_management_read_device_info(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 1, 0));
    match tc {
        TestConnection::UsbOtp => {
            use yubikit::management::ManagementOtpSession;
            let (dev, _) = get_device_and_info();
            let conn = dev.open_otp().expect("open OTP");
            let mut session = ManagementOtpSession::new(conn).expect("ManagementOtpSession::new");
            let info = session
                .read_device_info_unchecked()
                .expect("read_device_info_unchecked");
            assert_eq!(info.serial, Some(required_serial()));
        }
        _ => {
            let conn = open_smartcard_connection(&tc);
            let mut session = if let Some((kid, kvn, pk)) = scp_params(&tc) {
                let params = make_scp_key_params(*kid, *kvn, pk);
                ManagementCcidSession::new_with_scp(conn, &params)
                    .expect("ManagementCcidSession with SCP")
            } else {
                ManagementCcidSession::new(conn).expect("ManagementCcidSession::new")
            };
            let info = session
                .read_device_info_unchecked()
                .expect("read_device_info_unchecked");
            assert!(info.serial.is_some(), "Expected serial number");
            if matches!(
                tc,
                TestConnection::UsbSmartCard | TestConnection::UsbSmartCardScp11b
            ) {
                assert_eq!(info.serial, Some(required_serial()));
            } else if let Some(nfc_serial) = required_nfc_serial() {
                assert_eq!(info.serial, Some(nfc_serial));
            }
        }
    }
    eprintln!("  PASS {tc:?}");
}

#[test]
fn test_management_device_info_capabilities() {
    if std::env::var("YUBIKEY_SERIAL").is_err() {
        eprintln!("  SKIP: YUBIKEY_SERIAL not set");
        return;
    }
    let (_, info) = get_device_and_info();
    let caps = info
        .supported_capabilities
        .get(&Transport::Usb)
        .expect("USB capabilities should be present");
    // Every modern YubiKey has at least OTP
    assert!(!caps.is_empty(), "Expected at least one capability on USB");
}

// ───────────────────────── OATH ─────────────────────────

mod oath {
    use super::*;
    use yubikit::oath::{CredentialData, HashAlgorithm, OathSession, OathType};

    fn open_oath_session(tc: &TestConnection) -> OathSession<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        if let Some((kid, kvn, pk)) = scp_params(tc) {
            let params = make_scp_key_params(*kid, *kvn, pk);
            OathSession::new_with_scp(conn, &params).expect("OathSession with SCP")
        } else {
            OathSession::new(conn).expect("OathSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_oath_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OATH);
        let session = open_oath_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_oath_reset_and_list(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OATH);
        let mut session = open_oath_session(&tc);
        session.reset().expect("reset");

        let creds = session.list_credentials().expect("list_credentials");
        assert!(creds.is_empty(), "Expected no credentials after reset");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_oath_put_list_delete(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OATH);
        let mut session = open_oath_session(&tc);
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
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_oath_calculate_all(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OATH);
        let mut session = open_oath_session(&tc);
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
        eprintln!("  PASS {tc:?}");
    }
}

// ───────────────────────── PIV ─────────────────────────

mod piv {
    use super::*;
    use x509_cert::der::{Decode, Encode};
    use yubikit::piv::{
        DEFAULT_MANAGEMENT_KEY, HashAlgorithm, KeyType, PinPolicy, PivSession, PivSignature,
        PivSigner, Slot, TouchPolicy, device_pubkey_to_spki, hash_data,
    };

    fn open_piv_session(tc: &TestConnection) -> PivSession<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        if let Some((kid, kvn, pk)) = scp_params(tc) {
            let params = make_scp_key_params(*kid, *kvn, pk);
            PivSession::new_with_scp(conn, &params).expect("PivSession with SCP")
        } else {
            PivSession::new(conn).expect("PivSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_piv_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let session = open_piv_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_piv_verify_default_pin(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");

        session.verify_pin("123456").expect("verify default PIN");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_piv_pin_attempts(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");

        let attempts = session.get_pin_attempts().expect("get_pin_attempts");
        assert!(attempts > 0, "Expected positive PIN attempts");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_generate_key_ec_p256(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        assert!(!pub_key.is_empty());

        let spki = device_pubkey_to_spki(KeyType::EccP256, &pub_key).expect("to_spki");
        assert!(spki.len() > 50, "SPKI should be substantial");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_generate_key_rsa2048(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        assert!(!pub_key.is_empty());

        let spki = device_pubkey_to_spki(KeyType::Rsa2048, &pub_key).expect("to_spki");
        assert!(spki.len() > 256, "RSA SPKI should be large");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_sign_ec_p256(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        let spki_der = device_pubkey_to_spki(KeyType::EccP256, &pub_key).expect("to_spki");

        let message = b"test data to sign";
        let hash = hash_data(HashAlgorithm::Sha256, message);
        let sig = session
            .sign(Slot::Retired1, KeyType::EccP256, &hash)
            .expect("sign");
        assert!(!sig.is_empty(), "Signature should not be empty");

        // Verify the signature using the public key
        use ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(
            x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki_der)
                .unwrap()
                .subject_public_key
                .as_bytes()
                .unwrap(),
        )
        .expect("parse verifying key");
        let sig = Signature::from_der(&sig).expect("parse DER signature");
        vk.verify(message, &sig).expect("signature verification");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_self_signed_cert_ec(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        let spki_der = device_pubkey_to_spki(KeyType::EccP256, &pub_key).expect("to_spki");

        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let subject: Name = "CN=YubiKey Test".parse().unwrap();
        let serial = SerialNumber::new(&[0x01]).unwrap();
        let validity = Validity::from_now(core::time::Duration::new(365 * 86400, 0)).unwrap();
        let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap();

        let signer = PivSigner::new(
            &mut session,
            Slot::Retired1,
            KeyType::EccP256,
            HashAlgorithm::Sha256,
            &spki_der,
        );
        let cert = CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &signer)
            .unwrap()
            .build::<PivSignature>()
            .expect("build cert");

        let cert_der = cert.to_der().expect("encode cert");
        assert!(
            cert_der.len() > 100,
            "Certificate DER should be substantial"
        );

        // Parse it back and verify the signature
        let parsed = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");
        assert_eq!(
            parsed.tbs_certificate.subject.to_string(),
            "CN=YubiKey Test"
        );

        // Verify the certificate signature using the embedded public key
        use ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(
            parsed
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .unwrap(),
        )
        .expect("parse verifying key from cert");
        let tbs_der = parsed.tbs_certificate.to_der().expect("encode TBS");
        let cert_sig =
            Signature::from_der(parsed.signature.raw_bytes()).expect("parse cert signature");
        vk.verify(&tbs_der, &cert_sig)
            .expect("certificate signature verification");

        // Store and retrieve - drop signer first to regain session access
        drop(signer);
        session
            .put_certificate(Slot::Retired1, &cert_der, false)
            .expect("put_certificate");
        let retrieved = session
            .get_certificate(Slot::Retired1)
            .expect("get_certificate");
        assert_eq!(cert_der, retrieved, "Certificate round-trip should match");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_generate_csr(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        let spki_der = device_pubkey_to_spki(KeyType::EccP256, &pub_key).expect("to_spki");

        use x509_cert::builder::{Builder, RequestBuilder};
        use x509_cert::name::Name;

        let subject: Name = "CN=CSR Test,O=Yubico".parse().unwrap();
        let signer = PivSigner::new(
            &mut session,
            Slot::Retired1,
            KeyType::EccP256,
            HashAlgorithm::Sha256,
            &spki_der,
        );
        let csr = RequestBuilder::new(subject, &signer)
            .unwrap()
            .build::<PivSignature>()
            .expect("build CSR");

        let csr_der = csr.to_der().expect("encode CSR");
        assert!(csr_der.len() > 50, "CSR DER should be substantial");

        // Verify the CSR signature
        use ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let parsed_csr = x509_cert::request::CertReq::from_der(&csr_der).expect("parse CSR back");
        let vk = VerifyingKey::from_sec1_bytes(
            parsed_csr
                .info
                .public_key
                .subject_public_key
                .as_bytes()
                .unwrap(),
        )
        .expect("parse verifying key from CSR");
        let info_der = parsed_csr.info.to_der().expect("encode CSR info");
        let csr_sig =
            Signature::from_der(parsed_csr.signature.raw_bytes()).expect("parse CSR signature");
        vk.verify(&info_der, &csr_sig)
            .expect("CSR signature verification");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_self_signed_cert_rsa(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        let spki_der = device_pubkey_to_spki(KeyType::Rsa2048, &pub_key).expect("to_spki");

        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let subject: Name = "CN=RSA Test".parse().unwrap();
        let serial = SerialNumber::new(&[0x42]).unwrap();
        let validity = Validity::from_now(core::time::Duration::new(30 * 86400, 0)).unwrap();
        let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap();

        let signer = PivSigner::new(
            &mut session,
            Slot::Retired1,
            KeyType::Rsa2048,
            HashAlgorithm::Sha256,
            &spki_der,
        );
        let cert = CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &signer)
            .unwrap()
            .build::<PivSignature>()
            .expect("build RSA cert");

        let cert_der = cert.to_der().expect("encode cert");
        let parsed = x509_cert::Certificate::from_der(&cert_der).expect("parse cert back");
        assert_eq!(parsed.tbs_certificate.subject.to_string(), "CN=RSA Test");

        // Verify the RSA certificate signature
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::pkcs8::DecodePublicKey;
        use rsa::signature::Verifier;
        let rsa_pub =
            rsa::RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA public key");
        let vk = VerifyingKey::<sha2::Sha256>::new(rsa_pub);
        let tbs_der = parsed.tbs_certificate.to_der().expect("encode TBS");
        let sig = Signature::try_from(parsed.signature.raw_bytes()).expect("parse RSA signature");
        vk.verify(&tbs_der, &sig)
            .expect("RSA certificate signature verification");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_decrypt_rsa(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        let spki_der = device_pubkey_to_spki(KeyType::Rsa2048, &pub_key).expect("to_spki");

        // Encrypt a message with the public key
        use rsa::pkcs8::DecodePublicKey;
        let rsa_pub =
            rsa::RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA public key");
        let plaintext = b"Hello from PIV decrypt test!";
        let ciphertext = rsa_pub
            .encrypt(&mut rsa::rand_core::OsRng, rsa::Pkcs1v15Encrypt, plaintext)
            .expect("encrypt");

        // Decrypt with the YubiKey
        let decrypted = session
            .decrypt(Slot::Retired1, &ciphertext)
            .expect("decrypt");
        // RSA PKCS#1 v1.5 decrypt returns padded data; strip padding
        // The PIV decrypt returns the raw unpadded result after PKCS#1 processing
        assert_eq!(
            &decrypted[decrypted.len() - plaintext.len()..],
            plaintext,
            "Decrypted plaintext should match"
        );
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_piv_ecdh_p256(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let pub_key = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        let spki_der = device_pubkey_to_spki(KeyType::EccP256, &pub_key).expect("to_spki");

        // Generate an ephemeral key pair on the host
        use p256::PublicKey;
        use p256::ecdh::EphemeralSecret;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let host_secret = EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let host_public = p256::PublicKey::from(&host_secret);
        let host_public_bytes = host_public.to_encoded_point(false);

        // Derive shared secret on the YubiKey using ECDH
        let device_shared = session
            .calculate_secret(
                Slot::Retired1,
                KeyType::EccP256,
                host_public_bytes.as_bytes(),
            )
            .expect("calculate_secret");

        // Derive shared secret on the host
        let device_pk = PublicKey::from_sec1_bytes(
            x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki_der)
                .unwrap()
                .subject_public_key
                .as_bytes()
                .unwrap(),
        )
        .expect("parse device public key");
        let host_shared = host_secret.diffie_hellman(&device_pk);

        assert_eq!(
            device_shared,
            host_shared.raw_secret_bytes().as_slice(),
            "ECDH shared secrets should match"
        );
        eprintln!("  PASS {tc:?}");
    }
}

// ───────────────────────── OpenPGP ─────────────────────────

mod openpgp {
    use super::*;
    use yubikit::openpgp::OpenPgpSession;

    fn open_openpgp_session(tc: &TestConnection) -> OpenPgpSession<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        if let Some((kid, kvn, pk)) = scp_params(tc) {
            let params = make_scp_key_params(*kid, *kvn, pk);
            OpenPgpSession::new_with_scp(conn, &params).expect("OpenPgpSession with SCP")
        } else {
            OpenPgpSession::new(conn).expect("OpenPgpSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_openpgp_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        let session = open_openpgp_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_openpgp_get_application_data(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        let mut session = open_openpgp_session(&tc);
        let app_data = session
            .get_application_related_data()
            .expect("get_application_related_data");
        let (major, minor) = app_data.aid.version();
        assert!(
            major >= 2,
            "Expected OpenPGP version >= 2.0, got {major}.{minor}"
        );
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_openpgp_get_challenge(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        let mut session = open_openpgp_session(&tc);
        match session.get_challenge(8) {
            Ok(challenge) => {
                assert_eq!(challenge.len(), 8);
                assert!(challenge.iter().any(|&b| b != 0));
            }
            Err(_) => {
                eprintln!("  NOTE: get_challenge not supported on this device");
            }
        }
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_openpgp_generate_ec_key_and_sign(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        require_version!(Version(5, 2, 0));
        let mut session = open_openpgp_session(&tc);
        session.reset().expect("reset");
        session
            .verify_admin(yubikit::openpgp::DEFAULT_ADMIN_PIN)
            .expect("verify admin");
        session
            .verify_pin(yubikit::openpgp::DEFAULT_USER_PIN, false)
            .expect("verify PIN");

        // Generate EC P-256 signing key
        let pk_data = session
            .generate_ec_key(
                yubikit::openpgp::KeyRef::Sig,
                yubikit::openpgp::curve_oid::SECP256R1,
            )
            .expect("generate_ec_key");
        assert!(!pk_data.is_empty(), "Public key data should not be empty");

        // Extract EC point from TLV (tag 0x86)
        let pk_dict = yubikit::tlv::parse_tlv_dict(&pk_data).expect("parse pk TLV");
        let ec_point = pk_dict.get(&0x86).expect("EC point tag 0x86");
        assert_eq!(
            ec_point.len(),
            65,
            "Uncompressed P-256 point should be 65 bytes"
        );

        // Sign a message
        let message = b"OpenPGP EC sign test";
        let signature = session
            .sign(message, yubikit::openpgp::SignHashAlgorithm::Sha256)
            .expect("sign");
        assert!(!signature.is_empty(), "Signature should not be empty");

        // Verify: OpenPGP EC sign returns raw r||s (64 bytes for P-256)
        use p256::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(ec_point).expect("parse verifying key");
        // OpenPGP sign() hashes the message internally with SHA-256 and returns raw r||s
        // We need to verify against the pre-hashed digest using DigestVerifier
        use ecdsa::signature::DigestVerifier;
        use sha2::Digest;
        let digest = sha2::Sha256::new_with_prefix(message);
        let sig = Signature::from_bytes((&signature[..]).into()).expect("parse signature");
        vk.verify_digest(digest, &sig)
            .expect("EC signature verification");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_openpgp_generate_rsa_key_and_sign(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        let mut session = open_openpgp_session(&tc);
        session.reset().expect("reset");
        session
            .verify_admin(yubikit::openpgp::DEFAULT_ADMIN_PIN)
            .expect("verify admin");
        session
            .verify_pin(yubikit::openpgp::DEFAULT_USER_PIN, false)
            .expect("verify PIN");

        // Generate RSA 2048 signing key
        let pk_data = session
            .generate_rsa_key(
                yubikit::openpgp::KeyRef::Sig,
                yubikit::openpgp::RsaSize::Rsa2048,
            )
            .expect("generate_rsa_key");
        assert!(!pk_data.is_empty(), "Public key data should not be empty");

        // Extract modulus (0x81) and exponent (0x82) from TLV
        let pk_dict = yubikit::tlv::parse_tlv_dict(&pk_data).expect("parse pk TLV");
        let modulus_bytes = pk_dict.get(&0x81).expect("modulus tag 0x81");
        let exponent_bytes = pk_dict.get(&0x82).expect("exponent tag 0x82");

        // Reconstruct RSA public key
        use rsa::BigUint;
        let n = BigUint::from_bytes_be(modulus_bytes);
        let e = BigUint::from_bytes_be(exponent_bytes);
        let rsa_pub = rsa::RsaPublicKey::new(n, e).expect("construct RSA public key");

        // Sign a message
        let message = b"OpenPGP RSA sign test";
        let signature = session
            .sign(message, yubikit::openpgp::SignHashAlgorithm::Sha256)
            .expect("sign");
        assert!(!signature.is_empty(), "Signature should not be empty");

        // Verify the signature
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;
        let vk = VerifyingKey::<sha2::Sha256>::new(rsa_pub);
        let sig = Signature::try_from(signature.as_slice()).expect("parse RSA signature");
        vk.verify(message, &sig)
            .expect("RSA signature verification");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_openpgp_rsa_decrypt(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        let mut session = open_openpgp_session(&tc);
        session.reset().expect("reset");
        session
            .verify_admin(yubikit::openpgp::DEFAULT_ADMIN_PIN)
            .expect("verify admin");
        session
            .verify_pin(yubikit::openpgp::DEFAULT_USER_PIN, true)
            .expect("verify PIN for decrypt");

        // Generate RSA 2048 decryption key
        let pk_data = session
            .generate_rsa_key(
                yubikit::openpgp::KeyRef::Dec,
                yubikit::openpgp::RsaSize::Rsa2048,
            )
            .expect("generate_rsa_key");

        // Extract modulus and exponent
        let pk_dict = yubikit::tlv::parse_tlv_dict(&pk_data).expect("parse pk TLV");
        let modulus_bytes = pk_dict.get(&0x81).expect("modulus");
        let exponent_bytes = pk_dict.get(&0x82).expect("exponent");
        use rsa::BigUint;
        let n = BigUint::from_bytes_be(modulus_bytes);
        let e = BigUint::from_bytes_be(exponent_bytes);
        let rsa_pub = rsa::RsaPublicKey::new(n, e).expect("construct RSA public key");

        // Encrypt a message with the public key
        let plaintext = b"OpenPGP RSA decrypt test!";
        let ciphertext = rsa_pub
            .encrypt(&mut rsa::rand_core::OsRng, rsa::Pkcs1v15Encrypt, plaintext)
            .expect("encrypt");

        // Decrypt with the YubiKey
        let decrypted = session.decrypt(&ciphertext).expect("decrypt");
        // OpenPGP RSA decrypt returns raw PKCS#1 decrypted data
        assert_eq!(
            &decrypted[decrypted.len() - plaintext.len()..],
            plaintext,
            "Decrypted plaintext should match"
        );
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    fn test_openpgp_ec_ecdh(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        require_version!(Version(5, 2, 0));
        let mut session = open_openpgp_session(&tc);
        session.reset().expect("reset");
        session
            .verify_admin(yubikit::openpgp::DEFAULT_ADMIN_PIN)
            .expect("verify admin");
        session
            .verify_pin(yubikit::openpgp::DEFAULT_USER_PIN, true)
            .expect("verify PIN for decrypt");

        // Generate EC P-256 decryption key
        let pk_data = session
            .generate_ec_key(
                yubikit::openpgp::KeyRef::Dec,
                yubikit::openpgp::curve_oid::SECP256R1,
            )
            .expect("generate_ec_key");

        // Extract EC point
        let pk_dict = yubikit::tlv::parse_tlv_dict(&pk_data).expect("parse pk TLV");
        let ec_point = pk_dict.get(&0x86).expect("EC point tag 0x86");

        // Generate ephemeral key on host
        use p256::PublicKey;
        use p256::ecdh::EphemeralSecret;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let host_secret = EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let host_public = PublicKey::from(&host_secret);
        let host_public_bytes = host_public.to_encoded_point(false);

        // Derive shared secret on YubiKey (OpenPGP decrypt with EC = ECDH)
        let device_shared = session
            .decrypt(host_public_bytes.as_bytes())
            .expect("ECDH via decrypt");

        // Derive shared secret on host
        let device_pk = PublicKey::from_sec1_bytes(ec_point).expect("parse device EC public key");
        let host_shared = host_secret.diffie_hellman(&device_pk);

        assert_eq!(
            device_shared,
            host_shared.raw_secret_bytes().as_slice(),
            "ECDH shared secrets should match"
        );
        eprintln!("  PASS {tc:?}");
    }
}

// ───────────────────────── YubiOTP ─────────────────────────

mod yubiotp {
    use super::*;
    use yubikit::yubiotp::{YubiOtpCcidSession, YubiOtpOtpSession, YubiOtpSession};

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::UsbOtp)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_yubiotp_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OTP);
        match tc {
            TestConnection::UsbOtp => {
                let (dev, _) = get_device_and_info();
                let conn = dev.open_otp().expect("open OTP");
                let session = YubiOtpOtpSession::new(conn).expect("YubiOtpOtpSession::new");
                let _v = session.version();
            }
            _ => {
                let conn = open_smartcard_connection(&tc);
                let session = if let Some((kid, kvn, pk)) = scp_params(&tc) {
                    let params = make_scp_key_params(*kid, *kvn, pk);
                    YubiOtpCcidSession::new_with_scp(conn, &params)
                        .expect("YubiOtpCcidSession with SCP")
                } else {
                    YubiOtpCcidSession::new(conn).expect("YubiOtpCcidSession::new")
                };
                let _v = session.version();
            }
        }
        eprintln!("  PASS {tc:?}");
    }
}

// ───────────────────────── HSM Auth ─────────────────────────

mod hsmauth {
    use super::*;
    use yubikit::hsmauth::HsmAuthSession;

    fn open_hsmauth_session(tc: &TestConnection) -> HsmAuthSession<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        if let Some((kid, kvn, pk)) = scp_params(tc) {
            let params = make_scp_key_params(*kid, *kvn, pk);
            HsmAuthSession::new_with_scp(conn, &params).expect("HsmAuthSession with SCP")
        } else {
            HsmAuthSession::new(conn).expect("HsmAuthSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_hsmauth_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::HSMAUTH);
        let session = open_hsmauth_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::UsbSmartCardScp11b)]
    #[case(TestConnection::NfcSmartCard)]
    #[case(TestConnection::NfcSmartCardScp11b)]
    fn test_hsmauth_reset_and_list(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::HSMAUTH);
        let mut session = open_hsmauth_session(&tc);
        session.reset().expect("reset");

        let creds = session.list_credentials().expect("list_credentials");
        assert!(creds.is_empty(), "Expected no credentials after reset");
        eprintln!("  PASS {tc:?}");
    }
}

// ───────────────────────── Security Domain ─────────────────────────
// SecurityDomain tests do NOT run with SCP (they test SCP infrastructure itself).

mod securitydomain {
    use super::*;
    use yubikit::scp::ScpKeyParams;
    use yubikit::securitydomain::{Curve, KeyRef, ScpKid, SecurityDomainSession, StaticKeys};

    /// Path to SCP test files relative to the workspace root.
    fn scp_test_file(name: &str) -> std::path::PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // crates/yubikit -> workspace root
        manifest.join("../../tests/files/scp").join(name)
    }

    /// Read a PEM file and return the DER-decoded contents of all blocks.
    fn read_pem_certs(path: &std::path::Path) -> Vec<Vec<u8>> {
        let pem_data = std::fs::read_to_string(path).expect("read PEM file");
        let mut certs = Vec::new();
        // Split on PEM boundaries and decode each cert
        for block in pem_data.split("-----BEGIN CERTIFICATE-----") {
            if let Some(b64) = block.split("-----END CERTIFICATE-----").next() {
                let b64 = b64.trim();
                if b64.is_empty() {
                    continue;
                }
                // manual base64 decode
                let der = base64_decode(b64);
                certs.push(der);
            }
        }
        certs
    }

    /// Decode base64 with whitespace stripped.
    fn base64_decode(b64: &str) -> Vec<u8> {
        let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        // Simple base64 decode using the constant table
        base64_decode_raw(&clean)
    }

    fn base64_decode_raw(input: &str) -> Vec<u8> {
        // Use a minimal base64 decoder
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        fn val(c: u8) -> u8 {
            TABLE.iter().position(|&x| x == c).unwrap_or(0) as u8
        }
        let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes.chunks(4) {
            let n = chunk.len();
            let a = if n > 0 { val(chunk[0]) } else { 0 };
            let b = if n > 1 { val(chunk[1]) } else { 0 };
            let c = if n > 2 { val(chunk[2]) } else { 0 };
            let d = if n > 3 { val(chunk[3]) } else { 0 };
            out.push((a << 2) | (b >> 4));
            if n > 2 {
                out.push((b << 4) | (c >> 2));
            }
            if n > 3 {
                out.push((c << 6) | d);
            }
        }
        out
    }

    /// Read a PEM private key file and return the raw EC scalar bytes.
    fn read_ec_private_key(path: &std::path::Path) -> Vec<u8> {
        use elliptic_curve::SecretKey;
        let pem_data = std::fs::read_to_string(path).expect("read PEM key file");
        // Extract DER from PEM
        let der = if pem_data.contains("-----BEGIN PRIVATE KEY-----") {
            let b64 = pem_data
                .split("-----BEGIN PRIVATE KEY-----")
                .nth(1)
                .unwrap()
                .split("-----END PRIVATE KEY-----")
                .next()
                .unwrap()
                .trim();
            base64_decode(b64)
        } else if pem_data.contains("-----BEGIN EC PRIVATE KEY-----") {
            let b64 = pem_data
                .split("-----BEGIN EC PRIVATE KEY-----")
                .nth(1)
                .unwrap()
                .split("-----END EC PRIVATE KEY-----")
                .next()
                .unwrap()
                .trim();
            base64_decode(b64)
        } else {
            panic!("Unrecognized PEM format in {path:?}");
        };

        // Try PKCS#8 first, then SEC1
        use elliptic_curve::pkcs8::DecodePrivateKey;
        if let Ok(sk) = SecretKey::<p256::NistP256>::from_pkcs8_der(&der) {
            sk.to_bytes().as_slice().to_vec()
        } else if let Ok(sk) = SecretKey::<p256::NistP256>::from_sec1_der(&der) {
            sk.to_bytes().as_slice().to_vec()
        } else {
            panic!("Failed to parse EC private key from {path:?}");
        }
    }

    /// Extract the SubjectKeyIdentifier extension value from a DER certificate.
    fn extract_ski(cert_der: &[u8]) -> Vec<u8> {
        use x509_cert::Certificate;
        use x509_cert::der::Decode;
        let cert = Certificate::from_der(cert_der).expect("parse certificate");
        // SubjectKeyIdentifier OID: 2.5.29.14
        let ski_oid = x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.14");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .expect("extensions");
        for ext in exts.iter() {
            if ext.extn_id == ski_oid {
                // The value is an OCTET STRING wrapping another OCTET STRING
                let outer = ext.extn_value.as_bytes();
                // Parse the inner OCTET STRING: tag 0x04, length, value
                if outer.len() >= 2 && outer[0] == 0x04 {
                    let len = outer[1] as usize;
                    return outer[2..2 + len].to_vec();
                }
                return outer.to_vec();
            }
        }
        panic!("SubjectKeyIdentifier not found in certificate");
    }

    /// Extract the serial number from a DER certificate as big-endian bytes.
    fn extract_serial(cert_der: &[u8]) -> Vec<u8> {
        use x509_cert::Certificate;
        use x509_cert::der::Decode;
        let cert = Certificate::from_der(cert_der).expect("parse certificate");
        cert.tbs_certificate.serial_number.as_bytes().to_vec()
    }

    /// Ensure the default SCP03 key (KID=0x01, KVN=0xFF) is present, resetting if needed.
    fn ensure_default_keys(
        session: &mut SecurityDomainSession<impl yubikit::smartcard::SmartCardConnection>,
    ) {
        let default_key = KeyRef::new(0x01, 0xFF);
        let key_info = session.get_key_information().expect("get_key_information");
        if !key_info.contains_key(&default_key) {
            session.reset().expect("reset to restore default keys");
        }
    }

    /// Verify full authentication by generating and deleting a temp EC key.
    fn verify_auth(
        session: &mut SecurityDomainSession<impl yubikit::smartcard::SmartCardConnection>,
    ) {
        let temp_ref = KeyRef::new(0x13, 0x7F);
        session
            .generate_ec_key(temp_ref, Curve::Secp256r1, 0)
            .expect("generate_ec_key for auth verification");
        session
            .delete_key(temp_ref.kid, temp_ref.kvn, false)
            .expect("delete temp key");
    }

    /// Load SCP11a/c keys: generate SD key, import OCE certs, return ScpKeyParams.
    fn load_scp11_keys(
        session: &mut SecurityDomainSession<impl yubikit::smartcard::SmartCardConnection>,
        kid: u8,
        kvn: u8,
    ) -> ScpKeyParams {
        let sd_ref = KeyRef::new(kid, kvn);
        let oce_ref = KeyRef::new(0x10, kvn);

        // Generate the SD ECKA key
        let pk_sd = session
            .generate_ec_key(sd_ref, Curve::Secp256r1, 0)
            .expect("generate SD EC key");

        // Load CA certificate and import its public key
        let ca_der = read_pem_certs(&scp_test_file("cert.ca-kloc.ecdsa.pem"));
        assert!(!ca_der.is_empty(), "Expected at least one CA cert");
        let ca_pubkey = extract_ec_p256_pubkey(&ca_der[0]).expect("extract CA public key");
        session
            .put_key_ec_public(oce_ref, &ca_pubkey, Curve::Secp256r1, 0)
            .expect("put OCE public key");

        // Store CA issuer (SKI)
        let ski = extract_ski(&ca_der[0]);
        session
            .store_ca_issuer(oce_ref, &ski)
            .expect("store CA issuer");

        // Load OCE certificate chain (ka-kloc + oce.ecka)
        let ka_der = read_pem_certs(&scp_test_file("cert.ka-kloc.ecdsa.pem"));
        let ecka_der = read_pem_certs(&scp_test_file("cert.oce.ecka.pem"));

        // Load OCE private key
        let sk_oce = read_ec_private_key(&scp_test_file("sk.oce.ecka.pem"));

        // Build certificates list (DER encoded)
        let mut certificates = Vec::new();
        for c in &ka_der {
            certificates.push(c.clone());
        }
        for c in &ecka_der {
            certificates.push(c.clone());
        }

        ScpKeyParams::Scp11ac {
            kid,
            kvn,
            pk_sd_ecka: pk_sd,
            sk_oce_ecka: sk_oce,
            certificates,
            oce_ref: Some((oce_ref.kid, oce_ref.kvn)),
        }
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_securitydomain_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        match SecurityDomainSession::new(conn) {
            Ok(session) => {
                let _v = session.version();
                eprintln!("  PASS {tc:?}");
            }
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
            }
        }
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_securitydomain_get_key_information(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        let key_info = session.get_key_information().expect("get_key_information");
        assert!(!key_info.is_empty(), "Expected at least one key entry");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_card_recognition_data(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let data = session
            .get_card_recognition_data()
            .expect("get_card_recognition_data");
        assert!(
            !data.is_empty(),
            "Card recognition data should not be empty"
        );
        // First byte should be a valid TLV tag (0x06 = OID per the spec)
        assert_eq!(
            data[0], 0x06,
            "Expected OID tag (0x06) as first TLV element"
        );
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp03_authenticate(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Authenticate with default SCP03 keys (0x40..0x4F)
        let conn = open_smartcard_connection(&tc);
        let params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: (0x40..=0x4Fu8).collect(),
            key_mac: (0x40..=0x4Fu8).collect(),
            key_dek: Some((0x40..=0x4Fu8).collect()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP03 authentication with default keys");
        verify_auth(&mut session);
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp03_wrong_key(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Try authenticating with wrong keys
        let conn = open_smartcard_connection(&tc);
        let params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: vec![0x01u8; 16],
            key_mac: vec![0x01u8; 16],
            key_dek: Some(vec![0x01u8; 16]),
        };
        let result = SecurityDomainSession::new_with_scp(conn, &params).map_err(|(e, _)| e);
        assert!(result.is_err(), "SCP03 with wrong keys should fail");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp03_change_key(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Authenticate with default keys
        let conn = open_smartcard_connection(&tc);
        let default_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: (0x40..=0x4Fu8).collect(),
            key_mac: (0x40..=0x4Fu8).collect(),
            key_dek: Some((0x40..=0x4Fu8).collect()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &default_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth with default keys");

        // Generate random keys
        let mut new_enc = [0u8; 16];
        let mut new_mac = [0u8; 16];
        let mut new_dek = [0u8; 16];
        getrandom::fill(&mut new_enc).expect("getrandom");
        getrandom::fill(&mut new_mac).expect("getrandom");
        getrandom::fill(&mut new_dek).expect("getrandom");

        let new_ref = KeyRef::new(0x01, 0x02);
        let new_keys = StaticKeys::new(new_enc.to_vec(), new_mac.to_vec(), Some(new_dek.to_vec()));
        session
            .put_key_static(new_ref, &new_keys, 0)
            .expect("put new SCP03 keys");
        drop(session);

        // Verify new keys work
        let conn = open_smartcard_connection(&tc);
        let new_params = ScpKeyParams::Scp03 {
            kvn: 0x02,
            key_enc: new_enc.to_vec(),
            key_mac: new_mac.to_vec(),
            key_dek: Some(new_dek.to_vec()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &new_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth with new keys");
        verify_auth(&mut session);
        drop(session);

        // Verify old default keys no longer work
        let conn = open_smartcard_connection(&tc);
        let result = SecurityDomainSession::new_with_scp(conn, &default_params).map_err(|(e, _)| e);
        assert!(result.is_err(), "Default keys should fail after key change");

        // Reset to restore defaults
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp11b_ok(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);

        let scp11b_ref = KeyRef::new(0x13, 0x01);
        let chain = session
            .get_certificate_bundle(scp11b_ref)
            .expect("get_certificate_bundle");
        if chain.is_empty() {
            eprintln!("  SKIP {tc:?}: No SCP11b certificate bundle on device");
            return;
        }
        let leaf_cert = chain.last().unwrap();
        let pk = extract_ec_p256_pubkey(leaf_cert).expect("extract public key from leaf cert");
        drop(session);

        // Authenticate with SCP11b
        let conn = open_smartcard_connection(&tc);
        let params = ScpKeyParams::Scp11b {
            kid: 0x13,
            kvn: 0x01,
            pk_sd_ecka: pk,
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11b authentication");

        // SCP11b grants read-only access; generate_ec_key should fail
        let temp_ref = KeyRef::new(0x13, 0x7F);
        let result = session.generate_ec_key(temp_ref, Curve::Secp256r1, 0);
        assert!(
            result.is_err(),
            "SCP11b should not allow key generation (read-only)"
        );
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp11b_import(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Authenticate with SCP03 to get write access
        let conn = open_smartcard_connection(&tc);
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: (0x40..=0x4Fu8).collect(),
            key_mac: (0x40..=0x4Fu8).collect(),
            key_dek: Some((0x40..=0x4Fu8).collect()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth for SCP11b import");

        // Generate a new P-256 private key
        use elliptic_curve::SecretKey;
        use p256::NistP256;
        let sk = SecretKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let scalar_bytes = sk.to_bytes();

        let import_ref = KeyRef::new(0x13, 0x02);
        session
            .put_key_ec_private(import_ref, scalar_bytes.as_slice(), Curve::Secp256r1, 0)
            .expect("put_key_ec_private for SCP11b");

        // Get the public key for authentication
        let pk = sk.public_key();
        use elliptic_curve::sec1::ToEncodedPoint;
        let pk_bytes = pk.to_encoded_point(false);
        drop(session);

        // Authenticate with the imported SCP11b key
        let conn = open_smartcard_connection(&tc);
        let params = ScpKeyParams::Scp11b {
            kid: 0x13,
            kvn: 0x02,
            pk_sd_ecka: pk_bytes.as_bytes().to_vec(),
        };
        let _session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11b auth with imported key");

        // Clean up: reset to restore defaults
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp11a_ok(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Authenticate with SCP03
        let conn = open_smartcard_connection(&tc);
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: (0x40..=0x4Fu8).collect(),
            key_mac: (0x40..=0x4Fu8).collect(),
            key_dek: Some((0x40..=0x4Fu8).collect()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth for SCP11a setup");

        let kvn = 0x03;
        let params = load_scp11_keys(&mut session, ScpKid::Scp11a as u8, kvn);
        drop(session);

        // Authenticate with SCP11a
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11a authentication");

        // Verify full access by deleting the keys we created
        session
            .delete_key(0, kvn, false)
            .expect("delete keys by kvn");

        // Reset to restore defaults
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp11a_allowlist(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Authenticate with SCP03
        let conn = open_smartcard_connection(&tc);
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: (0x40..=0x4Fu8).collect(),
            key_mac: (0x40..=0x4Fu8).collect(),
            key_dek: Some((0x40..=0x4Fu8).collect()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth for SCP11a allowlist setup");

        let kvn = 0x03;
        let params = load_scp11_keys(&mut session, ScpKid::Scp11a as u8, kvn);

        // Get certificate serial numbers for the allowlist
        let serials: Vec<Vec<u8>> = if let ScpKeyParams::Scp11ac {
            ref certificates, ..
        } = params
        {
            certificates.iter().map(|c| extract_serial(c)).collect()
        } else {
            panic!("Expected Scp11ac params");
        };

        let oce_ref = KeyRef::new(0x10, kvn);
        session
            .store_allowlist(oce_ref, &serials)
            .expect("store_allowlist");
        drop(session);

        // Authenticate with SCP11a
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11a auth with allowlist");

        // Verify by deleting keys
        session
            .delete_key(0, kvn, false)
            .expect("delete keys by kvn");

        // Reset to restore defaults
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp11a_allowlist_blocked(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Authenticate with SCP03
        let conn = open_smartcard_connection(&tc);
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: (0x40..=0x4Fu8).collect(),
            key_mac: (0x40..=0x4Fu8).collect(),
            key_dek: Some((0x40..=0x4Fu8).collect()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth for allowlist_blocked setup");

        // Replace default SCP03 keys with new ones
        let mut new_enc = [0u8; 16];
        let mut new_mac = [0u8; 16];
        let mut new_dek = [0u8; 16];
        getrandom::fill(&mut new_enc).expect("getrandom");
        getrandom::fill(&mut new_mac).expect("getrandom");
        getrandom::fill(&mut new_dek).expect("getrandom");

        let new_scp03_ref = KeyRef::new(0x01, 0x02);
        let new_keys = StaticKeys::new(new_enc.to_vec(), new_mac.to_vec(), Some(new_dek.to_vec()));
        session
            .put_key_static(new_scp03_ref, &new_keys, 0)
            .expect("put new SCP03 keys");

        // Delete default SCP11b key
        session
            .delete_key(ScpKid::Scp11b as u8, 0, false)
            .expect("delete SCP11b");

        let kvn = 0x03;
        let params = load_scp11_keys(&mut session, ScpKid::Scp11a as u8, kvn);

        // Set wrong allowlist (arbitrary serial numbers)
        let wrong_serials: Vec<Vec<u8>> =
            vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04], vec![0x05]];
        let oce_ref = KeyRef::new(0x10, kvn);
        session
            .store_allowlist(oce_ref, &wrong_serials)
            .expect("store wrong allowlist");
        drop(session);

        // Attempt SCP11a auth — should fail due to wrong allowlist
        let conn = open_smartcard_connection(&tc);
        let result = SecurityDomainSession::new_with_scp(conn, &params).map_err(|(e, _)| e);
        assert!(result.is_err(), "SCP11a should fail with wrong allowlist");

        // Remove allowlist by authenticating with new SCP03 keys
        let conn = open_smartcard_connection(&tc);
        let new_scp03_params = ScpKeyParams::Scp03 {
            kvn: 0x02,
            key_enc: new_enc.to_vec(),
            key_mac: new_mac.to_vec(),
            key_dek: Some(new_dek.to_vec()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &new_scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth with new keys to remove allowlist");
        session
            .store_allowlist(oce_ref, &[])
            .expect("remove allowlist");
        drop(session);

        // Now SCP11a should work
        let conn = open_smartcard_connection(&tc);
        let _session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11a auth after removing allowlist");

        // Reset to restore defaults
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::UsbSmartCard)]
    #[case(TestConnection::NfcSmartCard)]
    fn test_scp11c_ok(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        drop(session);

        // Authenticate with SCP03
        let conn = open_smartcard_connection(&tc);
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: (0x40..=0x4Fu8).collect(),
            key_mac: (0x40..=0x4Fu8).collect(),
            key_dek: Some((0x40..=0x4Fu8).collect()),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth for SCP11c setup");

        let kvn = 0x03;
        let params = load_scp11_keys(&mut session, ScpKid::Scp11c as u8, kvn);
        drop(session);

        // Authenticate with SCP11c
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11c authentication");

        // SCP11c grants read-only access; delete_key should fail
        let result = session.delete_key(0, kvn, false);
        assert!(
            result.is_err(),
            "SCP11c should not allow key deletion (read-only)"
        );

        // Reset to restore defaults
        let conn = open_smartcard_connection(&tc);
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        eprintln!("  PASS {tc:?}");
    }
}
