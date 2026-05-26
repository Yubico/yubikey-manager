//! Integration tests that run against a real YubiKey.
//!
//! These tests require a YubiKey to be connected and the `YUBIKEY_SERIAL`
//! environment variable to be set to the device's serial number.
//! For devices without a serial, set `YUBIKEY_NO_SERIAL=1` instead.
//!
//! The device is found automatically whether it is connected over USB or NFC.
//!
//! ```sh
//! YUBIKEY_SERIAL=12345678 cargo test -p yubikit --test device_tests -- --test-threads=1
//! YUBIKEY_NO_SERIAL=1 cargo test -p yubikit --test device_tests -- --test-threads=1
//! ```
//!
//! **WARNING**: Some tests are destructive (they reset applications).
//! Only run against a test/development YubiKey.

use rstest::{fixture, rstest};
use std::sync::{Mutex, OnceLock};
use yubikit::core::Transport;
use yubikit::core::{Version, set_override_version};
use yubikit::management::{Capability, DeviceInfo, ManagementSession, ReleaseType, UsbInterface};
use yubikit::platform::device::{LocalYubiKeyDevice, list_devices};
use yubikit::platform::pcsc::PcscSmartCardConnection;
use yubikit::securitydomain::SecurityDomainSession;

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
            eprintln!("  SKIP {:?}: {}", $tc, reason);
            return;
        }
    };
}

// ───────────────────────── Device ─────────────────────────

/// Cached device — resolved once and reused across all tests.
static DEVICE: OnceLock<LocalYubiKeyDevice> = OnceLock::new();

/// Whether the device supports SCP11b (version >= 5.7.2).
static SCP11B_SUPPORTED: OnceLock<bool> = OnceLock::new();

/// Cached SCP11b parameters: (kid, kvn, pk_sd_ecka).
/// Uses Mutex so it can be invalidated after SD reset tests.
static SCP11B_PARAMS: Mutex<Option<Option<(u8, u8, Vec<u8>)>>> = Mutex::new(None);

fn required_serial() -> Option<u32> {
    if std::env::var("YUBIKEY_NO_SERIAL").is_ok() {
        return None;
    }
    let s = std::env::var("YUBIKEY_SERIAL").expect(
        "Set YUBIKEY_SERIAL to the device serial, or YUBIKEY_NO_SERIAL=1 for devices without one.\n\
         Example: YUBIKEY_SERIAL=12345678 cargo test -p yubikit --test device_tests",
    );
    Some(s.parse().expect("YUBIKEY_SERIAL must be a valid integer"))
}

fn get_device() -> &'static LocalYubiKeyDevice {
    DEVICE.get_or_init(|| {
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
                        panic!("Multiple YubiKeys without serial found ({n}), cannot disambiguate")
                    }
                }
            }
        };

        if dev.info().version_qualifier.release_type != ReleaseType::Final {
            set_override_version(dev.info().version);
        }
        dev
    })
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
    if std::env::var("YUBIKEY_SERIAL").is_err() && std::env::var("YUBIKEY_NO_SERIAL").is_err() {
        return Some("YUBIKEY_SERIAL or YUBIKEY_NO_SERIAL not set".into());
    }

    let dev = get_device();

    match tc {
        TestConnection::SmartCard => {
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
    get_device().info()
}

/// Fixture providing device capabilities for the active transport.
#[fixture]
fn capabilities(device_info: &DeviceInfo) -> Capability {
    device_info
        .supported_capabilities
        .get(&device_transport())
        .copied()
        .unwrap_or(Capability::NONE)
}

fn device_capabilities() -> Capability {
    let dev = get_device();
    dev.info()
        .supported_capabilities
        .get(&dev.transport())
        .copied()
        .unwrap_or(Capability::NONE)
}

fn device_version() -> Version {
    get_device().info().version
}

macro_rules! require_capability {
    ($cap:expr) => {
        if !device_capabilities().contains($cap) {
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

macro_rules! require_transport {
    ($transport:expr) => {
        if device_transport() != $transport {
            eprintln!("SKIP: test requires {:?} transport", $transport);
            return;
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
    if std::env::var("YUBIKEY_SERIAL").is_err() && std::env::var("YUBIKEY_NO_SERIAL").is_err() {
        eprintln!("  SKIP: YUBIKEY_SERIAL or YUBIKEY_NO_SERIAL not set");
        return;
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
#[case(TestConnection::SmartCard)]
#[case(TestConnection::SmartCardScp11b)]
#[case(TestConnection::UsbHid)]
fn test_management_read_device_info(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 1, 0));
    match tc {
        TestConnection::UsbHid => {
            require_transport!(Transport::Usb);
            let conn = get_device().open_otp().expect("open OTP");
            let mut session = ManagementSession::new_otp(conn).expect("ManagementSession::new_otp");
            let info = session.read_device_info().expect("read_device_info");
            assert_eq!(info.serial, required_serial());
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
    eprintln!("  PASS {tc:?}");
}

#[test]
fn test_management_device_info_capabilities() {
    if std::env::var("YUBIKEY_SERIAL").is_err() && std::env::var("YUBIKEY_NO_SERIAL").is_err() {
        eprintln!("  SKIP: YUBIKEY_SERIAL or YUBIKEY_NO_SERIAL not set");
        return;
    }
    let caps = device_capabilities();
    // Every YubiKey has at least one capability on its active transport
    assert!(
        !caps.is_empty(),
        "Expected at least one capability on active transport"
    );
}

// ───────────────────────── OATH ─────────────────────────

mod oath {
    use super::*;
    use yubikit::oath::{CredentialData, HashAlgorithm, OathSession, OathType};

    fn open_oath_session(tc: &TestConnection) -> OathSession<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        if let Some((kid, kvn, pk)) = scp_params(tc) {
            let params = make_scp_key_params(kid, kvn, &pk);
            OathSession::new_with_scp(conn, &params).expect("OathSession with SCP")
        } else {
            OathSession::new(conn).expect("OathSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_oath_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OATH);
        let session = open_oath_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
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
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
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
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
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
        PivSigner, Slot, TouchPolicy,
    };

    fn open_piv_session(tc: &TestConnection) -> PivSession<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        if let Some((kid, kvn, pk)) = scp_params(tc) {
            let params = make_scp_key_params(kid, kvn, &pk);
            PivSession::new_with_scp(conn, &params).expect("PivSession with SCP")
        } else {
            PivSession::new(conn).expect("PivSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_piv_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let session = open_piv_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_piv_verify_default_pin(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");

        session.verify_pin("123456").expect("verify default PIN");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
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
    #[case(TestConnection::SmartCard)]
    fn test_piv_generate_key_ec_p256(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        assert!(!spki_der.is_empty());
        assert!(spki_der.len() > 50, "SPKI should be substantial");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_piv_generate_key_rsa2048(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");
        assert!(!spki_der.is_empty());
        assert!(spki_der.len() > 256, "RSA SPKI should be large");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_piv_sign_ec_p256(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");

        let message = b"test data to sign";
        let hash = <sha2::Sha256 as sha2::Digest>::digest(message);
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
    #[case(TestConnection::SmartCard)]
    fn test_piv_self_signed_cert_ec(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");

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
    #[case(TestConnection::SmartCard)]
    fn test_piv_generate_csr(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");

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
    #[case(TestConnection::SmartCard)]
    fn test_piv_self_signed_cert_rsa(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");

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
    #[case(TestConnection::SmartCard)]
    fn test_piv_decrypt_rsa(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");

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
    #[case(TestConnection::SmartCard)]
    fn test_piv_ecdh_p256(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(4, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");
        session.verify_pin("123456").expect("verify PIN");

        let spki_der = session
            .generate_key(
                Slot::Retired1,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Never,
            )
            .expect("generate_key");

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

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_piv_generate_mldsa44(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(6, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let spki_der = session
            .generate_key(
                Slot::Authentication,
                KeyType::MlDsa44,
                PinPolicy::Default,
                TouchPolicy::Default,
            )
            .expect("generate_key MlDsa44");
        assert!(!spki_der.is_empty());
        assert_eq!(
            KeyType::from_public_key_der(&spki_der).expect("detect ML-DSA key type"),
            KeyType::MlDsa44
        );

        session.verify_pin("123456").expect("verify PIN");
        let sig = session
            .sign(Slot::Authentication, KeyType::MlDsa44, b"test message")
            .expect("sign MlDsa44");
        assert!(!sig.is_empty());
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_piv_generate_mlkem768(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(6, 0, 0));
        require_capability!(Capability::PIV);
        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let spki_der = session
            .generate_key(
                Slot::KeyManagement,
                KeyType::MlKem768,
                PinPolicy::Default,
                TouchPolicy::Default,
            )
            .expect("generate_key MlKem768");
        assert!(!spki_der.is_empty());
        assert_eq!(
            KeyType::from_public_key_der(&spki_der).expect("detect ML-KEM key type"),
            KeyType::MlKem768
        );
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_piv_mldsa44_verify(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(6, 0, 0));
        require_capability!(Capability::PIV);

        use ml_dsa::{MlDsa44, Signature, VerifyingKey, common::KeyInit, signature::Verifier};
        use x509_cert::der::Decode;
        use x509_cert::spki::SubjectPublicKeyInfoRef;

        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let spki_der = session
            .generate_key(
                Slot::Authentication,
                KeyType::MlDsa44,
                PinPolicy::Default,
                TouchPolicy::Default,
            )
            .expect("generate_key MlDsa44");

        let msg = b"test message for ml-dsa44 verification";
        session.verify_pin("123456").expect("verify PIN");
        let sig_bytes = session
            .sign(Slot::Authentication, KeyType::MlDsa44, msg)
            .expect("sign");

        // Extract raw public key bytes from SPKI
        let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("parse SPKI");
        let raw_key = spki.subject_public_key.raw_bytes();

        // Parse with ml-dsa and verify
        let vk_bytes: &[u8; 1312] = raw_key
            .try_into()
            .expect("ML-DSA-44 public key must be 1312 bytes");
        let vk = VerifyingKey::<MlDsa44>::new(vk_bytes.into());
        let sig = Signature::<MlDsa44>::try_from(sig_bytes.as_slice()).expect("parse signature");
        vk.verify(msg, &sig).expect("signature verification failed");

        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_piv_mlkem768_decapsulate(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(6, 0, 0));
        require_capability!(Capability::PIV);

        use ml_kem::EncapsulationKey768;
        use x509_cert::der::Decode;
        use x509_cert::spki::SubjectPublicKeyInfoRef;

        let mut session = open_piv_session(&tc);
        session.reset().expect("reset");
        session
            .authenticate(DEFAULT_MANAGEMENT_KEY)
            .expect("authenticate");

        let spki_der = session
            .generate_key(
                Slot::KeyManagement,
                KeyType::MlKem768,
                PinPolicy::Default,
                TouchPolicy::Default,
            )
            .expect("generate_key MlKem768");

        // Extract raw encapsulation key bytes from SPKI
        let spki = SubjectPublicKeyInfoRef::from_der(&spki_der).expect("parse SPKI");
        let raw_key = spki.subject_public_key.raw_bytes();

        // Parse encapsulation key and encapsulate with random seed
        let ek_bytes: &[u8; 1184] = raw_key
            .try_into()
            .expect("ML-KEM-768 public key must be 1184 bytes");
        let ek = EncapsulationKey768::new(ek_bytes.into()).expect("parse encapsulation key");
        let mut m = [0u8; 32];
        getrandom::fill(&mut m).expect("getrandom");
        let (ciphertext, host_shared_secret) = ek.encapsulate_deterministic(&m.into());

        // Device decapsulates and returns shared secret
        session.verify_pin("123456").expect("verify PIN");
        let device_shared_secret = session
            .calculate_secret(
                Slot::KeyManagement,
                KeyType::MlKem768,
                ciphertext.as_slice(),
            )
            .expect("calculate_secret");

        assert_eq!(
            device_shared_secret.as_slice(),
            host_shared_secret.as_slice(),
            "Shared secrets must match"
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
            let params = make_scp_key_params(kid, kvn, &pk);
            OpenPgpSession::new_with_scp(conn, &params).expect("OpenPgpSession with SCP")
        } else {
            OpenPgpSession::new(conn).expect("OpenPgpSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_openpgp_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OPENPGP);
        let session = open_openpgp_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
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
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
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
    #[case(TestConnection::SmartCard)]
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
    #[case(TestConnection::SmartCard)]
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
    #[case(TestConnection::SmartCard)]
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
    #[case(TestConnection::SmartCard)]
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
    use yubikit::yubiotp::{Slot, SlotConfiguration, YubiOtpSession};

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    #[case(TestConnection::UsbHid)]
    fn test_yubiotp_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OTP);
        match tc {
            TestConnection::UsbHid => {
                require_transport!(Transport::Usb);
                let conn = get_device().open_otp().expect("open OTP");
                let session = YubiOtpSession::new_otp(conn).expect("YubiOtpSession::new_otp");
                let _v = session.version();
            }
            _ => {
                let conn = open_smartcard_connection(&tc);
                let session = if let Some((kid, kvn, ref pk)) = scp_params(&tc) {
                    let params = make_scp_key_params(kid, kvn, pk);
                    YubiOtpSession::new_with_scp(conn, &params).expect("YubiOtpSession with SCP")
                } else {
                    YubiOtpSession::new(conn).expect("YubiOtpSession::new")
                };
                let _v = session.version();
            }
        }
        eprintln!("  PASS {tc:?}");
    }

    /// Test that cancelling an OTP HMAC challenge-response with touch works.
    ///
    /// Programs slot 2 with HMAC-SHA1 + require_touch, starts a
    /// calculate_hmac_sha1 and immediately cancels it, verifying
    /// that it returns a Timeout error promptly.
    #[rstest]
    #[case(TestConnection::UsbHid)]
    fn test_calculate_hmac_sha1_cancel(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::OTP);
        require_transport!(Transport::Usb);

        let dev = get_device();

        // Program slot 2 with HMAC-SHA1 requiring touch (use CCID)
        {
            let conn = dev.open_smartcard().expect("open smartcard");
            let mut session = YubiOtpSession::new(conn).expect("YubiOtpSession");
            let config = SlotConfiguration::hmac_sha1(&[0x0b; 20])
                .expect("hmac config")
                .require_touch(true);
            session
                .put_configuration(Slot::Two, &config, None, None)
                .expect("put_configuration");
        }

        // Open OTP session and attempt calculate, cancel after first keepalive
        let conn = dev.open_otp().expect("open OTP");
        let mut session = YubiOtpSession::new_otp(conn).expect("YubiOtpSession");

        let got_keepalive = std::sync::atomic::AtomicBool::new(false);
        let start = std::time::Instant::now();
        let result = session.calculate_hmac_sha1_with_cancel(
            Slot::Two,
            b"test challenge",
            Some(&|| got_keepalive.load(std::sync::atomic::Ordering::Relaxed)),
            Some(&|_status| {
                got_keepalive.store(true, std::sync::atomic::Ordering::Relaxed);
            }),
        );
        let elapsed = start.elapsed();

        assert!(result.is_err(), "Expected error from cancelled operation");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cancelled") || err_msg.contains("Timeout"),
            "Expected cancel/timeout error, got: {err_msg}"
        );
        assert!(
            elapsed.as_secs() < 10,
            "Cancel took too long: {elapsed:?} (expected < 10s)"
        );

        // Clean up: delete slot 2
        {
            let conn = dev.open_smartcard().expect("open smartcard");
            let mut session = YubiOtpSession::new(conn).expect("YubiOtpSession");
            session.delete_slot(Slot::Two, None).expect("delete slot");
        }

        eprintln!("  PASS {tc:?} (cancelled in {elapsed:?})");
    }
}

// ───────────────────────── FIDO / CTAP2 ─────────────────────────

mod fido {
    use super::*;
    use yubikit::core::Connection;
    use yubikit::ctap::CtapSession;
    use yubikit::ctap2::{
        Aaguid, ClientPin, CredentialManagement, Ctap2Error, Ctap2Session, CtapStatus, LargeBlobs,
        Permissions, PinProtocol, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
        PublicKeyCredentialUserEntity,
    };
    use yubikit::fido::FidoConnection;
    use yubikit::webauthn::types::PublicKeyCredentialType;

    const TEST_PIN: &str = "12345679";
    const TEST_RP_ID: &str = "test.rs.yubikey.example";

    /// One-time setup: ensure the FIDO PIN is in a known state.
    ///
    /// If a PIN is already set on the device and it matches TEST_PIN, nothing
    /// extra is done.  If the PIN is set but doesn't match (or is blocked),
    /// the FIDO applet is reset first (which on NFC requires a recent power-up),
    /// then TEST_PIN is set.  Runs at most once per test-process invocation.
    fn setup_fido_pin() -> bool {
        eprintln!("  FIDO setup: initializing PIN state...");

        // Always power-cycle the NFC card at the start of a test run so any
        // accumulated PinAuthBlocked state from a previous run is cleared.
        // For USB devices this is a no-op (power_cycle_nfc returns Err quickly).
        if let Err(e) = power_cycle_nfc() {
            eprintln!("  FIDO setup: power_cycle_nfc skipped: {e}");
        }

        let open_session = || -> Result<Ctap2Session<PcscSmartCardConnection>, String> {
            let conn = open_smartcard_connection(&TestConnection::SmartCard);
            let ctap = CtapSession::new(conn).map_err(|(e, _)| e.to_string())?;
            Ctap2Session::new(ctap).map_err(|(e, _)| e.to_string())
        };

        // Check current PIN state.
        let needs_reset = {
            let mut session = match open_session() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("  FIDO setup: open session failed: {e}");
                    return false;
                }
            };
            let info = match session.get_info() {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("  FIDO setup: get_info failed: {e}");
                    return false;
                }
            };

            let pin_set = info.options.get("clientPin").copied().unwrap_or(false);
            if !pin_set {
                // No PIN set; proceed straight to set_pin below — no reset needed.
                false
            } else {
                // PIN is set — try to verify it's already TEST_PIN.
                let mut cp = match ClientPin::new(session).map_err(|(e, _)| e.to_string()) {
                    Ok(cp) => cp,
                    Err(e) => {
                        eprintln!("  FIDO setup: ClientPin::new failed: {e}");
                        return false;
                    }
                };
                match cp.get_pin_token(TEST_PIN, None, None) {
                    Ok(_) => {
                        // PIN is already TEST_PIN — no reset required.
                        eprintln!("  FIDO setup: PIN already set to TEST_PIN, no reset needed");
                        return true;
                    }
                    Err(Ctap2Error::StatusError(CtapStatus::PinInvalid))
                    | Err(Ctap2Error::StatusError(CtapStatus::PinAuthBlocked))
                    | Err(Ctap2Error::StatusError(CtapStatus::PinBlocked)) => {
                        // Wrong PIN or blocked — reset required.
                        // Check that this transport allows reset before proceeding.
                        if !info.transports_for_reset.is_empty() {
                            let current = match get_device().transport() {
                                Transport::Usb => "usb",
                                Transport::Nfc => "nfc",
                            };
                            if !info
                                .transports_for_reset
                                .iter()
                                .any(|t| t.eq_ignore_ascii_case(current))
                            {
                                eprintln!(
                                    "  FIDO setup: reset not allowed over {current} \
                                     (transports_for_reset={:?}); skipping PIN tests",
                                    info.transports_for_reset
                                );
                                return false;
                            }
                        }
                        true
                    }
                    Err(e) => {
                        eprintln!("  FIDO setup: unexpected error checking PIN: {e}");
                        return false;
                    }
                }
            }
        };

        if needs_reset {
            eprintln!("  FIDO setup: PIN mismatch or blocked, resetting applet...");
            // Power-cycle the NFC card so the "recently powered up" window is
            // satisfied for the FIDO reset command (NFC only).
            if get_device().transport() == Transport::Nfc
                && let Err(e) = power_cycle_nfc()
            {
                eprintln!("  FIDO setup: NFC power cycle failed: {e}");
                return false;
            }
            let mut session = match open_session() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("  FIDO setup: open session (post-power-cycle) failed: {e}");
                    return false;
                }
            };
            if let Err(e) = session.reset(None, None) {
                eprintln!(
                    "  FIDO setup: reset failed: {e}\n  \
                     NOTE: For NFC, remove the card and re-tap it, then \
                     run the tests within 10 seconds."
                );
                return false;
            }
            eprintln!("  FIDO setup: reset done");
        }

        // Set the PIN on a fresh connection (avoids stale cached state after reset).
        let session = match open_session() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  FIDO setup: re-open after reset failed: {e}");
                return false;
            }
        };
        let mut cp = match ClientPin::new(session).map_err(|(e, _)| e.to_string()) {
            Ok(cp) => cp,
            Err(e) => {
                eprintln!("  FIDO setup: ClientPin::new failed: {e}");
                return false;
            }
        };
        if let Err(e) = cp.set_pin(TEST_PIN) {
            eprintln!("  FIDO setup: set_pin failed: {e}");
            return false;
        }
        eprintln!("  FIDO setup: PIN set to TEST_PIN");
        true
    }

    /// Power-cycle the NFC card using PCSC so the "recently powered up"
    /// window is reset for commands like FIDO reset.
    ///
    /// Tries `UnpowerCard` first; falls back to `ResetCard` (warm reset /
    /// NFC deactivation + reactivation) if the card is unavailable after
    /// unpowering.
    fn power_cycle_nfc() -> Result<(), String> {
        use ::pcsc::{Context, Disposition, Protocols, Scope, ShareMode};
        use std::ffi::CString;

        let reader_name = get_device()
            .reader_name
            .as_deref()
            .ok_or("device has no PCSC reader name")?;
        let c_reader = CString::new(reader_name).map_err(|e| e.to_string())?;
        let ctx = Context::establish(Scope::User).map_err(|e| e.to_string())?;

        eprintln!("  FIDO setup: power-cycling NFC card via PCSC...");

        // Try UnpowerCard (cold reset / field off) first.
        {
            let card = ctx
                .connect(&c_reader, ShareMode::Shared, Protocols::ANY)
                .map_err(|e| e.to_string())?;
            card.disconnect(Disposition::UnpowerCard)
                .map_err(|(_, e)| e.to_string())?;
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));

        // Reconnect to confirm the card came back; use ResetCard to also
        // ensure the card goes through its ATR sequence (warm reset).
        {
            let mut card = ctx
                .connect(&c_reader, ShareMode::Shared, Protocols::ANY)
                .map_err(|e| e.to_string())?;
            card.reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard)
                .map_err(|e| e.to_string())?;
            card.disconnect(Disposition::LeaveCard)
                .map_err(|(_, e)| e.to_string())?;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));

        eprintln!("  FIDO setup: NFC card power-cycled");
        Ok(())
    }

    fn ensure_fido_pin() -> bool {
        use std::sync::OnceLock;
        static FIDO_PIN_READY: OnceLock<bool> = OnceLock::new();
        *FIDO_PIN_READY.get_or_init(setup_fido_pin)
    }

    /// Skip the calling test if the global FIDO PIN setup failed.
    macro_rules! require_fido_pin {
        () => {
            if !ensure_fido_pin() {
                eprintln!("  SKIP: FIDO PIN setup failed (see setup output above)");
                return;
            }
        };
    }

    /// Whether the FIDO CCID interface is usable.
    ///
    /// Over NFC it is always available; over USB the FIDOCCID capability must be
    /// enabled in the device's configuration.
    fn fido_ccid_available() -> bool {
        let dev = get_device();
        if dev.transport() == Transport::Nfc {
            return true;
        }
        dev.info()
            .config
            .enabled_capabilities
            .get(&Transport::Usb)
            .copied()
            .unwrap_or(Capability::NONE)
            .contains(Capability::FIDOCCID)
    }

    /// Skip a SmartCard / SmartCardScp11b test if FIDOCCID is not enabled over USB.
    macro_rules! require_fido_ccid {
        ($tc:expr) => {
            if matches!(
                $tc,
                TestConnection::SmartCard | TestConnection::SmartCardScp11b
            ) && !fido_ccid_available()
            {
                eprintln!("  SKIP {:?}: FIDOCCID not enabled over USB", $tc);
                return;
            }
        };
    }

    /// Get a PIN token, skipping the test if the PIN is wrong or auth is blocked.
    macro_rules! get_pin_token_or_skip {
        ($cp:expr, $pin:expr, $perms:expr, $rpid:expr) => {
            match $cp.get_pin_token($pin, $perms, $rpid) {
                Ok(t) => t,
                Err(Ctap2Error::StatusError(CtapStatus::PinInvalid)) => {
                    eprintln!("  SKIP: device PIN is not TEST_PIN; reset FIDO applet to rerun");
                    return;
                }
                Err(Ctap2Error::StatusError(CtapStatus::PinAuthBlocked)) => {
                    eprintln!("  SKIP: PIN auth blocked (re-power/re-tap device to clear)");
                    return;
                }
                Err(e) => panic!("get_pin_token failed: {e}"),
            }
        };
    }

    fn open_ctap2_smartcard(tc: &TestConnection) -> Ctap2Session<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        let ctap = if let Some((kid, kvn, ref pk)) = scp_params(tc) {
            let params = make_scp_key_params(kid, kvn, pk);
            CtapSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| e)
                .expect("CtapSession::new_with_scp")
        } else {
            CtapSession::new(conn)
                .map_err(|(e, _)| e)
                .expect("CtapSession::new")
        };
        Ctap2Session::new(ctap)
            .map_err(|(e, _)| e)
            .expect("Ctap2Session::new")
    }

    /// Simple [`UserInteraction`] for tests: always returns `TEST_PIN`, never uses UV.
    struct TestInteraction;

    impl yubikit::webauthn::UserInteraction for TestInteraction {
        fn prompt_up(&self) {}
        fn request_pin(&self, _permissions: Permissions, _rp_id: Option<&str>) -> Option<String> {
            Some(TEST_PIN.to_string())
        }
        fn request_uv(&self, _permissions: Permissions, _rp_id: Option<&str>) -> bool {
            false
        }
    }

    // ── Generic helpers (work for any C: Connection + 'static) ───────────────

    fn assert_info<C: Connection + 'static>(mut session: Ctap2Session<C>) {
        let info = session.get_info().expect("get_info");
        assert!(!info.versions.is_empty(), "versions should not be empty");
        assert!(
            info.versions.iter().any(|v| v.starts_with("FIDO_2_")),
            "expected a FIDO_2_x version, got: {:?}",
            info.versions
        );
        assert_ne!(info.aaguid, Aaguid::NONE, "AAGUID should not be all zeros");
        assert!(!info.options.is_empty(), "options should not be empty");
        eprintln!("  versions: {:?}", info.versions);
        eprintln!("  aaguid: {:?}", info.aaguid);
        eprintln!("  extensions: {:?}", info.extensions);
    }

    fn assert_pin_retries<C: Connection + 'static>(mut session: Ctap2Session<C>) {
        let info = session.get_info().expect("get_info for pin retries check");
        if !ClientPin::<C>::is_supported(&info) {
            eprintln!("  SKIP: clientPin not supported on this device");
            return;
        }
        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .expect("ClientPin::new");
        match cp.get_pin_retries() {
            Ok((retries, pcs)) => {
                assert!(retries <= 8, "retries should be <= 8, got {retries}");
                eprintln!("  PIN retries: {retries} (power_cycle_state: {pcs:?})");
            }
            Err(Ctap2Error::StatusError(CtapStatus::PinNotSet)) => {
                eprintln!("  PIN not set (no retries to report)");
            }
            Err(e) => panic!("get_pin_retries: {e}"),
        }
    }

    // ── 1. authenticatorGetInfo ─────────────────────────────────────────────

    /// Verify that authenticatorGetInfo returns valid data on all transports.
    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    #[case(TestConnection::UsbHid)]
    fn test_ctap2_get_info(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::FIDO2);
        require_fido_ccid!(tc);
        match &tc {
            TestConnection::UsbHid => {
                let conn = get_device().open_fido().expect("open FIDO HID");
                let ctap = CtapSession::new_fido(conn)
                    .map_err(|(e, _)| e)
                    .expect("CtapSession::new_fido");
                let session = Ctap2Session::new(ctap)
                    .map_err(|(e, _)| e)
                    .expect("Ctap2Session::new");
                assert_info(session);
            }
            _ => assert_info(open_ctap2_smartcard(&tc)),
        }
    }

    // ── 2. PIN retries ─────────────────────────────────────────────────────

    /// Verify that PIN retries can be read (no UP required) on all transports.
    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    #[case(TestConnection::UsbHid)]
    fn test_ctap2_pin_retries(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::FIDO2);
        require_fido_ccid!(tc);
        match &tc {
            TestConnection::UsbHid => {
                let conn = get_device().open_fido().expect("open FIDO HID");
                let ctap = CtapSession::new_fido(conn)
                    .map_err(|(e, _)| e)
                    .expect("CtapSession::new_fido");
                let session = Ctap2Session::new(ctap)
                    .map_err(|(e, _)| e)
                    .expect("Ctap2Session::new");
                assert_pin_retries(session);
            }
            _ => assert_pin_retries(open_ctap2_smartcard(&tc)),
        }
    }

    // ── 3. authenticatorSelection over NFC ─────────────────────────────────

    /// Verify that authenticatorSelection succeeds over NFC (UP is satisfied
    /// immediately because the card is on the reader).
    ///
    /// Requires CTAP 2.1 or the FIDO_2_1_PRE preview.
    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_ctap2_selection_nfc(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_transport!(Transport::Nfc);
        require_capability!(Capability::FIDO2);

        let mut session = open_ctap2_smartcard(&tc);
        let info = session.get_info().expect("get_info for selection check");
        let supports_selection = info
            .versions
            .iter()
            .any(|v| v == "FIDO_2_1" || v == "FIDO_2_1_PRE");
        if !supports_selection {
            eprintln!("  SKIP: authenticatorSelection requires CTAP 2.1");
            return;
        }

        // On NFC the card is already present, so UP is satisfied without physical touch.
        match session.selection(None, None) {
            Ok(()) => eprintln!("  selection: OK"),
            Err(e) => panic!("  selection: {e}"),
        }
    }

    // ── 4. make_credential + get_assertion over NFC ─────────────────────────

    /// Register a credential then verify it via assertion using [`WebAuthnClient`].
    ///
    /// Two separate NFC connections are used: one for make_credential and one
    /// for get_assertion. On NFC, each physical "tap" (logical connection) gives
    /// one user-presence (UP) budget. Closing and reopening the smartcard
    /// connection resets that budget for the next UP-requiring command.
    /// Cleans up the test credential with CredentialManagement when supported.
    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_ctap2_make_and_get_credential_nfc(#[case] tc: TestConnection) {
        use yubikit::webauthn::{
            AuthenticatorSelectionCriteria, DefaultClientDataCollector,
            PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
            PublicKeyCredentialRpEntity, ResidentKeyRequirement, UserVerificationRequirement,
            WebAuthnClient,
        };
        skip_if_needed!(tc);
        require_transport!(Transport::Nfc);
        require_capability!(Capability::FIDO2);
        require_fido_pin!();

        // ── Registration ─────────────────────────────────────────────────────
        let session = open_ctap2_smartcard(&tc);
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut mc_client = WebAuthnClient::new(session, TestInteraction, collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "Rust Device Tests".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"test-user-01".to_vec(),
                name: Some("test@rs.example".to_string()),
                display_name: Some("Test User".to_string()),
            },
            challenge: vec![0x42; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7, // ES256
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Required),
                user_verification: Some(UserVerificationRequirement::Preferred),
                ..Default::default()
            }),
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: None,
        };

        let reg = mc_client
            .make_credential(&create_options, None)
            .expect("make_credential");
        let cred_id = reg.id.clone();
        eprintln!("  make_credential: cred_id={} bytes", cred_id.len());
        assert!(!cred_id.is_empty(), "credential ID should not be empty");
        // Drop the session so the NFC card resets its UP budget for the next connection.
        // Hardware-reset the NFC card so the UP budget is fresh for the next connection.
        // (NFC CTAP2 allows one UP-requiring command per "tap"; PCSC power_cycle_nfc
        // is equivalent to removing and re-tapping the card.)
        drop(mc_client);
        power_cycle_nfc().expect("power_cycle_nfc between MC and GA");

        // ── Authentication ────────────────────────────────────────────────────
        // Open a NEW connection so the NFC card's per-connection UP budget is
        // fresh.  Omit allow_credentials so the authenticator discovers the
        // resident credential directly (avoids a pre-flight silent assertion
        // with up:false, which CTAP 2.2 §6.2.2 step 5(vi) forbids when the
        // token has userPresenceRequired set).
        let session2 = open_ctap2_smartcard(&tc);
        let collector2 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut ga_client = WebAuthnClient::new(session2, TestInteraction, collector2);

        let get_options = PublicKeyCredentialRequestOptions {
            challenge: vec![0xAB; 32],
            timeout: None,
            rp_id: Some(TEST_RP_ID.to_string()),
            allow_credentials: None,
            user_verification: Some(UserVerificationRequirement::Preferred),
            hints: None,
            extensions: None,
        };

        let assertions = ga_client
            .get_assertion(&get_options, None)
            .expect("get_assertion");
        assert!(!assertions.is_empty(), "expected at least one assertion");
        let a = &assertions[0];
        assert!(
            !a.response.signature.is_empty(),
            "signature should not be empty"
        );
        assert!(
            !a.response.authenticator_data.is_empty(),
            "auth_data should not be empty"
        );
        let flags = a.response.authenticator_data[32];
        assert!(flags & 0x01 != 0, "UP flag should be set in assertion");
        eprintln!("  get_assertion: sig={} bytes", a.response.signature.len());

        // ── Cleanup ───────────────────────────────────────────────────────────
        // Delete the test credential via CredentialManagement (best-effort).
        // The GA session's UP budget is consumed; power-cycle and open a fresh
        // connection for cleanup.
        drop(ga_client);
        power_cycle_nfc().expect("power_cycle_nfc before cleanup");
        let mut session3 = open_ctap2_smartcard(&tc);
        let info = session3.get_info().expect("get_info for cleanup check");
        if CredentialManagement::<PcscSmartCardConnection>::is_supported(&info) {
            let mut cp = ClientPin::new(session3)
                .map_err(|(e, _)| e)
                .expect("ClientPin for credmgmt cleanup");
            match cp.get_pin_token(TEST_PIN, Some(Permissions::CREDENTIAL_MGMT), None) {
                Ok(token) => {
                    let protocol = cp.protocol();
                    let session = cp.into_session();
                    let mut credmgmt = CredentialManagement::new(session, protocol, token)
                        .map_err(|(e, _)| e)
                        .expect("CredentialManagement for cleanup");
                    let cred_desc = PublicKeyCredentialDescriptor {
                        type_: PublicKeyCredentialType::PublicKey,
                        id: cred_id,
                        transports: None,
                    };
                    match credmgmt.delete_cred(&cred_desc) {
                        Ok(()) => eprintln!("  cleanup: test credential deleted"),
                        Err(e) => eprintln!("  cleanup: delete_cred failed (non-fatal): {e}"),
                    }
                }
                Err(e) => eprintln!("  cleanup: could not get PIN token (non-fatal): {e}"),
            }
        } else {
            eprintln!("  cleanup: CredentialManagement not supported, skipping");
        }
    }

    // ── 5. CredentialManagement metadata over NFC ──────────────────────────

    /// Read credential storage metadata via CredentialManagement.
    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_ctap2_credential_management_nfc(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_transport!(Transport::Nfc);
        require_capability!(Capability::FIDO2);
        require_fido_pin!();

        let mut session = open_ctap2_smartcard(&tc);
        let info = session.get_info().expect("get_info for credmgmt check");
        if !CredentialManagement::<PcscSmartCardConnection>::is_supported(&info) {
            eprintln!("  SKIP: CredentialManagement not supported");
            return;
        }

        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .expect("ClientPin for credmgmt");
        let token = get_pin_token_or_skip!(cp, TEST_PIN, Some(Permissions::CREDENTIAL_MGMT), None);
        let protocol = cp.protocol();
        let session = cp.into_session();
        let mut credmgmt = CredentialManagement::new(session, protocol, token)
            .map_err(|(e, _)| e)
            .expect("CredentialManagement::new");

        let (existing, max_remaining) = credmgmt.get_metadata().expect("get_metadata");
        eprintln!("  credentials: existing={existing}, max_remaining={max_remaining}");
        // Total capacity must be non-zero.
        assert!(
            existing + max_remaining > 0,
            "total credential capacity should be > 0"
        );

        if existing > 0 {
            let rps = credmgmt.enumerate_rps().expect("enumerate_rps");
            eprintln!("  RPs: {}", rps.len());
            assert!(
                !rps.is_empty(),
                "enumerate_rps returned empty for existing credentials"
            );
            for rp in &rps {
                eprintln!("    rp_id={}", rp.rp.id);
                let creds = credmgmt
                    .enumerate_creds(&rp.rp_id_hash)
                    .expect("enumerate_creds");
                eprintln!("    creds: {}", creds.len());
            }
        }
    }

    // ── 6. Large Blobs read over NFC ───────────────────────────────────────

    /// Verify that the large-blob array can be read (no UP required).
    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_ctap2_large_blobs_nfc(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_transport!(Transport::Nfc);
        require_capability!(Capability::FIDO2);

        let mut session = open_ctap2_smartcard(&tc);
        let info = session.get_info().expect("get_info for largeblobs check");
        if !LargeBlobs::<PcscSmartCardConnection>::is_supported(&info) {
            eprintln!("  SKIP: largeBlobs not supported");
            return;
        }

        // Reads don't require a PIN token; pass dummy values.
        let mut lb = LargeBlobs::new(session, PinProtocol::V1, vec![])
            .map_err(|(e, _)| e)
            .expect("LargeBlobs::new");
        let blob_array = lb.read_blob_array().expect("read_blob_array");
        eprintln!("  large blob array: {} bytes", blob_array.len());
    }

    // ── 7. authenticatorSelection cancel over USB HID ──────────────────────

    /// Verify that cancelling a CTAP2 selection command over USB HID works.
    ///
    /// Sends an authenticatorSelection CBOR command and cancels it after the
    /// first keepalive, checking that the authenticator responds with
    /// KeepaliveCancel (0x2D) promptly.
    ///
    /// This test is USB HID–only: the cancel mechanism relies on the HID
    /// out-of-band cancel packet; NFCCTAP uses a different cancel path that
    /// is tested via `test_ctap2_selection_nfc` above.
    #[rstest]
    #[case(TestConnection::UsbHid)]
    fn test_fido_selection_cancel(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::FIDO2);
        require_transport!(Transport::Usb);

        let mut conn = get_device().open_fido().expect("open FIDO HID");

        let got_keepalive = std::sync::atomic::AtomicBool::new(false);
        let start = std::time::Instant::now();
        let result = conn.call(
            0x10,
            &[0x0B], // CBOR authenticatorSelection
            Some(&mut |_status| {
                got_keepalive.store(true, std::sync::atomic::Ordering::Relaxed);
            }),
            Some(&|| got_keepalive.load(std::sync::atomic::Ordering::Relaxed)),
        );
        let elapsed = start.elapsed();

        match &result {
            Ok(response) if !response.is_empty() && response[0] == 0x01 => {
                // CTAP1_ERR_INVALID_COMMAND: selection not supported (pre-CTAP 2.1)
                eprintln!("  SKIP: authenticatorSelection not supported on this device");
                return;
            }
            Ok(response) => {
                assert!(
                    !response.is_empty() && response[0] == 0x2D,
                    "Expected KeepaliveCancel (0x2D), got: {:#04X?}",
                    response.first()
                );
            }
            Err(e) => panic!("Unexpected error: {e}"),
        }

        assert!(
            elapsed.as_secs() < 10,
            "Cancel took too long: {elapsed:?} (expected < 10s)"
        );
        eprintln!("  PASS {tc:?} (cancelled in {elapsed:?})");
    }
}

// ───────────────────────── HSM Auth ─────────────────────────

mod hsmauth {
    use super::*;
    use yubikit::hsmauth::HsmAuthSession;

    fn open_hsmauth_session(tc: &TestConnection) -> HsmAuthSession<PcscSmartCardConnection> {
        let conn = open_smartcard_connection(tc);
        if let Some((kid, kvn, pk)) = scp_params(tc) {
            let params = make_scp_key_params(kid, kvn, &pk);
            HsmAuthSession::new_with_scp(conn, &params).expect("HsmAuthSession with SCP")
        } else {
            HsmAuthSession::new(conn).expect("HsmAuthSession::new")
        }
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
    fn test_hsmauth_session_version(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_capability!(Capability::HSMAUTH);
        let session = open_hsmauth_session(&tc);
        let _v = session.version();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    #[case(TestConnection::SmartCardScp11b)]
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
    use yubikit::securitydomain::{Curve, KeyRef, ScpKid, SecurityDomainSession, StaticKeys};
    use yubikit::smartcard::ScpKeyParams;

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
            invalidate_scp11b_params();
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
            sk_oce_ecka: sk_oce.try_into().expect("sk_oce must be 32 bytes"),
            certificates,
            oce_ref: Some((oce_ref.kid, oce_ref.kvn)),
        }
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
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
    #[case(TestConnection::SmartCard)]
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
    #[case(TestConnection::SmartCard)]
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
    #[case(TestConnection::SmartCard)]
    fn test_scp03_authenticate(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let conn = session.into_connection();

        // Authenticate with default SCP03 keys (0x40..0x4F)
        let params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: std::array::from_fn(|i| 0x40 + i as u8),
            key_mac: std::array::from_fn(|i| 0x40 + i as u8),
            key_dek: Some(std::array::from_fn(|i| 0x40 + i as u8)),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP03 authentication with default keys");
        verify_auth(&mut session);
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
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
        let conn = session.into_connection();

        // Try authenticating with wrong keys
        let params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: [0x01u8; 16],
            key_mac: [0x01u8; 16],
            key_dek: Some([0x01u8; 16]),
        };
        let result = SecurityDomainSession::new_with_scp(conn, &params).map_err(|(e, _)| e);
        assert!(result.is_err(), "SCP03 with wrong keys should fail");
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_scp03_change_key(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let conn = session.into_connection();

        // Authenticate with default keys
        let default_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: std::array::from_fn(|i| 0x40 + i as u8),
            key_mac: std::array::from_fn(|i| 0x40 + i as u8),
            key_dek: Some(std::array::from_fn(|i| 0x40 + i as u8)),
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
        let new_keys = StaticKeys::new(new_enc, new_mac, Some(new_dek));
        session
            .put_key_static(new_ref, &new_keys, 0)
            .expect("put new SCP03 keys");
        let conn = session.into_connection();

        // Verify new keys work
        let new_params = ScpKeyParams::Scp03 {
            kvn: 0x02,
            key_enc: new_enc,
            key_mac: new_mac,
            key_dek: Some(new_dek),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &new_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth with new keys");
        verify_auth(&mut session);
        let conn = session.into_connection();

        // Verify old default keys no longer work
        let conn = match SecurityDomainSession::new_with_scp(conn, &default_params) {
            Err((_, conn)) => conn,
            Ok(_) => panic!("Default keys should fail after key change"),
        };

        // Reset to restore defaults
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        invalidate_scp11b_params();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_scp11b_ok(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
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
        let conn = session.into_connection();

        // Authenticate with SCP11b
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
    #[case(TestConnection::SmartCard)]
    fn test_scp11b_import(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let conn = session.into_connection();

        // Authenticate with SCP03 to get write access
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: std::array::from_fn(|i| 0x40 + i as u8),
            key_mac: std::array::from_fn(|i| 0x40 + i as u8),
            key_dek: Some(std::array::from_fn(|i| 0x40 + i as u8)),
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
        let conn = session.into_connection();

        // Authenticate with the imported SCP11b key
        let params = ScpKeyParams::Scp11b {
            kid: 0x13,
            kvn: 0x02,
            pk_sd_ecka: pk_bytes.as_bytes().to_vec(),
        };
        let session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11b auth with imported key");
        let conn = session.into_connection();

        // Clean up: reset to restore defaults
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        invalidate_scp11b_params();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_scp11a_ok(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let conn = session.into_connection();

        // Authenticate with SCP03
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: std::array::from_fn(|i| 0x40 + i as u8),
            key_mac: std::array::from_fn(|i| 0x40 + i as u8),
            key_dek: Some(std::array::from_fn(|i| 0x40 + i as u8)),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth for SCP11a setup");

        let kvn = 0x03;
        let params = load_scp11_keys(&mut session, ScpKid::Scp11a as u8, kvn);
        let conn = session.into_connection();

        // Authenticate with SCP11a
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11a authentication");

        // Verify full access by deleting the keys we created
        session
            .delete_key(0, kvn, false)
            .expect("delete keys by kvn");
        let conn = session.into_connection();

        // Reset to restore defaults
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        invalidate_scp11b_params();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_scp11a_allowlist(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let conn = session.into_connection();

        // Authenticate with SCP03
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: std::array::from_fn(|i| 0x40 + i as u8),
            key_mac: std::array::from_fn(|i| 0x40 + i as u8),
            key_dek: Some(std::array::from_fn(|i| 0x40 + i as u8)),
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
        let conn = session.into_connection();

        // Authenticate with SCP11a
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11a auth with allowlist");

        // Verify by deleting keys
        session
            .delete_key(0, kvn, false)
            .expect("delete keys by kvn");
        let conn = session.into_connection();

        // Reset to restore defaults
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        invalidate_scp11b_params();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_scp11a_allowlist_blocked(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let conn = session.into_connection();

        // Authenticate with SCP03
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: std::array::from_fn(|i| 0x40 + i as u8),
            key_mac: std::array::from_fn(|i| 0x40 + i as u8),
            key_dek: Some(std::array::from_fn(|i| 0x40 + i as u8)),
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
        let new_keys = StaticKeys::new(new_enc, new_mac, Some(new_dek));
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
        let conn = session.into_connection();

        // Attempt SCP11a auth — should fail due to wrong allowlist
        let conn = match SecurityDomainSession::new_with_scp(conn, &params) {
            Err((_, conn)) => conn,
            Ok(_) => panic!("SCP11a should fail with wrong allowlist"),
        };

        // Remove allowlist by authenticating with new SCP03 keys
        let new_scp03_params = ScpKeyParams::Scp03 {
            kvn: 0x02,
            key_enc: new_enc,
            key_mac: new_mac,
            key_dek: Some(new_dek),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &new_scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth with new keys to remove allowlist");
        session
            .store_allowlist(oce_ref, &[])
            .expect("remove allowlist");
        let conn = session.into_connection();

        // Now SCP11a should work
        let session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11a auth after removing allowlist");
        let conn = session.into_connection();

        // Reset to restore defaults
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        invalidate_scp11b_params();
        eprintln!("  PASS {tc:?}");
    }

    #[rstest]
    #[case(TestConnection::SmartCard)]
    fn test_scp11c_ok(#[case] tc: TestConnection) {
        skip_if_needed!(tc);
        require_version!(Version(5, 7, 2));
        let conn = open_smartcard_connection(&tc);
        let mut session = match SecurityDomainSession::new(conn) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  SKIP {tc:?}: SecurityDomain not available on this device");
                return;
            }
        };
        ensure_default_keys(&mut session);
        let conn = session.into_connection();

        // Authenticate with SCP03
        let scp03_params = ScpKeyParams::Scp03 {
            kvn: 0xFF,
            key_enc: std::array::from_fn(|i| 0x40 + i as u8),
            key_mac: std::array::from_fn(|i| 0x40 + i as u8),
            key_dek: Some(std::array::from_fn(|i| 0x40 + i as u8)),
        };
        let mut session = SecurityDomainSession::new_with_scp(conn, &scp03_params)
            .map_err(|(e, _)| e)
            .expect("SCP03 auth for SCP11c setup");

        let kvn = 0x03;
        let params = load_scp11_keys(&mut session, ScpKid::Scp11c as u8, kvn);
        let conn = session.into_connection();

        // Authenticate with SCP11c
        let mut session = SecurityDomainSession::new_with_scp(conn, &params)
            .map_err(|(e, _)| e)
            .expect("SCP11c authentication");

        // SCP11c grants read-only access; delete_key should fail
        let result = session.delete_key(0, kvn, false);
        assert!(
            result.is_err(),
            "SCP11c should not allow key deletion (read-only)"
        );
        let conn = session.into_connection();

        // Reset to restore defaults
        let mut session = SecurityDomainSession::new(conn).expect("open session for reset");
        session.reset().expect("reset");
        invalidate_scp11b_params();
        eprintln!("  PASS {tc:?}");
    }
}
