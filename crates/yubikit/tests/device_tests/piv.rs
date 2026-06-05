use super::*;
use x509_cert::der::{Decode, Encode};
use yubikit::piv::{
    DEFAULT_MANAGEMENT_KEY, HashAlgorithm, KeyType, ManagementKey, PinPolicy, PivPin, PivSession,
    PivSignature, PivSigner, Slot, TouchPolicy,
};

fn open_piv_session(tc: &TestConnection) -> PivSession<PcscSmartCardConnection> {
    let conn = open_smartcard_connection(tc);
    if let Some((kid, kvn, pk)) = scp_params(tc) {
        let params = make_scp_key_params(kid, kvn, &pk);
        match PivSession::new_with_scp(conn, &params) {
            Ok(s) => s,
            Err((e, _)) => panic!("PivSession with SCP: {e:?}"),
        }
    } else {
        PivSession::new(conn).expect("PivSession::new")
    }
}

fn default_piv_pin() -> PivPin {
    PivPin::new("123456").unwrap()
}

/// PIN to use for FIPS keys where the default must be changed.
/// FIPS requires minimum 8-character PINs.
fn fips_piv_pin() -> PivPin {
    PivPin::new("97463218").unwrap()
}

fn fips_piv_puk() -> PivPin {
    PivPin::new("83726145").unwrap()
}

/// Get the effective PIN (FIPS keys require changing from default).
fn effective_piv_pin() -> PivPin {
    if device_is_fips() {
        fips_piv_pin()
    } else {
        default_piv_pin()
    }
}

fn default_management_key_for(session: &PivSession<PcscSmartCardConnection>) -> ManagementKey {
    let key_type = session.management_key_type();
    ManagementKey::new(key_type, DEFAULT_MANAGEMENT_KEY).unwrap()
}

/// Non-default management key for FIPS (AES-128).
const FIPS_MGMT_KEY: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];

/// Get the effective management key.
fn effective_management_key(session: &PivSession<PcscSmartCardConnection>) -> ManagementKey {
    if device_is_fips() {
        ManagementKey::new(yubikit::piv::ManagementKeyType::Aes128, &FIPS_MGMT_KEY).unwrap()
    } else {
        default_management_key_for(session)
    }
}

/// After reset on FIPS keys, change PIN/PUK/management key from defaults.
/// FIPS requires all defaults to be changed before crypto operations are allowed,
/// and PINs must be at least 8 characters.
fn fips_init_piv(session: &mut PivSession<PcscSmartCardConnection>) {
    if !device_is_fips() {
        return;
    }
    session
        .authenticate(&default_management_key_for(session))
        .expect("FIPS: authenticate mgmt key");
    session
        .change_pin(&default_piv_pin(), &fips_piv_pin())
        .expect("FIPS: change PIN from default");
    session
        .change_puk(&PivPin::new("12345678").unwrap(), &fips_piv_puk())
        .expect("FIPS: change PUK from default");
    // Change management key to AES-128
    let new_mgmt =
        ManagementKey::new(yubikit::piv::ManagementKeyType::Aes128, &FIPS_MGMT_KEY).unwrap();
    session
        .set_management_key(&new_mgmt, false)
        .expect("FIPS: change management key");
}

/// Reset PIV and perform FIPS initialization if needed.
fn reset_piv(session: &mut PivSession<PcscSmartCardConnection>) {
    session.reset().expect("reset");
    fips_init_piv(session);
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_session_version(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    let session = open_piv_session(&tc);
    let _v = session.version();
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_verify_default_pin(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    session
        .verify_pin(&effective_piv_pin())
        .expect("verify default PIN");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_pin_attempts(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let attempts = session.get_pin_attempts().expect("get_pin_attempts");
    assert!(attempts > 0, "Expected positive PIN attempts");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_generate_key_ec_p256(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_generate_key_rsa2048(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");

    match session.generate_key(
        Slot::Retired1,
        KeyType::Rsa2048,
        PinPolicy::Default,
        TouchPolicy::Never,
    ) {
        Ok(spki_der) => {
            assert!(!spki_der.is_empty());
            assert!(spki_der.len() > 256, "RSA SPKI should be large");
        }
        Err(e) if has_sw(&e, 0x6A80) || is_conditions_not_satisfied(&e) => {
            skip!("RSA2048 not supported on this device (FIPS may require RSA3072+)");
        }
        Err(e) => panic!("generate_key: {e}"),
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_sign_ec_p256(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");

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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_self_signed_cert_ec(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");

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
    let cert_sig = Signature::from_der(parsed.signature.raw_bytes()).expect("parse cert signature");
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_generate_csr(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");

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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_self_signed_cert_rsa(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");

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
    let rsa_pub = rsa::RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA public key");
    let vk = VerifyingKey::<sha2::Sha256>::new(rsa_pub);
    let tbs_der = parsed.tbs_certificate.to_der().expect("encode TBS");
    let sig = Signature::try_from(parsed.signature.raw_bytes()).expect("parse RSA signature");
    vk.verify(&tbs_der, &sig)
        .expect("RSA certificate signature verification");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_decrypt_rsa(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");

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
    let rsa_pub = rsa::RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA public key");
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_ecdh_p256(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(4, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");

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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_generate_mldsa44(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(6, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
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

    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");
    let sig = session
        .sign(Slot::Authentication, KeyType::MlDsa44, b"test message")
        .expect("sign MlDsa44");
    assert!(!sig.is_empty());
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_generate_mlkem768(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(6, 0, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_mldsa44_verify(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(6, 0, 0));
    require_capability!(Capability::PIV);

    use ml_dsa::{MlDsa44, Signature, VerifyingKey, common::KeyInit, signature::Verifier};
    use x509_cert::der::Decode;
    use x509_cert::spki::SubjectPublicKeyInfoRef;

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
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
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_mlkem768_decapsulate(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(6, 0, 0));
    require_capability!(Capability::PIV);

    use ml_kem::EncapsulationKey768;
    use x509_cert::der::Decode;
    use x509_cert::spki::SubjectPublicKeyInfoRef;

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
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
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify PIN");
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
}

/// Test PIV PIN change, wrong PIN rejection, and PUK unblock.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_pin_management(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let current_pin = effective_piv_pin();
    let current_puk = if device_is_fips() {
        fips_piv_puk()
    } else {
        PivPin::new("12345678").unwrap()
    };
    let new_pin = PivPin::new("71829364").unwrap();

    // Change PIN
    match session.change_pin(&current_pin, &new_pin) {
        Ok(()) => {}
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("PIN complexity rejected new PIN");
        }
        Err(e) => panic!("change_pin: {e}"),
    }

    // Old PIN should fail
    assert!(session.verify_pin(&current_pin).is_err());

    // New PIN should work
    session.verify_pin(&new_pin).expect("verify new PIN");

    // Wrong PIN should decrement attempts
    let wrong = PivPin::new("99887766").unwrap();
    assert!(session.verify_pin(&wrong).is_err());
    let attempts = session.get_pin_attempts().expect("get_pin_attempts");
    assert!(attempts < 3, "attempts should have decreased from 3");

    // Block PIN by exhausting retries
    for _ in 0..attempts {
        let _ = session.verify_pin(&wrong);
    }
    assert!(
        session.verify_pin(&new_pin).is_err(),
        "PIN should be blocked"
    );

    // Unblock with PUK
    let unblocked_pin = PivPin::new("83726145").unwrap();
    match session.unblock_pin(&current_puk, &unblocked_pin) {
        Ok(()) => {}
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("PIN complexity rejected unblocked PIN");
        }
        Err(e) => panic!("unblock_pin: {e}"),
    }
    session
        .verify_pin(&unblocked_pin)
        .expect("verify unblocked PIN");
}

/// Test PIV key attestation and slot metadata.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_attest_and_metadata(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 3, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");

    // Generate a key
    session
        .generate_key(
            Slot::Retired2,
            KeyType::EccP256,
            PinPolicy::Default,
            TouchPolicy::Never,
        )
        .expect("generate_key");

    // Attest key
    let cert_der = session.attest_key(Slot::Retired2).expect("attest_key");
    assert!(!cert_der.is_empty(), "attestation cert should not be empty");
    // Attestation cert is DER-encoded X.509
    assert_eq!(cert_der[0], 0x30, "should start with SEQUENCE tag");

    // Get slot metadata
    let meta = session
        .get_slot_metadata(Slot::Retired2)
        .expect("get_slot_metadata");
    assert_eq!(meta.key_type, KeyType::EccP256);
}

/// Test PIV management key change and PIN/PUK metadata.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_management_key_and_metadata(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 3, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");

    // Get metadata - on non-FIPS should show default key, on FIPS already changed
    let mk_meta = session
        .get_management_key_metadata()
        .expect("get_management_key_metadata");
    if !device_is_fips() {
        assert!(mk_meta.default_value, "should be default after reset");
    } else {
        assert!(!mk_meta.default_value, "FIPS key was changed from default");
    }

    // Get PIN metadata
    let pin_meta = session.get_pin_metadata().expect("get_pin_metadata");
    assert!(pin_meta.attempts_remaining > 0);

    // Get PUK metadata
    let puk_meta = session.get_puk_metadata().expect("get_puk_metadata");
    assert!(puk_meta.attempts_remaining > 0);

    // Change management key
    let key_type = session.management_key_type();
    let new_key_bytes: Vec<u8> = match key_type {
        yubikit::piv::ManagementKeyType::Tdes | yubikit::piv::ManagementKeyType::Aes192 => {
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            ]
        }
        yubikit::piv::ManagementKeyType::Aes256 => vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ],
        _ => vec![
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30,
        ],
    };
    let new_key = ManagementKey::new(key_type, &new_key_bytes).unwrap();
    session
        .set_management_key(&new_key, false)
        .expect("set_management_key");

    // Old key should fail
    let old_key = effective_management_key(&session);
    assert!(
        session.authenticate(&old_key).is_err(),
        "old key should fail"
    );

    // New key should work
    session.authenticate(&new_key).expect("auth with new key");

    // Metadata should no longer show default
    let mk_meta2 = session
        .get_management_key_metadata()
        .expect("get_management_key_metadata");
    assert!(
        !mk_meta2.default_value,
        "should not be default after change"
    );
}

/// Test PIV key move and delete operations.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_move_and_delete_key(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 0));
    require_capability!(Capability::PIV);
    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);
    session
        .authenticate(&effective_management_key(&session))
        .expect("authenticate");

    // Generate key in Retired3
    session
        .generate_key(
            Slot::Retired3,
            KeyType::EccP256,
            PinPolicy::Default,
            TouchPolicy::Never,
        )
        .expect("generate_key");

    // Move to Retired4
    session
        .move_key(Slot::Retired3, Slot::Retired4)
        .expect("move_key");

    // Retired3 should be empty now
    assert!(
        session.get_slot_metadata(Slot::Retired3).is_err(),
        "source slot should be empty after move"
    );

    // Retired4 should have the key
    let meta = session
        .get_slot_metadata(Slot::Retired4)
        .expect("get_slot_metadata Retired4");
    assert_eq!(meta.key_type, KeyType::EccP256);

    // Delete key
    session.delete_key(Slot::Retired4).expect("delete_key");
    assert!(
        session.get_slot_metadata(Slot::Retired4).is_err(),
        "slot should be empty after delete"
    );
}

/// Test P-384 key generation and ECDSA signing.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_generate_and_sign_ec_p384(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    require_version!(Version(4, 0, 0));

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let mgmt_key = effective_management_key(&session);
    session.authenticate(&mgmt_key).expect("authenticate");

    let pub_key_der = session
        .generate_key(
            Slot::Retired1,
            KeyType::EccP384,
            PinPolicy::Default,
            TouchPolicy::Never,
        )
        .expect("generate P-384 key");
    assert!(!pub_key_der.is_empty(), "Expected public key data");

    // Sign with P-384
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify_pin");
    let message = b"P-384 test message";
    let hash = {
        use sha2::Digest;
        sha2::Sha384::digest(message)
    };
    let signature = session
        .sign(Slot::Retired1, KeyType::EccP384, &hash)
        .expect("sign P-384");
    assert!(!signature.is_empty(), "Expected signature data");

    // Verify the signature
    use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let raw_key = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&pub_key_der)
        .unwrap()
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec();
    let vk = VerifyingKey::from_sec1_bytes(&raw_key).expect("parse P-384 public key");
    let sig = Signature::from_der(&signature).expect("parse P-384 signature");
    vk.verify(message.as_slice(), &sig)
        .expect("P-384 signature verification");
}

/// Test Ed25519 key generation and signing.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_generate_and_sign_ed25519(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    require_version!(Version(5, 7, 0));

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let mgmt_key = effective_management_key(&session);
    session.authenticate(&mgmt_key).expect("authenticate");

    let pub_key_der = session
        .generate_key(
            Slot::Retired2,
            KeyType::Ed25519,
            PinPolicy::Default,
            TouchPolicy::Never,
        )
        .expect("generate Ed25519 key");
    assert!(!pub_key_der.is_empty(), "Expected public key data");

    // Sign with Ed25519
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify_pin");
    let message = b"Ed25519 test message";
    let signature = session
        .sign(Slot::Retired2, KeyType::Ed25519, message)
        .expect("sign Ed25519");
    assert!(!signature.is_empty(), "Expected signature data");

    // Verify the signature
    use ed25519_dalek::Verifier as _;
    use ed25519_dalek::{Signature as Ed25519Sig, VerifyingKey as Ed25519Vk};
    let raw_key = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&pub_key_der)
        .unwrap()
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec();
    let vk_bytes: [u8; 32] = raw_key
        .try_into()
        .expect("Ed25519 public key should be 32 bytes");
    let vk = Ed25519Vk::from_bytes(&vk_bytes).expect("parse Ed25519 public key");
    let sig = Ed25519Sig::from_slice(&signature).expect("parse Ed25519 signature");
    vk.verify(message, &sig)
        .expect("Ed25519 signature verification");
}

/// Test X25519 key generation and ECDH key agreement.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_x25519_key_agreement(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    require_version!(Version(5, 7, 0));

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let mgmt_key = effective_management_key(&session);
    session.authenticate(&mgmt_key).expect("authenticate");

    let spki_der = session
        .generate_key(
            Slot::Retired3,
            KeyType::X25519,
            PinPolicy::Default,
            TouchPolicy::Never,
        )
        .expect("generate X25519 key");
    let pub_key_bytes = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .unwrap()
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec();
    assert_eq!(
        pub_key_bytes.len(),
        32,
        "X25519 public key should be 32 bytes"
    );

    // Generate an ephemeral client key and perform key agreement
    use x25519_dalek::{EphemeralSecret, PublicKey};
    let client_secret = EphemeralSecret::random_from_rng(p256::elliptic_curve::rand_core::OsRng);
    let client_public = PublicKey::from(&client_secret);

    session
        .verify_pin(&effective_piv_pin())
        .expect("verify_pin");
    let shared_from_device = session
        .calculate_secret(Slot::Retired3, KeyType::X25519, client_public.as_bytes())
        .expect("X25519 key agreement");
    assert_eq!(
        shared_from_device.len(),
        32,
        "X25519 shared secret should be 32 bytes"
    );

    // Compute expected shared secret from the other side
    let device_pub: [u8; 32] = pub_key_bytes.try_into().unwrap();
    let device_public = PublicKey::from(device_pub);
    let shared_from_client = client_secret.diffie_hellman(&device_public);
    assert_eq!(
        shared_from_device,
        shared_from_client.as_bytes(),
        "X25519 shared secret mismatch"
    );
}

/// Test PIV PIN policy enforcement: PinPolicy::Always requires PIN for every operation.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_pin_policy_always(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    require_version!(Version(4, 0, 0));

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let mgmt_key = effective_management_key(&session);
    session.authenticate(&mgmt_key).expect("authenticate");

    // Generate key with PinPolicy::Always
    match session.generate_key(
        Slot::Retired1,
        KeyType::EccP256,
        PinPolicy::Always,
        TouchPolicy::Never,
    ) {
        Ok(_) => {}
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("PinPolicy::Always not supported: {e}");
        }
        Err(e) => panic!("generate_key: {e}"),
    }

    // Attempt signing without PIN — should fail
    let hash = <sha2::Sha256 as sha2::Digest>::digest(b"test");
    let result = session.sign(Slot::Retired1, KeyType::EccP256, &hash);
    assert!(
        result.is_err(),
        "Sign without PIN should fail with Always policy"
    );

    // Verify PIN and sign — should succeed
    session
        .verify_pin(&effective_piv_pin())
        .expect("verify_pin");
    session
        .sign(Slot::Retired1, KeyType::EccP256, &hash)
        .expect("sign after PIN");
}

/// Test PIV PIN policy: PinPolicy::Never allows signing without PIN.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_pin_policy_never(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    require_version!(Version(4, 0, 0));

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let mgmt_key = effective_management_key(&session);
    session.authenticate(&mgmt_key).expect("authenticate");

    // Generate key with PinPolicy::Never
    match session.generate_key(
        Slot::Retired1,
        KeyType::EccP256,
        PinPolicy::Never,
        TouchPolicy::Never,
    ) {
        Ok(_) => {}
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("PinPolicy::Never not supported on this key: {e}");
        }
        Err(e) => panic!("generate_key: {e}"),
    }

    // Sign without verifying PIN — should succeed with Never policy
    let hash = <sha2::Sha256 as sha2::Digest>::digest(b"test no pin");
    session
        .sign(Slot::Retired1, KeyType::EccP256, &hash)
        .expect("sign without PIN (Never policy)");
}

/// Test that PIV operations requiring authentication fail without it.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_auth_required(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);

    let mut session = open_piv_session(&tc);
    // Don't authenticate — operations should fail

    // generate_key requires management authentication
    let result = session.generate_key(
        Slot::Retired1,
        KeyType::EccP256,
        PinPolicy::Default,
        TouchPolicy::Never,
    );
    assert!(result.is_err(), "generate_key without auth should fail");
    assert!(
        has_sw(&result.unwrap_err(), 0x6982),
        "Expected security status not satisfied (0x6982)"
    );
}

/// Test PIV certificate compression (storing a cert with compression flag).
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_piv_compressed_cert(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::PIV);
    require_version!(Version(5, 3, 0));

    let mut session = open_piv_session(&tc);
    reset_piv(&mut session);

    let mgmt_key = effective_management_key(&session);
    session.authenticate(&mgmt_key).expect("authenticate");

    // Generate a key and create a self-signed cert
    let pub_key = session
        .generate_key(
            Slot::Retired1,
            KeyType::EccP256,
            PinPolicy::Default,
            TouchPolicy::Never,
        )
        .expect("generate_key");

    session
        .verify_pin(&effective_piv_pin())
        .expect("verify_pin");

    // Create a minimal self-signed cert
    let spki_der = pub_key;
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&spki_der).expect("parse SPKI");
    let signer = PivSigner::new(
        &mut session,
        Slot::Retired1,
        KeyType::EccP256,
        HashAlgorithm::Sha256,
        &spki_der,
    );
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    let subject: Name = "CN=Compress Test".parse().unwrap();
    let serial = SerialNumber::new(&[0x01]).unwrap();
    let validity = Validity::from_now(core::time::Duration::new(365 * 86400, 0)).unwrap();

    let cert = CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &signer)
        .expect("CertificateBuilder")
        .build::<PivSignature>()
        .expect("build cert");
    let cert_der = cert.to_der().expect("cert to DER");

    // Store with compression enabled
    session
        .put_certificate(Slot::Retired1, &cert_der, true)
        .expect("put_certificate compressed");

    // Retrieve and verify it decompresses correctly
    let retrieved = session
        .get_certificate(Slot::Retired1)
        .expect("get_certificate");
    assert_eq!(
        retrieved, cert_der,
        "Retrieved cert should match original after decompression"
    );
}
