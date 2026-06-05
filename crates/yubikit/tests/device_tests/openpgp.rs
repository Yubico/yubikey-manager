use super::*;
use yubikit::openpgp::{OpenPgpPin, OpenPgpSession};

fn open_openpgp_session(tc: &TestConnection) -> OpenPgpSession<PcscSmartCardConnection> {
    let conn = open_smartcard_connection(tc);
    if let Some((kid, kvn, pk)) = scp_params(tc) {
        let params = make_scp_key_params(kid, kvn, &pk);
        OpenPgpSession::new_with_scp(conn, &params).expect("OpenPgpSession with SCP")
    } else {
        OpenPgpSession::new(conn).expect("OpenPgpSession::new")
    }
}

fn default_admin_pin() -> OpenPgpPin {
    OpenPgpPin::new(yubikit::openpgp::DEFAULT_ADMIN_PIN)
}

fn default_user_pin() -> OpenPgpPin {
    OpenPgpPin::new(yubikit::openpgp::DEFAULT_USER_PIN)
}

fn fips_user_pin() -> OpenPgpPin {
    OpenPgpPin::new("97463218")
}

fn fips_admin_pin() -> OpenPgpPin {
    OpenPgpPin::new("8372614597")
}

fn effective_user_pin() -> OpenPgpPin {
    if device_is_fips() {
        fips_user_pin()
    } else {
        default_user_pin()
    }
}

fn effective_admin_pin() -> OpenPgpPin {
    if device_is_fips() {
        fips_admin_pin()
    } else {
        default_admin_pin()
    }
}

/// Reset OpenPGP and change default PINs on FIPS keys.
fn reset_openpgp(session: &mut OpenPgpSession<PcscSmartCardConnection>) {
    session.reset().expect("reset");
    if device_is_fips() {
        // FIPS requires admin auth before PIN changes
        session
            .verify_admin(&default_admin_pin())
            .expect("FIPS: verify admin");
        session
            .change_pin(&default_user_pin(), &fips_user_pin())
            .expect("FIPS: change user PIN");
        session
            .change_admin(&default_admin_pin(), &fips_admin_pin())
            .expect("FIPS: change admin PIN");
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_openpgp_session_version(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    let session = open_openpgp_session(&tc);
    let _v = session.version();
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_openpgp_get_challenge(#[case] tc: TestConnection) {
    use yubikit::openpgp::OpenPgpError;

    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    let mut session = open_openpgp_session(&tc);
    match session.get_challenge(8) {
        Ok(challenge) => {
            assert_eq!(challenge.len(), 8);
            assert!(challenge.iter().any(|&b| b != 0));
        }
        Err(OpenPgpError::NotSupported(_)) => {
            skip!("get_challenge not supported");
        }
        Err(e) => {
            panic!("get_challenge failed: {e}");
        }
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_openpgp_generate_ec_key_and_sign(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = open_openpgp_session(&tc);
    reset_openpgp(&mut session);
    session
        .verify_admin(&effective_admin_pin())
        .expect("verify admin");
    session
        .verify_pin(&effective_user_pin(), false)
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_openpgp_generate_rsa_key_and_sign(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    let mut session = open_openpgp_session(&tc);
    reset_openpgp(&mut session);
    session
        .verify_admin(&effective_admin_pin())
        .expect("verify admin");
    session
        .verify_pin(&effective_user_pin(), false)
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_openpgp_rsa_decrypt(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    let mut session = open_openpgp_session(&tc);
    reset_openpgp(&mut session);
    session
        .verify_admin(&effective_admin_pin())
        .expect("verify admin");
    session
        .verify_pin(&effective_user_pin(), true)
        .expect("verify PIN for decrypt");

    // Generate RSA 2048 decryption key
    let pk_data = match session.generate_rsa_key(
        yubikit::openpgp::KeyRef::Dec,
        yubikit::openpgp::RsaSize::Rsa2048,
    ) {
        Ok(data) => data,
        Err(e) if has_sw(&e, 0x6A80) || is_conditions_not_satisfied(&e) => {
            skip!("RSA2048 not supported on this device (FIPS may require larger keys)");
        }
        Err(e) => panic!("generate_rsa_key: {e}"),
    };

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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_openpgp_ec_ecdh(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = open_openpgp_session(&tc);
    reset_openpgp(&mut session);
    session
        .verify_admin(&effective_admin_pin())
        .expect("verify admin");
    session
        .verify_pin(&effective_user_pin(), true)
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_openpgp_pin_management(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    let mut session = open_openpgp_session(&tc);

    // Reset to known state
    session.reset().expect("reset");

    // Verify default user PIN
    session
        .verify_pin(&default_user_pin(), false)
        .expect("verify default pin");

    // Verify default admin PIN
    session
        .verify_admin(&default_admin_pin())
        .expect("verify default admin");

    // Get PIN status
    let status = session.get_pin_status().expect("get_pin_status");
    assert!(status.attempts_user > 0);

    // Change user PIN
    let new_pin = OpenPgpPin::new("974632");
    match session.change_pin(&default_user_pin(), &new_pin) {
        Ok(()) => {
            // Verify new PIN works
            session.verify_pin(&new_pin, false).expect("verify new pin");
        }
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("PIN complexity rejected new PIN");
        }
        Err(e) => panic!("change_pin: {e}"),
    }

    // Reset to restore defaults
    session.reset().expect("reset after pin change");

    // Change admin PIN
    session
        .verify_admin(&default_admin_pin())
        .expect("verify default admin after reset");
    let new_admin = OpenPgpPin::new("83726145");
    match session.change_admin(&default_admin_pin(), &new_admin) {
        Ok(()) => {
            session.verify_admin(&new_admin).expect("verify new admin");
        }
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("PIN complexity rejected new admin PIN");
        }
        Err(e) => panic!("change_admin: {e}"),
    }

    // Reset again to restore defaults for reset code test
    session.reset().expect("reset after admin change");

    // Set reset code and use it to reset PIN
    session
        .verify_admin(&default_admin_pin())
        .expect("verify admin for reset code");
    let reset_code = OpenPgpPin::new("83726145");
    match session.set_reset_code(&reset_code) {
        Ok(()) => {
            // Use wrong PIN 3 times to lock it
            let wrong = OpenPgpPin::new("000000");
            for _ in 0..3 {
                let _ = session.verify_pin(&wrong, false);
            }
            // Now reset PIN using reset code
            match session.reset_pin(&default_user_pin(), Some(&reset_code)) {
                Ok(()) => {
                    session
                        .verify_pin(&default_user_pin(), false)
                        .expect("verify after reset");
                }
                Err(e) if is_conditions_not_satisfied(&e) => {
                    // Can't reset to weak default PIN, just reset applet
                }
                Err(e) => panic!("reset_pin: {e}"),
            }
        }
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("PIN complexity rejected reset code");
        }
        Err(e) => panic!("set_reset_code: {e}"),
    }

    // Final reset to clean up
    session.reset().expect("final reset");
}
