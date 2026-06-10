use super::*;
use yubikit::keys::{EcCurve, EcPrivateKey, PrivateKey, RsaKeySize, RsaPrivateKey};
use yubikit::openpgp::{KeyRef, OpenPgpPin, OpenPgpSession};

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
    let pk = session
        .generate_ec_key(
            yubikit::openpgp::KeyRef::Sig,
            yubikit::openpgp::OpenPgpCurve::P256,
        )
        .expect("generate_ec_key");

    // Extract EC point from PublicKey
    let ec_point = match &pk {
        yubikit::keys::PublicKey::Ec { point, .. } => point.as_slice(),
        _ => panic!("Expected EC public key"),
    };
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
    let pk = session
        .generate_rsa_key(
            yubikit::openpgp::KeyRef::Sig,
            yubikit::keys::RsaKeySize::Rsa2048,
        )
        .expect("generate_rsa_key");

    // Extract modulus and exponent from PublicKey
    let (modulus_bytes, exponent_bytes) = match &pk {
        yubikit::keys::PublicKey::Rsa { n, e, .. } => (n.as_slice(), e.as_slice()),
        _ => panic!("Expected RSA public key"),
    };

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
    let pk = match session.generate_rsa_key(
        yubikit::openpgp::KeyRef::Dec,
        yubikit::keys::RsaKeySize::Rsa2048,
    ) {
        Ok(data) => data,
        Err(e) if has_sw(&e, 0x6A80) || is_conditions_not_satisfied(&e) => {
            skip!("RSA2048 not supported on this device (FIPS may require larger keys)");
        }
        Err(e) => panic!("generate_rsa_key: {e}"),
    };

    // Extract modulus and exponent
    let (modulus_bytes, exponent_bytes) = match &pk {
        yubikit::keys::PublicKey::Rsa { n, e, .. } => (n.as_slice(), e.as_slice()),
        _ => panic!("Expected RSA public key"),
    };
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
    let pk = session
        .generate_ec_key(
            yubikit::openpgp::KeyRef::Dec,
            yubikit::openpgp::OpenPgpCurve::P256,
        )
        .expect("generate_ec_key");

    // Extract EC point
    let ec_point = match &pk {
        yubikit::keys::PublicKey::Ec { point, .. } => point.as_slice(),
        _ => panic!("Expected EC public key"),
    };

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

// ---------------------------------------------------------------------------
// Key import tests
// ---------------------------------------------------------------------------

/// Helper: open session, reset, and verify admin + user PINs.
fn setup_for_import(tc: &TestConnection) -> OpenPgpSession<PcscSmartCardConnection> {
    let mut session = open_openpgp_session(tc);
    reset_openpgp(&mut session);
    session
        .verify_admin(&effective_admin_pin())
        .expect("verify admin");
    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN");
    session
}

#[rstest]
#[case::rsa_2048(TestConnection::SmartCard, 2048)]
#[case::rsa_3072(TestConnection::SmartCard, 3072)]
#[case::rsa_4096(TestConnection::SmartCard, 4096)]
fn test_import_rsa(#[case] tc: TestConnection, #[case] bits: usize) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    let mut session = setup_for_import(&tc);

    let key = generate_rsa_private_key(bits);
    session.put_key(KeyRef::Sig, &key).expect("put_key RSA");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let sig = session
        .sign(b"test", yubikit::openpgp::SignHashAlgorithm::Sha256)
        .expect("sign with imported RSA");
    assert!(!sig.is_empty());
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_ec_p256(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    let (key, vk) = generate_ec_private_key_p256();
    session
        .put_key(KeyRef::Sig, &key)
        .expect("put_key EC P-256");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let message = b"test";
    let sig = session
        .sign(message, yubikit::openpgp::SignHashAlgorithm::Sha256)
        .expect("sign with imported EC P-256");

    // Verify signature
    use ecdsa::signature::DigestVerifier;
    use sha2::Digest;
    let digest = sha2::Sha256::new_with_prefix(message);
    let ecdsa_sig =
        p256::ecdsa::Signature::from_bytes((&sig[..]).into()).expect("parse P-256 signature");
    vk.verify_digest(digest, &ecdsa_sig)
        .expect("P-256 signature verification");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_ec_p384(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    let (key, vk) = generate_ec_private_key_p384();
    session
        .put_key(KeyRef::Sig, &key)
        .expect("put_key EC P-384");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let message = b"test";
    let sig = session
        .sign(message, yubikit::openpgp::SignHashAlgorithm::Sha384)
        .expect("sign with imported EC P-384");

    use ecdsa::signature::DigestVerifier;
    use sha2::Digest;
    let digest = sha2::Sha384::new_with_prefix(message);
    let ecdsa_sig =
        p384::ecdsa::Signature::from_bytes((&sig[..]).into()).expect("parse P-384 signature");
    vk.verify_digest(digest, &ecdsa_sig)
        .expect("P-384 signature verification");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_ec_secp256k1(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    let (key, vk) = generate_ec_private_key_secp256k1();
    session
        .put_key(KeyRef::Sig, &key)
        .expect("put_key EC secp256k1");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let message = b"test";
    let sig = session
        .sign(message, yubikit::openpgp::SignHashAlgorithm::Sha256)
        .expect("sign with secp256k1");

    use ecdsa::signature::DigestVerifier;
    use sha2::Digest;
    let digest = sha2::Sha256::new_with_prefix(message);
    let ecdsa_sig =
        k256::ecdsa::Signature::from_bytes((&sig[..]).into()).expect("parse k256 signature");

    vk.verify_digest(digest, &ecdsa_sig)
        .expect("secp256k1 signature verification");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_ec_brainpool_p256r1(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    let key = generate_ec_private_key_bp256();
    session
        .put_key(KeyRef::Sig, &key)
        .expect("put_key EC BrainpoolP256r1");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let sig = session
        .sign(b"test", yubikit::openpgp::SignHashAlgorithm::Sha256)
        .expect("sign with BrainpoolP256r1");
    assert!(!sig.is_empty());
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_ec_brainpool_p384r1(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    let key = generate_ec_private_key_bp384();
    session
        .put_key(KeyRef::Sig, &key)
        .expect("put_key EC BrainpoolP384r1");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let sig = session
        .sign(b"test", yubikit::openpgp::SignHashAlgorithm::Sha384)
        .expect("sign with BrainpoolP384r1");
    assert!(!sig.is_empty());
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_ec_brainpool_p512r1(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    let key = generate_ec_private_key_bp512();
    session
        .put_key(KeyRef::Sig, &key)
        .expect("put_key EC BrainpoolP512r1");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let sig = session
        .sign(b"test", yubikit::openpgp::SignHashAlgorithm::Sha512)
        .expect("sign with BrainpoolP512r1");
    assert!(!sig.is_empty());
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_ed25519(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    let (key, vk) = generate_ed25519_private_key();
    session.put_key(KeyRef::Sig, &key).expect("put_key Ed25519");

    session
        .verify_pin(&effective_user_pin(), false)
        .expect("verify PIN for sign");
    let message = b"test";
    let sig = session
        .sign(message, yubikit::openpgp::SignHashAlgorithm::None)
        .expect("sign with imported Ed25519");
    assert_eq!(sig.len(), 64, "Ed25519 signature should be 64 bytes");

    // Verify signature
    use ed25519_dalek::Verifier;
    let ed_sig = ed25519_dalek::Signature::from_bytes(sig[..].try_into().unwrap());
    vk.verify(message, &ed_sig)
        .expect("Ed25519 signature verification");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_import_x25519(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OPENPGP);
    require_version!(Version(5, 2, 0));
    let mut session = setup_for_import(&tc);

    use x25519_dalek::StaticSecret;
    let secret = StaticSecret::random_from_rng(rsa::rand_core::OsRng);
    let key = PrivateKey::X25519 {
        secret: secret.to_bytes().to_vec(),
    };

    session.put_key(KeyRef::Dec, &key).expect("put_key X25519");

    // Verify we can do ECDH with the imported key
    session
        .verify_pin(&effective_user_pin(), true)
        .expect("verify PIN for decrypt");

    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
    let host_secret = EphemeralSecret::random_from_rng(rsa::rand_core::OsRng);
    let host_public = X25519PublicKey::from(&host_secret);

    let device_shared = session
        .decrypt(host_public.as_bytes())
        .expect("X25519 ECDH via decrypt");

    let device_public = X25519PublicKey::from(&secret);
    let host_shared = host_secret.diffie_hellman(&device_public).to_bytes();
    assert_eq!(
        host_shared, *device_shared,
        "X25519 shared secrets should match"
    );
    assert_eq!(
        device_shared.len(),
        32,
        "X25519 shared secret should be 32 bytes"
    );
}

// ---------------------------------------------------------------------------
// Key generation helpers
// ---------------------------------------------------------------------------

fn generate_rsa_private_key(bits: usize) -> PrivateKey {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).expect("generate RSA");
    let pub_key = private.to_public_key();
    let e = pub_key.e().to_bytes_be();
    let primes = private.primes();
    let p = primes[0].to_bytes_be();
    let q = primes[1].to_bytes_be();
    let key_size = RsaKeySize::from_bit_len(bits).expect("valid RSA key size");
    PrivateKey::Rsa(RsaPrivateKey {
        key_size,
        e,
        p,
        q,
        n: Vec::new(),
        dp: Vec::new(),
        dq: Vec::new(),
        qinv: Vec::new(),
    })
}

fn generate_ec_private_key_p256() -> (PrivateKey, p256::ecdsa::VerifyingKey) {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let scalar = secret.to_bytes().to_vec();
    let public_point = secret.public_key().to_encoded_point(false);
    let signing_key = p256::ecdsa::SigningKey::from(&secret);
    let vk = *signing_key.verifying_key();
    let key = PrivateKey::Ec(EcPrivateKey {
        curve: EcCurve::P256,
        scalar,
        public_key: Some(public_point.as_bytes().to_vec()),
    });
    (key, vk)
}

fn generate_ec_private_key_p384() -> (PrivateKey, p384::ecdsa::VerifyingKey) {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p384::SecretKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
    let scalar = secret.to_bytes().to_vec();
    let public_point = secret.public_key().to_encoded_point(false);
    let signing_key = p384::ecdsa::SigningKey::from(&secret);
    let vk = *signing_key.verifying_key();
    let key = PrivateKey::Ec(EcPrivateKey {
        curve: EcCurve::P384,
        scalar,
        public_key: Some(public_point.as_bytes().to_vec()),
    });
    (key, vk)
}

fn generate_ec_private_key_secp256k1() -> (PrivateKey, k256::ecdsa::VerifyingKey) {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = k256::SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let scalar = secret.to_bytes().to_vec();
    let public_point = secret.public_key().to_encoded_point(false);
    let signing_key = k256::ecdsa::SigningKey::from(&secret);
    let vk = *signing_key.verifying_key();
    let key = PrivateKey::Ec(EcPrivateKey {
        curve: EcCurve::Secp256k1,
        scalar,
        public_key: Some(public_point.as_bytes().to_vec()),
    });
    (key, vk)
}

/// Generate BrainpoolP256r1 key — bp256 lacks CurveArithmetic so no software
/// verification; we only check that the card accepts import + sign.
/// Order starts with 0xA9, so masking scalar[0] to 0x7F ensures scalar < order.
fn generate_ec_private_key_bp256() -> PrivateKey {
    use rsa::rand_core::RngCore;
    let mut scalar = vec![0u8; 32];
    rsa::rand_core::OsRng.fill_bytes(&mut scalar);
    scalar[0] &= 0x7F;
    scalar[31] |= 0x01; // ensure non-zero
    PrivateKey::Ec(EcPrivateKey {
        curve: EcCurve::BrainpoolP256r1,
        scalar,
        public_key: None,
    })
}

/// Generate BrainpoolP384r1 key — bp384 lacks CurveArithmetic so no software
/// verification; we only check that the card accepts import + sign.
/// Order starts with 0x8C, so masking scalar[0] to 0x7F ensures scalar < order.
fn generate_ec_private_key_bp384() -> PrivateKey {
    use rsa::rand_core::RngCore;
    let mut scalar = vec![0u8; 48];
    rsa::rand_core::OsRng.fill_bytes(&mut scalar);
    scalar[0] &= 0x7F;
    scalar[47] |= 0x01; // ensure non-zero
    PrivateKey::Ec(EcPrivateKey {
        curve: EcCurve::BrainpoolP384r1,
        scalar,
        public_key: None,
    })
}

/// Generate BrainpoolP512r1 key — no Rust crate available for verification,
/// so we only check that the card accepts import + sign.
/// Order starts with 0xAA, so masking scalar[0] to 0x7F ensures scalar < order.
fn generate_ec_private_key_bp512() -> PrivateKey {
    use rsa::rand_core::RngCore;
    let mut scalar = vec![0u8; 64];
    rsa::rand_core::OsRng.fill_bytes(&mut scalar);
    scalar[0] &= 0x7F;
    scalar[63] |= 0x01; // ensure non-zero
    PrivateKey::Ec(EcPrivateKey {
        curve: EcCurve::BrainpoolP512r1,
        scalar,
        public_key: None,
    })
}

fn generate_ed25519_private_key() -> (PrivateKey, ed25519_dalek::VerifyingKey) {
    use rsa::rand_core::RngCore;
    let mut secret = [0u8; 32];
    rsa::rand_core::OsRng.fill_bytes(&mut secret);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let key = PrivateKey::Ed25519 {
        secret: secret.to_vec(),
    };
    (key, verifying_key)
}
