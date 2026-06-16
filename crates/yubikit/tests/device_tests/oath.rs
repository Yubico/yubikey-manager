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

/// On FIPS keys, set an access key after reset so operations are allowed.
fn reset_oath(session: &mut OathSession<PcscSmartCardConnection>) {
    if device_is_fips() && get_device().transport() == Transport::Nfc {
        skip!("OATH blocked on FIPS+NFC");
    }
    session.reset().expect("reset");
    if device_is_fips() {
        let key = session.derive_key("fips-test-password");
        session.set_key(&key).expect("FIPS: set OATH access key");
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_session_version(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let session = open_oath_session(&tc);
    let _v = session.version();
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_reset_and_list(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

    let creds = session.list_credentials().expect("list_credentials");
    assert!(creds.is_empty(), "Expected no credentials after reset");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_put_list_delete(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

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

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_calculate_all(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

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

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_access_key_lifecycle(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    if device_is_fips() && get_device().transport() == Transport::Nfc {
        skip!("OATH blocked on FIPS+NFC");
    }
    session.reset().expect("reset");

    if device_is_fips() {
        // FIPS requires an access key to be set before operations.
        // However, set_key is blocked over NFC even with SCP.
        let key = session.derive_key("fips_password");
        session.set_key(&key).expect("set_key");

        // Re-open — should be locked
        drop(session);
        let mut session = open_oath_session(&tc);
        assert!(session.has_key());
        assert!(session.locked());

        // Validate
        let key = session.derive_key("fips_password");
        session.validate(&key).expect("validate");
        session.list_credentials().expect("list after validate");

        // FIPS doesn't allow unset_key, so just verify we can change the key
        let new_key = session.derive_key("new_fips_password");
        session.set_key(&new_key).expect("change key");

        // Clean up
        session.reset().expect("reset");
        let key = session.derive_key("cleanup");
        session.set_key(&key).expect("FIPS cleanup set_key");
    } else {
        // Non-FIPS: full lifecycle including unset_key
        assert!(!session.has_key());
        assert!(!session.locked());

        let key = session.derive_key("test_password");
        session.set_key(&key).expect("set_key");

        // Re-open — should be locked
        drop(session);
        let mut session = open_oath_session(&tc);
        assert!(session.has_key());
        assert!(session.locked());

        // Validate
        let key = session.derive_key("test_password");
        session.validate(&key).expect("validate");
        session.list_credentials().expect("list after validate");

        // Remove the key
        session.unset_key().expect("unset_key");

        // Re-open — should be unlocked
        drop(session);
        let mut session = open_oath_session(&tc);
        assert!(!session.has_key());
        assert!(!session.locked());

        session.reset().expect("reset");
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_rename_credential(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

    let cred_data = CredentialData {
        name: "original@test.com".into(),
        oath_type: OathType::Totp,
        hash_algorithm: HashAlgorithm::Sha1,
        secret: b"12345678901234567890".to_vec(),
        digits: 6,
        period: 30,
        counter: 0,
        issuer: Some("OldIssuer".into()),
    };
    session
        .put_credential(&cred_data, false)
        .expect("put_credential");

    session
        .rename_credential(&cred_data.get_id(), "renamed@test.com", Some("NewIssuer"))
        .expect("rename_credential");

    let creds = session.list_credentials().expect("list");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].issuer.as_deref(), Some("NewIssuer"));
    assert_eq!(creds[0].name, "renamed@test.com");

    reset_oath(&mut session);
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_calculate_single(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

    // Add HOTP credential
    let hotp_data = CredentialData {
        name: "hotp@test.com".into(),
        oath_type: OathType::Hotp,
        hash_algorithm: HashAlgorithm::Sha1,
        secret: b"12345678901234567890".to_vec(),
        digits: 6,
        period: 0,
        counter: 0,
        issuer: None,
    };
    let hotp_cred = session.put_credential(&hotp_data, false).expect("put hotp");

    // Calculate HOTP — should give different codes on successive calls
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code1 = session
        .calculate_code(&hotp_cred, now)
        .expect("calculate hotp 1");
    let code2 = session
        .calculate_code(&hotp_cred, now)
        .expect("calculate hotp 2");
    assert_ne!(code1.value, code2.value, "HOTP counter should advance");

    // Add TOTP with SHA-256
    let totp_sha256 = CredentialData {
        name: "totp256@test.com".into(),
        oath_type: OathType::Totp,
        hash_algorithm: HashAlgorithm::Sha256,
        secret: b"12345678901234567890123456789012".to_vec(),
        digits: 8,
        period: 30,
        counter: 0,
        issuer: None,
    };
    let totp_cred = session
        .put_credential(&totp_sha256, false)
        .expect("put totp256");

    let code = session
        .calculate_code(&totp_cred, now)
        .expect("calculate totp256");
    assert_eq!(code.value.len(), 8, "Expected 8-digit code");

    reset_oath(&mut session);
}

/// Test HOTP with RFC 4226 test vectors.
/// Secret: "12345678901234567890" (ASCII), counter starts at 0.
/// Expected codes for counters 0-4: 755224, 287082, 359152, 969429, 338314
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_hotp_rfc4226_vectors(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

    let expected = ["755224", "287082", "359152", "969429", "338314"];

    let cred_data = CredentialData {
        name: "rfc4226@test".into(),
        oath_type: OathType::Hotp,
        hash_algorithm: HashAlgorithm::Sha1,
        secret: b"12345678901234567890".to_vec(),
        digits: 6,
        period: 0,
        counter: 0,
        issuer: None,
    };
    let cred = session
        .put_credential(&cred_data, false)
        .expect("put_credential");

    for (i, exp) in expected.iter().enumerate() {
        let code = session.calculate_code(&cred, 0).expect("calculate_code");
        assert_eq!(
            &code.value, exp,
            "HOTP counter {i}: expected {exp}, got {}",
            code.value
        );
    }

    reset_oath(&mut session);
}

/// Test TOTP with SHA-256, verifying consistency: same timestamp → same code.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_totp_sha256_consistency(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

    let cred_data = CredentialData {
        name: "sha256-totp@test".into(),
        oath_type: OathType::Totp,
        hash_algorithm: HashAlgorithm::Sha256,
        secret: b"12345678901234567890123456789012".to_vec(),
        digits: 8,
        period: 30,
        counter: 0,
        issuer: None,
    };
    let cred = session
        .put_credential(&cred_data, false)
        .expect("put_credential");

    // Use a fixed timestamp for reproducibility
    let timestamp = 59;
    let code1 = session
        .calculate_code(&cred, timestamp)
        .expect("calculate 1");
    let code2 = session
        .calculate_code(&cred, timestamp)
        .expect("calculate 2");

    assert_eq!(code1.value.len(), 8, "Expected 8-digit code");
    assert_eq!(
        code1.value, code2.value,
        "Same timestamp should give same code"
    );

    // Verify a different time step gives a different code
    let code3 = session
        .calculate_code(&cred, timestamp + 30)
        .expect("calculate next step");
    assert_ne!(
        code1.value, code3.value,
        "Different time step should give different code"
    );

    reset_oath(&mut session);
}

/// Test OATH with SHA-512 algorithm (covers all hash algorithm variants).
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_oath_totp_sha512(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OATH);
    let mut session = open_oath_session(&tc);
    reset_oath(&mut session);

    let cred_data = CredentialData {
        name: "sha512@test".into(),
        oath_type: OathType::Totp,
        hash_algorithm: HashAlgorithm::Sha512,
        secret: vec![0x31; 64], // 64-byte key for SHA-512
        digits: 8,
        period: 30,
        counter: 0,
        issuer: None,
    };
    let cred = session
        .put_credential(&cred_data, false)
        .expect("put_credential");

    let code = session.calculate_code(&cred, 59).expect("calculate");
    assert_eq!(code.value.len(), 8);

    reset_oath(&mut session);
}
