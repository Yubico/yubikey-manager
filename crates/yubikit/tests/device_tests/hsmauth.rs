use super::*;
use yubikit::hsmauth::{
    CredentialPassword, DEFAULT_MANAGEMENT_KEY, HsmAuthManagementKey, HsmAuthSession,
};

fn open_hsmauth_session(tc: &TestConnection) -> HsmAuthSession<PcscSmartCardConnection> {
    let conn = open_smartcard_connection(tc);
    if let Some((kid, kvn, pk)) = scp_params(tc) {
        let params = make_scp_key_params(kid, kvn, &pk);
        HsmAuthSession::new_with_scp(conn, &params).expect("HsmAuthSession with SCP")
    } else {
        HsmAuthSession::new(conn).expect("HsmAuthSession::new")
    }
}

const FIPS_MANAGEMENT_KEY: [u8; 16] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF,
];

/// Get the effective management key — use default since FIPS key change may not work.
fn effective_hsmauth_mgmt_key() -> HsmAuthManagementKey {
    HsmAuthManagementKey::new(DEFAULT_MANAGEMENT_KEY).unwrap()
}

/// Reset HSMAuth and change management key on FIPS keys.
/// Returns the effective management key to use.
fn reset_hsmauth(session: &mut HsmAuthSession<PcscSmartCardConnection>) {
    session.reset().expect("reset");
    if device_is_fips() {
        let old_key = HsmAuthManagementKey::new(DEFAULT_MANAGEMENT_KEY).unwrap();
        let new_key = HsmAuthManagementKey::new(&FIPS_MANAGEMENT_KEY).unwrap();
        // On some FIPS keys, management key change may not be allowed
        if session.put_management_key(&old_key, &new_key).is_err() {
            // Fall back to using default key (some FIPS keys allow operations with default)
        }
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hsmauth_session_version(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::HSMAUTH);
    let session = open_hsmauth_session(&tc);
    let _v = session.version();
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hsmauth_reset_and_list(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::HSMAUTH);
    let mut session = open_hsmauth_session(&tc);
    session.reset().expect("reset");

    let creds = session.list_credentials().expect("list_credentials");
    assert!(creds.is_empty(), "Expected no credentials after reset");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hsmauth_credential_lifecycle(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::HSMAUTH);
    let mut session = open_hsmauth_session(&tc);
    reset_hsmauth(&mut session);

    let mgmt_key = effective_hsmauth_mgmt_key();
    let cred_pw = CredentialPassword::from_password("test-password");

    // Put symmetric credential with explicit keys
    let key_enc = [0x11u8; 16];
    let key_mac = [0x22u8; 16];
    let cred = match session
        .put_credential_symmetric(&mgmt_key, "sym-test", &key_enc, &key_mac, &cred_pw, false)
    {
        Ok(c) => c,
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("HSMAuth credential operations not available (FIPS restrictions)");
        }
        Err(e) => panic!("put_credential_symmetric: {e}"),
    };
    assert_eq!(cred.label, "sym-test");

    // Put derived credential
    let cred2 = session
        .put_credential_derived(
            &mgmt_key,
            "derived-test",
            "my-derivation-pw",
            &cred_pw,
            false,
        )
        .expect("put_credential_derived");
    assert_eq!(cred2.label, "derived-test");

    // List — should have 2
    let creds = session.list_credentials().expect("list");
    assert_eq!(creds.len(), 2);

    // Delete one
    session
        .delete_credential(&mgmt_key, "sym-test")
        .expect("delete_credential");
    let creds = session.list_credentials().expect("list after delete");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].label, "derived-test");

    // Calculate session keys with the derived credential
    let context = [0u8; 16];
    let keys = session
        .calculate_session_keys_symmetric("derived-test", &context, &cred_pw, None)
        .expect("calculate_session_keys_symmetric");
    // SessionKeys should have non-zero fields
    assert_ne!(keys.key_senc, [0u8; 16]);
    assert_ne!(keys.key_smac, [0u8; 16]);
    assert_ne!(keys.key_srmac, [0u8; 16]);

    // Clean up
    session.reset().expect("reset");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hsmauth_management_key(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::HSMAUTH);
    let mut session = open_hsmauth_session(&tc);
    session.reset().expect("reset");

    // Check retries
    let retries = session
        .get_management_key_retries()
        .expect("get_management_key_retries");
    assert!(retries > 0);

    // Change management key
    let old_key = HsmAuthManagementKey::new(DEFAULT_MANAGEMENT_KEY).expect("default mgmt key");
    let new_key_bytes = [0xAAu8; 16];
    let new_key = HsmAuthManagementKey::new(&new_key_bytes).expect("new mgmt key");
    match session.put_management_key(&old_key, &new_key) {
        Ok(()) => {
            // Verify new key works by using it for a put
            let cred_pw = CredentialPassword::from_password("test");
            session
                .put_credential_derived(&new_key, "key-test", "pw123", &cred_pw, false)
                .expect("put with new key");
        }
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("Management key change not allowed on this device");
        }
        Err(e) => panic!("put_management_key: {e}"),
    }

    // Clean up
    session.reset().expect("reset");
}

/// Test HSMAuth error handling: wrong credential password.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hsmauth_wrong_credential_password(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::HSMAUTH);
    let mut session = open_hsmauth_session(&tc);
    reset_hsmauth(&mut session);

    let mgmt_key = effective_hsmauth_mgmt_key();
    let cred_pw = CredentialPassword::from_password("correct-password");

    match session.put_credential_derived(&mgmt_key, "pw-test", "derivation-secret", &cred_pw, false)
    {
        Ok(_) => {}
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("HSMAuth credential operations not available");
        }
        Err(e) => panic!("put_credential_derived: {e}"),
    }

    // Try calculating session keys with wrong password
    let wrong_pw = CredentialPassword::from_password("wrong-password");
    let context = [0u8; 16];
    let result = session.calculate_session_keys_symmetric("pw-test", &context, &wrong_pw, None);
    assert!(result.is_err(), "Wrong password should fail");

    session.reset().expect("reset");
}

/// Test HSMAuth error handling: wrong management key.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hsmauth_wrong_management_key(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::HSMAUTH);
    let mut session = open_hsmauth_session(&tc);
    session.reset().expect("reset");

    // Try using wrong management key to store a credential
    let wrong_key = HsmAuthManagementKey::new(&[0xFFu8; 16]).expect("wrong key");
    let cred_pw = CredentialPassword::from_password("test");
    let result = session.put_credential_derived(&wrong_key, "fail-test", "pw", &cred_pw, false);
    assert!(result.is_err(), "Wrong management key should fail");

    session.reset().expect("reset");
}

/// Test HSMAuth asymmetric credential: generate, get public key, calculate session keys.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hsmauth_asymmetric_credential(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::HSMAUTH);
    require_version!(Version(5, 6, 0));

    let mut session = open_hsmauth_session(&tc);
    reset_hsmauth(&mut session);

    let mgmt_key = effective_hsmauth_mgmt_key();
    let cred_pw = CredentialPassword::from_password("asym-password");

    // Generate an asymmetric credential on-device
    match session.generate_credential_asymmetric(&mgmt_key, "asym-test", &cred_pw, false) {
        Ok(cred) => {
            assert_eq!(cred.label, "asym-test");
        }
        Err(e) if is_conditions_not_satisfied(&e) => {
            skip!("HSMAuth asymmetric not available: {e}");
        }
        Err(e) => panic!("generate_credential_asymmetric: {e}"),
    }

    // Get the public key
    let public_key = session.get_public_key("asym-test").expect("get_public_key");

    // Verify it's a valid P-256 point (uncompressed, 65 bytes encoded)
    let encoded = p256::EncodedPoint::from(&public_key);
    assert!(
        !encoded.is_identity(),
        "Public key should not be identity point"
    );

    // List credentials — should include the asymmetric one
    let creds = session.list_credentials().expect("list");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].label, "asym-test");

    session.reset().expect("reset");
}
