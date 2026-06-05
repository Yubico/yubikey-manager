use super::*;
use base64::prelude::*;
use yubikit::securitydomain::{Curve, KeyRef, ScpKid, SecurityDomainSession, StaticKeys};
use yubikit::smartcard::ScpKeyParams;

/// Default SCP03 key value (all three keys: ENC, MAC, DEK).
const SCP03_DEFAULT_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

/// Build default SCP03 key params for authentication.
fn default_scp03_params() -> ScpKeyParams {
    ScpKeyParams::Scp03 {
        kvn: 0xFF,
        key_enc: SCP03_DEFAULT_KEY,
        key_mac: SCP03_DEFAULT_KEY,
        key_dek: Some(SCP03_DEFAULT_KEY),
    }
}

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
    for block in pem_data.split("-----BEGIN CERTIFICATE-----") {
        if let Some(b64) = block.split("-----END CERTIFICATE-----").next() {
            let b64 = b64.trim();
            if b64.is_empty() {
                continue;
            }
            let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            let der = BASE64_STANDARD.decode(&clean).expect("base64 decode cert");
            certs.push(der);
        }
    }
    certs
}

/// Read a PEM private key file and return the raw EC scalar bytes.
fn read_ec_private_key(path: &std::path::Path) -> Vec<u8> {
    use elliptic_curve::SecretKey;
    use elliptic_curve::pkcs8::DecodePrivateKey;

    let pem_data = std::fs::read_to_string(path).expect("read PEM key file");
    let (label_begin, label_end) = if pem_data.contains("-----BEGIN PRIVATE KEY-----") {
        ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
    } else if pem_data.contains("-----BEGIN EC PRIVATE KEY-----") {
        (
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
        )
    } else {
        panic!("Unrecognized PEM format in {path:?}");
    };

    let b64 = pem_data
        .split(label_begin)
        .nth(1)
        .unwrap()
        .split(label_end)
        .next()
        .unwrap()
        .trim();
    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    let der = BASE64_STANDARD.decode(&clean).expect("base64 decode key");

    // Try PKCS#8 first, then SEC1
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
fn verify_auth(session: &mut SecurityDomainSession<impl yubikit::smartcard::SmartCardConnection>) {
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
#[case::smart_card(TestConnection::SmartCard)]
fn test_securitydomain_version(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    let conn = open_smartcard_connection(&tc);
    match SecurityDomainSession::new(conn) {
        Ok(session) => {
            let _v = session.version();
        }
        Err(_) => {
            eprintln!("SKIP {tc:?}: SecurityDomain not available");
        }
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_securitydomain_get_key_information(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    let key_info = session.get_key_information().expect("get_key_information");
    assert!(!key_info.is_empty(), "Expected at least one key entry");
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_card_recognition_data(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp03_authenticate(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    let params = default_scp03_params();
    let mut session = SecurityDomainSession::new_with_scp(conn, &params)
        .map_err(|(e, _)| e)
        .expect("SCP03 authentication with default keys");
    verify_auth(&mut session);
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp03_wrong_key(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp03_change_key(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    // Authenticate with default keys
    let default_params = default_scp03_params();
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp11b_ok(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);

    let scp11b_ref = KeyRef::new(0x13, 0x01);
    let chain = session
        .get_certificate_bundle(scp11b_ref)
        .expect("get_certificate_bundle");
    if chain.is_empty() {
        skip!("{tc:?}: No SCP11b certificate bundle on device");
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp11b_import(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    // Authenticate with SCP03 to get write access
    let scp03_params = default_scp03_params();
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp11a_ok(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    // Authenticate with SCP03
    let scp03_params = default_scp03_params();
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp11a_allowlist(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    // Authenticate with SCP03
    let scp03_params = default_scp03_params();
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp11a_allowlist_blocked(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    // Authenticate with SCP03
    let scp03_params = default_scp03_params();
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
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp11c_ok(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    // Authenticate with SCP03
    let scp03_params = default_scp03_params();
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
}

/// Test SCP03 session with store/retrieve data to verify APDU encryption.
/// This exercises the full encrypt→transmit→decrypt pipeline with real data.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
fn test_scp03_apdu_echo(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_version!(Version(5, 7, 2));
    let conn = open_smartcard_connection(&tc);
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => {
            skip!("{tc:?}: SecurityDomain not available");
        }
    };
    ensure_default_keys(&mut session);
    let conn = session.into_connection();

    let params = default_scp03_params();
    let mut session = SecurityDomainSession::new_with_scp(conn, &params)
        .map_err(|(e, _)| e)
        .expect("SCP03 auth");

    // After SCP03 authentication, all APDUs are encrypted.
    // Verify by performing operations that require correct encrypt/decrypt:

    // 1. Get key information (response must be decrypted correctly)
    let key_info = session.get_key_information().expect("get_key_information");
    assert!(!key_info.is_empty(), "Should have at least one key");

    // 2. Get card recognition data (tests larger response decryption)
    let crd = session
        .get_card_recognition_data()
        .expect("get_card_recognition_data");
    assert!(!crd.is_empty(), "Card recognition data should not be empty");

    // 3. Generate and delete a key (tests command encryption with varying sizes)
    let temp_ref = KeyRef::new(0x13, 0x7E);
    session
        .generate_ec_key(temp_ref, Curve::Secp256r1, 0)
        .expect("generate key through SCP03");
    session
        .delete_key(temp_ref.kid, temp_ref.kvn, false)
        .expect("delete key through SCP03");
}
