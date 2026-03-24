use std::io::{self, Read, Write};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::iso7816::SmartCardProtocol;
use yubikit_rs::management::Capability;
use yubikit_rs::piv::{
    DEFAULT_MANAGEMENT_KEY, KeyType, ManagementKeyType, ObjectId, PinPolicy, PivSession, Slot,
    TouchPolicy,
};

use crate::scp;
use crate::util::CliError;

fn open_session(
    dev: &YubiKeyDevice,
) -> Result<PivSession<impl yubikit_rs::iso7816::SmartCardConnection + use<'_>>, CliError> {
    if scp::needs_scp11b(dev, Capability::PIV) {
        let (kid, kvn, pk) = scp::find_scp11b_params(dev)?;
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        let mut protocol = SmartCardProtocol::new(conn);
        // Select PIV first, then init SCP (matching Python's approach)
        protocol
            .select(yubikit_rs::iso7816::Aid::PIV)
            .map_err(|e| CliError(format!("Failed to select PIV: {e}")))?;
        protocol
            .init_scp11(kid, kvn, &pk, None, &[], None)
            .map_err(|e| CliError(format!("SCP11b initialization failed: {e}")))?;
        PivSession::from_protocol(protocol)
            .map_err(|e| CliError(format!("Failed to open PIV session: {e}")))
    } else {
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        PivSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open PIV session: {e}")))
    }
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn read_file_or_stdin(path: &str) -> Result<Vec<u8>, CliError> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError(format!("Failed to read from stdin: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read(path).map_err(|e| CliError(format!("Failed to read file '{path}': {e}")))
    }
}

fn parse_slot(s: &str) -> Result<Slot, CliError> {
    // Accept hex (9a, 9c, etc.), names, or slot numbers
    let s_up = s.to_ascii_uppercase();
    match s_up.as_str() {
        "AUTHENTICATION" | "9A" => Ok(Slot::Authentication),
        "SIGNATURE" | "9C" => Ok(Slot::Signature),
        "KEY-MANAGEMENT" | "KEY_MANAGEMENT" | "KEYMANAGEMENT" | "9D" => Ok(Slot::KeyManagement),
        "CARD-AUTH" | "CARD_AUTH" | "CARDAUTH" | "9E" => Ok(Slot::CardAuth),
        "ATTESTATION" | "F9" => Ok(Slot::Attestation),
        _ => {
            // Try parsing as hex byte for retired slots
            if let Ok(v) =
                u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
            {
                Slot::from_u8(v).ok_or_else(|| CliError(format!("Invalid PIV slot: 0x{v:02X}")))
            } else {
                Err(CliError(format!(
                    "Invalid slot: {s}. Use 9a, 9c, 9d, 9e, f9, or 82-95."
                )))
            }
        }
    }
}

fn parse_key_type(s: &str) -> Result<KeyType, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "RSA1024" => Ok(KeyType::Rsa1024),
        "RSA2048" => Ok(KeyType::Rsa2048),
        "RSA3072" => Ok(KeyType::Rsa3072),
        "RSA4096" => Ok(KeyType::Rsa4096),
        "ECCP256" | "ECC-P256" | "P256" => Ok(KeyType::EccP256),
        "ECCP384" | "ECC-P384" | "P384" => Ok(KeyType::EccP384),
        "ED25519" => Ok(KeyType::Ed25519),
        "X25519" => Ok(KeyType::X25519),
        _ => Err(CliError(format!("Invalid key type: {s}"))),
    }
}

fn parse_mgmt_key_type(s: &str) -> Result<ManagementKeyType, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "TDES" | "3DES" => Ok(ManagementKeyType::Tdes),
        "AES128" => Ok(ManagementKeyType::Aes128),
        "AES192" => Ok(ManagementKeyType::Aes192),
        "AES256" => Ok(ManagementKeyType::Aes256),
        _ => Err(CliError(format!("Invalid management key type: {s}"))),
    }
}

fn parse_pin_policy(s: &str) -> Result<PinPolicy, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "DEFAULT" => Ok(PinPolicy::Default),
        "NEVER" => Ok(PinPolicy::Never),
        "ONCE" => Ok(PinPolicy::Once),
        "ALWAYS" => Ok(PinPolicy::Always),
        "MATCH-ONCE" | "MATCH_ONCE" => Ok(PinPolicy::MatchOnce),
        "MATCH-ALWAYS" | "MATCH_ALWAYS" => Ok(PinPolicy::MatchAlways),
        _ => Err(CliError(format!("Invalid PIN policy: {s}"))),
    }
}

fn parse_touch_policy(s: &str) -> Result<TouchPolicy, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "DEFAULT" => Ok(TouchPolicy::Default),
        "NEVER" => Ok(TouchPolicy::Never),
        "ALWAYS" => Ok(TouchPolicy::Always),
        "CACHED" => Ok(TouchPolicy::Cached),
        _ => Err(CliError(format!("Invalid touch policy: {s}"))),
    }
}

fn parse_management_key(s: &str) -> Result<Vec<u8>, CliError> {
    hex::decode(s).map_err(|_| CliError("Management key must be hex-encoded.".into()))
}

fn authenticate_session(
    session: &mut PivSession<impl yubikit_rs::iso7816::SmartCardConnection>,
    mgmt_key: Option<&str>,
) -> Result<(), CliError> {
    let key = match mgmt_key {
        Some(k) => parse_management_key(k)?,
        None => DEFAULT_MANAGEMENT_KEY.to_vec(),
    };
    session
        .authenticate(&key)
        .map_err(|e| CliError(format!("Authentication failed: {e}")))
}

fn parse_object_id(s: &str) -> Result<ObjectId, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "CHUID" => Ok(ObjectId::Chuid),
        "CCC" | "CAPABILITY" => Ok(ObjectId::Capability),
        "AUTHENTICATION" => Ok(ObjectId::Authentication),
        "SIGNATURE" => Ok(ObjectId::Signature),
        "KEY-MANAGEMENT" | "KEY_MANAGEMENT" => Ok(ObjectId::KeyManagement),
        "CARD-AUTH" | "CARD_AUTH" | "CARDAUTH" => Ok(ObjectId::CardAuth),
        "DISCOVERY" => Ok(ObjectId::Discovery),
        "KEY-HISTORY" | "KEY_HISTORY" => Ok(ObjectId::KeyHistory),
        "FINGERPRINTS" => Ok(ObjectId::Fingerprints),
        "FACIAL" => Ok(ObjectId::Facial),
        "IRIS" => Ok(ObjectId::Iris),
        "PRINTED" => Ok(ObjectId::Printed),
        "ATTESTATION" => Ok(ObjectId::Attestation),
        _ => Err(CliError(format!(
            "Unknown object ID: {s}. Use CHUID, CCC, AUTHENTICATION, etc."
        ))),
    }
}

pub fn run_info(dev: &YubiKeyDevice) -> Result<(), CliError> {
    let mut session = open_session(dev)?;
    let version = session.version();
    println!("PIV version:              {version}");

    let mut warnings = Vec::new();

    // PIN metadata
    match session.get_pin_metadata() {
        Ok(meta) => {
            println!(
                "PIN tries remaining:      {}/{}",
                meta.attempts_remaining, meta.total_attempts
            );
            if meta.default_value {
                warnings.push("WARNING: Using default PIN!");
            }
        }
        Err(_) => match session.get_pin_attempts() {
            Ok(n) => println!("PIN tries remaining:      {n}"),
            Err(_) => {}
        },
    }

    // PUK metadata
    if let Ok(meta) = session.get_puk_metadata() {
        println!(
            "PUK tries remaining:      {}/{}",
            meta.attempts_remaining, meta.total_attempts
        );
        if meta.default_value {
            warnings.push("WARNING: Using default PUK!");
        }
    }

    // Management key metadata
    if let Ok(meta) = session.get_management_key_metadata() {
        let algo = format!("{}", meta.key_type);
        println!("Management key algorithm: {algo}");
        if meta.default_value {
            warnings.push("WARNING: Using default Management key!");
        }
    }

    // Print collected warnings
    for w in &warnings {
        println!("{w}");
    }

    // CHUID
    match session.get_object(ObjectId::Chuid) {
        Ok(data) => println!("CHUID: {}", hex::encode(&data)),
        Err(_) => println!("CHUID: No data available"),
    }

    // CCC
    match session.get_object(ObjectId::Capability) {
        Ok(data) => println!("CCC:   {}", hex::encode(&data)),
        Err(_) => println!("CCC:   No data available"),
    }

    // Slot details
    let slots = [
        (Slot::Authentication, "9A", "AUTHENTICATION"),
        (Slot::Signature, "9C", "SIGNATURE"),
        (Slot::KeyManagement, "9D", "KEY MANAGEMENT"),
        (Slot::CardAuth, "9E", "CARD AUTH"),
    ];

    for (slot, hex_id, name) in slots {
        let has_key = session.get_slot_metadata(slot).ok();
        let has_cert = session.get_certificate(slot).ok();

        if has_key.is_none() && has_cert.is_none() {
            continue;
        }

        println!("\nSlot {hex_id} ({name}):");

        if let Some(ref meta) = has_key {
            println!("  Private key type: {}", meta.key_type);
        }

        if let Some(ref cert_der) = has_cert {
            // Parse certificate to show details
            if let Some(info) = parse_cert_info(cert_der) {
                if has_key.is_some() {
                    println!("  Public key type:  {}", info.key_type);
                }
                println!("  Subject DN:       {}", info.subject);
                println!("  Issuer DN:        {}", info.issuer);
                println!("  Serial:           {}", info.serial);
                println!("  Fingerprint:      {}", info.fingerprint);
                println!("  Not before:       {}", info.not_before);
                println!("  Not after:        {}", info.not_after);
            }
        }
    }

    Ok(())
}

struct CertInfo {
    key_type: String,
    subject: String,
    issuer: String,
    serial: String,
    fingerprint: String,
    not_before: String,
    not_after: String,
}

fn parse_cert_info(cert_der: &[u8]) -> Option<CertInfo> {
    use sha2::Digest;
    let fingerprint = hex::encode(sha2::Sha256::digest(cert_der));

    // Parse the outer SEQUENCE
    let (_, seq_off, seq_len, _) = parse_der_tlv(cert_der, 0).ok()?;
    let seq = &cert_der[seq_off..seq_off + seq_len];

    // TBSCertificate is the first element
    let (_, tbs_off, tbs_len, _tbs_end) = parse_der_tlv(seq, 0).ok()?;
    let tbs = &seq[tbs_off..tbs_off + tbs_len];

    // Parse TBS fields: version, serialNumber, signature, issuer, validity, subject, spki
    let mut pos = 0;

    // version [0] EXPLICIT - optional
    let (tag, _, _, next) = parse_der_tlv(tbs, pos).ok()?;
    if tag == 0xA0 {
        pos = next;
    }

    // serialNumber INTEGER
    let (_, sn_off, sn_len, next) = parse_der_tlv(tbs, pos).ok()?;
    let serial_bytes = &tbs[sn_off..sn_off + sn_len];
    let serial = serial_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    pos = next;

    // signature AlgorithmIdentifier
    let (_, _, _, next) = parse_der_tlv(tbs, pos).ok()?;
    pos = next;

    // issuer Name
    let (_, iss_off, iss_len, next) = parse_der_tlv(tbs, pos).ok()?;
    let issuer = parse_dn_from_der(&tbs[iss_off..iss_off + iss_len]);
    pos = next;

    // validity Sequence { notBefore, notAfter }
    let (_, val_off, val_len, next) = parse_der_tlv(tbs, pos).ok()?;
    let validity = &tbs[val_off..val_off + val_len];
    let (_, nb_off, nb_len, nb_end) = parse_der_tlv(validity, 0).ok()?;
    let not_before = std::str::from_utf8(&validity[nb_off..nb_off + nb_len])
        .unwrap_or("?")
        .to_string();
    let (_, na_off, na_len, _) = parse_der_tlv(validity, nb_end).ok()?;
    let not_after = std::str::from_utf8(&validity[na_off..na_off + na_len])
        .unwrap_or("?")
        .to_string();
    pos = next;

    // subject Name
    let (_, sub_off, sub_len, next) = parse_der_tlv(tbs, pos).ok()?;
    let subject = parse_dn_from_der(&tbs[sub_off..sub_off + sub_len]);
    pos = next;

    // subjectPublicKeyInfo
    let (_, spki_off, spki_len, _) = parse_der_tlv(tbs, pos).ok()?;
    let spki = &tbs[spki_off..spki_off + spki_len];
    let key_type = identify_key_type_from_spki(spki);

    // Format times with ISO 8601-ish format
    let not_before = format_asn1_time(&not_before);
    let not_after = format_asn1_time(&not_after);

    Some(CertInfo {
        key_type,
        subject,
        issuer,
        serial,
        fingerprint,
        not_before,
        not_after,
    })
}

fn parse_der_tlv(data: &[u8], offset: usize) -> Result<(u32, usize, usize, usize), ()> {
    if offset >= data.len() {
        return Err(());
    }
    let tag = data[offset] as u32;
    let mut pos = offset + 1;
    if pos >= data.len() {
        return Err(());
    }
    let len = if data[pos] < 0x80 {
        let l = data[pos] as usize;
        pos += 1;
        l
    } else if data[pos] == 0x81 {
        pos += 1;
        if pos >= data.len() {
            return Err(());
        }
        let l = data[pos] as usize;
        pos += 1;
        l
    } else if data[pos] == 0x82 {
        pos += 1;
        if pos + 1 >= data.len() {
            return Err(());
        }
        let l = ((data[pos] as usize) << 8) | data[pos + 1] as usize;
        pos += 2;
        l
    } else {
        return Err(());
    };
    Ok((tag, pos, len, pos + len))
}

fn parse_dn_from_der(dn_content: &[u8]) -> String {
    // Parse SEQUENCE of SETs of SEQUENCE { OID, value }
    let mut parts = Vec::new();
    let mut pos = 0;
    while pos < dn_content.len() {
        if let Ok((_, set_off, set_len, set_end)) = parse_der_tlv(dn_content, pos) {
            let set_data = &dn_content[set_off..set_off + set_len];
            if let Ok((_, seq_off, seq_len, _)) = parse_der_tlv(set_data, 0) {
                let seq_data = &set_data[seq_off..seq_off + seq_len];
                if let Ok((_, oid_off, oid_len, oid_end)) = parse_der_tlv(seq_data, 0) {
                    let oid = &seq_data[oid_off..oid_off + oid_len];
                    if let Ok((_, val_off, val_len, _)) = parse_der_tlv(seq_data, oid_end) {
                        let value =
                            std::str::from_utf8(&seq_data[val_off..val_off + val_len]).unwrap_or("?");
                        let attr_name = oid_to_attr_name(oid);
                        parts.push(format!("{attr_name}={value}"));
                    }
                }
            }
            pos = set_end;
        } else {
            break;
        }
    }
    parts.join(", ")
}

fn oid_to_attr_name(oid: &[u8]) -> &'static str {
    match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0A] => "O",
        [0x55, 0x04, 0x0B] => "OU",
        _ => "OID",
    }
}

fn identify_key_type_from_spki(spki_content: &[u8]) -> String {
    // Parse AlgorithmIdentifier to determine key type
    if let Ok((_, algo_off, algo_len, _)) = parse_der_tlv(spki_content, 0) {
        let algo = &spki_content[algo_off..algo_off + algo_len];
        if let Ok((_, oid_off, oid_len, _)) = parse_der_tlv(algo, 0) {
            let oid = &algo[oid_off..oid_off + oid_len];
            return match oid {
                // EC public key OID
                [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] => {
                    // Check curve parameter OID
                    if let Ok((_, p_off, p_len, _)) = parse_der_tlv(algo, oid_off + oid_len) {
                        match &algo[p_off..p_off + p_len] {
                            [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => {
                                "ECCP256".to_string()
                            }
                            [0x2B, 0x81, 0x04, 0x00, 0x22] => "ECCP384".to_string(),
                            _ => "EC".to_string(),
                        }
                    } else {
                        "EC".to_string()
                    }
                }
                // RSA OID
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] => "RSA".to_string(),
                // Ed25519 OID
                [0x2B, 0x65, 0x70] => "ED25519".to_string(),
                // X25519 OID
                [0x2B, 0x65, 0x6E] => "X25519".to_string(),
                _ => "Unknown".to_string(),
            };
        }
    }
    "Unknown".to_string()
}

fn format_asn1_time(t: &str) -> String {
    // Parse UTCTime (YYMMDDHHmmSSZ) or GeneralizedTime (YYYYMMDDHHmmSSZ)
    let t = t.trim_end_matches('Z');
    if t.len() == 12 {
        // UTCTime: YYMMDDHHMMSS
        let yy: u16 = t[0..2].parse().unwrap_or(0);
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        format!(
            "{year}-{}-{}T{}:{}:{}+00:00",
            &t[2..4],
            &t[4..6],
            &t[6..8],
            &t[8..10],
            &t[10..12]
        )
    } else if t.len() == 14 {
        // GeneralizedTime: YYYYMMDDHHMMSS
        format!(
            "{}-{}-{}T{}:{}:{}+00:00",
            &t[0..4],
            &t[4..6],
            &t[6..8],
            &t[8..10],
            &t[10..12],
            &t[12..14]
        )
    } else {
        t.to_string()
    }
}

pub fn run_reset(dev: &YubiKeyDevice, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!("WARNING! This will delete all stored PIV data and restore factory settings.");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }
    let mut session = open_session(dev)?;

    // Block PIN and PUK first (required by reset)
    for _ in 0..15 {
        let _ = session.verify_pin("00000000");
        let _ = session.change_puk("00000000", "00000000");
    }

    session
        .reset()
        .map_err(|e| CliError(format!("Failed to reset PIV: {e}")))?;
    println!("PIV application has been reset.");
    Ok(())
}

pub fn run_change_pin(
    dev: &YubiKeyDevice,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let old = pin.unwrap_or("123456");
    let new = new_pin.ok_or_else(|| CliError("--new-pin is required.".into()))?;

    if new.len() < 6 || new.len() > 8 {
        return Err(CliError("PIN must be 6-8 characters.".into()));
    }

    let mut session = open_session(dev)?;
    session
        .change_pin(old, new)
        .map_err(|e| CliError(format!("Failed to change PIN: {e}")))?;
    println!("PIN changed.");
    Ok(())
}

pub fn run_change_puk(
    dev: &YubiKeyDevice,
    puk: Option<&str>,
    new_puk: Option<&str>,
) -> Result<(), CliError> {
    let old = puk.unwrap_or("12345678");
    let new = new_puk.ok_or_else(|| CliError("--new-puk is required.".into()))?;

    if new.len() < 6 || new.len() > 8 {
        return Err(CliError("PUK must be 6-8 characters.".into()));
    }

    let mut session = open_session(dev)?;
    session
        .change_puk(old, new)
        .map_err(|e| CliError(format!("Failed to change PUK: {e}")))?;
    println!("PUK changed.");
    Ok(())
}

pub fn run_unblock_pin(
    dev: &YubiKeyDevice,
    puk: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let puk = puk.unwrap_or("12345678");
    let new = new_pin.ok_or_else(|| CliError("--new-pin is required.".into()))?;

    if new.len() < 6 || new.len() > 8 {
        return Err(CliError("New PIN must be 6-8 characters.".into()));
    }

    let mut session = open_session(dev)?;
    session
        .unblock_pin(puk, new)
        .map_err(|e| CliError(format!("Failed to unblock PIN: {e}")))?;
    println!("PIN unblocked.");
    Ok(())
}

pub fn run_set_retries(
    dev: &YubiKeyDevice,
    pin_retries: u8,
    puk_retries: u8,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    if !force
        && !confirm(&format!(
            "Set PIN retries to {pin_retries} and PUK retries to {puk_retries}? This will reset PIN and PUK to defaults."
        ))
    {
        return Err(CliError("Aborted.".into()));
    }

    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    } else {
        session
            .verify_pin("123456")
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    session
        .set_pin_attempts(pin_retries, puk_retries)
        .map_err(|e| CliError(format!("Failed to set retries: {e}")))?;
    println!("PIN and PUK retry counts set.");
    Ok(())
}

pub fn run_change_management_key(
    dev: &YubiKeyDevice,
    mgmt_key: Option<&str>,
    new_mgmt_key: Option<&str>,
    algorithm: &str,
    touch: bool,
    generate: bool,
    force: bool,
    pin: Option<&str>,
    protect: bool,
) -> Result<(), CliError> {
    let key_type = parse_mgmt_key_type(algorithm)?;
    let key_len = key_type.key_len();

    let new_key = if generate {
        let mut k = vec![0u8; key_len];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        k
    } else if let Some(k) = new_mgmt_key {
        let bytes = parse_management_key(k)?;
        if bytes.len() != key_len {
            return Err(CliError(format!(
                "Management key must be {key_len} bytes for {algorithm}."
            )));
        }
        bytes
    } else {
        return Err(CliError(
            "Provide --new-management-key or --generate.".into(),
        ));
    };

    if !force && !confirm("Change management key?") {
        return Err(CliError("Aborted.".into()));
    }

    let mut session = open_session(dev)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    authenticate_session(&mut session, mgmt_key)?;
    session
        .set_management_key(key_type, &new_key, touch)
        .map_err(|e| CliError(format!("Failed to set management key: {e}")))?;

    if protect {
        eprintln!("WARNING: --protect (storing management key on device) is not yet supported.");
    }

    if generate {
        println!("Management key set: {}", hex::encode(&new_key));
    } else {
        println!("Management key changed.");
    }
    Ok(())
}

pub fn run_keys_generate(
    dev: &YubiKeyDevice,
    slot: &str,
    output: &str,
    algorithm: &str,
    pin_policy: &str,
    touch_policy: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    format: &str,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let key_type = parse_key_type(algorithm)?;
    let pp = parse_pin_policy(pin_policy)?;
    let tp = parse_touch_policy(touch_policy)?;

    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }

    let pub_key_device = session
        .generate_key(slot, key_type, pp, tp)
        .map_err(|e| CliError(format!("Failed to generate key: {e}")))?;

    let spki_der = device_pubkey_to_spki(key_type, &pub_key_device)?;

    match format.to_ascii_uppercase().as_str() {
        "DER" => {
            std::fs::write(output, &spki_der)
                .map_err(|e| CliError(format!("Failed to write file: {e}")))?;
        }
        "PEM" | _ => {
            let pem = pem_encode("PUBLIC KEY", &spki_der);
            std::fs::write(output, pem)
                .map_err(|e| CliError(format!("Failed to write file: {e}")))?;
        }
    }

    println!("Generated {algorithm} key in slot {slot}. Public key written to {output}.");
    Ok(())
}

pub fn run_keys_import(
    dev: &YubiKeyDevice,
    slot: &str,
    key_file: &str,
    pin_policy: &str,
    touch_policy: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let pp = parse_pin_policy(pin_policy)?;
    let tp = parse_touch_policy(touch_policy)?;

    let data =
        std::fs::read(key_file).map_err(|e| CliError(format!("Failed to read file: {e}")))?;

    // Try to detect PEM vs DER
    let der = if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("-----BEGIN") {
            pem_decode(text)?
        } else {
            data
        }
    } else {
        data
    };

    // Auto-detect key type from DER
    let key_type = KeyType::from_public_key_der(&der)
        .map_err(|_| CliError("Could not determine key type from file.".into()))?;

    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }

    session
        .put_key(slot, key_type, &der, pp, tp)
        .map_err(|e| CliError(format!("Failed to import key: {e}")))?;

    println!("Private key imported to slot {slot}.");
    Ok(())
}

pub fn run_keys_info(dev: &YubiKeyDevice, slot: &str) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev)?;
    let meta = session
        .get_slot_metadata(slot)
        .map_err(|e| CliError(format!("Failed to get slot metadata: {e}")))?;

    println!("Slot: {slot}");
    println!("Algorithm: {:?}", meta.key_type);
    println!(
        "Origin: {}",
        if meta.generated {
            "generated"
        } else {
            "imported"
        }
    );
    println!("PIN policy: {:?}", meta.pin_policy);
    println!("Touch policy: {:?}", meta.touch_policy);
    Ok(())
}

pub fn run_keys_attest(
    dev: &YubiKeyDevice,
    slot: &str,
    output: &str,
    format: &str,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev)?;
    let cert_der = session
        .attest_key(slot)
        .map_err(|e| CliError(format!("Failed to attest key: {e}")))?;

    write_cert_file(output, &cert_der, format)?;
    println!("Attestation certificate written to {output}.");
    Ok(())
}

pub fn run_keys_export(
    dev: &YubiKeyDevice,
    slot: &str,
    output: &str,
    format: &str,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev)?;

    // Try metadata first (5.3.0+)
    if let Ok(meta) = session.get_slot_metadata(slot) {
        if !meta.public_key_der.is_empty() {
            let spki_der = device_pubkey_to_spki(meta.key_type, &meta.public_key_der)?;
            match format.to_ascii_uppercase().as_str() {
                "DER" => std::fs::write(output, &spki_der)
                    .map_err(|e| CliError(format!("Failed to write: {e}")))?,
                _ => {
                    let pem = pem_encode("PUBLIC KEY", &spki_der);
                    std::fs::write(output, pem)
                        .map_err(|e| CliError(format!("Failed to write: {e}")))?;
                }
            }
            println!("Public key exported to {output}.");
            return Ok(());
        }
    }

    Err(CliError(
        "Could not export public key. Slot metadata not available on this firmware.".into(),
    ))
}

pub fn run_keys_move(
    dev: &YubiKeyDevice,
    source: &str,
    dest: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let from = parse_slot(source)?;
    let to = parse_slot(dest)?;
    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    session
        .move_key(from, to)
        .map_err(|e| CliError(format!("Failed to move key: {e}")))?;
    println!("Key moved from {from} to {to}.");
    Ok(())
}

pub fn run_keys_delete(
    dev: &YubiKeyDevice,
    slot: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    session
        .delete_key(slot)
        .map_err(|e| CliError(format!("Failed to delete key: {e}")))?;
    println!("Key in slot {slot} deleted.");
    Ok(())
}

pub fn run_certificates_export(
    dev: &YubiKeyDevice,
    slot: &str,
    output: &str,
    format: &str,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev)?;
    let cert_der = session
        .get_certificate(slot)
        .map_err(|e| CliError(format!("Failed to get certificate: {e}")))?;

    write_cert_file(output, &cert_der, format)?;
    println!("Certificate exported to {output}.");
    Ok(())
}

pub fn run_certificates_import(
    dev: &YubiKeyDevice,
    slot: &str,
    cert_file: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    compress: bool,
    update_chuid: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;

    let data =
        std::fs::read(cert_file).map_err(|e| CliError(format!("Failed to read file: {e}")))?;

    let der = if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("-----BEGIN") {
            pem_decode(text)?
        } else {
            data
        }
    } else {
        data
    };

    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }

    session
        .put_certificate(slot, &der, compress)
        .map_err(|e| CliError(format!("Failed to import certificate: {e}")))?;
    println!("Certificate imported to slot {slot}.");

    if update_chuid {
        generate_chuid(dev, mgmt_key, pin)?;
    }
    Ok(())
}

pub fn run_certificates_delete(
    dev: &YubiKeyDevice,
    slot: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    update_chuid: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    session
        .delete_certificate(slot)
        .map_err(|e| CliError(format!("Failed to delete certificate: {e}")))?;
    println!("Certificate in slot {slot} deleted.");

    if update_chuid {
        generate_chuid(dev, mgmt_key, pin)?;
    }
    Ok(())
}

pub fn run_objects_export(
    dev: &YubiKeyDevice,
    object: &str,
    output: &str,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let obj_id = parse_object_id(object)?;
    let mut session = open_session(dev)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    let data = session
        .get_object(obj_id)
        .map_err(|e| CliError(format!("Failed to read object: {e}")))?;

    if output == "-" {
        io::stdout()
            .write_all(&data)
            .map_err(|e| CliError(format!("Failed to write: {e}")))?;
    } else {
        std::fs::write(output, &data)
            .map_err(|e| CliError(format!("Failed to write file: {e}")))?;
        println!("Object exported to {output}.");
    }
    Ok(())
}

pub fn run_objects_import(
    dev: &YubiKeyDevice,
    object: &str,
    data_file: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let obj_id = parse_object_id(object)?;
    let data =
        std::fs::read(data_file).map_err(|e| CliError(format!("Failed to read file: {e}")))?;

    let mut session = open_session(dev)?;
    authenticate_session(&mut session, mgmt_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    session
        .put_object(obj_id, Some(&data))
        .map_err(|e| CliError(format!("Failed to write object: {e}")))?;
    println!("Object imported.");
    Ok(())
}

/// Generate a new CHUID and write it to the device.
fn generate_chuid(
    dev: &YubiKeyDevice,
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let mut session = open_session(dev)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    authenticate_session(&mut session, management_key)?;

    let mut chuid = Vec::new();
    chuid.extend_from_slice(&[0x30, 0x19]);
    chuid.extend_from_slice(&[0x9E; 25]);
    chuid.push(0x34);
    chuid.push(0x10);
    let mut guid = [0u8; 16];
    getrandom::fill(&mut guid).map_err(|e| CliError(format!("RNG error: {e}")))?;
    guid[6] = (guid[6] & 0x0f) | 0x40;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    chuid.extend_from_slice(&guid);
    chuid.push(0x35);
    chuid.push(0x08);
    chuid.extend_from_slice(b"20301231");
    chuid.push(0x3E);
    chuid.push(0x00);
    chuid.push(0xFE);
    chuid.push(0x00);

    session
        .put_object(ObjectId::Chuid, Some(&chuid))
        .map_err(|e| CliError(format!("Failed to update CHUID: {e}")))?;
    Ok(())
}

pub fn run_objects_generate(
    dev: &YubiKeyDevice,
    object: &str,
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let mut session = open_session(dev)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    authenticate_session(&mut session, management_key)?;

    match object.to_uppercase().as_str() {
        "CHUID" => {
            // Generate CHUID per SP 800-73-4
            let mut chuid = Vec::new();
            // FASC-N (tag 0x30, 25 bytes, all 0x9E = default)
            chuid.extend_from_slice(&[0x30, 0x19]);
            chuid.extend_from_slice(&[0x9E; 25]);
            // GUID (tag 0x34, 16 bytes random UUID v4)
            chuid.push(0x34);
            chuid.push(0x10);
            let mut guid = [0u8; 16];
            getrandom::fill(&mut guid).map_err(|e| CliError(format!("RNG error: {e}")))?;
            guid[6] = (guid[6] & 0x0f) | 0x40;
            guid[8] = (guid[8] & 0x3f) | 0x80;
            chuid.extend_from_slice(&guid);
            // Expiry date (tag 0x35, 8 bytes YYYYMMDD)
            chuid.push(0x35);
            chuid.push(0x08);
            chuid.extend_from_slice(b"20301231");
            // Issuer asymmetric signature (empty, tag 0x3E)
            chuid.push(0x3E);
            chuid.push(0x00);
            // Error Detection Code (tag 0xFE)
            chuid.push(0xFE);
            chuid.push(0x00);

            session
                .put_object(ObjectId::Chuid, Some(&chuid))
                .map_err(|e| CliError(format!("Failed to write CHUID: {e}")))?;
            println!("CHUID generated.");
        }
        "CCC" => {
            // Generate CCC per SP 800-73-4
            let mut ccc = Vec::new();
            // Card Identifier (tag 0xF0, 21 bytes)
            ccc.push(0xF0);
            ccc.push(0x15);
            let mut card_id = [0u8; 21];
            getrandom::fill(&mut card_id).map_err(|e| CliError(format!("RNG error: {e}")))?;
            ccc.extend_from_slice(&card_id);
            // Capability Container version number (tag 0xF1)
            ccc.extend_from_slice(&[0xF1, 0x01, 0x21]);
            // Capability Grammar version number (tag 0xF2)
            ccc.extend_from_slice(&[0xF2, 0x01, 0x21]);
            // Applications CardURL (tag 0xF3, empty)
            ccc.extend_from_slice(&[0xF3, 0x00]);
            // PKCS#15 (tag 0xF4)
            ccc.extend_from_slice(&[0xF4, 0x01, 0x00]);
            // Registered Data Model (tag 0xF5)
            ccc.extend_from_slice(&[0xF5, 0x01, 0x10]);
            // Access Control Rule Table (tag 0xF6, empty)
            ccc.extend_from_slice(&[0xF6, 0x00]);
            // Error Detection Code (tag 0xFE)
            ccc.push(0xFE);
            ccc.push(0x00);

            session
                .put_object(ObjectId::Capability, Some(&ccc))
                .map_err(|e| CliError(format!("Failed to write CCC: {e}")))?;
            println!("CCC generated.");
        }
        other => {
            return Err(CliError(format!(
                "Unknown object type: {other}. Use CHUID or CCC."
            )));
        }
    }
    Ok(())
}

pub fn run_certificates_generate(
    dev: &YubiKeyDevice,
    slot: &str,
    subject: &str,
    valid_days: u32,
    hash_algorithm: &str,
    management_key: Option<&str>,
    pin: Option<&str>,
    public_key_file: Option<&str>,
    update_chuid: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let hash_alg = parse_hash_algorithm(hash_algorithm)?;

    let mut session = open_session(dev)?;
    authenticate_session(&mut session, management_key)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }

    let (key_type, spki_der) = if let Some(pk_file) = public_key_file {
        let data = read_file_or_stdin(pk_file)?;
        let der = if let Ok(text) = std::str::from_utf8(&data) {
            if text.contains("-----BEGIN") {
                pem_decode(text)?
            } else {
                data
            }
        } else {
            data
        };
        let kt = KeyType::from_public_key_der(&der)
            .map_err(|_| CliError("Could not determine key type from public key file.".into()))?;
        (kt, der)
    } else {
        let metadata = session
            .get_slot_metadata(slot)
            .map_err(|e| CliError(format!("Failed to get slot metadata (is a key present?): {e}")))?;
        let kt = metadata.key_type;
        let spki = device_pubkey_to_spki(kt, &metadata.public_key_der)?;
        (kt, spki)
    };

    let sig_alg_id = signature_algorithm_id(key_type, hash_alg)?;
    let subject_dn = encode_distinguished_name(subject)?;
    let serial = random_serial_number();
    let (not_before, not_after) = validity_dates(valid_days);

    let tbs = build_tbs_certificate(&serial, &sig_alg_id, &subject_dn, &not_before, &not_after, &spki_der);
    let signature = sign_data(&mut session, slot, key_type, hash_alg, &tbs)?;

    let cert_der = der_sequence(&[&tbs, &sig_alg_id, &der_bit_string(&signature)]);

    session
        .put_certificate(slot, &cert_der, false)
        .map_err(|e| CliError(format!("Failed to store certificate: {e}")))?;

    println!("Certificate generated and stored in slot {slot:?}.");

    if update_chuid {
        generate_chuid(dev, management_key, pin)?;
    }
    Ok(())
}

pub fn run_certificates_request(
    dev: &YubiKeyDevice,
    slot: &str,
    subject: &str,
    hash_algorithm: &str,
    output: &str,
    pin: Option<&str>,
    public_key_file: Option<&str>,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let hash_alg = parse_hash_algorithm(hash_algorithm)?;

    let mut session = open_session(dev)?;
    if let Some(p) = pin {
        session
            .verify_pin(p)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }

    let (key_type, spki_der) = if let Some(pk_file) = public_key_file {
        let data = read_file_or_stdin(pk_file)?;
        let der = if let Ok(text) = std::str::from_utf8(&data) {
            if text.contains("-----BEGIN") {
                pem_decode(text)?
            } else {
                data
            }
        } else {
            data
        };
        let kt = KeyType::from_public_key_der(&der)
            .map_err(|_| CliError("Could not determine key type from public key file.".into()))?;
        (kt, der)
    } else {
        let metadata = session
            .get_slot_metadata(slot)
            .map_err(|e| CliError(format!("Failed to get slot metadata (is a key present?): {e}")))?;
        let kt = metadata.key_type;
        let spki = device_pubkey_to_spki(kt, &metadata.public_key_der)?;
        (kt, spki)
    };

    let sig_alg_id = signature_algorithm_id(key_type, hash_alg)?;
    let subject_dn = encode_distinguished_name(subject)?;

    let csr_info = build_certification_request_info(&subject_dn, &spki_der);
    let signature = sign_data(&mut session, slot, key_type, hash_alg, &csr_info)?;

    let csr_der = der_sequence(&[&csr_info, &sig_alg_id, &der_bit_string(&signature)]);

    let pem = pem_encode("CERTIFICATE REQUEST", &csr_der);
    if output == "-" {
        print!("{pem}");
    } else {
        std::fs::write(output, &pem)
            .map_err(|e| CliError(format!("Failed to write CSR to {output}: {e}")))?;
        println!("CSR written to {output}.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hash algorithm selection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

fn parse_hash_algorithm(s: &str) -> Result<HashAlgorithm, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "SHA256" | "SHA-256" => Ok(HashAlgorithm::Sha256),
        "SHA384" | "SHA-384" => Ok(HashAlgorithm::Sha384),
        "SHA512" | "SHA-512" => Ok(HashAlgorithm::Sha512),
        other => Err(CliError(format!(
            "Unsupported hash algorithm: {other}. Use SHA256, SHA384, or SHA512."
        ))),
    }
}

// ---------------------------------------------------------------------------
// DER encoding helpers
// ---------------------------------------------------------------------------

fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn der_tag_length_value(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_encode_length(data.len()));
    out.extend_from_slice(data);
    out
}

fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tag_length_value(0x30, &body)
}

fn der_set(items: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tag_length_value(0x31, &body)
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    // Ensure positive by prepending 0x00 if high bit is set
    if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
        let mut padded = vec![0x00];
        padded.extend_from_slice(bytes);
        der_tag_length_value(0x02, &padded)
    } else {
        der_tag_length_value(0x02, bytes)
    }
}

fn der_oid(oid_bytes: &[u8]) -> Vec<u8> {
    der_tag_length_value(0x06, oid_bytes)
}

fn der_utf8string(s: &str) -> Vec<u8> {
    der_tag_length_value(0x0C, s.as_bytes())
}

fn der_printable_string(s: &str) -> Vec<u8> {
    der_tag_length_value(0x13, s.as_bytes())
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    // BIT STRING: unused-bits byte (0x00) + data
    let mut body = vec![0x00];
    body.extend_from_slice(data);
    der_tag_length_value(0x03, &body)
}

fn der_explicit_context(tag_num: u8, data: &[u8]) -> Vec<u8> {
    der_tag_length_value(0xA0 | tag_num, data)
}

fn der_utc_time(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> Vec<u8> {
    let s = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        hour,
        min,
        sec
    );
    der_tag_length_value(0x17, s.as_bytes())
}

fn der_generalized_time(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> Vec<u8> {
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hour, min, sec
    );
    der_tag_length_value(0x18, s.as_bytes())
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

// ---------------------------------------------------------------------------
// Signature algorithm identifiers (AlgorithmIdentifier SEQUENCE)
// ---------------------------------------------------------------------------

// OID bytes (encoded value, without tag+length)
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];
const OID_RSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_RSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
const OID_RSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

fn signature_algorithm_id(key_type: KeyType, hash_alg: HashAlgorithm) -> Result<Vec<u8>, CliError> {
    match key_type {
        KeyType::EccP256 => match hash_alg {
            HashAlgorithm::Sha256 => Ok(der_sequence(&[&der_oid(OID_ECDSA_SHA256)])),
            HashAlgorithm::Sha384 => Ok(der_sequence(&[&der_oid(OID_ECDSA_SHA384)])),
            HashAlgorithm::Sha512 => Ok(der_sequence(&[&der_oid(OID_ECDSA_SHA512)])),
        },
        KeyType::EccP384 => match hash_alg {
            HashAlgorithm::Sha256 => Ok(der_sequence(&[&der_oid(OID_ECDSA_SHA256)])),
            HashAlgorithm::Sha384 => Ok(der_sequence(&[&der_oid(OID_ECDSA_SHA384)])),
            HashAlgorithm::Sha512 => Ok(der_sequence(&[&der_oid(OID_ECDSA_SHA512)])),
        },
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let oid = match hash_alg {
                HashAlgorithm::Sha256 => OID_RSA_SHA256,
                HashAlgorithm::Sha384 => OID_RSA_SHA384,
                HashAlgorithm::Sha512 => OID_RSA_SHA512,
            };
            Ok(der_sequence(&[&der_oid(oid), &der_null()]))
        }
        KeyType::Ed25519 => Ok(der_sequence(&[&der_oid(OID_ED25519)])),
        _ => Err(CliError(format!("Unsupported key type for signing: {key_type:?}"))),
    }
}

// ---------------------------------------------------------------------------
// Distinguished Name encoding
// ---------------------------------------------------------------------------

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x55, 0x04, 0x0A];
const OID_OU: &[u8] = &[0x55, 0x04, 0x0B];
const OID_C: &[u8] = &[0x55, 0x04, 0x06];
const OID_ST: &[u8] = &[0x55, 0x04, 0x08];
const OID_L: &[u8] = &[0x55, 0x04, 0x07];

fn attr_type_to_oid(attr: &str) -> Result<&'static [u8], CliError> {
    match attr.to_ascii_uppercase().as_str() {
        "CN" => Ok(OID_CN),
        "O" => Ok(OID_O),
        "OU" => Ok(OID_OU),
        "C" => Ok(OID_C),
        "ST" | "S" => Ok(OID_ST),
        "L" => Ok(OID_L),
        other => Err(CliError(format!(
            "Unknown DN attribute: {other}. Supported: CN, O, OU, C, ST, L."
        ))),
    }
}

fn encode_rdn_attribute(oid: &[u8], value: &str) -> Vec<u8> {
    // Country uses PrintableString, everything else uses UTF8String
    let val_der = if std::ptr::eq(oid, OID_C) {
        der_printable_string(value)
    } else {
        der_utf8string(value)
    };
    let attr_tv = der_sequence(&[&der_oid(oid), &val_der]);
    der_set(&[&attr_tv])
}

fn encode_distinguished_name(subject: &str) -> Result<Vec<u8>, CliError> {
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(CliError("Subject must not be empty.".into()));
    }

    // If no '=' present, treat entire string as CN value (Python ykman compatibility)
    if !subject.contains('=') {
        let rdn = encode_rdn_attribute(OID_CN, subject);
        return Ok(der_sequence(&[&rdn]));
    }

    // Split on ',' but respect escaped commas (\,) and quoted values
    let parts = split_dn_components(subject);
    let mut rdns = Vec::new();
    for part in &parts {
        let part = part.trim();
        let eq_pos = part
            .find('=')
            .ok_or_else(|| CliError(format!("Invalid DN component (no '='): {part}")))?;
        let attr = part[..eq_pos].trim();
        let value = part[eq_pos + 1..].trim();
        let oid = attr_type_to_oid(attr)?;
        rdns.push(encode_rdn_attribute(oid, value));
    }
    let rdn_refs: Vec<&[u8]> = rdns.iter().map(|r| r.as_slice()).collect();
    Ok(der_sequence(&rdn_refs))
}

fn split_dn_components(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                current.push(c);
                if let Some(&next) = chars.peek() {
                    current.push(next);
                    chars.next();
                }
            }
            ',' | '/' => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    parts.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }
    parts
}

// ---------------------------------------------------------------------------
// PIV device public key encoding → SubjectPublicKeyInfo (SPKI) DER
// ---------------------------------------------------------------------------

// OIDs for public key algorithms (for SPKI AlgorithmIdentifier, NOT signature)
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_CURVE_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
const OID_CURVE_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22]; // 1.3.132.0.34
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
const OID_ED25519_KEY: &[u8] = &[0x2B, 0x65, 0x70]; // 1.3.101.112
const OID_X25519_KEY: &[u8] = &[0x2B, 0x65, 0x6E]; // 1.3.101.110

/// Parse a single TLV from PIV device-encoded public key data.
/// Returns (tag, value_bytes, end_offset).
fn parse_device_tlv(data: &[u8], offset: usize) -> Result<(u8, Vec<u8>, usize), CliError> {
    if offset >= data.len() {
        return Err(CliError("Unexpected end of device public key data".into()));
    }
    let tag = data[offset];
    let mut pos = offset + 1;
    if pos >= data.len() {
        return Err(CliError("Truncated TLV length".into()));
    }
    let len = if data[pos] < 0x80 {
        let l = data[pos] as usize;
        pos += 1;
        l
    } else if data[pos] == 0x81 {
        pos += 1;
        let l = data[pos] as usize;
        pos += 1;
        l
    } else if data[pos] == 0x82 {
        pos += 1;
        let l = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;
        l
    } else {
        return Err(CliError("Unsupported TLV length encoding".into()));
    };
    if pos + len > data.len() {
        return Err(CliError("TLV value extends past data".into()));
    }
    Ok((tag, data[pos..pos + len].to_vec(), pos + len))
}

/// Convert PIV device-encoded public key bytes to SubjectPublicKeyInfo (SPKI) DER.
///
/// PIV device encoding (from generate_key/get_slot_metadata):
/// - EC keys: `86 <len> <uncompressed_point>`
/// - RSA keys: `81 <len> <modulus> 82 <len> <exponent>`
/// - Ed25519/X25519: `86 <len> <32_bytes>`
fn device_pubkey_to_spki(key_type: KeyType, device_bytes: &[u8]) -> Result<Vec<u8>, CliError> {
    match key_type {
        KeyType::EccP256 | KeyType::EccP384 => {
            // Parse tag 0x86 containing the EC point
            let (tag, ec_point, _) = parse_device_tlv(device_bytes, 0)?;
            if tag != 0x86 {
                return Err(CliError(format!("Expected tag 0x86 for EC point, got 0x{tag:02X}")));
            }
            let curve_oid = if key_type == KeyType::EccP256 {
                OID_CURVE_P256
            } else {
                OID_CURVE_P384
            };
            // AlgorithmIdentifier: SEQUENCE { OID ecPublicKey, OID namedCurve }
            let algo_id = der_sequence(&[&der_oid(OID_EC_PUBLIC_KEY), &der_oid(curve_oid)]);
            // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING(point) }
            Ok(der_sequence(&[&algo_id, &der_bit_string(&ec_point)]))
        }
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            // Parse tag 0x81 (modulus) and 0x82 (exponent)
            let (tag1, modulus, end1) = parse_device_tlv(device_bytes, 0)?;
            if tag1 != 0x81 {
                return Err(CliError(format!("Expected tag 0x81 for RSA modulus, got 0x{tag1:02X}")));
            }
            let (tag2, exponent, _) = parse_device_tlv(device_bytes, end1)?;
            if tag2 != 0x82 {
                return Err(CliError(format!("Expected tag 0x82 for RSA exponent, got 0x{tag2:02X}")));
            }
            // RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }
            let rsa_pub_key = der_sequence(&[&der_integer(&modulus), &der_integer(&exponent)]);
            // AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
            let algo_id = der_sequence(&[&der_oid(OID_RSA_ENCRYPTION), &der_null()]);
            Ok(der_sequence(&[&algo_id, &der_bit_string(&rsa_pub_key)]))
        }
        KeyType::Ed25519 => {
            let (tag, raw_key, _) = parse_device_tlv(device_bytes, 0)?;
            if tag != 0x86 {
                return Err(CliError(format!("Expected tag 0x86 for Ed25519 key, got 0x{tag:02X}")));
            }
            let algo_id = der_sequence(&[&der_oid(OID_ED25519_KEY)]);
            Ok(der_sequence(&[&algo_id, &der_bit_string(&raw_key)]))
        }
        KeyType::X25519 => {
            let (tag, raw_key, _) = parse_device_tlv(device_bytes, 0)?;
            if tag != 0x86 {
                return Err(CliError(format!("Expected tag 0x86 for X25519 key, got 0x{tag:02X}")));
            }
            let algo_id = der_sequence(&[&der_oid(OID_X25519_KEY)]);
            Ok(der_sequence(&[&algo_id, &der_bit_string(&raw_key)]))
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate / CSR structure building
// ---------------------------------------------------------------------------

fn random_serial_number() -> Vec<u8> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("failed to generate random serial number");
    // Ensure positive (clear high bit)
    buf[0] &= 0x7F;
    // Ensure non-zero leading byte
    if buf[0] == 0 {
        buf[0] = 0x01;
    }
    buf.to_vec()
}

fn validity_dates(valid_days: u32) -> (Vec<u8>, Vec<u8>) {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch");
    let not_after_ts = now + Duration::from_secs(u64::from(valid_days) * 86400);

    fn timestamp_to_fields(d: Duration) -> (u16, u8, u8, u8, u8, u8) {
        // Simple civil date calculation from Unix timestamp
        let secs = d.as_secs();
        let days_since_epoch = (secs / 86400) as i64;
        let time_of_day = secs % 86400;
        let hour = (time_of_day / 3600) as u8;
        let min = ((time_of_day % 3600) / 60) as u8;
        let sec = (time_of_day % 60) as u8;

        // Days to Y/M/D (algorithm from Howard Hinnant)
        let z = days_since_epoch + 719468;
        let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe = (z - era * 146097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = (yoe as i64) + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let y = if m <= 2 { y + 1 } else { y } as u16;
        (y, m, d, hour, min, sec)
    }

    let (y1, m1, d1, h1, mn1, s1) = timestamp_to_fields(now);
    let (y2, m2, d2, h2, mn2, s2) = timestamp_to_fields(not_after_ts);

    fn encode_time(y: u16, m: u8, d: u8, h: u8, mn: u8, s: u8) -> Vec<u8> {
        if y >= 2050 {
            der_generalized_time(y, m, d, h, mn, s)
        } else {
            der_utc_time(y, m, d, h, mn, s)
        }
    }

    (
        encode_time(y1, m1, d1, h1, mn1, s1),
        encode_time(y2, m2, d2, h2, mn2, s2),
    )
}

fn build_tbs_certificate(
    serial: &[u8],
    sig_alg_id: &[u8],
    subject_dn: &[u8],
    not_before: &[u8],
    not_after: &[u8],
    spki_der: &[u8],
) -> Vec<u8> {
    // version [0] EXPLICIT INTEGER { v3(2) }
    let version = der_explicit_context(0, &der_integer(&[2]));
    let serial_num = der_integer(serial);
    let validity = der_sequence(&[not_before, not_after]);
    // Self-signed: issuer == subject
    let issuer = subject_dn;

    der_sequence(&[
        &version,
        &serial_num,
        sig_alg_id,
        issuer,
        &validity,
        subject_dn,
        spki_der,
    ])
}

fn build_certification_request_info(subject_dn: &[u8], spki_der: &[u8]) -> Vec<u8> {
    let version = der_integer(&[0]); // v1(0)
    // attributes [0] IMPLICIT SET OF Attribute (empty)
    let attributes = der_explicit_context(0, &[]);

    der_sequence(&[&version, subject_dn, spki_der, &attributes])
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0x05, 0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0x05, 0x00, 0x04, 0x40,
];

fn hash_data(hash_alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match hash_alg {
        HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

fn pkcs1v15_pad(hash_alg: HashAlgorithm, hash: &[u8], key_byte_len: usize) -> Vec<u8> {
    let digest_info_prefix = match hash_alg {
        HashAlgorithm::Sha256 => DIGEST_INFO_SHA256,
        HashAlgorithm::Sha384 => DIGEST_INFO_SHA384,
        HashAlgorithm::Sha512 => DIGEST_INFO_SHA512,
    };
    let t_len = digest_info_prefix.len() + hash.len();
    // 0x00 0x01 [0xFF padding] 0x00 [DigestInfo]
    let pad_len = key_byte_len - 3 - t_len;
    let mut padded = Vec::with_capacity(key_byte_len);
    padded.push(0x00);
    padded.push(0x01);
    padded.extend(std::iter::repeat_n(0xFF, pad_len));
    padded.push(0x00);
    padded.extend_from_slice(digest_info_prefix);
    padded.extend_from_slice(hash);
    padded
}

fn sign_data(
    session: &mut PivSession<impl yubikit_rs::iso7816::SmartCardConnection>,
    slot: Slot,
    key_type: KeyType,
    hash_alg: HashAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>, CliError> {
    let message = match key_type {
        KeyType::EccP256 | KeyType::EccP384 => hash_data(hash_alg, data),
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let hash = hash_data(hash_alg, data);
            let key_byte_len = (key_type.bit_len() / 8) as usize;
            pkcs1v15_pad(hash_alg, &hash, key_byte_len)
        }
        KeyType::Ed25519 => data.to_vec(),
        _ => {
            return Err(CliError(format!(
                "Unsupported key type for signing: {key_type:?}"
            )));
        }
    };

    session
        .sign(slot, key_type, &message)
        .map_err(|e| CliError(format!("Signing failed: {e}")))
}
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn pem_decode(text: &str) -> Result<Vec<u8>, CliError> {
    use base64::Engine;
    let mut in_block = false;
    let mut b64 = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| CliError(format!("Invalid PEM data: {e}")))
}

fn write_cert_file(output: &str, der: &[u8], format: &str) -> Result<(), CliError> {
    match format.to_ascii_uppercase().as_str() {
        "DER" => {
            std::fs::write(output, der).map_err(|e| CliError(format!("Failed to write: {e}")))?;
        }
        _ => {
            let pem = pem_encode("CERTIFICATE", der);
            std::fs::write(output, pem).map_err(|e| CliError(format!("Failed to write: {e}")))?;
        }
    }
    Ok(())
}
