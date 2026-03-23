use std::io::{self, Write};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::piv::{
    DEFAULT_MANAGEMENT_KEY, KeyType, ManagementKeyType, ObjectId, PinPolicy, PivSession, Slot,
    TouchPolicy,
};

use crate::util::CliError;

fn open_session(
    dev: &YubiKeyDevice,
) -> Result<PivSession<impl yubikit_rs::iso7816::SmartCardConnection + use<'_>>, CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    PivSession::new(conn).map_err(|e| CliError(format!("Failed to open PIV session: {e}")))
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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
    println!("PIV version: {version}");

    // PIN metadata
    match session.get_pin_metadata() {
        Ok(meta) => {
            println!(
                "PIN tries remaining: {}/{}",
                meta.attempts_remaining, meta.total_attempts
            );
            if meta.default_value {
                println!("WARNING: PIN is set to factory default.");
            }
        }
        Err(_) => match session.get_pin_attempts() {
            Ok(n) => println!("PIN tries remaining: {n}"),
            Err(_) => {}
        },
    }

    // PUK metadata
    if let Ok(meta) = session.get_puk_metadata() {
        println!(
            "PUK tries remaining: {}/{}",
            meta.attempts_remaining, meta.total_attempts
        );
        if meta.default_value {
            println!("WARNING: PUK is set to factory default.");
        }
    }

    // Management key metadata
    if let Ok(meta) = session.get_management_key_metadata() {
        println!("Management key algorithm: {:?}", meta.key_type);
        if meta.default_value {
            println!("WARNING: Management key is set to factory default.");
        }
        println!("Management key touch policy: {:?}", meta.touch_policy);
    }

    // Bio metadata
    if let Ok(meta) = session.get_bio_metadata() {
        println!(
            "Biometric: configured={}, attempts_remaining={}",
            meta.configured, meta.attempts_remaining
        );
    }

    Ok(())
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
    authenticate_session(&mut session, mgmt_key)?;
    session
        .set_management_key(key_type, &new_key, touch)
        .map_err(|e| CliError(format!("Failed to set management key: {e}")))?;

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

    let pub_key_der = session
        .generate_key(slot, key_type, pp, tp)
        .map_err(|e| CliError(format!("Failed to generate key: {e}")))?;

    match format.to_ascii_uppercase().as_str() {
        "DER" => {
            std::fs::write(output, &pub_key_der)
                .map_err(|e| CliError(format!("Failed to write file: {e}")))?;
        }
        "PEM" | _ => {
            // Write as PEM-encoded DER
            let pem = pem_encode("PUBLIC KEY", &pub_key_der);
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
            match format.to_ascii_uppercase().as_str() {
                "DER" => std::fs::write(output, &meta.public_key_der)
                    .map_err(|e| CliError(format!("Failed to write: {e}")))?,
                _ => {
                    let pem = pem_encode("PUBLIC KEY", &meta.public_key_der);
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
    Ok(())
}

pub fn run_certificates_delete(
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
        .delete_certificate(slot)
        .map_err(|e| CliError(format!("Failed to delete certificate: {e}")))?;
    println!("Certificate in slot {slot} deleted.");
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
    _dev: &YubiKeyDevice,
    _slot: &str,
    _subject: &str,
    _valid_days: u32,
    _hash_algorithm: &str,
    _management_key: Option<&str>,
    _pin: Option<&str>,
) -> Result<(), CliError> {
    Err(CliError(
        "Self-signed certificate generation requires an x509 library. \
         Use 'piv keys generate' to create a key, then use an external tool \
         (e.g., openssl) to generate a certificate and import it with \
         'piv certificates import'."
            .into(),
    ))
}

pub fn run_certificates_request(
    _dev: &YubiKeyDevice,
    _slot: &str,
    _subject: &str,
    _hash_algorithm: &str,
    _output: &str,
    _pin: Option<&str>,
) -> Result<(), CliError> {
    Err(CliError(
        "CSR generation requires an x509 library. \
         Use 'piv keys generate' to create a key, then use an external tool \
         (e.g., openssl) to generate a CSR."
            .into(),
    ))
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
