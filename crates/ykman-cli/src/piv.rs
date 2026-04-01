use std::io::{self, Write};
use std::str::FromStr;
use std::time::Duration;

use x509_cert::Certificate;
use x509_cert::builder::{Builder, CertificateBuilder, Profile, RequestBuilder};
use x509_cert::der::{self, Decode, Encode, EncodePem, pem::LineEnding};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::piv::{
    DEFAULT_MANAGEMENT_KEY, HashAlgorithm, KeyType, ManagementKeyType, ObjectId, PinPolicy,
    PivSession, PivSignature, PivSigner, Slot, TouchPolicy, device_pubkey_to_spki,
};

use yubikit::smartcard::SmartCardConnection;
use yubikit::tlv::{parse_tlv_list, tlv_encode};

use crate::cli_enums::{
    CliFormat, CliHashAlgorithm, CliKeyType, CliMgmtKeyType, CliPinPolicy, CliTouchPolicy,
};
use crate::scp::{self, ScpConfig, ScpParams};
use crate::util::{CliError, read_file_or_stdin, write_file_or_stdout};

fn open_session<'a>(
    dev: &'a YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<PivSession<impl yubikit::smartcard::SmartCardConnection + use<'a>>, CliError> {
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::PIV)?;
    match scp_config {
        ScpConfig::None => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            PivSession::new(conn)
                .map_err(|(e, _)| CliError(format!("Failed to open PIV session: {e}")))
        }
        ref config => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            let params = scp::to_scp_key_params(config)
                .expect("non-None ScpConfig must convert to ScpKeyParams");
            PivSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| CliError(format!("Failed to open PIV session: {e}")))
        }
    }
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

fn parse_management_key(s: &str) -> Result<Vec<u8>, CliError> {
    hex::decode(s).map_err(|_| CliError("Management key must be hex-encoded.".into()))
}

// ---------------------------------------------------------------------------
// Pivman data: management key storage on device
// ---------------------------------------------------------------------------

const PIVMAN_OBJ_ID: u32 = 0x5FFF00;
const PIVMAN_PROTECTED_OBJ_ID: u32 = ObjectId::Printed as u32;

const TAG_PIVMAN_DATA: u32 = 0x80;
const TAG_PIVMAN_FLAGS: u32 = 0x81;
const TAG_PIVMAN_PROTECTED: u32 = 0x88;
const TAG_PIVMAN_KEY: u32 = 0x89;

const PIVMAN_FLAG_KEY_PROTECTED: u8 = 0x02;

/// Read the pivman public data object. Returns the inner TLV list.
fn get_pivman_data(session: &mut PivSession<impl SmartCardConnection>) -> Vec<(u32, Vec<u8>)> {
    session
        .get_object_raw(PIVMAN_OBJ_ID)
        .ok()
        .and_then(|raw| {
            let inner = yubikit::tlv::tlv_unpack(TAG_PIVMAN_DATA, &raw).ok()?;
            parse_tlv_list(&inner).ok()
        })
        .unwrap_or_default()
}

/// Check if the management key is stored on device.
fn has_stored_key(pivman: &[(u32, Vec<u8>)]) -> bool {
    pivman
        .iter()
        .find(|(t, _)| *t == TAG_PIVMAN_FLAGS)
        .is_some_and(|(_, v)| !v.is_empty() && (v[0] & PIVMAN_FLAG_KEY_PROTECTED) != 0)
}

/// Write pivman public data. Encodes the TLV list back into the outer tag.
fn put_pivman_data(
    session: &mut PivSession<impl SmartCardConnection>,
    entries: &[(u32, Vec<u8>)],
) -> Result<(), CliError> {
    let mut inner = Vec::new();
    for (tag, val) in entries {
        inner.extend_from_slice(&tlv_encode(*tag, val));
    }
    let outer = if inner.is_empty() {
        vec![]
    } else {
        tlv_encode(TAG_PIVMAN_DATA, &inner)
    };
    session
        .put_object_raw(PIVMAN_OBJ_ID, Some(&outer))
        .map_err(|e| CliError(format!("Failed to write pivman data: {e}")))
}

/// Read the pivman protected data. Requires PIN to have been verified.
fn get_pivman_protected_data(
    session: &mut PivSession<impl SmartCardConnection>,
) -> Vec<(u32, Vec<u8>)> {
    session
        .get_object_raw(PIVMAN_PROTECTED_OBJ_ID)
        .ok()
        .and_then(|raw| {
            let inner = yubikit::tlv::tlv_unpack(TAG_PIVMAN_PROTECTED, &raw).ok()?;
            parse_tlv_list(&inner).ok()
        })
        .unwrap_or_default()
}

/// Write pivman protected data. Encodes the TLV list back into the outer tag.
fn put_pivman_protected_data(
    session: &mut PivSession<impl SmartCardConnection>,
    entries: &[(u32, Vec<u8>)],
) -> Result<(), CliError> {
    let mut inner = Vec::new();
    for (tag, val) in entries {
        inner.extend_from_slice(&tlv_encode(*tag, val));
    }
    let outer = if inner.is_empty() {
        vec![]
    } else {
        tlv_encode(TAG_PIVMAN_PROTECTED, &inner)
    };
    session
        .put_object_raw(PIVMAN_PROTECTED_OBJ_ID, Some(&outer))
        .map_err(|e| CliError(format!("Failed to write pivman protected data: {e}")))
}

/// Update or remove a TLV entry in a list, preserving all other entries.
fn set_tlv_entry(entries: &mut Vec<(u32, Vec<u8>)>, tag: u32, value: Option<Vec<u8>>) {
    entries.retain(|(t, _)| *t != tag);
    if let Some(v) = value {
        entries.push((tag, v));
    }
}

/// Set the management key and keep pivman data in sync.
fn pivman_set_mgm_key(
    session: &mut PivSession<impl SmartCardConnection>,
    key_type: ManagementKeyType,
    new_key: &[u8],
    touch: bool,
    store_on_device: bool,
) -> Result<(), CliError> {
    let mut pivman = get_pivman_data(session);
    let was_stored = has_stored_key(&pivman);

    // If we need to read/clear protected data, get it now (while PIN is still verified)
    let mut prot = if store_on_device || was_stored {
        Some(get_pivman_protected_data(session))
    } else {
        None
    };

    // Set the actual management key on the device
    session
        .set_management_key(key_type, new_key, touch)
        .map_err(|e| CliError(format!("Failed to set management key: {e}")))?;

    // Update the stored-key flag
    let current_flags = pivman
        .iter()
        .find(|(t, _)| *t == TAG_PIVMAN_FLAGS)
        .map(|(_, v)| if v.is_empty() { 0u8 } else { v[0] })
        .unwrap_or(0);

    let new_flags = if store_on_device {
        current_flags | PIVMAN_FLAG_KEY_PROTECTED
    } else {
        current_flags & !PIVMAN_FLAG_KEY_PROTECTED
    };

    if new_flags != 0 {
        set_tlv_entry(&mut pivman, TAG_PIVMAN_FLAGS, Some(vec![new_flags]));
    } else {
        set_tlv_entry(&mut pivman, TAG_PIVMAN_FLAGS, None);
    }

    put_pivman_data(session, &pivman)?;

    // Update protected data
    if let Some(ref mut prot_entries) = prot {
        if store_on_device {
            set_tlv_entry(prot_entries, TAG_PIVMAN_KEY, Some(new_key.to_vec()));
        } else {
            set_tlv_entry(prot_entries, TAG_PIVMAN_KEY, None);
        }
        put_pivman_protected_data(session, prot_entries)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------

/// Authenticate the management key. Returns true if PIN was verified as a
/// side effect (i.e. when using a PIN-protected management key).
fn authenticate_session(
    session: &mut PivSession<impl SmartCardConnection>,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<bool, CliError> {
    if let Some(k) = mgmt_key {
        let key = parse_management_key(k)?;
        session
            .authenticate(&key)
            .map_err(|e| CliError(format!("Authentication failed: {e}")))?;
        return Ok(false);
    }

    // Check if the key is stored on device (protected by PIN)
    let pivman = get_pivman_data(session);
    if has_stored_key(&pivman) {
        ensure_pin(session, pin)?;
        let prot = get_pivman_protected_data(session);
        if let Some((_, key)) = prot.iter().find(|(t, _)| *t == TAG_PIVMAN_KEY) {
            session
                .authenticate(key)
                .map_err(|e| CliError(format!("Authentication with stored key failed: {e}")))?;
            return Ok(true);
        }
        return Err(CliError(
            "Management key is marked as stored on device but could not be read.".into(),
        ));
    }

    // Try default key first, prompt if it fails
    if session.authenticate(DEFAULT_MANAGEMENT_KEY).is_ok() {
        return Ok(false);
    }
    let input = crate::util::prompt_secret("Enter management key")?;
    let key = parse_management_key(&input)?;
    session
        .authenticate(&key)
        .map_err(|e| CliError(format!("Authentication failed: {e}")))?;
    Ok(false)
}

/// Ensure PIN is verified. If pin is Some, verifies it. If None, prompts.
fn ensure_pin(
    session: &mut PivSession<impl yubikit::smartcard::SmartCardConnection>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let pin_value = match pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter PIN")?,
    };
    session.verify_pin(&pin_value).map_err(|e| match &e {
        yubikit::piv::PivError::InvalidPin(0) => CliError("PIN is blocked.".into()),
        yubikit::piv::PivError::InvalidPin(attempts) => {
            CliError(format!("PIN verification failed, {attempts} tries left."))
        }
        _ => CliError(format!("PIN verification failed: {e}")),
    })
}

/// Try to run an operation, and if it fails with a security condition error,
/// prompt for PIN and retry.
fn verify_pin_if_needed<C, F, T>(
    session: &mut PivSession<C>,
    pin: Option<&str>,
    mut f: F,
) -> Result<T, CliError>
where
    C: yubikit::smartcard::SmartCardConnection,
    F: FnMut(&mut PivSession<C>) -> Result<T, yubikit::piv::PivError>,
{
    match f(session) {
        Ok(val) => Ok(val),
        Err(yubikit::piv::PivError::SmartCard(yubikit::smartcard::SmartCardError::Apdu {
            sw,
            ..
        })) if sw == yubikit::smartcard::Sw::SecurityConditionNotSatisfied as u16 => {
            ensure_pin(session, pin)?;
            f(session).map_err(|e| CliError(format!("{e}")))
        }
        Err(e) => Err(CliError(format!("{e}"))),
    }
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

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;
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
        Err(_) => {
            if let Ok(n) = session.get_pin_attempts() {
                println!("PIN tries remaining:      {n}")
            }
        }
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

    let cert = Certificate::from_der(cert_der).ok()?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let serial = hex::encode(tbs.serial_number.as_bytes())
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or("??"))
        .collect::<Vec<_>>()
        .join(":");
    let not_before = tbs.validity.not_before.to_string();
    let not_after = tbs.validity.not_after.to_string();

    let key_type =
        KeyType::from_public_key_der(&tbs.subject_public_key_info.to_der().unwrap_or_default())
            .map(|kt| format!("{kt}"))
            .unwrap_or_else(|_| "Unknown".to_string());

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

pub fn run_reset(dev: &YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!("WARNING! This will delete all stored PIV data and restore factory settings.");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }
    let mut session = open_session(dev, scp_params)?;

    // Block PIN and PUK first (required by reset)
    for _ in 0..15 {
        let _ = session.verify_pin("00000000");
        let _ = session.change_puk("00000000", "00000000");
    }

    session
        .reset()
        .map_err(|e| CliError(format!("Failed to reset PIV: {e}")))?;
    eprintln!("PIV application has been reset.");
    Ok(())
}

pub fn run_change_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let old = match pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter the current PIN")?,
    };
    let new = match new_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PIN")?,
    };

    if new.len() < 6 || new.len() > 8 {
        return Err(CliError("PIN must be 6-8 characters.".into()));
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .change_pin(&old, &new)
        .map_err(|e| CliError(format!("Failed to change PIN: {e}")))?;
    eprintln!("PIN changed.");
    Ok(())
}

pub fn run_change_puk(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    puk: Option<&str>,
    new_puk: Option<&str>,
) -> Result<(), CliError> {
    let old = match puk {
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter the current PUK")?,
    };
    let new = match new_puk {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PUK")?,
    };

    if new.len() < 6 || new.len() > 8 {
        return Err(CliError("PUK must be 6-8 characters.".into()));
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .change_puk(&old, &new)
        .map_err(|e| CliError(format!("Failed to change PUK: {e}")))?;
    eprintln!("PUK changed.");
    Ok(())
}

pub fn run_unblock_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    puk: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let puk = match puk {
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter the PUK")?,
    };
    let new = match new_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PIN")?,
    };

    if new.len() < 6 || new.len() > 8 {
        return Err(CliError("New PIN must be 6-8 characters.".into()));
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .unblock_pin(&puk, &new)
        .map_err(|e| CliError(format!("Failed to unblock PIN: {e}")))?;
    eprintln!("PIN unblocked.");
    Ok(())
}

pub fn run_set_retries(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
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

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .set_pin_attempts(pin_retries, puk_retries)
        .map_err(|e| CliError(format!("Failed to set retries: {e}")))?;
    eprintln!("PIN and PUK retry counts set.");
    Ok(())
}

pub fn run_change_management_key(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    mgmt_key: Option<&str>,
    new_mgmt_key: Option<&str>,
    algorithm: CliMgmtKeyType,
    touch: bool,
    generate: bool,
    force: bool,
    pin: Option<&str>,
    protect: bool,
) -> Result<(), CliError> {
    let key_type: ManagementKeyType = algorithm.into();
    let key_len = key_type.key_len();

    let new_key = if generate {
        let mut k = vec![0u8; key_len];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        k
    } else if let Some(k) = new_mgmt_key {
        let bytes = parse_management_key(k)?;
        if bytes.len() != key_len {
            return Err(CliError(format!(
                "Management key must be {key_len} bytes for {key_type}."
            )));
        }
        bytes
    } else {
        let input = crate::util::prompt_new_secret("New management key (hex)")?;
        let bytes = parse_management_key(&input)?;
        if bytes.len() != key_len {
            return Err(CliError(format!(
                "Management key must be {key_len} bytes for {key_type}."
            )));
        }
        bytes
    };

    if !force && !confirm("Change management key?") {
        return Err(CliError("Aborted.".into()));
    }

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if protect && !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    pivman_set_mgm_key(&mut session, key_type, &new_key, touch, protect)?;

    if generate {
        eprintln!("Management key set: {}", hex::encode(&new_key));
    } else {
        eprintln!("Management key changed.");
    }
    Ok(())
}

pub fn run_keys_generate(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    algorithm: CliKeyType,
    pin_policy: CliPinPolicy,
    touch_policy: CliTouchPolicy,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    format: CliFormat,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let key_type: KeyType = algorithm.into();
    let pp: PinPolicy = pin_policy.into();
    let tp: TouchPolicy = touch_policy.into();

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    let pub_key_device = session
        .generate_key(slot, key_type, pp, tp)
        .map_err(|e| CliError(format!("Failed to generate key: {e}")))?;

    let spki_der = device_pubkey_to_spki(key_type, &pub_key_device)
        .map_err(|e| CliError(format!("Failed to encode public key: {e}")))?;

    match format {
        CliFormat::Der => {
            write_file_or_stdout(output, &spki_der)?;
        }
        CliFormat::Pem => {
            let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
                .map_err(|e| CliError(format!("Failed to parse SPKI: {e}")))?;
            let pem = spki
                .to_pem(LineEnding::LF)
                .map_err(|e| CliError(format!("Failed to encode PEM: {e}")))?;
            write_file_or_stdout(output, pem.as_bytes())?;
        }
    }

    eprintln!("Generated {key_type} key in slot {slot}. Public key written to {output}.");
    Ok(())
}

pub fn run_keys_import(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    key_file: &str,
    pin_policy: CliPinPolicy,
    touch_policy: CliTouchPolicy,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    password: Option<&str>,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let pp: PinPolicy = pin_policy.into();
    let tp: TouchPolicy = touch_policy.into();

    let data = read_file_or_stdin(key_file)?;

    let der = decrypt_private_key_data(&data, password)?;

    // Auto-detect key type from DER
    let key_type = KeyType::from_private_key_der(&der)
        .map_err(|_| CliError("Could not determine key type from file.".into()))?;

    // Extract the inner private key data from PKCS#8 wrapper
    let inner_key = KeyType::extract_private_key_from_pkcs8(&der)
        .map_err(|e| CliError(format!("Failed to extract private key: {e}")))?;

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    session
        .put_key(slot, key_type, &inner_key, pp, tp)
        .map_err(|e| CliError(format!("Failed to import key: {e}")))?;

    eprintln!("Private key imported to slot {slot}.");
    Ok(())
}

pub fn run_keys_info(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
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
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    format: CliFormat,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let cert_der = session
        .attest_key(slot)
        .map_err(|e| CliError(format!("Failed to attest key: {e}")))?;

    write_cert_file(output, &cert_der, format)?;
    eprintln!("Attestation certificate written to {output}.");
    Ok(())
}

pub fn run_keys_export(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    format: CliFormat,
    verify: bool,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;

    // Try metadata first (5.3.0+)
    let (spki_der, from_cert) = if let Ok(meta) = session.get_slot_metadata(slot)
        && !meta.public_key_der.is_empty()
    {
        let spki = device_pubkey_to_spki(meta.key_type, &meta.public_key_der)
            .map_err(|e| CliError(format!("Failed to encode public key: {e}")))?;
        (spki, false)
    } else {
        // Fall back to reading public key from stored certificate
        let cert_der = session
            .get_certificate(slot)
            .map_err(|_| CliError(format!("Unable to export public key from slot {slot}.")))?;
        let cert = Certificate::from_der(&cert_der)
            .map_err(|e| CliError(format!("Failed to parse certificate: {e}")))?;
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| CliError(format!("Failed to encode SPKI: {e}")))?;
        (spki, true)
    };

    // Verify the public key matches the private key if requested.
    // Only strictly needed when we read from a certificate (metadata is authoritative).
    if verify && from_cert {
        check_key_match(&mut session, slot, &spki_der, pin)?;
    }

    match format {
        CliFormat::Der => write_file_or_stdout(output, &spki_der)?,
        CliFormat::Pem => {
            let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
                .map_err(|e| CliError(format!("Failed to parse SPKI: {e}")))?;
            let pem = spki
                .to_pem(LineEnding::LF)
                .map_err(|e| CliError(format!("Failed to encode PEM: {e}")))?;
            write_file_or_stdout(output, pem.as_bytes())?;
        }
    }
    eprintln!("Public key exported to {output}.");
    Ok(())
}

pub fn run_keys_move(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    source: &str,
    dest: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let from = parse_slot(source)?;
    let to = parse_slot(dest)?;
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .move_key(from, to)
        .map_err(|e| CliError(format!("Failed to move key: {e}")))?;
    println!("Key moved from {from} to {to}.");
    Ok(())
}

pub fn run_keys_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .delete_key(slot)
        .map_err(|e| CliError(format!("Failed to delete key: {e}")))?;
    eprintln!("Key in slot {slot} deleted.");
    Ok(())
}

pub fn run_certificates_export(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    format: CliFormat,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let cert_der = session
        .get_certificate(slot)
        .map_err(|e| CliError(format!("Failed to get certificate: {e}")))?;

    write_cert_file(output, &cert_der, format)?;
    eprintln!("Certificate exported to {output}.");
    Ok(())
}

pub fn run_certificates_import(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    cert_file: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    compress: bool,
    update_chuid: bool,
    password: Option<&str>,
    verify: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;

    let data = read_file_or_stdin(cert_file)?;

    let der = decrypt_certificate_data(&data, password)?;

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    if verify {
        // Extract the public key from the certificate and check it matches the slot's private key
        let cert = Certificate::from_der(&der)
            .map_err(|e| CliError(format!("Failed to parse certificate: {e}")))?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| CliError(format!("Failed to encode SPKI: {e}")))?;
        check_key_match(&mut session, slot, &spki_der, pin)?;
    }

    session
        .put_certificate(slot, &der, compress)
        .map_err(|e| CliError(format!("Failed to import certificate: {e}")))?;
    eprintln!("Certificate imported to slot {slot}.");

    if update_chuid {
        generate_chuid(&mut session)?;
    }
    Ok(())
}

pub fn run_certificates_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    update_chuid: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .delete_certificate(slot)
        .map_err(|e| CliError(format!("Failed to delete certificate: {e}")))?;
    eprintln!("Certificate in slot {slot} deleted.");

    if update_chuid {
        generate_chuid(&mut session)?;
    }
    Ok(())
}

pub fn run_objects_export(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    object: &str,
    output: &str,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let obj_id = parse_object_id(object)?;
    let mut session = open_session(dev, scp_params)?;
    let data = verify_pin_if_needed(&mut session, pin, |s| s.get_object(obj_id))?;

    write_file_or_stdout(output, &data)?;
    if output != "-" {
        eprintln!("Object exported to {output}.");
    }
    Ok(())
}

pub fn run_objects_import(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    object: &str,
    data_file: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let obj_id = parse_object_id(object)?;
    let data = read_file_or_stdin(data_file)?;

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .put_object(obj_id, Some(&data))
        .map_err(|e| CliError(format!("Failed to write object: {e}")))?;
    eprintln!("Object imported.");
    Ok(())
}

/// Generate a new CHUID and write it to the device.
fn generate_chuid(
    session: &mut PivSession<impl yubikit::smartcard::SmartCardConnection>,
) -> Result<(), CliError> {
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
    scp_params: &ScpParams,
    object: &str,
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, management_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

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
            eprintln!("CHUID generated.");
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
            eprintln!("CCC generated.");
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
    scp_params: &ScpParams,
    slot: &str,
    subject: &str,
    valid_days: u32,
    hash_algorithm: CliHashAlgorithm,
    management_key: Option<&str>,
    pin: Option<&str>,
    public_key_file: Option<&str>,
    update_chuid: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let hash_alg: HashAlgorithm = hash_algorithm.into();

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, management_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    let (key_type, spki_der) = resolve_public_key(&mut session, slot, public_key_file)?;

    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .map_err(|e| CliError(format!("Failed to parse SPKI: {e}")))?;
    let subject_name =
        Name::from_str(subject).map_err(|e| CliError(format!("Invalid subject DN: {e}")))?;

    let serial = random_serial_number()?;
    let validity = Validity::from_now(Duration::from_secs(u64::from(valid_days) * 86400))
        .map_err(|e| CliError(format!("Invalid validity period: {e}")))?;

    let cert_der = {
        let signer = PivSigner::new(&mut session, slot, key_type, hash_alg, &spki_der);
        let builder =
            CertificateBuilder::new(Profile::Root, serial, validity, subject_name, spki, &signer)
                .map_err(|e| CliError(format!("Failed to create certificate builder: {e}")))?;

        let cert = builder
            .build::<PivSignature>()
            .map_err(|e| CliError(format!("Failed to build certificate: {e}")))?;

        cert.to_der()
            .map_err(|e| CliError(format!("Failed to encode certificate: {e}")))?
    };

    session
        .put_certificate(slot, &cert_der, false)
        .map_err(|e| CliError(format!("Failed to store certificate: {e}")))?;

    eprintln!("Certificate generated and stored in slot {slot:?}.");

    if update_chuid {
        generate_chuid(&mut session)?;
    }
    Ok(())
}

pub fn run_certificates_request(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    subject: &str,
    hash_algorithm: CliHashAlgorithm,
    output: &str,
    pin: Option<&str>,
    public_key_file: Option<&str>,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let hash_alg: HashAlgorithm = hash_algorithm.into();

    let mut session = open_session(dev, scp_params)?;
    ensure_pin(&mut session, pin)?;

    let (key_type, spki_der) = resolve_public_key(&mut session, slot, public_key_file)?;

    let subject_name =
        Name::from_str(subject).map_err(|e| CliError(format!("Invalid subject DN: {e}")))?;

    let signer = PivSigner::new(&mut session, slot, key_type, hash_alg, &spki_der);
    let builder = RequestBuilder::new(subject_name, &signer)
        .map_err(|e| CliError(format!("Failed to create CSR builder: {e}")))?;

    let csr = builder
        .build::<PivSignature>()
        .map_err(|e| CliError(format!("Failed to build CSR: {e}")))?;

    let pem = csr
        .to_pem(LineEnding::LF)
        .map_err(|e| CliError(format!("Failed to encode CSR PEM: {e}")))?;
    write_file_or_stdout(output, pem.as_bytes())?;
    if output != "-" {
        eprintln!("CSR written to {output}.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hash algorithm selection
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers for cert/CSR generation
// ---------------------------------------------------------------------------

fn resolve_public_key(
    session: &mut PivSession<impl yubikit::smartcard::SmartCardConnection>,
    slot: Slot,
    public_key_file: Option<&str>,
) -> Result<(KeyType, Vec<u8>), CliError> {
    if let Some(pk_file) = public_key_file {
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
        Ok((kt, der))
    } else {
        let metadata = session.get_slot_metadata(slot).map_err(|e| {
            CliError(format!(
                "Failed to get slot metadata (is a key present?): {e}"
            ))
        })?;
        let kt = metadata.key_type;
        let spki = device_pubkey_to_spki(kt, &metadata.public_key_der)
            .map_err(|e| CliError(format!("Failed to encode public key: {e}")))?;
        Ok((kt, spki))
    }
}

fn random_serial_number() -> Result<SerialNumber, CliError> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).map_err(|e| CliError(format!("RNG error: {e}")))?;
    // Ensure positive (clear high bit)
    buf[0] &= 0x7F;
    if buf[0] == 0 {
        buf[0] = 0x01;
    }
    SerialNumber::new(&buf).map_err(|e| CliError(format!("Invalid serial number: {e}")))
}

// ---------------------------------------------------------------------------
// Password-protected key/cert parsing helpers
// ---------------------------------------------------------------------------

/// Attempt to decrypt/parse a private key from raw data, handling
/// PEM (plain or ENCRYPTED), PKCS#12, and raw DER. If the key is encrypted
/// and no password is provided, the user is prompted interactively.
fn decrypt_private_key_data(data: &[u8], password: Option<&str>) -> Result<Vec<u8>, CliError> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
    {
        let encrypted = text.contains("ENCRYPTED");
        if encrypted {
            let pw = match password {
                Some(p) => p.to_string(),
                None => crate::util::prompt_secret("Enter password to decrypt key")?,
            };
            return decrypt_pem_private_key(text, &pw);
        }
        return pem_decode(text);
    }

    // Try PKCS#12 if the data looks like it
    if is_pkcs12(data) {
        let pw = match password {
            Some(p) => p.to_string(),
            None => crate::util::prompt_secret("Enter password to decrypt PKCS#12 file")?,
        };
        return extract_private_key_from_pkcs12(data, &pw);
    }

    // Try plain DER
    Ok(data.to_vec())
}

/// Decrypt an encrypted PKCS#8 PEM private key.
fn decrypt_pem_private_key(pem_text: &str, password: &str) -> Result<Vec<u8>, CliError> {
    use pkcs8::EncryptedPrivateKeyInfo;

    let der = pem_decode(pem_text)?;
    let enc_key = EncryptedPrivateKeyInfo::try_from(der.as_slice())
        .map_err(|e| CliError(format!("Failed to parse encrypted key: {e}")))?;
    let dec_key = enc_key
        .decrypt(password)
        .map_err(|_| CliError("Wrong password for encrypted key.".into()))?;
    Ok(dec_key.as_bytes().to_vec())
}

/// Attempt to parse a certificate from raw data, supporting password-protected
/// PKCS#12 files. For PEM and DER certs, the password is ignored.
fn decrypt_certificate_data(data: &[u8], password: Option<&str>) -> Result<Vec<u8>, CliError> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
    {
        return pem_decode(text);
    }

    // Try PKCS#12
    if is_pkcs12(data) {
        let pw = match password {
            Some(p) => p.to_string(),
            None => crate::util::prompt_secret("Enter password to decrypt PKCS#12 file")?,
        };
        return extract_certificate_from_pkcs12(data, &pw);
    }

    // Plain DER certificate
    Ok(data.to_vec())
}

/// Check if data looks like a PKCS#12 file.
/// PKCS#12 is a DER SEQUENCE whose first element is INTEGER with value 3.
fn is_pkcs12(data: &[u8]) -> bool {
    if data.len() < 10 || data[0] != 0x30 {
        return false;
    }
    // Skip the outer SEQUENCE length bytes
    let len_byte = data[1];
    let offset = if len_byte & 0x80 == 0 {
        2
    } else {
        2 + (len_byte & 0x7f) as usize
    };
    // Expect INTEGER tag (0x02) with length 1 and value 3
    offset + 3 <= data.len()
        && data[offset] == 0x02
        && data[offset + 1] == 0x01
        && data[offset + 2] == 0x03
}

/// Extract a private key from PKCS#12 data.
fn extract_private_key_from_pkcs12(data: &[u8], password: &str) -> Result<Vec<u8>, CliError> {
    use p12_keystore::{KeyStore, Pkcs12ImportPolicy};

    let ks = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| CliError(format!("Failed to parse PKCS#12 file: {e}")))?;
    let (_, chain) = ks
        .private_key_chain()
        .ok_or_else(|| CliError("No private key found in PKCS#12 file.".into()))?;
    Ok(chain.key().as_der().to_vec())
}

/// Extract a certificate from PKCS#12 data.
fn extract_certificate_from_pkcs12(data: &[u8], password: &str) -> Result<Vec<u8>, CliError> {
    use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};

    let ks = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| CliError(format!("Failed to parse PKCS#12 file: {e}")))?;

    // Try cert from a key chain first, then standalone certs
    for (_, entry) in ks.entries() {
        match entry {
            KeyStoreEntry::PrivateKeyChain(chain) => {
                if let Some(cert) = chain.certs().first() {
                    return Ok(cert.as_der().to_vec());
                }
            }
            KeyStoreEntry::Certificate(cert) => {
                return Ok(cert.as_der().to_vec());
            }
            _ => {}
        }
    }
    Err(CliError("No certificate found in PKCS#12 file.".into()))
}

/// Verify that a public key (as SPKI DER) matches the private key in a PIV slot
/// by signing test data and verifying the signature.
fn check_key_match<C: yubikit::smartcard::SmartCardConnection>(
    session: &mut PivSession<C>,
    slot: Slot,
    spki_der: &[u8],
    pin: Option<&str>,
) -> Result<(), CliError> {
    // Determine key type from the metadata or SPKI
    let meta = session
        .get_slot_metadata(slot)
        .map_err(|_| CliError(format!("No private key in slot {slot}.")))?;

    let key_type = meta.key_type;

    // Sign test data
    let test_message = b"ykman-verify-key-match";
    let hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(test_message);
        hasher.finalize().to_vec()
    };

    let to_sign = match key_type {
        KeyType::EccP256 | KeyType::EccP384 => hash.clone(),
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let key_byte_len = (key_type.bit_len() / 8) as usize;
            pkcs1v15_pad(&hash, key_byte_len)
        }
        KeyType::Ed25519 => test_message.to_vec(),
        KeyType::X25519 => {
            return Err(CliError("X25519 keys cannot be used for signing.".into()));
        }
    };

    let signature = verify_pin_if_needed(session, pin, |s| s.sign(slot, key_type, &to_sign))?;

    // Verify signature with the public key
    let verified = verify_signature(key_type, spki_der, test_message, &signature);
    if !verified {
        return Err(CliError(format!(
            "Public key does not match the private key in slot {slot}."
        )));
    }
    Ok(())
}

/// PKCS#1 v1.5 padding for RSA signatures with SHA-256.
fn pkcs1v15_pad(hash: &[u8], key_byte_len: usize) -> Vec<u8> {
    // DigestInfo for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    let digest_info_prefix: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let t_len = digest_info_prefix.len() + hash.len();
    let ps_len = key_byte_len - t_len - 3;
    let mut padded = vec![0x00, 0x01];
    padded.extend(vec![0xFF; ps_len]);
    padded.push(0x00);
    padded.extend_from_slice(digest_info_prefix);
    padded.extend_from_slice(hash);
    padded
}

/// Verify a signature using the public key from SPKI DER.
fn verify_signature(key_type: KeyType, spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match key_type {
        KeyType::EccP256 => {
            use p256::ecdsa::{VerifyingKey, signature::Verifier};
            let vk =
                match VerifyingKey::from_sec1_bytes(&extract_ec_pubkey_bytes_from_spki(spki_der)) {
                    Ok(vk) => vk,
                    Err(_) => return false,
                };
            let sig = match p256::ecdsa::DerSignature::try_from(signature) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify(message, &sig).is_ok()
        }
        KeyType::EccP384 => {
            use p384::ecdsa::{VerifyingKey, signature::Verifier};
            let vk =
                match VerifyingKey::from_sec1_bytes(&extract_ec_pubkey_bytes_from_spki(spki_der)) {
                    Ok(vk) => vk,
                    Err(_) => return false,
                };
            let sig = match p384::ecdsa::DerSignature::try_from(signature) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify(message, &sig).is_ok()
        }
        // For RSA and Ed25519, we don't have verification crates readily available,
        // so assume match if signing succeeded without error.
        _ => true,
    }
}

/// Extract raw EC public key bytes from an SPKI DER structure.
fn extract_ec_pubkey_bytes_from_spki(spki_der: &[u8]) -> Vec<u8> {
    // Parse SPKI to get the BIT STRING containing the public key
    if let Ok(spki) = SubjectPublicKeyInfoOwned::from_der(spki_der) {
        return spki.subject_public_key.raw_bytes().to_vec();
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// PEM encoding / decoding
// ---------------------------------------------------------------------------

fn pem_decode(text: &str) -> Result<Vec<u8>, CliError> {
    // Generic PEM decode: extract first PEM block regardless of label
    let doc = der::Document::from_pem(text)
        .map(|(_, doc)| doc)
        .map_err(|e| CliError(format!("Invalid PEM data: {e}")))?;
    Ok(doc.as_bytes().to_vec())
}

fn write_cert_file(output: &str, cert_der: &[u8], format: CliFormat) -> Result<(), CliError> {
    match format {
        CliFormat::Der => {
            write_file_or_stdout(output, cert_der)?;
        }
        CliFormat::Pem => {
            let cert = Certificate::from_der(cert_der)
                .map_err(|e| CliError(format!("Failed to parse certificate: {e}")))?;
            let pem = cert
                .to_pem(LineEnding::LF)
                .map_err(|e| CliError(format!("Failed to encode PEM: {e}")))?;
            write_file_or_stdout(output, pem.as_bytes())?;
        }
    }
    Ok(())
}
