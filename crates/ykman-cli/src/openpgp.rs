use std::io::{self, Write};

use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::openpgp::{KeyRef, KeyStatus, OpenPgpSession, PinPolicy, Uif};

use crate::cli_enums::{CliFormat, CliKeyRef, CliOpenpgpPinPolicy, CliUif};
use crate::scp::{self, ScpConfig, ScpParams};
use crate::util::{CliError, read_file_or_stdin, write_file_or_stdout};

fn open_session<'a>(
    dev: &'a YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<OpenPgpSession<impl yubikit::smartcard::SmartCardConnection + use<'a>>, CliError> {
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::OPENPGP)?;
    match scp_config {
        ScpConfig::None => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            OpenPgpSession::new(conn)
                .map_err(|(e, _)| CliError(format!("Failed to open OpenPGP session: {e}")))
        }
        ref config => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            let params = scp::to_scp_key_params(config)
                .expect("non-None ScpConfig must convert to ScpKeyParams");
            OpenPgpSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| CliError(format!("Failed to open OpenPGP session: {e}")))
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

fn ensure_admin_pin(admin_pin: Option<&str>) -> Result<String, CliError> {
    match admin_pin {
        Some(p) => Ok(p.to_string()),
        None => crate::util::prompt_secret("Enter Admin PIN"),
    }
}

fn ensure_pin(pin: Option<&str>) -> Result<String, CliError> {
    match pin {
        Some(p) => Ok(p.to_string()),
        None => crate::util::prompt_secret("Enter PIN"),
    }
}

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;

    let aid = session.aid().clone();
    let (major, minor) = aid.version();
    // OpenPGP spec version is from the AID, application version is firmware
    println!("OpenPGP version:            {major}.{minor}");
    println!("Application version:        {}", session.version());

    if let Ok(pw_status) = session.get_pin_status() {
        println!(
            "PIN tries remaining:        {}",
            pw_status.get_attempts(yubikit::openpgp::Pw::User),
        );
        println!(
            "Reset code tries remaining: {}",
            pw_status.get_attempts(yubikit::openpgp::Pw::Reset),
        );
        println!(
            "Admin PIN tries remaining:  {}",
            pw_status.get_attempts(yubikit::openpgp::Pw::Admin),
        );

        let pin_policy = match pw_status.pin_policy_user {
            PinPolicy::Once => "Once",
            PinPolicy::Always => "Always",
        };
        println!("Require PIN for signature:  {pin_policy}");
    }

    if let Ok(kdf) = session.get_kdf() {
        let enabled = if matches!(kdf, yubikit::openpgp::Kdf::None) {
            "False"
        } else {
            "True"
        };
        println!("KDF enabled:                {enabled}");
    } else {
        println!("KDF enabled:                False");
    }

    // Show key information
    if let Ok(data) = session.get_application_related_data() {
        let disc = &data.discretionary;
        let ver = session.version();

        for key_ref in &[KeyRef::Sig, KeyRef::Dec, KeyRef::Aut] {
            let fp = disc.fingerprints.get(key_ref);
            let status = disc.key_information.get(key_ref);

            // Decide whether to show this key
            let show = if ver >= yubikit::core::Version(5, 2, 0) {
                // For 5.2+, show if key_information has a non-None status
                matches!(status, Some(s) if *s != KeyStatus::None)
            } else {
                // For older, show if fingerprint is non-zero
                fp.is_some_and(|f| f.iter().any(|&b| b != 0))
            };

            if !show {
                continue;
            }

            let name = match key_ref {
                KeyRef::Sig => "Signature key",
                KeyRef::Dec => "Decryption key",
                KeyRef::Aut => "Authentication key",
                KeyRef::Att => "Attestation key",
            };

            let fp_str = format_fingerprint(fp.map(|v| v.as_slice()).unwrap_or(&[]));
            let touch = disc.get_uif(*key_ref).map_or("N/A".to_string(), format_uif);

            println!("{name}:");
            println!("  Fingerprint:  {fp_str}");
            println!("  Touch policy: {touch}");
        }
    }

    Ok(())
}

fn format_fingerprint(fp: &[u8]) -> String {
    if fp.is_empty() {
        return "N/A".to_string();
    }
    let hex: Vec<String> = fp.iter().map(|b| format!("{b:02X}")).collect();
    // Format as groups of 4 hex chars (2 bytes), with extra space in the middle
    let mut parts = Vec::new();
    for chunk in hex.chunks(2) {
        parts.push(chunk.join(""));
    }
    let mid = parts.len() / 2;
    let left = parts[..mid].join(" ");
    let right = parts[mid..].join(" ");
    format!("{left}  {right}")
}

fn format_uif(uif: Uif) -> String {
    match uif {
        Uif::Off => "Off",
        Uif::On => "On",
        Uif::Fixed => "Fixed",
        Uif::Cached => "Cached",
        Uif::CachedFixed => "Cached Fixed",
    }
    .to_string()
}

pub fn run_reset(dev: &YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!(
            "WARNING! This will delete all stored OpenPGP keys and restore factory settings."
        );
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }

    if scp_params.is_explicit() {
        let mut session = open_session(dev, scp_params)?;
        session
            .reset()
            .map_err(|e| CliError(format!("Failed to reset OpenPGP: {e}")))?;
    } else {
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        yubikit::openpgp::safe_reset(conn)
            .map_err(|e| CliError(format!("Failed to reset OpenPGP: {e}")))?;
    }
    eprintln!("OpenPGP application has been reset.");
    Ok(())
}

pub fn run_set_retries(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin_retries: u8,
    reset_code_retries: u8,
    admin_pin_retries: u8,
    admin_pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    if !force
        && !confirm(&format!(
            "Set PIN retries to {pin_retries}/{reset_code_retries}/{admin_pin_retries}?"
        ))
    {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_session(dev, scp_params)?;
    let ap = ensure_admin_pin(admin_pin)?;
    session
        .verify_admin(&ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_pin_attempts(pin_retries, reset_code_retries, admin_pin_retries)
        .map_err(|e| CliError(format!("Failed to set retries: {e}")))?;
    eprintln!("Retry counts set.");
    Ok(())
}

pub fn run_change_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let old = ensure_pin(pin)?;
    let new = match new_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PIN")?,
    };
    let mut session = open_session(dev, scp_params)?;
    session
        .change_pin(&old, &new)
        .map_err(|e| CliError(format!("Failed to change PIN: {e}")))?;
    eprintln!("PIN changed.");
    Ok(())
}

pub fn run_change_admin_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    admin_pin: Option<&str>,
    new_admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let old = ensure_admin_pin(admin_pin)?;
    let new = match new_admin_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New Admin PIN")?,
    };
    let mut session = open_session(dev, scp_params)?;
    session
        .change_admin(&old, &new)
        .map_err(|e| CliError(format!("Failed to change Admin PIN: {e}")))?;
    eprintln!("Admin PIN changed.");
    Ok(())
}

pub fn run_change_reset_code(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    admin_pin: Option<&str>,
    reset_code: Option<&str>,
) -> Result<(), CliError> {
    let rc = match reset_code {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New reset code")?,
    };
    let ap = ensure_admin_pin(admin_pin)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .verify_admin(&ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_reset_code(&rc)
        .map_err(|e| CliError(format!("Failed to set reset code: {e}")))?;
    eprintln!("Reset code set.");
    Ok(())
}

pub fn run_unblock_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    admin_pin: Option<&str>,
    reset_code: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let new = match new_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PIN")?,
    };
    let mut session = open_session(dev, scp_params)?;
    if let Some(ap) = admin_pin {
        let ap = ap.to_string();
        session
            .verify_admin(&ap)
            .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    }
    session
        .reset_pin(&new, reset_code)
        .map_err(|e| CliError(format!("Failed to unblock PIN: {e}")))?;
    eprintln!("PIN unblocked.");
    Ok(())
}

pub fn run_set_signature_policy(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    policy: CliOpenpgpPinPolicy,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let pp: PinPolicy = policy.into();
    let ap = ensure_admin_pin(admin_pin)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .verify_admin(&ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_signature_pin_policy(pp)
        .map_err(|e| CliError(format!("Failed to set policy: {e}")))?;
    eprintln!("Signature PIN policy set to {pp:?}.");
    Ok(())
}

pub fn run_keys_info(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    key: CliKeyRef,
) -> Result<(), CliError> {
    let key_ref: KeyRef = key.into();
    let mut session = open_session(dev, scp_params)?;

    let data = session
        .get_application_related_data()
        .map_err(|e| CliError(format!("Failed to get application data: {e}")))?;
    let disc = &data.discretionary;

    let status = disc.key_information.get(&key_ref);
    let has_key = if session.version() >= yubikit::core::Version(5, 2, 0) {
        matches!(status, Some(s) if *s != KeyStatus::None)
    } else {
        disc.fingerprints
            .get(&key_ref)
            .is_some_and(|f| f.iter().any(|&b| b != 0))
    };

    if !has_key {
        return Err(CliError(format!(
            "No key stored in slot {}.",
            format_key_ref(key_ref)
        )));
    }

    let name = format_key_ref(key_ref);
    println!("Key slot:     {name}");

    let fp = disc.fingerprints.get(&key_ref);
    println!(
        "Fingerprint:  {}",
        format_fingerprint(fp.map(|v| v.as_slice()).unwrap_or(&[]))
    );

    if let Ok(attrs) = session.get_algorithm_attributes(key_ref) {
        println!("Algorithm:    {}", format_algorithm(&attrs));
    }

    if let Some(s) = status {
        println!("Origin:       {}", format_key_status(*s));
    }

    if let Some(t) = disc.generation_times.get(&key_ref) {
        println!("Created:      {}", format_timestamp(*t));
    }

    if let Ok(uif) = session.get_uif(key_ref) {
        println!("Touch policy: {}", format_uif(uif));
    }

    Ok(())
}

fn format_key_ref(key_ref: KeyRef) -> &'static str {
    match key_ref {
        KeyRef::Sig => "Signature key",
        KeyRef::Dec => "Decryption key",
        KeyRef::Aut => "Authentication key",
        KeyRef::Att => "Attestation key",
    }
}

fn format_algorithm(attrs: &yubikit::openpgp::AlgorithmAttributes) -> String {
    match attrs {
        yubikit::openpgp::AlgorithmAttributes::Rsa(rsa) => format!("RSA{}", rsa.n_len),
        yubikit::openpgp::AlgorithmAttributes::Ec(ec) => {
            ec.oid_string().unwrap_or_else(|_| "Unknown EC".to_string())
        }
    }
}

fn format_key_status(s: KeyStatus) -> &'static str {
    match s {
        KeyStatus::None => "NONE",
        KeyStatus::Generated => "GENERATED",
        KeyStatus::Imported => "IMPORTED",
    }
}

fn format_timestamp(t: u32) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(t as i64, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| format!("{t}"))
}

pub fn run_keys_set_touch(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    key: CliKeyRef,
    policy: CliUif,
    admin_pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let key_ref: KeyRef = key.into();
    let uif: Uif = policy.into();

    if uif.is_fixed() && !force {
        eprintln!("WARNING: Setting a FIXED touch policy cannot be undone without a full reset!");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }

    let ap = ensure_admin_pin(admin_pin)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .verify_admin(&ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_uif(key_ref, uif)
        .map_err(|e| CliError(format!("Failed to set touch policy: {e}")))?;
    eprintln!(
        "Touch policy for {} set to {}.",
        format_key_ref(key_ref),
        format_uif(uif)
    );
    Ok(())
}

pub fn run_keys_import(
    _dev: &YubiKeyDevice,
    _scp_params: &ScpParams,
    key: CliKeyRef,
    key_file: &str,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let _key_ref: KeyRef = key.into();
    let _data = read_file_or_stdin(key_file)?;

    let _ap = ensure_admin_pin(admin_pin)?;

    Err(CliError(
        "Key import requires parsing private key format. Not yet implemented.".into(),
    ))
}

pub fn run_keys_attest(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    key: CliKeyRef,
    output: &str,
    format: CliFormat,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let key_ref: KeyRef = key.into();
    let mut session = open_session(dev, scp_params)?;
    let p = ensure_pin(pin)?;
    session
        .verify_pin(&p, false)
        .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    let cert_der = session
        .attest_key(key_ref)
        .map_err(|e| CliError(format!("Failed to attest key: {e}")))?;

    write_output(output, &cert_der, format, "CERTIFICATE")?;
    eprintln!("Attestation certificate written to {output}.");
    Ok(())
}

pub fn run_certificates_export(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    key: CliKeyRef,
    output: &str,
    format: CliFormat,
) -> Result<(), CliError> {
    let key_ref: KeyRef = key.into();
    let mut session = open_session(dev, scp_params)?;
    let cert_der = session
        .get_certificate(key_ref)
        .map_err(|e| CliError(format!("Failed to get certificate: {e}")))?;

    write_output(output, &cert_der, format, "CERTIFICATE")?;
    eprintln!("Certificate exported to {output}.");
    Ok(())
}

pub fn run_certificates_import(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    key: CliKeyRef,
    cert_file: &str,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let key_ref: KeyRef = key.into();
    let data = read_file_or_stdin(cert_file)?;

    let der = if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("-----BEGIN") {
            pem_decode(text)?
        } else {
            data
        }
    } else {
        data
    };

    let ap = ensure_admin_pin(admin_pin)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .verify_admin(&ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .put_certificate(key_ref, &der)
        .map_err(|e| CliError(format!("Failed to import certificate: {e}")))?;
    eprintln!("Certificate imported.");
    Ok(())
}

pub fn run_certificates_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    key: CliKeyRef,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let key_ref: KeyRef = key.into();
    let ap = ensure_admin_pin(admin_pin)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .verify_admin(&ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .delete_certificate(key_ref)
        .map_err(|e| CliError(format!("Failed to delete certificate: {e}")))?;
    eprintln!("Certificate deleted.");
    Ok(())
}

fn write_output(path: &str, der: &[u8], format: CliFormat, label: &str) -> Result<(), CliError> {
    match format {
        CliFormat::Der => {
            write_file_or_stdout(path, der)?;
        }
        CliFormat::Pem => {
            let pem = pem_encode(label, der);
            write_file_or_stdout(path, pem.as_bytes())?;
        }
    }
    Ok(())
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
