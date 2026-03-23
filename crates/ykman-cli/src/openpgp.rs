use std::io::{self, Write};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::management::Capability;
use yubikit_rs::openpgp::{KeyRef, OpenPgpSession, PinPolicy, Uif};

use crate::scp;
use crate::util::CliError;

fn open_session(
    dev: &YubiKeyDevice,
) -> Result<OpenPgpSession<impl yubikit_rs::iso7816::SmartCardConnection + use<'_>>, CliError> {
    if scp::needs_scp11b(dev, Capability::OPENPGP) {
        let (kid, kvn, pk) = scp::find_scp11b_params(dev)?;
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        let mut protocol = yubikit_rs::iso7816::SmartCardProtocol::new(conn);
        protocol
            .select(yubikit_rs::iso7816::Aid::OPENPGP)
            .map_err(|e| CliError(format!("Failed to select OpenPGP: {e}")))?;
        protocol
            .init_scp11(kid, kvn, &pk, None, &[], None)
            .map_err(|e| CliError(format!("SCP11b initialization failed: {e}")))?;
        OpenPgpSession::from_protocol(protocol)
            .map_err(|e| CliError(format!("Failed to open OpenPGP session: {e}")))
    } else {
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        OpenPgpSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open OpenPGP session: {e}")))
    }
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn parse_key_ref(s: &str) -> Result<KeyRef, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "SIG" | "SIGNATURE" => Ok(KeyRef::Sig),
        "DEC" | "DECRYPTION" => Ok(KeyRef::Dec),
        "AUT" | "AUTHENTICATION" => Ok(KeyRef::Aut),
        "ATT" | "ATTESTATION" => Ok(KeyRef::Att),
        _ => Err(CliError(format!(
            "Invalid key reference: {s}. Use sig, dec, aut, or att."
        ))),
    }
}

fn parse_uif(s: &str) -> Result<Uif, CliError> {
    match s.to_ascii_uppercase().as_str() {
        "OFF" | "DISABLED" => Ok(Uif::Off),
        "ON" | "ENABLED" => Ok(Uif::On),
        "FIXED" => Ok(Uif::Fixed),
        "CACHED" => Ok(Uif::Cached),
        "CACHED-FIXED" | "CACHED_FIXED" => Ok(Uif::CachedFixed),
        _ => Err(CliError(format!(
            "Invalid touch policy: {s}. Use off, on, fixed, cached, or cached-fixed."
        ))),
    }
}

pub fn run_info(dev: &YubiKeyDevice) -> Result<(), CliError> {
    let mut session = open_session(dev)?;

    let aid = session.aid().clone();
    let (major, minor) = aid.version();
    // OpenPGP spec version is from the AID, application version is firmware
    println!("OpenPGP version:            {major}.{minor}");
    println!("Application version:        {}", session.version());

    if let Ok(pw_status) = session.get_pin_status() {
        println!(
            "PIN tries remaining:        {}",
            pw_status.get_attempts(yubikit_rs::openpgp::Pw::User),
        );
        println!(
            "Reset code tries remaining: {}",
            pw_status.get_attempts(yubikit_rs::openpgp::Pw::Reset),
        );
        println!(
            "Admin PIN tries remaining:  {}",
            pw_status.get_attempts(yubikit_rs::openpgp::Pw::Admin),
        );

        let pin_policy = match pw_status.pin_policy_user {
            PinPolicy::Once => "Once",
            PinPolicy::Always => "Always",
        };
        println!("Require PIN for signature:  {pin_policy}");
    }

    if let Ok(kdf) = session.get_kdf() {
        let enabled = !matches!(kdf, yubikit_rs::openpgp::Kdf::None);
        println!("KDF enabled:                {enabled}");
    } else {
        println!("KDF enabled:                False");
    }

    Ok(())
}

pub fn run_reset(dev: &YubiKeyDevice, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!(
            "WARNING! This will delete all stored OpenPGP keys and restore factory settings."
        );
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }
    let mut session = open_session(dev)?;
    session
        .reset()
        .map_err(|e| CliError(format!("Failed to reset OpenPGP: {e}")))?;
    println!("OpenPGP application has been reset.");
    Ok(())
}

pub fn run_set_retries(
    dev: &YubiKeyDevice,
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
    let mut session = open_session(dev)?;
    let ap = admin_pin.unwrap_or("12345678");
    session
        .verify_admin(ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_pin_attempts(pin_retries, reset_code_retries, admin_pin_retries)
        .map_err(|e| CliError(format!("Failed to set retries: {e}")))?;
    println!("Retry counts set.");
    Ok(())
}

pub fn run_change_pin(
    dev: &YubiKeyDevice,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let old = pin.unwrap_or("123456");
    let new = new_pin.ok_or_else(|| CliError("--new-pin is required.".into()))?;
    let mut session = open_session(dev)?;
    session
        .change_pin(old, new)
        .map_err(|e| CliError(format!("Failed to change PIN: {e}")))?;
    println!("PIN changed.");
    Ok(())
}

pub fn run_change_admin_pin(
    dev: &YubiKeyDevice,
    admin_pin: Option<&str>,
    new_admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let old = admin_pin.unwrap_or("12345678");
    let new = new_admin_pin.ok_or_else(|| CliError("--new-admin-pin is required.".into()))?;
    let mut session = open_session(dev)?;
    session
        .change_admin(old, new)
        .map_err(|e| CliError(format!("Failed to change Admin PIN: {e}")))?;
    println!("Admin PIN changed.");
    Ok(())
}

pub fn run_change_reset_code(
    dev: &YubiKeyDevice,
    admin_pin: Option<&str>,
    reset_code: Option<&str>,
) -> Result<(), CliError> {
    let rc = reset_code
        .ok_or_else(|| CliError("--reset-code is required.".into()))?;
    let ap = admin_pin.unwrap_or("12345678");
    let mut session = open_session(dev)?;
    session
        .verify_admin(ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_reset_code(rc)
        .map_err(|e| CliError(format!("Failed to set reset code: {e}")))?;
    println!("Reset code set.");
    Ok(())
}

pub fn run_unblock_pin(
    dev: &YubiKeyDevice,
    admin_pin: Option<&str>,
    reset_code: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let new = new_pin.ok_or_else(|| CliError("--new-pin is required.".into()))?;
    let mut session = open_session(dev)?;
    if let Some(ap) = admin_pin {
        session
            .verify_admin(ap)
            .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    }
    session
        .reset_pin(new, reset_code)
        .map_err(|e| CliError(format!("Failed to unblock PIN: {e}")))?;
    println!("PIN unblocked.");
    Ok(())
}

pub fn run_set_signature_policy(
    dev: &YubiKeyDevice,
    policy: &str,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let pp = match policy.to_ascii_uppercase().as_str() {
        "ONCE" => PinPolicy::Once,
        "ALWAYS" => PinPolicy::Always,
        _ => {
            return Err(CliError(format!(
                "Invalid policy: {policy}. Use once or always."
            )));
        }
    };
    let ap = admin_pin.unwrap_or("12345678");
    let mut session = open_session(dev)?;
    session
        .verify_admin(ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_signature_pin_policy(pp)
        .map_err(|e| CliError(format!("Failed to set policy: {e}")))?;
    println!("Signature PIN policy set to {policy}.");
    Ok(())
}

pub fn run_keys_info(dev: &YubiKeyDevice, key: &str) -> Result<(), CliError> {
    let key_ref = parse_key_ref(key)?;
    let mut session = open_session(dev)?;
    if let Ok(attrs) = session.get_algorithm_attributes(key_ref) {
        println!("Algorithm: {attrs:?}");
    }
    if let Ok(uif) = session.get_uif(key_ref) {
        println!("Touch policy: {uif:?}");
    }
    if let Ok(times) = session.get_generation_times() {
        if let Some(t) = times.get(&key_ref) {
            if *t > 0 {
                println!("Generated: timestamp {t}");
            }
        }
    }
    if let Ok(fps) = session.get_fingerprints() {
        if let Some(fp) = fps.get(&key_ref) {
            if fp.iter().any(|&b| b != 0) {
                println!("Fingerprint: {}", hex::encode(fp));
            }
        }
    }
    Ok(())
}

pub fn run_keys_set_touch(
    dev: &YubiKeyDevice,
    key: &str,
    policy: &str,
    admin_pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let key_ref = parse_key_ref(key)?;
    let uif = parse_uif(policy)?;

    if uif.is_fixed() && !force {
        eprintln!("WARNING: Setting a FIXED touch policy cannot be undone without a full reset!");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }

    let ap = admin_pin.unwrap_or("12345678");
    let mut session = open_session(dev)?;
    session
        .verify_admin(ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .set_uif(key_ref, uif)
        .map_err(|e| CliError(format!("Failed to set touch policy: {e}")))?;
    println!("Touch policy for {key} set to {policy}.");
    Ok(())
}

pub fn run_keys_import(
    _dev: &YubiKeyDevice,
    key: &str,
    key_file: &str,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let _key_ref = parse_key_ref(key)?;
    let _data =
        std::fs::read(key_file).map_err(|e| CliError(format!("Failed to read file: {e}")))?;

    let _ap = admin_pin.unwrap_or("12345678");

    Err(CliError(
        "Key import requires parsing private key format. Not yet implemented.".into(),
    ))
}

pub fn run_keys_attest(
    dev: &YubiKeyDevice,
    key: &str,
    output: &str,
    format: &str,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let key_ref = parse_key_ref(key)?;
    let mut session = open_session(dev)?;
    if let Some(p) = pin {
        session
            .verify_pin(p, false)
            .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;
    }
    let cert_der = session
        .attest_key(key_ref)
        .map_err(|e| CliError(format!("Failed to attest key: {e}")))?;

    write_output(output, &cert_der, format, "CERTIFICATE")?;
    println!("Attestation certificate written to {output}.");
    Ok(())
}

pub fn run_certificates_export(
    dev: &YubiKeyDevice,
    key: &str,
    output: &str,
    format: &str,
) -> Result<(), CliError> {
    let key_ref = parse_key_ref(key)?;
    let mut session = open_session(dev)?;
    let cert_der = session
        .get_certificate(key_ref)
        .map_err(|e| CliError(format!("Failed to get certificate: {e}")))?;

    write_output(output, &cert_der, format, "CERTIFICATE")?;
    println!("Certificate exported to {output}.");
    Ok(())
}

pub fn run_certificates_import(
    dev: &YubiKeyDevice,
    key: &str,
    cert_file: &str,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let key_ref = parse_key_ref(key)?;
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

    let ap = admin_pin.unwrap_or("12345678");
    let mut session = open_session(dev)?;
    session
        .verify_admin(ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .put_certificate(key_ref, &der)
        .map_err(|e| CliError(format!("Failed to import certificate: {e}")))?;
    println!("Certificate imported.");
    Ok(())
}

pub fn run_certificates_delete(
    dev: &YubiKeyDevice,
    key: &str,
    admin_pin: Option<&str>,
) -> Result<(), CliError> {
    let key_ref = parse_key_ref(key)?;
    let ap = admin_pin.unwrap_or("12345678");
    let mut session = open_session(dev)?;
    session
        .verify_admin(ap)
        .map_err(|e| CliError(format!("Admin PIN verification failed: {e}")))?;
    session
        .delete_certificate(key_ref)
        .map_err(|e| CliError(format!("Failed to delete certificate: {e}")))?;
    println!("Certificate deleted.");
    Ok(())
}

fn write_output(path: &str, der: &[u8], format: &str, label: &str) -> Result<(), CliError> {
    match format.to_ascii_uppercase().as_str() {
        "DER" => {
            std::fs::write(path, der).map_err(|e| CliError(format!("Failed to write: {e}")))?;
        }
        _ => {
            let pem = pem_encode(label, der);
            std::fs::write(path, pem).map_err(|e| CliError(format!("Failed to write: {e}")))?;
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
