use std::io::{self, Write};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::securitydomain::{KeyRef, SecurityDomainSession};

use crate::util::CliError;

fn open_session(
    dev: &YubiKeyDevice,
) -> Result<SecurityDomainSession<impl yubikit_rs::iso7816::SmartCardConnection + use<'_>>, CliError>
{
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    SecurityDomainSession::new(conn)
        .map_err(|e| CliError(format!("Failed to open Security Domain session: {e}")))
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub fn run_info(dev: &YubiKeyDevice) -> Result<(), CliError> {
    let mut session = open_session(dev)?;
    println!("Security Domain version: {}", session.version());

    let keys = session
        .get_key_information()
        .map_err(|e| CliError(format!("Failed to get key info: {e}")))?;

    if keys.is_empty() {
        println!("No keys stored.");
    } else {
        for (key_ref, components) in &keys {
            let comps: Vec<String> = components
                .iter()
                .map(|(comp_id, key_type)| format!("0x{comp_id:02X}=0x{key_type:02X}"))
                .collect();
            println!(
                "Key 0x{:02X} (KVN 0x{:02X}): {}",
                key_ref.kid,
                key_ref.kvn,
                comps.join(", ")
            );
        }
    }
    Ok(())
}

pub fn run_reset(dev: &YubiKeyDevice, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!("WARNING! This will reset all Security Domain data.");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }
    let mut session = open_session(dev)?;
    session
        .reset()
        .map_err(|e| CliError(format!("Failed to reset: {e}")))?;
    println!("Security Domain has been reset.");
    Ok(())
}

pub fn run_keys_generate(
    dev: &YubiKeyDevice,
    kid: u8,
    kvn: u8,
    output: &str,
    replace_kvn: Option<u8>,
) -> Result<(), CliError> {
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev)?;
    let pub_key = session
        .generate_ec_key(
            key_ref,
            yubikit_rs::securitydomain::Curve::Secp256r1,
            replace_kvn.unwrap_or(0),
        )
        .map_err(|e| CliError(format!("Failed to generate key: {e}")))?;

    std::fs::write(output, &pub_key)
        .map_err(|e| CliError(format!("Failed to write: {e}")))?;
    println!(
        "EC key generated (KID=0x{kid:02X}, KVN=0x{kvn:02X}). Public key written to {output}."
    );
    Ok(())
}

pub fn run_keys_delete(
    dev: &YubiKeyDevice,
    kid: u8,
    kvn: u8,
    force: bool,
) -> Result<(), CliError> {
    if !force
        && !confirm(&format!(
            "Delete key (KID=0x{kid:02X}, KVN=0x{kvn:02X})?"
        ))
    {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_session(dev)?;
    session
        .delete_key(kid, kvn, false)
        .map_err(|e| CliError(format!("Failed to delete key: {e}")))?;
    println!("Key deleted.");
    Ok(())
}

pub fn run_keys_export(
    dev: &YubiKeyDevice,
    kid: u8,
    kvn: u8,
    output: &str,
) -> Result<(), CliError> {
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev)?;
    let certs = session
        .get_certificate_bundle(key_ref)
        .map_err(|e| CliError(format!("Failed to get certificates: {e}")))?;

    if certs.is_empty() {
        return Err(CliError("No certificate bundle found.".into()));
    }

    // Write all certs concatenated as PEM
    use base64::Engine;
    let mut pem_out = String::new();
    for cert_der in &certs {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
        pem_out.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem_out.push_str(std::str::from_utf8(chunk).unwrap());
            pem_out.push('\n');
        }
        pem_out.push_str("-----END CERTIFICATE-----\n");
    }
    std::fs::write(output, &pem_out)
        .map_err(|e| CliError(format!("Failed to write: {e}")))?;
    println!(
        "Exported {} certificate(s) to {output}.",
        certs.len()
    );
    Ok(())
}
