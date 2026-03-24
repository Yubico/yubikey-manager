use std::io::{self, Write};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::securitydomain::{KeyRef, SecurityDomainSession};

use crate::util::{CliError, read_file_or_stdin, write_file_or_stdout};
use crate::scp::ScpParams;

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

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let _ = scp_params;
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

pub fn run_reset(dev: &YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<(), CliError> {
    let _ = scp_params;
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
    scp_params: &ScpParams,
    kid: u8,
    kvn: u8,
    output: &str,
    replace_kvn: Option<u8>,
) -> Result<(), CliError> {
    let _ = scp_params;
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev)?;
    let pub_key = session
        .generate_ec_key(
            key_ref,
            yubikit_rs::securitydomain::Curve::Secp256r1,
            replace_kvn.unwrap_or(0),
        )
        .map_err(|e| CliError(format!("Failed to generate key: {e}")))?;

    write_file_or_stdout(output, &pub_key)?;
    println!(
        "EC key generated (KID=0x{kid:02X}, KVN=0x{kvn:02X}). Public key written to {output}."
    );
    Ok(())
}

pub fn run_keys_delete(dev: &YubiKeyDevice, scp_params: &ScpParams, kid: u8, kvn: u8, force: bool) -> Result<(), CliError> {
    let _ = scp_params;
    if !force && !confirm(&format!("Delete key (KID=0x{kid:02X}, KVN=0x{kvn:02X})?")) {
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
    scp_params: &ScpParams,
    kid: u8,
    kvn: u8,
    output: &str,
) -> Result<(), CliError> {
    let _ = scp_params;
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
    write_file_or_stdout(output, pem_out.as_bytes())?;
    println!("Exported {} certificate(s) to {output}.", certs.len());
    Ok(())
}

pub fn run_keys_import(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    kid: u8,
    kvn: u8,
    key_type: &str,
    input: &str,
    replace_kvn: Option<u8>,
) -> Result<(), CliError> {
    let _ = scp_params;
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev)?;

    match key_type {
        "scp03" => {
            // Input is K-ENC:K-MAC[:K-DEK] hex
            let parts: Vec<&str> = input.split(':').collect();
            if parts.len() < 2 || parts.len() > 3 {
                return Err(CliError("SCP03 keys format: K-ENC:K-MAC[:K-DEK]".into()));
            }
            let enc = hex::decode(parts[0]).map_err(|_| CliError("Invalid K-ENC hex".into()))?;
            let mac = hex::decode(parts[1]).map_err(|_| CliError("Invalid K-MAC hex".into()))?;
            let dek = if parts.len() == 3 {
                Some(hex::decode(parts[2]).map_err(|_| CliError("Invalid K-DEK hex".into()))?)
            } else {
                None
            };
            let static_keys = yubikit_rs::securitydomain::StaticKeys {
                key_enc: enc,
                key_mac: mac,
                key_dek: dek,
            };
            session
                .put_key_static(key_ref, &static_keys, &[0u8; 16], replace_kvn.unwrap_or(0))
                .map_err(|e| CliError(format!("Failed to import SCP03 keys: {e}")))?;
            println!("SCP03 keys imported (KID=0x{kid:02X}, KVN=0x{kvn:02X}).");
        }
        "scp11" => {
            // Input is a PEM file with certificate(s) and/or private key
            let pem_bytes = read_file_or_stdin(input)?;
            let pem_data = String::from_utf8(pem_bytes)
                .map_err(|e| CliError(format!("Failed to read {input} as UTF-8: {e}")))?;

            let mut certs = Vec::new();
            let mut private_key: Option<Vec<u8>> = None;

            for block in pem_data.split("-----BEGIN ") {
                if block.trim().is_empty() {
                    continue;
                }
                if block.starts_with("CERTIFICATE-----") {
                    if let Some(b64) = block.split("-----END").next() {
                        let b64 = b64.trim_start_matches("CERTIFICATE-----").trim();
                        use base64::Engine;
                        let der = base64::engine::general_purpose::STANDARD
                            .decode(b64.replace('\n', "").replace('\r', ""))
                            .map_err(|_| CliError("Invalid certificate PEM".into()))?;
                        certs.push(der);
                    }
                } else if block.starts_with("EC PRIVATE KEY-----")
                    || block.starts_with("PRIVATE KEY-----")
                {
                    if let Some(b64) = block.split("-----END").next() {
                        let label = if block.starts_with("EC") {
                            "EC PRIVATE KEY-----"
                        } else {
                            "PRIVATE KEY-----"
                        };
                        let b64 = b64.trim_start_matches(label).trim();
                        use base64::Engine;
                        let der = base64::engine::general_purpose::STANDARD
                            .decode(b64.replace('\n', "").replace('\r', ""))
                            .map_err(|_| CliError("Invalid private key PEM".into()))?;
                        private_key = Some(der);
                    }
                }
            }

            if let Some(pk) = &private_key {
                session
                    .put_key_ec_private(
                        key_ref,
                        pk,
                        yubikit_rs::securitydomain::Curve::Secp256r1,
                        &[0u8; 16],
                        replace_kvn.unwrap_or(0),
                    )
                    .map_err(|e| CliError(format!("Failed to import EC private key: {e}")))?;
                println!("EC private key imported (KID=0x{kid:02X}, KVN=0x{kvn:02X}).");
            }

            if !certs.is_empty() {
                let cert_refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
                session
                    .store_certificate_bundle(key_ref, &cert_refs)
                    .map_err(|e| CliError(format!("Failed to store certificate bundle: {e}")))?;
                println!(
                    "{} certificate(s) imported (KID=0x{kid:02X}, KVN=0x{kvn:02X}).",
                    certs.len()
                );
            }

            if private_key.is_none() && certs.is_empty() {
                return Err(CliError(
                    "No certificate or private key found in PEM file.".into(),
                ));
            }
        }
        other => {
            return Err(CliError(format!(
                "Unknown key type: {other}. Use 'scp03' or 'scp11'."
            )));
        }
    }
    Ok(())
}

pub fn run_keys_set_allowlist(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    kid: u8,
    kvn: u8,
    serials: &[String],
) -> Result<(), CliError> {
    let _ = scp_params;
    let key_ref = KeyRef::new(kid, kvn);
    let serial_bytes: Vec<Vec<u8>> = serials
        .iter()
        .map(|s| hex::decode(s).map_err(|_| CliError(format!("Invalid hex serial: {s}"))))
        .collect::<Result<_, _>>()?;

    let mut session = open_session(dev)?;
    session
        .store_allowlist(key_ref, &serial_bytes)
        .map_err(|e| CliError(format!("Failed to set allowlist: {e}")))?;
    println!(
        "Allowlist set for KID=0x{kid:02X}, KVN=0x{kvn:02X} ({} serial(s)).",
        serial_bytes.len()
    );
    Ok(())
}
