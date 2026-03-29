use std::io::{self, Write};

use yubikit::device::YubiKeyDevice;
use yubikit::securitydomain::{KeyRef, ScpKid, SecurityDomainSession};

use crate::cli_enums::CliSdKeyType;
use crate::scp::ScpParams;
use crate::util::{CliError, read_file_or_stdin, write_file_or_stdout};

fn open_session(
    dev: &YubiKeyDevice,
) -> Result<SecurityDomainSession<impl yubikit::smartcard::SmartCardConnection + use<'_>>, CliError>
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

    let keys = session
        .get_key_information()
        .map_err(|e| CliError(format!("Failed to get key info: {e}")))?;

    let cas = session
        .get_supported_ca_identifiers(true, true)
        .unwrap_or_default();

    // Collect and sort keys: SCP03 (KID 1-3) first, then SCP11 by KID/KVN
    let mut key_refs: Vec<&KeyRef> = keys.keys().collect();
    key_refs.sort_by(|a, b| a.kid.cmp(&b.kid).then_with(|| a.kvn.cmp(&b.kvn)));

    println!("SCP keys:");

    let mut first = true;
    for key_ref in key_refs {
        // SCP03 key sets: KID 0x01-0x03 are always a group, skip 0x02/0x03
        if key_ref.kid == 0x02 || key_ref.kid == 0x03 {
            continue;
        }

        if !first {
            println!();
        }
        first = false;

        if key_ref.kid == 0x01 {
            // SCP03 key set
            let label = if key_ref.kvn == 0xFF {
                "Default key set"
            } else {
                "Imported key set"
            };
            println!("  SCP03 (KID=0x01-0x03, KVN=0x{:02X}):", key_ref.kvn);
            println!("    {label}");
        } else {
            // SCP11 variant
            let name = match ScpKid::from_u8(key_ref.kid) {
                Some(ScpKid::Scp11a) => "SCP11a",
                Some(ScpKid::Scp11b) => "SCP11b",
                Some(ScpKid::Scp11c) => "SCP11c",
                _ => "SCP11 OCE CA",
            };
            println!(
                "  {name} (KID=0x{:02X}, KVN=0x{:02X}):",
                key_ref.kid, key_ref.kvn
            );

            // Show CA Key Identifier if available
            if let Some(ca_id) = cas.get(key_ref) {
                let hex_str: Vec<String> = ca_id.iter().map(|b| format!("{b:02X}")).collect();
                println!("    CA Key Identifier: {}", hex_str.join(":"));
            }

            // Show certificate chain subjects
            match session.get_certificate_bundle(*key_ref) {
                Ok(certs) if !certs.is_empty() => {
                    println!("    Certificate chain:");
                    for cert_der in &certs {
                        let subject = extract_cert_subject(cert_der);
                        println!("      {subject}");
                    }
                }
                _ => {}
            }
        }
    }
    println!();
    Ok(())
}

/// Extract the subject CN from a DER-encoded certificate.
fn extract_cert_subject(der: &[u8]) -> String {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;
    match Certificate::from_der(der) {
        Ok(cert) => cert.tbs_certificate.subject.to_string(),
        Err(_) => "(unable to parse certificate)".to_string(),
    }
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
    eprintln!("Security Domain has been reset.");
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
            yubikit::securitydomain::Curve::Secp256r1,
            replace_kvn.unwrap_or(0),
        )
        .map_err(|e| CliError(format!("Failed to generate key: {e}")))?;

    write_file_or_stdout(output, &pub_key)?;
    println!(
        "EC key generated (KID=0x{kid:02X}, KVN=0x{kvn:02X}). Public key written to {output}."
    );
    Ok(())
}

pub fn run_keys_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    kid: u8,
    kvn: u8,
    force: bool,
) -> Result<(), CliError> {
    let _ = scp_params;
    if !force && !confirm(&format!("Delete key (KID=0x{kid:02X}, KVN=0x{kvn:02X})?")) {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_session(dev)?;
    session
        .delete_key(kid, kvn, false)
        .map_err(|e| CliError(format!("Failed to delete key: {e}")))?;
    eprintln!("Key deleted.");
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
    key_type: CliSdKeyType,
    input: &str,
    replace_kvn: Option<u8>,
) -> Result<(), CliError> {
    let _ = scp_params;
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev)?;

    match key_type {
        CliSdKeyType::Scp03 => {
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
            let static_keys = yubikit::securitydomain::StaticKeys {
                key_enc: enc,
                key_mac: mac,
                key_dek: dek,
            };
            session
                .put_key_static(key_ref, &static_keys, &[0u8; 16], replace_kvn.unwrap_or(0))
                .map_err(|e| CliError(format!("Failed to import SCP03 keys: {e}")))?;
            eprintln!("SCP03 keys imported (KID=0x{kid:02X}, KVN=0x{kvn:02X}).");
        }
        CliSdKeyType::Scp11 => {
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
                            .decode(b64.replace(['\n', '\r'], ""))
                            .map_err(|_| CliError("Invalid certificate PEM".into()))?;
                        certs.push(der);
                    }
                } else if (block.starts_with("EC PRIVATE KEY-----")
                    || block.starts_with("PRIVATE KEY-----"))
                    && let Some(b64) = block.split("-----END").next()
                {
                    let label = if block.starts_with("EC") {
                        "EC PRIVATE KEY-----"
                    } else {
                        "PRIVATE KEY-----"
                    };
                    let b64 = b64.trim_start_matches(label).trim();
                    use base64::Engine;
                    let der = base64::engine::general_purpose::STANDARD
                        .decode(b64.replace(['\n', '\r'], ""))
                        .map_err(|_| CliError("Invalid private key PEM".into()))?;
                    private_key = Some(der);
                }
            }

            if let Some(pk_der) = &private_key {
                // Extract raw EC scalar from PKCS#8 or SEC1 DER encoding
                use elliptic_curve::SecretKey;
                use elliptic_curve::pkcs8::DecodePrivateKey;
                let (scalar_bytes, curve) =
                    if let Ok(sk) = SecretKey::<p256::NistP256>::from_pkcs8_der(pk_der) {
                        (
                            sk.to_bytes().as_slice().to_vec(),
                            yubikit::securitydomain::Curve::Secp256r1,
                        )
                    } else if let Ok(sk) = SecretKey::<p256::NistP256>::from_sec1_der(pk_der) {
                        (
                            sk.to_bytes().as_slice().to_vec(),
                            yubikit::securitydomain::Curve::Secp256r1,
                        )
                    } else if let Ok(sk) = SecretKey::<p384::NistP384>::from_pkcs8_der(pk_der) {
                        (
                            sk.to_bytes().as_slice().to_vec(),
                            yubikit::securitydomain::Curve::Secp384r1,
                        )
                    } else if let Ok(sk) = SecretKey::<p384::NistP384>::from_sec1_der(pk_der) {
                        (
                            sk.to_bytes().as_slice().to_vec(),
                            yubikit::securitydomain::Curve::Secp384r1,
                        )
                    } else {
                        return Err(CliError(
                        "Failed to parse EC private key (expected P-256 or P-384 PKCS#8/SEC1 DER)"
                            .into(),
                    ));
                    };
                session
                    .put_key_ec_private(
                        key_ref,
                        &scalar_bytes,
                        curve,
                        &[0u8; 16],
                        replace_kvn.unwrap_or(0),
                    )
                    .map_err(|e| CliError(format!("Failed to import EC private key: {e}")))?;
                eprintln!("EC private key imported (KID=0x{kid:02X}, KVN=0x{kvn:02X}).");
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
