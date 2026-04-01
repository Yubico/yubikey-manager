use std::io::{self, Write};

use yubikit::device::YubiKeyDevice;
use yubikit::securitydomain::{KeyRef, ScpKid, SecurityDomainSession};

use crate::cli_enums::CliSdKeyType;
use crate::scp::{self, ScpConfig, ScpParams};
use crate::util::{CliError, read_file_or_stdin, write_file_or_stdout};

fn open_session<'a>(
    dev: &'a YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<SecurityDomainSession<impl yubikit::smartcard::SmartCardConnection + use<'a>>, CliError>
{
    if scp_params.is_explicit() {
        // SD doesn't use auto SCP11b (it manages those keys), but explicit SCP
        // is needed for authenticated operations like key management.
        let scp_config = scp::resolve_scp(dev, scp_params, yubikit::management::Capability::NONE)?;
        if let ScpConfig::None = scp_config {
            // resolve_scp returned None despite explicit params — shouldn't happen
        }
        match scp_config {
            ScpConfig::None => {}
            ref config => {
                let conn = dev
                    .open_smartcard()
                    .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
                let params = scp::to_scp_key_params(config)
                    .expect("non-None ScpConfig must convert to ScpKeyParams");
                return SecurityDomainSession::new_with_scp(conn, &params).map_err(|(e, _)| {
                    CliError(format!("Failed to open SD session with SCP: {e}"))
                });
            }
        }
    }
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    SecurityDomainSession::new(conn)
        .map_err(|(e, _)| CliError(format!("Failed to open Security Domain session: {e}")))
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;

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
    if !force {
        eprintln!("WARNING! This will reset all Security Domain data.");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }
    let mut session = open_session(dev, scp_params)?;
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
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev, scp_params)?;
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
    if !force && !confirm(&format!("Delete key (KID=0x{kid:02X}, KVN=0x{kvn:02X})?")) {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_session(dev, scp_params)?;
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
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev, scp_params)?;
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
    password: Option<&str>,
) -> Result<(), CliError> {
    let key_ref = KeyRef::new(kid, kvn);
    let mut session = open_session(dev, scp_params)?;

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
                key_enc: zeroize::Zeroizing::new(enc),
                key_mac: zeroize::Zeroizing::new(mac),
                key_dek: dek.map(zeroize::Zeroizing::new),
            };
            session
                .put_key_static(key_ref, &static_keys, replace_kvn.unwrap_or(0))
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
            let mut has_encrypted_key = false;

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
                } else if block.starts_with("ENCRYPTED PRIVATE KEY-----") {
                    has_encrypted_key = true;
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

            // Handle encrypted private keys
            if has_encrypted_key && private_key.is_none() {
                let pw = match password {
                    Some(p) => p.to_string(),
                    None => crate::util::prompt_secret("Enter password to decrypt key")?,
                };
                // Try to parse the encrypted key using EC key types
                private_key = try_decrypt_sd_private_key(&pem_data, &pw)?;
            }

            // OCE CA key references (KID=0x10 or 0x20-0x2F): extract public key
            // from cert and import as public key + store CA issuer (SKI).
            if kid == 0x10 || (0x20..=0x2F).contains(&kid) {
                if certs.is_empty() {
                    return Err(CliError(
                        "Input does not contain a certificate for CA key import.".into(),
                    ));
                }
                let (pubkey, curve) = extract_ec_pubkey_and_curve(&certs[0])?;
                session
                    .put_key_ec_public(key_ref, &pubkey, curve, replace_kvn.unwrap_or(0))
                    .map_err(|e| CliError(format!("Failed to import CA public key: {e}")))?;
                eprintln!("CA public key imported (KID=0x{kid:02X}, KVN=0x{kvn:02X}).");

                // Extract and store Subject Key Identifier (SKI) if present
                if let Some(ski) = extract_ski_from_cert(&certs[0]) {
                    session
                        .store_ca_issuer(key_ref, &ski)
                        .map_err(|e| CliError(format!("Failed to store CA issuer: {e}")))?;
                    eprintln!("CA key identifier stored.");
                }
                return Ok(());
            }

            // SCP11a/b/c key references: import private key + cert bundle
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
                    .put_key_ec_private(key_ref, &scalar_bytes, curve, replace_kvn.unwrap_or(0))
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
    let key_ref = KeyRef::new(kid, kvn);
    let serial_bytes: Vec<Vec<u8>> = serials
        .iter()
        .map(|s| hex::decode(s).map_err(|_| CliError(format!("Invalid hex serial: {s}"))))
        .collect::<Result<_, _>>()?;

    let mut session = open_session(dev, scp_params)?;
    session
        .store_allowlist(key_ref, &serial_bytes)
        .map_err(|e| CliError(format!("Failed to set allowlist: {e}")))?;
    println!(
        "Allowlist set for KID=0x{kid:02X}, KVN=0x{kvn:02X} ({} serial(s)).",
        serial_bytes.len()
    );
    Ok(())
}

/// Extract EC public key bytes and curve from a DER-encoded X.509 certificate.
fn extract_ec_pubkey_and_curve(
    cert_der: &[u8],
) -> Result<(Vec<u8>, yubikit::securitydomain::Curve), CliError> {
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode, oid::ObjectIdentifier};

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| CliError(format!("Failed to parse certificate: {e}")))?;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pk_bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CliError("Public key has unused bits".into()))?;

    // Determine curve from the algorithm parameters
    // P-256 OID: 1.2.840.10045.3.1.7, P-384 OID: 1.3.132.0.34
    const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| CliError("Missing EC curve parameters in certificate".into()))?;
    let curve_oid = ObjectIdentifier::from_der(
        &params
            .to_der()
            .map_err(|e| CliError(format!("Failed to encode algorithm parameters: {e}")))?,
    )
    .map_err(|e| CliError(format!("Failed to parse curve OID: {e}")))?;

    let curve = if curve_oid == P256_OID {
        yubikit::securitydomain::Curve::Secp256r1
    } else if curve_oid == P384_OID {
        yubikit::securitydomain::Curve::Secp384r1
    } else {
        return Err(CliError(format!("Unsupported EC curve OID: {curve_oid}")));
    };

    Ok((pk_bits.to_vec(), curve))
}

/// Extract Subject Key Identifier (SKI) from a DER-encoded X.509 certificate.
fn extract_ski_from_cert(cert_der: &[u8]) -> Option<Vec<u8>> {
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, oid::ObjectIdentifier};

    let cert = Certificate::from_der(cert_der).ok()?;
    let exts = cert.tbs_certificate.extensions.as_ref()?;

    // SubjectKeyIdentifier OID: 2.5.29.14
    const SKI_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

    for ext in exts.iter() {
        if ext.extn_id == SKI_OID {
            // Extension value is DER: OCTET STRING wrapping the key identifier
            let bytes = ext.extn_value.as_bytes();
            // Parse the outer OCTET STRING to get the raw SKI
            let ski = x509_cert::der::asn1::OctetString::from_der(bytes).ok()?;
            return Some(ski.as_bytes().to_vec());
        }
    }
    None
}

/// Try to decrypt an encrypted private key from PEM data.
/// Returns the DER-encoded PKCS#8 private key on success.
fn try_decrypt_sd_private_key(
    _pem_data: &str,
    _password: &str,
) -> Result<Option<Vec<u8>>, CliError> {
    // The pkcs8 crate at version 0.10 does not support encrypted PKCS#8 without
    // the "encryption" feature. Try to parse as unencrypted in case the tool
    // wrote an unencrypted key with the ENCRYPTED header.
    use elliptic_curve::SecretKey;
    use elliptic_curve::pkcs8::DecodePrivateKey;

    if let Ok(sk) = SecretKey::<p256::NistP256>::from_pkcs8_pem(_pem_data) {
        use elliptic_curve::pkcs8::EncodePrivateKey;
        let doc = sk
            .to_pkcs8_der()
            .map_err(|e| CliError(format!("Failed to re-encode key: {e}")))?;
        return Ok(Some(doc.as_bytes().to_vec()));
    }
    if let Ok(sk) = SecretKey::<p384::NistP384>::from_pkcs8_pem(_pem_data) {
        use elliptic_curve::pkcs8::EncodePrivateKey;
        let doc = sk
            .to_pkcs8_der()
            .map_err(|e| CliError(format!("Failed to re-encode key: {e}")))?;
        return Ok(Some(doc.as_bytes().to_vec()));
    }

    Err(CliError(
        "Cannot decrypt encrypted key in-process. Convert first:\n  \
         openssl pkey -in key.pem -out key_dec.pem"
            .into(),
    ))
}
