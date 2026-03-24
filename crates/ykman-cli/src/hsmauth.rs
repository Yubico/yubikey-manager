use std::io::{self, Write};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::hsmauth::{HsmAuthSession, credential_password_from_str};
use yubikit_rs::management::Capability;

use crate::scp::{self, ScpConfig, ScpParams};
use crate::util::{CliError, write_file_or_stdout};

const DEFAULT_MANAGEMENT_KEY: &[u8] = &[0u8; 16];

fn open_session<'a>(
    dev: &'a YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<HsmAuthSession<impl yubikit_rs::smartcard::SmartCardConnection + use<'a>>, CliError> {
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::HSMAUTH)?;
    match scp_config {
        ScpConfig::None => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            HsmAuthSession::new(conn)
                .map_err(|e| CliError(format!("Failed to open HSM Auth session: {e}")))
        }
        ref config => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            let params = scp::to_scp_key_params(config)
                .expect("non-None ScpConfig must convert to ScpKeyParams");
            HsmAuthSession::new_with_scp(conn, &params)
                .map_err(|e| CliError(format!("Failed to open HSM Auth session: {e}")))
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

fn parse_mgmt_key(s: Option<&str>) -> Result<Vec<u8>, CliError> {
    match s {
        Some(k) => {
            hex::decode(k).map_err(|_| CliError("Management key must be hex-encoded.".into()))
        }
        None => Ok(DEFAULT_MANAGEMENT_KEY.to_vec()),
    }
}

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;
    println!("YubiHSM Auth version:             {}", session.version());
    match session.get_management_key_retries() {
        Ok(retries) => println!("Management key retries remaining: {retries}/8"),
        Err(_) => {}
    }
    Ok(())
}

pub fn run_reset(dev: &YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!("WARNING! This will delete all stored HSM Auth credentials.");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }
    let mut session = open_session(dev, scp_params)?;
    session
        .reset()
        .map_err(|e| CliError(format!("Failed to reset: {e}")))?;
    eprintln!("HSM Auth application has been reset.");
    Ok(())
}

pub fn run_credentials_list(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;
    let creds = session
        .list_credentials()
        .map_err(|e| CliError(format!("Failed to list credentials: {e}")))?;

    if creds.is_empty() {
        eprintln!("No credentials stored.");
    } else {
        for cred in &creds {
            let touch = if cred.touch_required {
                " [touch required]"
            } else {
                ""
            };
            println!(
                "{}: {:?} (counter: {}){touch}",
                cred.label, cred.algorithm, cred.counter
            );
        }
    }
    Ok(())
}

pub fn run_credentials_generate(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = parse_mgmt_key(management_key)?;
    let pw = credential_password
        .map(credential_password_from_str)
        .unwrap_or_else(|| vec![0u8; 16]);

    let mut session = open_session(dev, scp_params)?;
    session
        .generate_credential_asymmetric(&mgmt, label, &pw, touch)
        .map_err(|e| CliError(format!("Failed to generate credential: {e}")))?;
    eprintln!("Asymmetric credential generated: {label}");
    Ok(())
}

pub fn run_credentials_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    management_key: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    if !force && !confirm(&format!("Delete credential '{label}'?")) {
        return Err(CliError("Aborted.".into()));
    }
    let mgmt = parse_mgmt_key(management_key)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .delete_credential(&mgmt, label)
        .map_err(|e| CliError(format!("Failed to delete credential: {e}")))?;
    eprintln!("Credential deleted: {label}");
    Ok(())
}

pub fn run_credentials_symmetric(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    enc_key: Option<&str>,
    mac_key: Option<&str>,
    generate: bool,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = parse_mgmt_key(management_key)?;
    let pw = credential_password
        .map(credential_password_from_str)
        .unwrap_or_else(|| vec![0u8; 16]);

    let (enc, mac) = if generate {
        let mut e = [0u8; 16];
        let mut m = [0u8; 16];
        getrandom::fill(&mut e).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        getrandom::fill(&mut m).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        (e.to_vec(), m.to_vec())
    } else {
        let e = enc_key
            .ok_or_else(|| CliError("--enc-key is required (or use --generate).".into()))
            .and_then(|k| {
                hex::decode(k).map_err(|_| CliError("ENC key must be hex-encoded.".into()))
            })?;
        let m = mac_key
            .ok_or_else(|| CliError("--mac-key is required (or use --generate).".into()))
            .and_then(|k| {
                hex::decode(k).map_err(|_| CliError("MAC key must be hex-encoded.".into()))
            })?;
        (e, m)
    };

    let mut session = open_session(dev, scp_params)?;
    session
        .put_credential_symmetric(&mgmt, label, &enc, &mac, &pw, touch)
        .map_err(|e| CliError(format!("Failed to store credential: {e}")))?;
    eprintln!("Symmetric credential stored: {label}");
    if generate {
        println!("ENC key: {}", hex::encode(&enc));
        println!("MAC key: {}", hex::encode(&mac));
    }
    Ok(())
}

pub fn run_credentials_derive(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    derivation_password: &str,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = parse_mgmt_key(management_key)?;
    let pw = credential_password
        .map(credential_password_from_str)
        .unwrap_or_else(|| vec![0u8; 16]);

    let mut session = open_session(dev, scp_params)?;
    session
        .put_credential_derived(&mgmt, label, derivation_password, &pw, touch)
        .map_err(|e| CliError(format!("Failed to derive credential: {e}")))?;
    eprintln!("Derived credential stored: {label}");
    Ok(())
}

pub fn run_credentials_change_password(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    credential_password: Option<&str>,
    new_credential_password: &str,
) -> Result<(), CliError> {
    let old_pw = credential_password
        .map(credential_password_from_str)
        .unwrap_or_else(|| vec![0u8; 16]);
    let new_pw = credential_password_from_str(new_credential_password);

    let mut session = open_session(dev, scp_params)?;
    session
        .change_credential_password(label, &old_pw, &new_pw)
        .map_err(|e| CliError(format!("Failed to change password: {e}")))?;
    eprintln!("Credential password changed for: {label}");
    Ok(())
}

pub fn run_credentials_export(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    output: &str,
    format: &str,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;
    let public_key = session
        .get_public_key(label)
        .map_err(|e| CliError(format!("Failed to get public key: {e}")))?;

    // Export as SubjectPublicKeyInfo
    use base64::Engine;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let pk_point = public_key.to_encoded_point(false);
    let pk_bytes = pk_point.as_bytes();

    // EC P256 AlgorithmIdentifier OID: 1.2.840.10045.2.1 + 1.2.840.10045.3.1.7
    let oid_bytes: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let bitstring_len = pk_bytes.len() + 1; // +1 for unused bits byte
    let mut spki = Vec::new();
    // SEQUENCE
    let inner_len = oid_bytes.len() + 2 + bitstring_len;
    spki.push(0x30);
    if inner_len >= 128 {
        spki.push(0x81);
        spki.push(inner_len as u8);
    } else {
        spki.push(inner_len as u8);
    }
    spki.extend_from_slice(oid_bytes);
    // BIT STRING
    spki.push(0x03);
    if bitstring_len >= 128 {
        spki.push(0x81);
        spki.push(bitstring_len as u8);
    } else {
        spki.push(bitstring_len as u8);
    }
    spki.push(0x00); // unused bits
    spki.extend_from_slice(pk_bytes);

    match format.to_ascii_uppercase().as_str() {
        "DER" => {
            write_file_or_stdout(output, &spki)?;
            if output != "-" {
                eprintln!("Public key exported to {output}.");
            }
        }
        _ => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
            let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push('\n');
            }
            pem.push_str("-----END PUBLIC KEY-----\n");

            write_file_or_stdout(output, pem.as_bytes())?;
            if output != "-" {
                eprintln!("Public key exported to {output}.");
            }
        }
    }
    Ok(())
}

pub fn run_access_change_management_key(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    management_key: Option<&str>,
    new_management_key: Option<&str>,
    generate: bool,
) -> Result<(), CliError> {
    let _old_mgmt = parse_mgmt_key(management_key)?;

    let new_key = if generate {
        let mut k = [0u8; 16];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        k.to_vec()
    } else if let Some(k) = new_management_key {
        hex::decode(k).map_err(|_| CliError("Management key must be hex-encoded.".into()))?
    } else {
        return Err(CliError(
            "Provide --new-management-key or --generate.".into(),
        ));
    };

    let old_mgmt = parse_mgmt_key(management_key)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .put_management_key(&old_mgmt, &new_key)
        .map_err(|e| CliError(format!("Failed to change management key: {e}")))?;
    if generate {
        eprintln!("Management key changed: {}", hex::encode(&new_key));
    } else {
        eprintln!("Management key changed.");
    }
    Ok(())
}
