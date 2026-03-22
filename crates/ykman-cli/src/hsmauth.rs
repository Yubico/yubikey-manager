use std::io::{self, Write};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::hsmauth::{credential_password_from_str, HsmAuthSession};

use crate::util::CliError;

const DEFAULT_MANAGEMENT_KEY: &[u8] = &[0u8; 16];

fn open_session(
    dev: &YubiKeyDevice,
) -> Result<HsmAuthSession<impl yubikit_rs::iso7816::SmartCardConnection + use<'_>>, CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    HsmAuthSession::new(conn)
        .map_err(|e| CliError(format!("Failed to open HSM Auth session: {e}")))
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
        Some(k) => hex::decode(k)
            .map_err(|_| CliError("Management key must be hex-encoded.".into())),
        None => Ok(DEFAULT_MANAGEMENT_KEY.to_vec()),
    }
}

pub fn run_info(dev: &YubiKeyDevice) -> Result<(), CliError> {
    let mut session = open_session(dev)?;
    println!("YubiHSM Auth version: {}", session.version());
    match session.get_management_key_retries() {
        Ok(retries) => println!("Management key retries: {retries}"),
        Err(_) => {}
    }
    Ok(())
}

pub fn run_reset(dev: &YubiKeyDevice, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!("WARNING! This will delete all stored HSM Auth credentials.");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted.".into()));
        }
    }
    let mut session = open_session(dev)?;
    session
        .reset()
        .map_err(|e| CliError(format!("Failed to reset: {e}")))?;
    println!("HSM Auth application has been reset.");
    Ok(())
}

pub fn run_credentials_list(dev: &YubiKeyDevice) -> Result<(), CliError> {
    let mut session = open_session(dev)?;
    let creds = session
        .list_credentials()
        .map_err(|e| CliError(format!("Failed to list credentials: {e}")))?;

    if creds.is_empty() {
        println!("No credentials stored.");
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
    label: &str,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = parse_mgmt_key(management_key)?;
    let pw = credential_password
        .map(credential_password_from_str)
        .unwrap_or_else(|| vec![0u8; 16]);

    let mut session = open_session(dev)?;
    session
        .generate_credential_asymmetric(&mgmt, label, &pw, touch)
        .map_err(|e| CliError(format!("Failed to generate credential: {e}")))?;
    println!("Asymmetric credential generated: {label}");
    Ok(())
}

pub fn run_credentials_delete(
    dev: &YubiKeyDevice,
    label: &str,
    management_key: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    if !force && !confirm(&format!("Delete credential '{label}'?")) {
        return Err(CliError("Aborted.".into()));
    }
    let mgmt = parse_mgmt_key(management_key)?;
    let mut session = open_session(dev)?;
    session
        .delete_credential(&mgmt, label)
        .map_err(|e| CliError(format!("Failed to delete credential: {e}")))?;
    println!("Credential deleted: {label}");
    Ok(())
}

pub fn run_credentials_symmetric(
    dev: &YubiKeyDevice,
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
        getrandom::fill(&mut e)
            .map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        getrandom::fill(&mut m)
            .map_err(|e| CliError(format!("Failed to generate: {e}")))?;
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

    let mut session = open_session(dev)?;
    session
        .put_credential_symmetric(&mgmt, label, &enc, &mac, &pw, touch)
        .map_err(|e| CliError(format!("Failed to store credential: {e}")))?;
    println!("Symmetric credential stored: {label}");
    if generate {
        println!("ENC key: {}", hex::encode(&enc));
        println!("MAC key: {}", hex::encode(&mac));
    }
    Ok(())
}

pub fn run_credentials_derive(
    dev: &YubiKeyDevice,
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

    let mut session = open_session(dev)?;
    session
        .put_credential_derived(&mgmt, label, derivation_password, &pw, touch)
        .map_err(|e| CliError(format!("Failed to derive credential: {e}")))?;
    println!("Derived credential stored: {label}");
    Ok(())
}

pub fn run_credentials_change_password(
    dev: &YubiKeyDevice,
    label: &str,
    credential_password: Option<&str>,
    new_credential_password: &str,
) -> Result<(), CliError> {
    let old_pw = credential_password
        .map(credential_password_from_str)
        .unwrap_or_else(|| vec![0u8; 16]);
    let new_pw = credential_password_from_str(new_credential_password);

    let mut session = open_session(dev)?;
    session
        .change_credential_password(label, &old_pw, &new_pw)
        .map_err(|e| CliError(format!("Failed to change password: {e}")))?;
    println!("Credential password changed for: {label}");
    Ok(())
}

pub fn run_access_change_management_key(
    dev: &YubiKeyDevice,
    management_key: Option<&str>,
    new_management_key: Option<&str>,
    generate: bool,
) -> Result<(), CliError> {
    let _old_mgmt = parse_mgmt_key(management_key)?;

    let new_key = if generate {
        let mut k = [0u8; 16];
        getrandom::fill(&mut k)
            .map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        k.to_vec()
    } else if let Some(k) = new_management_key {
        hex::decode(k).map_err(|_| CliError("Management key must be hex-encoded.".into()))?
    } else {
        return Err(CliError(
            "Provide --new-management-key or --generate.".into(),
        ));
    };

    let old_mgmt = parse_mgmt_key(management_key)?;
    let mut session = open_session(dev)?;
    session
        .put_management_key(&old_mgmt, &new_key)
        .map_err(|e| CliError(format!("Failed to change management key: {e}")))?;
    if generate {
        println!("Management key changed: {}", hex::encode(&new_key));
    } else {
        println!("Management key changed.");
    }
    Ok(())
}
