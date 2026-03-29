use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::oath::{
    Code, Credential, CredentialData, HashAlgorithm, OathSession, OathType, parse_b32_key,
};

use crate::appdata::AppData;
use crate::cli_enums::{CliOathAlgorithm, CliOathDigits, CliOathType};
use crate::scp::{self, ScpConfig, ScpParams};
use crate::util::CliError;

fn oath_keys() -> AppData {
    AppData::new("oath_keys")
}

/// Validate the key against the session, optionally remembering it.
fn validate_and_remember(
    session: &mut OathSession<impl yubikit::smartcard::SmartCardConnection>,
    key: &[u8],
    remember: bool,
    keys: &mut AppData,
) -> Result<(), CliError> {
    session
        .validate(key)
        .map_err(|_| CliError("Invalid password.".into()))?;
    if remember {
        keys.put_secret(session.device_id(), &hex::encode(key))
            .map_err(|e| CliError(format!("Failed to remember password: {e}")))?;
        eprintln!("Password remembered.");
    }
    Ok(())
}

/// Open an OATH session, unlocking it if needed.
///
/// Tries (in order): explicit password, stored key, interactive prompt.
fn open_session<'a>(
    dev: &'a YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
) -> Result<OathSession<impl yubikit::smartcard::SmartCardConnection + use<'a>>, CliError> {
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::OATH)?;
    let mut session = match scp_config {
        ScpConfig::None => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            OathSession::new(conn)
                .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
        }
        ref config => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            let params = scp::to_scp_key_params(config)
                .expect("non-None ScpConfig must convert to ScpKeyParams");
            OathSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
        }
    };

    if session.locked() {
        let mut keys = oath_keys();

        // 1. Explicit password from CLI
        if let Some(pw) = password {
            let key = session.derive_key(pw);
            validate_and_remember(&mut session, &key, remember, &mut keys)?;
            return Ok(session);
        }

        // 2. Try stored key
        let device_id = session.device_id().to_string();
        if keys.contains(&device_id) {
            match keys.get_secret(&device_id) {
                Ok(hex_key) => match hex::decode(&hex_key) {
                    Ok(key) => match session.validate(&key) {
                        Ok(()) => return Ok(session),
                        Err(_) => {
                            log::debug!("Remembered key incorrect, removing");
                            let _ = keys.remove(&device_id);
                        }
                    },
                    Err(_) => {
                        log::warn!("Corrupt stored key, removing");
                        let _ = keys.remove(&device_id);
                    }
                },
                Err(e) => {
                    log::warn!("Failed to decrypt stored key: {e}");
                }
            }
        }

        // 3. Prompt interactively
        let pw = crate::util::prompt_secret("Enter OATH password")?;
        let key = session.derive_key(&pw);
        validate_and_remember(&mut session, &key, remember, &mut keys)?;
    } else if password.is_some() {
        return Err(CliError(
            "Password provided, but no password is set.".into(),
        ));
    }
    Ok(session)
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn format_cred_name(cred: &Credential) -> String {
    match &cred.issuer {
        Some(issuer) => format!("{issuer}:{}", cred.name),
        None => cred.name.clone(),
    }
}

fn is_hidden(cred: &Credential) -> bool {
    cred.issuer.as_deref().unwrap_or("").starts_with('_') || cred.name.starts_with('_')
}

pub fn run_info(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
) -> Result<(), CliError> {
    // Open a raw session without unlocking — info doesn't require authentication
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::OATH)?;
    let session = match scp_config {
        ScpConfig::None => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            OathSession::new(conn)
                .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
        }
        ref config => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            let params = scp::to_scp_key_params(config)
                .expect("non-None ScpConfig must convert to ScpKeyParams");
            OathSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
        }
    };
    let _ = password; // Not needed for info
    let keys = oath_keys();
    println!("OATH version: {}", session.version());
    println!(
        "Password protection: {}",
        if session.has_key() {
            "enabled"
        } else {
            "disabled"
        }
    );
    if session.has_key() && keys.contains(session.device_id()) {
        println!("The password for this YubiKey is remembered by ykman.");
    }
    Ok(())
}

pub fn run_reset(dev: &YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<(), CliError> {
    let _ = scp_params;
    if !force {
        eprintln!(
            "WARNING! This will delete all stored OATH accounts and restore factory settings of the OATH application."
        );
        if !confirm("Proceed?") {
            return Err(CliError("Aborted by user.".into()));
        }
    }
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    let mut session = OathSession::new(conn)
        .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?;
    let device_id = session.device_id().to_string();
    session
        .reset()
        .map_err(|e| CliError(format!("Failed to reset OATH: {e}")))?;

    // Clean up any stored password for this device
    let mut keys = oath_keys();
    if keys.contains(&device_id) {
        let _ = keys.remove(&device_id);
    }
    eprintln!("OATH application has been reset.");
    Ok(())
}

pub fn run_accounts_list(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    show_hidden: bool,
    show_oath_type: bool,
    show_period: bool,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let creds = session
        .list_credentials()
        .map_err(|e| CliError(format!("Failed to list credentials: {e}")))?;

    for cred in &creds {
        if !show_hidden && is_hidden(cred) {
            continue;
        }
        let mut line = format_cred_name(cred);
        if show_oath_type {
            let t = match cred.oath_type {
                OathType::Totp => "TOTP",
                OathType::Hotp => "HOTP",
            };
            line = format!("{line} ({t})");
        }
        if show_period && cred.oath_type == OathType::Totp {
            line = format!("{line} [period: {}]", cred.period);
        }
        println!("{line}");
    }
    Ok(())
}

pub fn run_accounts_code(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    query: Option<&str>,
    show_hidden: bool,
    single: bool,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let timestamp = now_timestamp();

    let entries = session
        .calculate_all(timestamp)
        .map_err(|e| CliError(format!("Failed to calculate codes: {e}")))?;

    // Filter by query
    let filtered: Vec<&(Credential, Option<Code>)> = entries
        .iter()
        .filter(|(cred, _)| {
            if !show_hidden && is_hidden(cred) {
                return false;
            }
            if let Some(q) = query {
                let name = format_cred_name(cred);
                name.to_ascii_lowercase().contains(&q.to_ascii_lowercase())
            } else {
                true
            }
        })
        .collect();

    if single {
        if filtered.len() != 1 {
            return Err(CliError(format!(
                "Expected exactly 1 match, found {}.",
                filtered.len()
            )));
        }
        let (cred, code) = filtered[0];
        let code = match code {
            Some(c) => c.value.clone(),
            None => {
                // Touch required or HOTP - calculate individually
                let c = session
                    .calculate_code(cred, timestamp)
                    .map_err(|e| CliError(format!("Failed to calculate: {e}")))?;
                c.value
            }
        };
        println!("{code}");
    } else {
        // Find max name width for alignment
        let max_w = filtered
            .iter()
            .map(|(c, _)| format_cred_name(c).len())
            .max()
            .unwrap_or(0);

        for (cred, code) in &filtered {
            let name = format_cred_name(cred);
            let code_str = match code {
                Some(c) => c.value.clone(),
                None => {
                    if cred.touch_required == Some(true) {
                        "[Requires Touch]".into()
                    } else if cred.oath_type == OathType::Hotp {
                        "[HOTP]".into()
                    } else {
                        let c = session
                            .calculate_code(cred, timestamp)
                            .map_err(|e| CliError(format!("Failed to calculate: {e}")))?;
                        c.value
                    }
                }
            };
            println!("{name:<max_w$}  {code_str}");
        }
    }
    Ok(())
}

pub fn run_accounts_add(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    name: &str,
    secret: Option<&str>,
    issuer: Option<&str>,
    oath_type: CliOathType,
    digits: CliOathDigits,
    algorithm: CliOathAlgorithm,
    counter: u32,
    period: u32,
    touch: bool,
    force: bool,
) -> Result<(), CliError> {
    let oath_type: OathType = oath_type.into();
    let hash_algorithm: HashAlgorithm = algorithm.into();
    let digits = digits.as_u8();

    let secret_bytes = match secret {
        Some(s) => {
            parse_b32_key(s).map_err(|_| CliError("Invalid Base32-encoded secret.".into()))?
        }
        None => {
            // Generate random secret
            let mut key = vec![0u8; 20];
            getrandom::fill(&mut key)
                .map_err(|e| CliError(format!("Failed to generate random: {e}")))?;
            key
        }
    };

    let cred_data = CredentialData {
        name: name.to_string(),
        oath_type,
        hash_algorithm,
        secret: secret_bytes,
        digits,
        period,
        counter,
        issuer: issuer.map(|s| s.to_string()),
    };

    let mut session = open_session(dev, scp_params, password, remember)?;

    // Check for existing credential
    if !force {
        let existing = session
            .list_credentials()
            .map_err(|e| CliError(format!("Failed to list: {e}")))?;
        let display_name = match issuer {
            Some(i) => format!("{i}:{name}"),
            None => name.to_string(),
        };
        if existing.iter().any(|c| format_cred_name(c) == display_name)
            && !confirm(&format!(
                "A credential called {display_name} already exists, overwrite?"
            ))
        {
            return Err(CliError("Aborted by user.".into()));
        }
    }

    session
        .put_credential(&cred_data, touch)
        .map_err(|e| CliError(format!("Failed to add credential: {e}")))?;

    let display = match issuer {
        Some(i) => format!("{i}:{name}"),
        None => name.to_string(),
    };
    println!("Credential added: {display}");
    Ok(())
}

pub fn run_accounts_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    query: &str,
    force: bool,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let creds = session
        .list_credentials()
        .map_err(|e| CliError(format!("Failed to list: {e}")))?;

    let matching: Vec<_> = creds
        .iter()
        .filter(|c| {
            format_cred_name(c)
                .to_ascii_lowercase()
                .contains(&query.to_ascii_lowercase())
        })
        .collect();

    let cred = match matching.len() {
        0 => return Err(CliError(format!("No credential matching '{query}'."))),
        1 => matching[0],
        _ => {
            return Err(CliError(format!(
                "Multiple credentials matching '{query}'. Be more specific."
            )));
        }
    };

    let name = format_cred_name(cred);
    if !force && !confirm(&format!("Delete credential {name}?")) {
        return Err(CliError("Aborted by user.".into()));
    }

    session
        .delete_credential(&cred.id)
        .map_err(|e| CliError(format!("Failed to delete: {e}")))?;
    eprintln!("Credential deleted: {name}");
    Ok(())
}

pub fn run_accounts_rename(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    query: &str,
    new_name: &str,
    force: bool,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let creds = session
        .list_credentials()
        .map_err(|e| CliError(format!("Failed to list: {e}")))?;

    let matching: Vec<_> = creds
        .iter()
        .filter(|c| {
            format_cred_name(c)
                .to_ascii_lowercase()
                .contains(&query.to_ascii_lowercase())
        })
        .collect();

    let cred = match matching.len() {
        0 => return Err(CliError(format!("No credential matching '{query}'."))),
        1 => matching[0],
        _ => {
            return Err(CliError(format!(
                "Multiple credentials matching '{query}'. Be more specific."
            )));
        }
    };

    let old_name = format_cred_name(cred);
    // Parse new_name as "issuer:name" or just "name"
    let (new_issuer, new_account) = if let Some((i, n)) = new_name.split_once(':') {
        (Some(i), n)
    } else {
        (None, new_name)
    };

    if !force && !confirm(&format!("Rename {old_name} to {new_name}?")) {
        return Err(CliError("Aborted by user.".into()));
    }

    session
        .rename_credential(&cred.id, new_account, new_issuer)
        .map_err(|e| CliError(format!("Failed to rename: {e}")))?;
    println!("Credential renamed: {old_name} → {new_name}");
    Ok(())
}

pub fn run_access_change(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    new_password: Option<&str>,
    clear: bool,
    remember: bool,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params, password, false)?;

    if clear {
        session
            .unset_key()
            .map_err(|e| CliError(format!("Failed to clear password: {e}")))?;
        // Remove stored password
        let mut keys = oath_keys();
        let _ = keys.remove(session.device_id());
        println!("Password cleared.");
    } else {
        let new_pw = match new_password {
            Some(pw) => pw.to_string(),
            None => crate::util::prompt_new_secret("New OATH password")?,
        };
        let key = session.derive_key(&new_pw);
        session
            .set_key(&key)
            .map_err(|e| CliError(format!("Failed to set password: {e}")))?;
        eprintln!("Password set.");
        if remember {
            let mut keys = oath_keys();
            keys.put_secret(session.device_id(), &hex::encode(&key))
                .map_err(|e| CliError(format!("Failed to remember password: {e}")))?;
            eprintln!("Password remembered.");
        }
    }
    Ok(())
}

pub fn run_access_remember(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
) -> Result<(), CliError> {
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::OATH)?;
    let mut session = match scp_config {
        ScpConfig::None => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            OathSession::new(conn)
                .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
        }
        ref config => {
            let conn = dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            let params = scp::to_scp_key_params(config)
                .expect("non-None ScpConfig must convert to ScpKeyParams");
            OathSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
        }
    };

    if !session.locked() {
        return Err(CliError(
            "No password is set on this YubiKey's OATH application.".into(),
        ));
    }

    let pw = match password {
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter OATH password")?,
    };
    let key = session.derive_key(&pw);
    let mut keys = oath_keys();
    validate_and_remember(&mut session, &key, true, &mut keys)?;
    Ok(())
}

pub fn run_access_forget(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    all: bool,
) -> Result<(), CliError> {
    let mut keys = oath_keys();
    if all {
        keys.clear()
            .map_err(|e| CliError(format!("Failed to clear stored passwords: {e}")))?;
        eprintln!("All stored OATH passwords have been removed.");
    } else {
        // Need to open session to get device_id (without unlocking)
        let scp_config = scp::resolve_scp(dev, scp_params, Capability::OATH)?;
        let session = match scp_config {
            ScpConfig::None => {
                let conn = dev
                    .open_smartcard()
                    .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
                OathSession::new(conn)
                    .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
            }
            ref config => {
                let conn = dev
                    .open_smartcard()
                    .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
                let params = scp::to_scp_key_params(config)
                    .expect("non-None ScpConfig must convert to ScpKeyParams");
                OathSession::new_with_scp(conn, &params)
                    .map_err(|(e, _)| CliError(format!("Failed to open OATH session: {e}")))?
            }
        };
        let device_id = session.device_id();
        if keys.contains(device_id) {
            keys.remove(device_id)
                .map_err(|e| CliError(format!("Failed to remove stored password: {e}")))?;
            eprintln!("Stored OATH password removed.");
        } else {
            eprintln!("No stored password for this YubiKey.");
        }
    }
    Ok(())
}

pub fn run_accounts_uri(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    uri: &str,
    password: Option<&str>,
    remember: bool,
    touch: bool,
    force: bool,
) -> Result<(), CliError> {
    // Parse otpauth:// URI
    let url = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| CliError("URI must start with otpauth://".into()))?;

    let (oath_type_str, rest) = url
        .split_once('/')
        .ok_or_else(|| CliError("Invalid otpauth URI format".into()))?;

    let oath_type = match oath_type_str.to_lowercase().as_str() {
        "totp" => OathType::Totp,
        "hotp" => OathType::Hotp,
        _ => return Err(CliError(format!("Unknown oath type: {oath_type_str}"))),
    };

    // Split path from query
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));

    let label = urldecode(label);

    // Parse issuer:name from label
    let (issuer, name) = if let Some((i, n)) = label.split_once(':') {
        (Some(i.to_string()), n.trim().to_string())
    } else {
        (None, label.to_string())
    };

    // Parse query parameters
    let mut secret = None;
    let mut algorithm = HashAlgorithm::Sha1;
    let mut digits = 6u8;
    let mut period = 30u32;
    let mut counter = 0u32;
    let mut query_issuer = issuer;

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        match key.to_lowercase().as_str() {
            "secret" => {
                secret = Some(value.to_string());
            }
            "algorithm" => {
                algorithm = match value.to_uppercase().as_str() {
                    "SHA1" => HashAlgorithm::Sha1,
                    "SHA256" => HashAlgorithm::Sha256,
                    "SHA512" => HashAlgorithm::Sha512,
                    _ => return Err(CliError(format!("Unknown algorithm: {value}"))),
                };
            }
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| CliError(format!("Invalid digits: {value}")))?;
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| CliError(format!("Invalid period: {value}")))?;
            }
            "counter" => {
                counter = value
                    .parse()
                    .map_err(|_| CliError(format!("Invalid counter: {value}")))?;
            }
            "issuer" => {
                query_issuer = Some(urldecode(value));
            }
            _ => {}
        }
    }

    let secret_str = secret.ok_or_else(|| CliError("URI missing 'secret' parameter".into()))?;
    let secret_bytes = parse_b32_key(&secret_str)
        .map_err(|_| CliError("Invalid Base32-encoded secret.".into()))?;

    let issuer_ref = query_issuer.as_deref();

    if !force {
        eprintln!(
            "Add credential: {}{name} ({oath_type_str})?",
            issuer_ref.map(|i| format!("{i}:")).unwrap_or_default()
        );
        if !confirm("Proceed?") {
            return Err(CliError("Aborted by user.".into()));
        }
    }

    let cred_data = CredentialData {
        name: name.clone(),
        oath_type,
        hash_algorithm: algorithm,
        secret: secret_bytes,
        digits,
        period,
        counter,
        issuer: issuer_ref.map(|s| s.to_string()),
    };

    let mut session = open_session(dev, scp_params, password, remember)?;

    session
        .put_credential(&cred_data, touch)
        .map_err(|e| CliError(format!("Failed to add credential: {e}")))?;
    println!(
        "Credential added: {}{name}",
        issuer_ref.map(|i| format!("{i}:")).unwrap_or_default()
    );
    Ok(())
}

fn urldecode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next().unwrap_or(0);
            let h2 = chars.next().unwrap_or(0);
            let hex_str = format!("{}{}", h1 as char, h2 as char);
            if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                result.push(byte as char);
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}
