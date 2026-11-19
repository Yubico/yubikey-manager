use anyhow::{Result, anyhow};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::yk4_fips::is_yk4_fips;
use clap::Subcommand;
use yubikit::core::Version;
use yubikit::device::YubiKeyDevice;
use yubikit::management::{Capability, DeviceInfo};
use yubikit::oath::{
    Credential, CredentialData, HashAlgorithm, OathAccessKey, OathError, OathSession, OathType,
    format_cred_id, parse_b32_key,
};
use yubikit::smartcard::{SmartCardError, Sw};
use zeroize::Zeroizing;

use crate::appdata::AppData;
use crate::cli_enums::{CliOathAlgorithm, CliOathDigits, CliOathType};
use crate::pskc::{PskcEncryption, PskcFile, PskcProtection, write_pskc};
use crate::scp::{self, ScpParams};
use crate::util::{
    b32_encode, confirm, format_session_error, format_smartcard_connection_error, print_table,
    require_fips_approved,
};

#[derive(Subcommand)]
pub enum OathAction {
    /// Display general status of the OATH application
    Info,
    /// Reset all OATH data
    ///
    /// This action will delete all accounts and restore factory settings for
    /// the OATH application on the YubiKey.
    Reset {
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Manage OATH accounts
    #[command(subcommand)]
    Accounts(OathAccountAction),
    /// Manage OATH access (password)
    #[command(subcommand)]
    Access(OathAccessAction),
}

#[derive(Subcommand)]
pub enum OathAccessAction {
    /// Change the password used to protect OATH accounts
    ///
    /// Allows you to set or change a password that will be required to access
    /// the OATH accounts stored on the YubiKey. Use --clear to remove the
    /// password.
    Change {
        /// Current password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// New password to set
        #[arg(short = 'n', long, value_name = "PASSWORD")]
        new_password: Option<String>,
        /// Remove the password
        #[arg(short = 'c', long)]
        clear: bool,
        /// Remember the new password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
    },
    /// Remember the password for the current YubiKey on this computer
    ///
    /// Stores the OATH password of the YubiKey on this computer, to avoid
    /// having to enter it on each use.
    Remember {
        /// Password to store
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Remove a stored password from this computer
    Forget {
        /// Remove all stored passwords
        #[arg(short = 'a', long)]
        all: bool,
    },
}

#[derive(Subcommand)]
pub enum OathAccountAction {
    /// List stored OATH accounts
    List {
        /// Password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
        /// Show hidden accounts
        #[arg(short = 'H', long)]
        show_hidden: bool,
        /// Show OATH type (TOTP/HOTP)
        #[arg(short = 'o', long)]
        oath_type: bool,
        /// Show period
        #[arg(short = 'P', long)]
        period: bool,
    },
    /// Generate codes
    ///
    /// Generate codes from OATH accounts stored on the YubiKey. Provide a query
    /// string to match one or more specific accounts. Accounts of type HOTP, or
    /// those that require touch, require a single match to be triggered.
    Code {
        /// Password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
        /// Search filter
        query: Option<String>,
        /// Show hidden accounts
        #[arg(short = 'H', long)]
        show_hidden: bool,
        /// Ensure only a single match, and output only the code
        #[arg(short = 's', long)]
        single: bool,
    },
    /// Add an OATH account
    ///
    /// This will add a new OATH account to the YubiKey. If SECRET is not given,
    /// you will be prompted for it, unless --generate is used to create a
    /// random secret.
    ///
    /// Use --output to also write the account to a PSKC file, which can be
    /// used to back up the account or to add it to another YubiKey.
    Add {
        /// Account name
        name: String,
        /// Secret key (Base32 encoded)
        #[arg(conflicts_with = "generate")]
        secret: Option<String>,
        /// Password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
        /// Issuer name
        #[arg(short = 'i', long)]
        issuer: Option<String>,
        /// Credential type
        #[arg(short = 'o', long, default_value = "totp", value_name = "TYPE")]
        oath_type: CliOathType,
        /// Number of digits
        #[arg(long, default_value = "6")]
        digits: CliOathDigits,
        /// Hash algorithm
        #[arg(short = 'a', long, default_value = "sha1")]
        algorithm: CliOathAlgorithm,
        /// Initial counter value for HOTP
        #[arg(short = 'c', long, default_value_t = 0)]
        counter: u32,
        /// Time period for TOTP (seconds)
        #[arg(short = 'P', long, default_value_t = 30)]
        period: u32,
        /// Generate a random credential key
        #[arg(short = 'g', long)]
        generate: bool,
        /// Also write the account to a PSKC file (use '-' for stdout)
        #[arg(short = 'O', long, value_name = "FILE")]
        output: Option<String>,
        /// Encrypt the PSKC file with a pre-shared key (32 hex digits, use '-' to prompt)
        #[arg(
            long,
            value_name = "KEY",
            requires = "output",
            conflicts_with = "pskc_passphrase"
        )]
        pskc_key: Option<String>,
        /// Encrypt the PSKC file with a passphrase (use '-' to prompt)
        #[arg(long, value_name = "PASSPHRASE", requires = "output")]
        pskc_passphrase: Option<String>,
        /// Require touch for code generation
        #[arg(short = 't', long)]
        touch: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Add accounts from a PSKC file
    ///
    /// Reads accounts from a PSKC file, adding them to the YubiKey. The file
    /// can contain multiple accounts, and you will be prompted to confirm each
    /// one before it is added, unless --force is used, in which case all valid
    /// accounts will be added without prompting, overwriting any existing
    /// accounts with the same name.
    Import {
        /// PSKC file to import
        file: String,
        /// Password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
        /// Require touch for code generation
        #[arg(short = 't', long)]
        touch: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Delete an OATH account
    Delete {
        /// A query to match a single account (as shown in "list")
        query: String,
        /// Password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Rename an OATH account
    ///
    /// Requires YubiKey 5.3.1 or later.
    Rename {
        /// A query to match a single account (as shown in "list")
        query: String,
        /// The new name of the account (use "issuer:name" to specify issuer)
        new_name: String,
        /// Password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Add an OATH account from an otpauth:// URI
    ///
    /// Use a URI, such as one encoded in a QR code provided by a service, to
    /// add a new account to the YubiKey.
    Uri {
        /// otpauth:// URI string
        uri: String,
        /// Password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(short = 'r', long)]
        remember: bool,
        /// Require touch for code generation
        #[arg(short = 't', long)]
        touch: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
}

impl OathAction {
    pub fn run(self, dev: &dyn YubiKeyDevice, scp_params: &ScpParams) -> Result<()> {
        match self {
            Self::Info => run_info(dev, scp_params),
            Self::Reset { force } => run_reset(dev, scp_params, force),
            Self::Access(access) => match access {
                OathAccessAction::Change {
                    password,
                    new_password,
                    clear,
                    remember,
                } => run_access_change(
                    dev,
                    scp_params,
                    password.as_deref(),
                    new_password.as_deref(),
                    clear,
                    remember,
                ),
                OathAccessAction::Remember { password } => {
                    run_access_remember(dev, scp_params, password.as_deref())
                }
                OathAccessAction::Forget { all } => run_access_forget(dev, scp_params, all),
            },
            Self::Accounts(acct) => match acct {
                OathAccountAction::List {
                    password,
                    remember,
                    show_hidden,
                    oath_type,
                    period,
                } => run_accounts_list(
                    dev,
                    scp_params,
                    password.as_deref(),
                    remember,
                    show_hidden,
                    oath_type,
                    period,
                ),
                OathAccountAction::Code {
                    password,
                    remember,
                    query,
                    show_hidden,
                    single,
                } => run_accounts_code(
                    dev,
                    scp_params,
                    password.as_deref(),
                    remember,
                    query.as_deref(),
                    show_hidden,
                    single,
                ),
                OathAccountAction::Add {
                    name,
                    secret,
                    password,
                    remember,
                    issuer,
                    oath_type,
                    digits,
                    algorithm,
                    counter,
                    period,
                    generate,
                    output,
                    pskc_key,
                    pskc_passphrase,
                    touch,
                    force,
                } => run_accounts_add(
                    dev,
                    scp_params,
                    password.as_deref(),
                    remember,
                    &name,
                    secret.as_deref(),
                    generate,
                    issuer.as_deref(),
                    oath_type,
                    digits,
                    algorithm,
                    counter,
                    period,
                    output.as_deref().map(|path| PskcOutput {
                        path,
                        key: pskc_key.as_deref(),
                        passphrase: pskc_passphrase.as_deref(),
                    }),
                    touch,
                    force,
                ),
                OathAccountAction::Delete {
                    query,
                    password,
                    remember,
                    force,
                } => run_accounts_delete(
                    dev,
                    scp_params,
                    password.as_deref(),
                    remember,
                    &query,
                    force,
                ),
                OathAccountAction::Rename {
                    query,
                    new_name,
                    password,
                    remember,
                    force,
                } => run_accounts_rename(
                    dev,
                    scp_params,
                    password.as_deref(),
                    remember,
                    &query,
                    &new_name,
                    force,
                ),
                OathAccountAction::Uri {
                    uri,
                    password,
                    remember,
                    touch,
                    force,
                } => run_accounts_uri(
                    dev,
                    scp_params,
                    &uri,
                    password.as_deref(),
                    remember,
                    touch,
                    force,
                ),
                OathAccountAction::Import {
                    file,
                    password,
                    remember,
                    touch,
                    force,
                } => run_accounts_import(
                    dev,
                    scp_params,
                    &file,
                    password.as_deref(),
                    remember,
                    touch,
                    force,
                ),
            },
        }
    }
}

fn oath_keys() -> Result<AppData> {
    AppData::new("oath_keys").map_err(|e| anyhow!("Failed to open OATH key store: {e}"))
}

/// Validate the key against the session, optionally remembering it.
fn validate_and_remember(
    session: &mut OathSession<impl yubikit::smartcard::SmartCardConnection>,
    key: &OathAccessKey,
    remember: bool,
    keys: &mut AppData,
) -> Result<()> {
    session
        .validate(key)
        .map_err(|_| anyhow!("Wrong password."))?;
    if remember {
        keys.put_secret(session.device_id(), &hex::encode(key.expose_secret()))
            .map_err(|e| anyhow!("Failed to remember password: {e}"))?;
        eprintln!("Password remembered.");
    }
    Ok(())
}

fn require_algorithm_support(info: &DeviceInfo, algorithm: HashAlgorithm) -> Result<()> {
    if algorithm == HashAlgorithm::Sha512 && (info.version < Version(4, 3, 1) || is_yk4_fips(info))
    {
        return Err(anyhow!("Algorithm SHA512 not supported on this YubiKey."));
    }
    Ok(())
}

fn new_oath_session<'a>(
    dev: &'a dyn YubiKeyDevice,
    scp_config: &Option<yubikit::smartcard::ScpKeyParams>,
) -> Result<OathSession<impl yubikit::smartcard::SmartCardConnection + use<'a>>> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| format_smartcard_connection_error("OATH", e))?;
    match scp_config {
        None => OathSession::new(conn).map_err(|(e, _)| format_session_error("OATH", e)),
        Some(params) => OathSession::new_with_scp(conn, params)
            .map_err(|(e, _)| format_session_error("OATH", e)),
    }
}

/// Open an OATH session, unlocking it if needed.
///
/// Tries (in order): explicit password, stored key, interactive prompt.
fn open_session<'a>(
    dev: &'a dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
) -> Result<OathSession<impl yubikit::smartcard::SmartCardConnection + use<'a>>> {
    let scp_config = scp::resolve_scp_for_app(dev, scp_params, Capability::OATH, "OATH")?;
    let mut session = new_oath_session(dev, &scp_config)?;

    if session.locked() {
        let mut keys = oath_keys()?;

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
                    Ok(key_bytes) => match OathAccessKey::new(&key_bytes) {
                        Ok(key) => match session.validate(&key) {
                            Ok(()) => return Ok(session),
                            Err(_) => {
                                log::debug!("Remembered key incorrect, removing");
                                let _ = keys.remove(&device_id);
                            }
                        },
                        Err(_) => {
                            log::warn!("Stored key has invalid length, removing");
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
        return Err(anyhow!(
            "Password provided, but no password is set on this YubiKey's OATH application."
        ));
    }
    Ok(session)
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn is_hidden(cred: &Credential) -> bool {
    cred.issuer.as_deref().is_some_and(|i| i.starts_with('_'))
}

/// The full credential ID as a string, including any non-default period prefix.
fn cred_string_id(cred: &Credential) -> String {
    String::from_utf8_lossy(&cred.id).into_owned()
}

/// Sort key ordering credentials by issuer (or name), then name, case-insensitively.
fn cred_sort_key(cred: &Credential) -> (String, String) {
    (
        cred.issuer.as_deref().unwrap_or(&cred.name).to_lowercase(),
        cred.name.to_lowercase(),
    )
}

/// Find credentials matching a query. An exact ID match takes precedence over
/// case-insensitive substring matches.
fn search_creds<'a, T>(
    entries: &'a [T],
    cred_of: impl Fn(&T) -> &Credential,
    query: &str,
    show_hidden: bool,
) -> Vec<&'a T> {
    let query_lower = query.to_lowercase();
    let mut hits = Vec::new();
    for entry in entries {
        let cred = cred_of(entry);
        if !show_hidden && is_hidden(cred) {
            continue;
        }
        let id = cred_string_id(cred);
        if id == query {
            return vec![entry];
        }
        if id.to_lowercase().contains(&query_lower) {
            hits.push(entry);
        }
    }
    hits
}

fn multiple_matches_error<'a>(creds: impl Iterator<Item = &'a Credential>) -> anyhow::Error {
    let ids: Vec<String> = creds.map(cred_string_id).collect();
    anyhow!(
        "Multiple matches, make the query more specific.\n\n{}",
        ids.join("\n")
    )
}

const STEAM_CHAR_TABLE: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

fn is_steam(cred: &Credential) -> bool {
    cred.oath_type == OathType::Totp && cred.issuer.as_deref() == Some("Steam")
}

fn calculate_steam(
    session: &mut OathSession<impl yubikit::smartcard::SmartCardConnection>,
    cred: &Credential,
    timestamp: u64,
) -> Result<String, OathError> {
    let resp = session.calculate(&cred.id, &(timestamp / 30).to_be_bytes())?;
    format_steam(&resp).ok_or_else(|| OathError::InvalidData("Response too short".into()))
}

/// Format a full HMAC response as a 5-character Steam Guard code.
fn format_steam(resp: &[u8]) -> Option<String> {
    let offset = (resp.last()? & 0x0F) as usize;
    let bytes: [u8; 4] = resp.get(offset..offset + 4)?.try_into().ok()?;
    let mut code = u32::from_be_bytes(bytes) & 0x7FFF_FFFF;
    let mut chars = String::with_capacity(5);
    for _ in 0..5 {
        chars.push(STEAM_CHAR_TABLE[code as usize % STEAM_CHAR_TABLE.len()] as char);
        code /= STEAM_CHAR_TABLE.len() as u32;
    }
    Some(chars)
}

fn is_apdu_error(err: &OathError, sw: Sw) -> bool {
    matches!(err, OathError::Connection(SmartCardError::Apdu { sw: s, .. }) if *s == sw as u16)
}

/// Look for a single credential in a corrupted state and delete it.
///
/// Returns true if a broken credential was found and deleted.
fn delete_broken_credential(
    session: &mut OathSession<impl yubikit::smartcard::SmartCardConnection>,
) -> Result<bool> {
    log::debug!("Probing for broken credentials");
    let creds = session
        .list_credentials()
        .map_err(|e| anyhow!("Failed to list credentials: {e}"))?;
    let timestamp = now_timestamp();
    let mut broken = Vec::new();
    for cred in creds.iter().filter(|c| c.oath_type == OathType::Totp) {
        let mut ok = false;
        for i in 0..5 {
            match session.calculate_code(cred, timestamp) {
                Ok(_) => {
                    log::debug!("Credential appears OK: {}", cred_string_id(cred));
                    ok = true;
                    break;
                }
                Err(e) if is_apdu_error(&e, Sw::MemoryFailure) => {
                    if i == 0 {
                        log::debug!("Memory failure in: {}", cred_string_id(cred));
                    }
                }
                // Touch credentials can't be probed without user interaction.
                Err(e) if is_apdu_error(&e, Sw::SecurityConditionNotSatisfied) => {
                    ok = true;
                    break;
                }
                Err(e) => return Err(anyhow!("Failed to calculate: {e}")),
            }
        }
        if !ok {
            log::warn!("Credential appears to be broken: {}", cred_string_id(cred));
            broken.push(cred);
        }
    }

    if let [cred] = broken.as_slice() {
        log::info!("Deleting broken credential");
        session
            .delete_credential(&cred.id)
            .map_err(|e| anyhow!("Failed to delete credential: {e}"))?;
        return Ok(true);
    }
    log::warn!(
        "Requires a single broken credential, found {}",
        broken.len()
    );
    Ok(false)
}

fn prompt_for_touch() {
    eprintln!("Touch your YubiKey...");
}

/// Run `f`, prompting for touch if it hasn't completed within 500 ms.
fn with_touch_prompt_timeout<T>(f: impl FnOnce() -> T) -> T {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let timer = std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            rx.recv_timeout(std::time::Duration::from_millis(500))
        {
            prompt_for_touch();
        }
    });
    let result = f();
    drop(tx);
    let _ = timer.join();
    result
}

pub fn run_info(dev: &dyn YubiKeyDevice, scp_params: &ScpParams) -> Result<()> {
    // Open a raw session without unlocking — info doesn't require authentication
    let scp_config = scp::resolve_scp_for_app(dev, scp_params, Capability::OATH, "OATH")?;
    let session = new_oath_session(dev, &scp_config)?;
    let keys = oath_keys()?;
    print_table([
        ("OATH version", session.version().to_string()),
        (
            "Password protection",
            if session.has_key() {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            },
        ),
    ]);
    if session.has_key() && keys.contains(session.device_id()) {
        println!("The password for this YubiKey is remembered by ykman.");
    }
    Ok(())
}

pub fn run_reset(dev: &dyn YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<()> {
    if !force {
        eprintln!(
            "WARNING! This will delete all stored OATH accounts and restore factory settings of the OATH application."
        );
        if !confirm("Proceed?") {
            return Err(anyhow!("Aborted by user."));
        }
    }
    let scp_config = scp::resolve_scp_for_app(dev, scp_params, Capability::OATH, "OATH")?;
    let session = new_oath_session(dev, &scp_config)?;
    let device_id = session.device_id().to_string();
    session
        .reset()
        .map_err(|(e, _)| anyhow!("Failed to reset OATH: {e}"))?;

    // Clean up any stored password for this device
    let mut keys = oath_keys()?;
    if keys.contains(&device_id) {
        let _ = keys.remove(&device_id);
    }
    eprintln!("OATH application has been reset.");
    Ok(())
}

pub fn run_accounts_list(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    show_hidden: bool,
    show_oath_type: bool,
    show_period: bool,
) -> Result<()> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let creds = session
        .list_credentials()
        .map_err(|e| anyhow!("Failed to list credentials: {e}"))?;

    let mut creds: Vec<_> = creds
        .into_iter()
        .filter(|c| show_hidden || !is_hidden(c))
        .collect();
    creds.sort_by_key(cred_sort_key);
    for cred in &creds {
        let mut line = cred_string_id(cred);
        if show_oath_type {
            let t = match cred.oath_type {
                OathType::Totp => "TOTP",
                OathType::Hotp => "HOTP",
            };
            line.push_str(&format!(", {t}"));
        }
        if show_period {
            line.push_str(&format!(", {}", cred.period));
        }
        println!("{line}");
    }
    Ok(())
}

pub fn run_accounts_code(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    query: Option<&str>,
    show_hidden: bool,
    single: bool,
) -> Result<()> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let timestamp = now_timestamp();

    let entries = match session.calculate_all(timestamp) {
        Ok(entries) => entries,
        Err(e) if is_apdu_error(&e, Sw::MemoryFailure) => {
            log::warn!("Corrupted data in OATH accounts, attempting to fix");
            if !delete_broken_credential(&mut session)? {
                log::error!("Unable to fix memory failure");
                return Err(anyhow!("Failed to calculate codes: {e}"));
            }
            session
                .calculate_all(timestamp)
                .map_err(|e| anyhow!("Failed to calculate codes: {e}"))?
        }
        Err(e) => return Err(anyhow!("Failed to calculate codes: {e}")),
    };

    let mut hits = search_creds(&entries, |(c, _)| c, query.unwrap_or(""), show_hidden);

    if let [(cred, code)] = hits.as_slice() {
        if cred.touch_required == Some(true) {
            prompt_for_touch();
        }
        let value = if is_steam(cred) {
            calculate_steam(&mut session, cred, timestamp)
        } else if let Some(code) = code {
            Ok(code.value.clone())
        } else if cred.oath_type == OathType::Hotp {
            // HOTP might require touch, we don't know. Assume yes after 500ms.
            with_touch_prompt_timeout(|| session.calculate_code(cred, timestamp)).map(|c| c.value)
        } else {
            session.calculate_code(cred, timestamp).map(|c| c.value)
        };
        let value = match value {
            Ok(v) => v,
            Err(e) if is_apdu_error(&e, Sw::SecurityConditionNotSatisfied) => {
                return Err(anyhow!("Touch account timed out!"));
            }
            Err(e) => return Err(anyhow!("Failed to calculate: {e}")),
        };
        if single {
            println!("{value}");
        } else {
            println!("{}  {value}", cred_string_id(cred));
        }
    } else if single {
        if hits.is_empty() {
            return Err(anyhow!("No matching account found."));
        }
        return Err(multiple_matches_error(hits.iter().map(|(c, _)| c)));
    } else {
        hits.sort_by_key(|(c, _)| cred_sort_key(c));
        let mut outputs = Vec::with_capacity(hits.len());
        for (cred, code) in hits {
            let code_str = match code {
                Some(_) if is_steam(cred) => calculate_steam(&mut session, cred, timestamp)
                    .map_err(|e| anyhow!("Failed to calculate: {e}"))?,
                Some(c) => c.value.clone(),
                None if cred.touch_required == Some(true) => "[Requires Touch]".into(),
                None if cred.oath_type == OathType::Hotp => "[HOTP Account]".into(),
                None => String::new(),
            };
            outputs.push((cred_string_id(cred), code_str));
        }
        let max_w = outputs.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        for (name, code_str) in outputs {
            println!("{name:<max_w$}  {code_str}");
        }
    }
    Ok(())
}

/// Where and how to write a PSKC copy of an added account.
pub struct PskcOutput<'a> {
    path: &'a str,
    key: Option<&'a str>,
    passphrase: Option<&'a str>,
}

fn prompt_confirmed_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let value = Zeroizing::new(crate::util::prompt_secret(prompt)?);
    let confirm = Zeroizing::new(crate::util::prompt_secret("Repeat for confirmation")?);
    if value != confirm {
        return Err(anyhow!("The values do not match."));
    }
    Ok(value)
}

fn pskc_encryption(output: &PskcOutput) -> Result<Option<PskcEncryption>> {
    if let Some(passphrase) = output.passphrase {
        let passphrase = if passphrase == "-" {
            prompt_confirmed_secret("Enter passphrase to encrypt PSKC file")?
        } else {
            Zeroizing::new(passphrase.to_string())
        };
        if passphrase.chars().count() < 8 {
            return Err(anyhow!("Passphrase must be at least 8 characters."));
        }
        Ok(Some(PskcEncryption::Passphrase(passphrase)))
    } else if let Some(key) = output.key {
        let key = if key == "-" {
            prompt_confirmed_secret("Enter pre-shared key (hex) to encrypt PSKC file")?
        } else {
            Zeroizing::new(key.to_string())
        };
        let key = Zeroizing::new(hex::decode(key.trim()).unwrap_or_default());
        if key.len() != 16 {
            return Err(anyhow!(
                "Pre-shared key must be 16 bytes (32 hex characters)."
            ));
        }
        Ok(Some(PskcEncryption::PresharedKey(key)))
    } else {
        Ok(None)
    }
}

pub fn run_accounts_add(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    name: &str,
    secret: Option<&str>,
    generate: bool,
    issuer: Option<&str>,
    oath_type: CliOathType,
    digits: CliOathDigits,
    algorithm: CliOathAlgorithm,
    counter: u32,
    period: u32,
    output: Option<PskcOutput>,
    touch: bool,
    force: bool,
) -> Result<()> {
    require_fips_approved(dev.info(), Capability::OATH, "prior to adding accounts")?;
    let pskc = match &output {
        Some(output) => {
            let serial = dev.info().serial.ok_or_else(|| {
                anyhow!("YubiKey has no readable serial number, cannot write to PSKC file.")
            })?;
            Some((output.path, serial, pskc_encryption(output)?))
        }
        None => None,
    };
    let oath_type: OathType = oath_type.into();
    let hash_algorithm: HashAlgorithm = algorithm.into();
    require_algorithm_support(dev.info(), hash_algorithm)?;
    let digits = digits.as_u8();

    let secret_bytes = if let Some(s) = secret {
        parse_b32_key(s).map_err(|_| anyhow!("Invalid Base32-encoded secret."))?
    } else if generate {
        let mut key = vec![0u8; 20];
        getrandom::fill(&mut key).map_err(|e| anyhow!("Failed to generate random: {e}"))?;
        if pskc.is_none() {
            eprintln!(
                "Using a randomly generated secret (base32): {}",
                b32_encode(&key)
            );
        }
        key
    } else {
        loop {
            match crate::util::prompt_bytes(
                "Enter a secret key",
                &crate::util::ByteFormat::base32(crate::util::ByteLen::Any).masked(),
            ) {
                Ok(k) => break k,
                Err(e) => eprintln!("{e}"),
            }
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
            .map_err(|e| anyhow!("Failed to list: {e}"))?;
        let cred_id = cred_data.get_id();
        if existing.iter().any(|c| c.id == cred_id)
            && !confirm(&format!(
                "A credential called {} already exists, overwrite?",
                String::from_utf8_lossy(&cred_id)
            ))
        {
            return Err(anyhow!("Aborted by user."));
        }
    }

    session
        .put_credential(&cred_data, touch)
        .map_err(|e| anyhow!("Failed to add credential: {e}"))?;

    let display = match issuer {
        Some(i) => format!("{i}:{name}"),
        None => name.to_string(),
    };
    match pskc {
        Some((path, serial, encryption)) => {
            eprintln!("Credential added: {display}");
            let xml = write_pskc(&cred_data, serial, encryption.as_ref())?;
            crate::util::write_file_or_stdout(path, xml.as_bytes())?;
            if path != "-" {
                eprintln!("Credential written to PSKC file: {path}");
            }
        }
        None => println!("Credential added: {display}"),
    }
    Ok(())
}

pub fn run_accounts_delete(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    query: &str,
    force: bool,
) -> Result<()> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let creds = session
        .list_credentials()
        .map_err(|e| anyhow!("Failed to list: {e}"))?;

    let hits = search_creds(&creds, |c| c, query, true);
    let cred = match hits.as_slice() {
        [] => {
            println!("No matches, nothing to be done.");
            return Ok(());
        }
        [cred] => *cred,
        _ => return Err(multiple_matches_error(hits.into_iter())),
    };

    let id = cred_string_id(cred);
    if !force && !confirm(&format!("Delete account: {id} ?")) {
        return Err(anyhow!("Aborted by user."));
    }

    session
        .delete_credential(&cred.id)
        .map_err(|e| anyhow!("Failed to delete: {e}"))?;
    println!("Deleted {id}.");
    Ok(())
}

pub fn run_accounts_rename(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    remember: bool,
    query: &str,
    new_name: &str,
    force: bool,
) -> Result<()> {
    let mut session = open_session(dev, scp_params, password, remember)?;
    let creds = session
        .list_credentials()
        .map_err(|e| anyhow!("Failed to list: {e}"))?;

    let hits = search_creds(&creds, |c| c, query, true);
    let cred = match hits.as_slice() {
        [] => {
            println!("No matches, nothing to be done.");
            return Ok(());
        }
        [cred] => *cred,
        _ => return Err(multiple_matches_error(hits.into_iter())),
    };

    let (new_issuer, new_account) = match new_name.split_once(':') {
        Some((i, n)) => (Some(i), n),
        None => (None, new_name),
    };
    let new_id = format_cred_id(new_issuer, new_account, cred.oath_type, cred.period);
    let new_id_str = String::from_utf8_lossy(&new_id).into_owned();
    if creds.iter().any(|c| c.id == new_id) {
        return Err(anyhow!(
            "Another account with ID {new_id_str} already exists on this YubiKey."
        ));
    }

    let old_id = cred_string_id(cred);
    if !force && !confirm(&format!("Rename account: {old_id} ?")) {
        return Err(anyhow!("Aborted by user."));
    }

    session
        .rename_credential(&cred.id, new_account, new_issuer)
        .map_err(|e| anyhow!("Failed to rename: {e}"))?;
    println!("Renamed {old_id} to {new_id_str}.");
    Ok(())
}

pub fn run_access_change(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
    new_password: Option<&str>,
    clear: bool,
    remember: bool,
) -> Result<()> {
    if clear && dev.info().fips_capable.contains(Capability::OATH) {
        return Err(anyhow!(
            "Removing the password is not allowed on YubiKey FIPS."
        ));
    }
    let mut session = open_session(dev, scp_params, password, false)?;

    if clear {
        session
            .unset_key()
            .map_err(|e| anyhow!("Failed to clear password: {e}"))?;
        // Remove stored password
        let mut keys = oath_keys()?;
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
            .map_err(|e| anyhow!("Failed to set password: {e}"))?;
        eprintln!("Password set.");
        if remember {
            let mut keys = oath_keys()?;
            keys.put_secret(session.device_id(), &hex::encode(key.expose_secret()))
                .map_err(|e| anyhow!("Failed to remember password: {e}"))?;
            eprintln!("Password remembered.");
        }
    }
    Ok(())
}

pub fn run_access_remember(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    password: Option<&str>,
) -> Result<()> {
    let scp_config = scp::resolve_scp_for_app(dev, scp_params, Capability::OATH, "OATH")?;
    let mut session = new_oath_session(dev, &scp_config)?;

    if !session.locked() {
        return Err(anyhow!(
            "No password is set on this YubiKey's OATH application."
        ));
    }

    let pw = match password {
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter OATH password")?,
    };
    let key = session.derive_key(&pw);
    let mut keys = oath_keys()?;
    validate_and_remember(&mut session, &key, true, &mut keys)?;
    Ok(())
}

pub fn run_access_forget(dev: &dyn YubiKeyDevice, scp_params: &ScpParams, all: bool) -> Result<()> {
    let mut keys = oath_keys()?;
    if all {
        keys.clear()
            .map_err(|e| anyhow!("Failed to clear stored passwords: {e}"))?;
        eprintln!("All stored OATH passwords have been removed.");
    } else {
        // Need to open session to get device_id (without unlocking)
        let scp_config = scp::resolve_scp_for_app(dev, scp_params, Capability::OATH, "OATH")?;
        let session = new_oath_session(dev, &scp_config)?;
        let device_id = session.device_id();
        if keys.contains(device_id) {
            keys.remove(device_id)
                .map_err(|e| anyhow!("Failed to remove stored password: {e}"))?;
            eprintln!("Stored OATH password removed.");
        } else {
            eprintln!("No stored password for this YubiKey.");
        }
    }
    Ok(())
}

pub fn run_accounts_uri(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    uri: &str,
    password: Option<&str>,
    remember: bool,
    touch: bool,
    force: bool,
) -> Result<()> {
    require_fips_approved(dev.info(), Capability::OATH, "prior to adding accounts")?;
    // Parse otpauth:// URI
    let url = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| anyhow!("URI must start with otpauth://"))?;

    let (oath_type_str, rest) = url
        .split_once('/')
        .ok_or_else(|| anyhow!("Invalid otpauth URI format"))?;

    let oath_type = match oath_type_str.to_lowercase().as_str() {
        "totp" => OathType::Totp,
        "hotp" => OathType::Hotp,
        _ => return Err(anyhow!("Unknown oath type: {oath_type_str}")),
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
                    _ => return Err(anyhow!("Unknown algorithm: {value}")),
                };
            }
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| anyhow!("Invalid digits: {value}"))?;
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| anyhow!("Invalid period: {value}"))?;
            }
            "counter" => {
                counter = value
                    .parse()
                    .map_err(|_| anyhow!("Invalid counter: {value}"))?;
            }
            "issuer" => {
                query_issuer = Some(urldecode(value));
            }
            _ => {}
        }
    }

    require_algorithm_support(dev.info(), algorithm)?;
    let secret_str = secret.ok_or_else(|| anyhow!("URI missing 'secret' parameter"))?;
    let secret_bytes =
        parse_b32_key(&secret_str).map_err(|_| anyhow!("Invalid Base32-encoded secret."))?;

    let issuer_ref = query_issuer.as_deref();

    if !force {
        eprintln!(
            "Add credential: {}{name} ({oath_type_str})?",
            issuer_ref.map(|i| format!("{i}:")).unwrap_or_default()
        );
        if !confirm("Proceed?") {
            return Err(anyhow!("Aborted by user."));
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
        .map_err(|e| anyhow!("Failed to add credential: {e}"))?;
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

pub fn run_accounts_import(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    file: &str,
    password: Option<&str>,
    remember: bool,
    touch: bool,
    force: bool,
) -> Result<()> {
    require_fips_approved(dev.info(), Capability::OATH, "prior to adding accounts")?;
    let data = crate::util::read_file_or_stdin(file)?;
    let xml_str = String::from_utf8(data).map_err(|_| anyhow!("PSKC file is not valid UTF-8."))?;

    let pskc = PskcFile::parse(&xml_str)?;
    let key = match pskc.protection() {
        PskcProtection::None => None,
        PskcProtection::Passphrase => {
            let passphrase = Zeroizing::new(crate::util::prompt_secret(
                "Enter passphrase to decrypt PSKC file",
            )?);
            Some(pskc.derive_key(&passphrase)?)
        }
        PskcProtection::PresharedKey => {
            let key = Zeroizing::new(crate::util::prompt_secret(
                "Enter pre-shared key (32 hex digits) to decrypt PSKC file",
            )?);
            Some(Zeroizing::new(hex::decode(key.trim()).map_err(|_| {
                anyhow!("Invalid pre-shared key: must be valid hexadecimal.")
            })?))
        }
    };
    let credentials = pskc.credentials(key.as_ref().map(|k| k.as_slice()))?;

    if credentials.is_empty() {
        return Err(anyhow!("No valid OATH accounts found in the file."));
    }
    for cred in &credentials {
        require_algorithm_support(dev.info(), cred.hash_algorithm)?;
    }

    let mut session = open_session(dev, scp_params, password, remember)?;

    let existing = session
        .list_credentials()
        .map_err(|e| anyhow!("Failed to list credentials: {e}"))?;

    let mut n_keys = 0;
    for cred in &credentials {
        let account_name = match &cred.issuer {
            Some(i) => format!("{i}:{}", cred.name),
            None => cred.name.clone(),
        };

        if !force {
            eprint!("Import account: {account_name} ? [Y/n] ");
            io::stderr().flush().ok();
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            let answer = input.trim().to_ascii_lowercase();
            if answer == "n" || answer == "no" {
                continue;
            }
        }

        let cred_data = CredentialData {
            name: cred.name.clone(),
            oath_type: cred.oath_type,
            hash_algorithm: cred.hash_algorithm,
            secret: cred.secret.to_vec(),
            digits: cred.digits,
            period: cred.period,
            counter: cred.counter,
            issuer: cred.issuer.clone(),
        };

        // Check for duplicate when forcing
        if force {
            let id = cred_data.get_id();
            if existing.iter().any(|c| c.id == id) {
                // Delete existing before re-adding
                let _ = session.delete_credential(&id);
            }
        }

        session
            .put_credential(&cred_data, touch)
            .map_err(|e| anyhow!("Failed to add credential '{account_name}': {e}"))?;
        eprintln!("Added account: {account_name}");
        n_keys += 1;
    }

    eprintln!("{n_keys} OATH account(s) added.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(id: &str, issuer: Option<&str>, name: &str) -> Credential {
        Credential {
            device_id: String::new(),
            id: id.as_bytes().to_vec(),
            issuer: issuer.map(str::to_string),
            name: name.to_string(),
            oath_type: OathType::Totp,
            period: 30,
            touch_required: None,
        }
    }

    #[test]
    fn test_format_steam() {
        let resp = hex::decode("75a48a19d4cbe100644e8ac1397eea747a2d33ab").unwrap();
        assert_eq!(format_steam(&resp).as_deref(), Some("PV9M4"));
        let resp = hex::decode("278c02e53610f84c40bd9135acd4101012410a14").unwrap();
        assert_eq!(format_steam(&resp).as_deref(), Some("PY4YB"));
        assert_eq!(format_steam(&[0x0F]), None);
    }

    #[test]
    fn test_search_creds_exact_match_wins() {
        let creds = [
            cred("foobar", None, "foobar"),
            cred("foo", None, "foo"),
            cred("Foo:x", Some("Foo"), "x"),
        ];
        let hits = search_creds(&creds, |c| c, "foo", false);
        assert_eq!(hits, vec![&creds[1]]);
        let hits = search_creds(&creds, |c| c, "FOO", false);
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn test_search_creds_uses_period_prefixed_id() {
        let creds = [
            cred("Issuer:name", Some("Issuer"), "name"),
            cred("60/Issuer:name", Some("Issuer"), "name"),
        ];
        let hits = search_creds(&creds, |c| c, "60/", false);
        assert_eq!(hits, vec![&creds[1]]);
    }

    #[test]
    fn test_search_creds_hidden_by_issuer_only() {
        let creds = [
            cred("_hidden:a", Some("_hidden"), "a"),
            cred("_b", None, "_b"),
        ];
        assert_eq!(search_creds(&creds, |c| c, "", false), vec![&creds[1]]);
        assert_eq!(search_creds(&creds, |c| c, "", true).len(), 2);
    }

    #[test]
    fn test_cred_sort_key() {
        let mut creds = [
            cred("b:z", Some("b"), "z"),
            cred("A:y", Some("A"), "y"),
            cred("c", None, "c"),
            cred("a", None, "a"),
        ];
        creds.sort_by_key(cred_sort_key);
        let ids: Vec<_> = creds.iter().map(cred_string_id).collect();
        assert_eq!(ids, ["a", "A:y", "b:z", "c"]);
    }
}
