use clap::Subcommand;
use yubikit::device::YubiKeyDevice;
use yubikit::hsmauth::{CredentialPassword, HsmAuthManagementKey, HsmAuthSession};
use yubikit::management::Capability;

use crate::cli_enums::CliFormat;
use crate::scp::ScpParams;
use crate::util::{CliError, confirm, open_smartcard_session, print_table, write_file_or_stdout};

const MANAGEMENT_KEY_LEN: usize = 16;

#[derive(Subcommand)]
pub enum HsmauthAction {
    /// Display HSM Auth status
    Info,
    /// Reset the HSM Auth application
    Reset {
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Manage credentials
    #[command(subcommand)]
    Credentials(HsmauthCredAction),
    /// Manage access
    #[command(subcommand)]
    Access(HsmauthAccessAction),
}

#[derive(Subcommand)]
pub enum HsmauthCredAction {
    /// List credentials
    List,
    /// Generate asymmetric credential
    Generate {
        label: String,
        #[arg(short = 'c', long)]
        credential_password: Option<String>,
        /// Management password
        #[arg(short, long)]
        management_password: Option<String>,
        #[arg(short, long)]
        touch: bool,
    },
    /// Import symmetric credential
    Symmetric {
        label: String,
        #[arg(short = 'E', long)]
        enc_key: Option<String>,
        #[arg(short = 'M', long)]
        mac_key: Option<String>,
        #[arg(short, long)]
        generate: bool,
        #[arg(short = 'c', long)]
        credential_password: Option<String>,
        /// Management password
        #[arg(short, long)]
        management_password: Option<String>,
        #[arg(short, long)]
        touch: bool,
    },
    /// Import credential derived from password
    Derive {
        label: String,
        /// Derivation password
        derivation_password: String,
        #[arg(short = 'c', long)]
        credential_password: Option<String>,
        /// Management password
        #[arg(short, long)]
        management_password: Option<String>,
        #[arg(short, long)]
        touch: bool,
    },
    /// Delete credential
    Delete {
        label: String,
        /// Management password
        #[arg(short, long)]
        management_password: Option<String>,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Change credential password
    ChangePassword {
        label: String,
        #[arg(short = 'c', long)]
        credential_password: Option<String>,
        /// New credential password
        #[arg(short, long)]
        new_credential_password: Option<String>,
    },
    /// Import an asymmetric credential
    Import {
        /// Credential label
        label: String,
        /// File containing the private key (use '-' for stdin)
        #[arg(value_name = "PRIVATE-KEY")]
        private_key: String,
        /// Password to decrypt the private key
        #[arg(short, long)]
        password: Option<String>,
        /// Password to protect credential
        #[arg(short = 'c', long)]
        credential_password: Option<String>,
        /// Management password
        #[arg(short, long)]
        management_password: Option<String>,
        /// Require touch
        #[arg(short, long)]
        touch: bool,
    },
    /// Export public key for asymmetric credential
    Export {
        /// Credential label
        label: String,
        /// Output file (- for stdout)
        output: String,
        /// Output format
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
    },
}

#[derive(Subcommand)]
pub enum HsmauthAccessAction {
    /// Change the management key
    #[command(name = "change-management-password")]
    ChangeManagementPassword {
        #[arg(short, long)]
        management_password: Option<String>,
        #[arg(short, long)]
        new_management_password: Option<String>,
        #[arg(short, long)]
        generate: bool,
    },
}

impl HsmauthAction {
    pub fn run(self, dev: &dyn YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
        match self {
            Self::Info => run_info(dev, scp_params),
            Self::Reset { force } => run_reset(dev, scp_params, force),
            Self::Credentials(cred) => match cred {
                HsmauthCredAction::List => run_credentials_list(dev, scp_params),
                HsmauthCredAction::Generate {
                    label,
                    credential_password,
                    management_password,
                    touch,
                } => run_credentials_generate(
                    dev,
                    scp_params,
                    &label,
                    credential_password.as_deref(),
                    management_password.as_deref(),
                    touch,
                ),
                HsmauthCredAction::Symmetric {
                    label,
                    enc_key,
                    mac_key,
                    generate,
                    credential_password,
                    management_password,
                    touch,
                } => run_credentials_symmetric(
                    dev,
                    scp_params,
                    &label,
                    enc_key.as_deref(),
                    mac_key.as_deref(),
                    generate,
                    credential_password.as_deref(),
                    management_password.as_deref(),
                    touch,
                ),
                HsmauthCredAction::Derive {
                    label,
                    derivation_password,
                    credential_password,
                    management_password,
                    touch,
                } => run_credentials_derive(
                    dev,
                    scp_params,
                    &label,
                    &derivation_password,
                    credential_password.as_deref(),
                    management_password.as_deref(),
                    touch,
                ),
                HsmauthCredAction::Delete {
                    label,
                    management_password,
                    force,
                } => run_credentials_delete(
                    dev,
                    scp_params,
                    &label,
                    management_password.as_deref(),
                    force,
                ),
                HsmauthCredAction::ChangePassword {
                    label,
                    credential_password,
                    new_credential_password,
                } => run_credentials_change_password(
                    dev,
                    scp_params,
                    &label,
                    credential_password.as_deref(),
                    new_credential_password.as_deref(),
                ),
                HsmauthCredAction::Export {
                    label,
                    output,
                    format,
                } => run_credentials_export(dev, scp_params, &label, &output, format),
                HsmauthCredAction::Import {
                    label,
                    private_key,
                    password,
                    credential_password,
                    management_password,
                    touch,
                } => run_credentials_import(
                    dev,
                    scp_params,
                    &label,
                    &private_key,
                    password.as_deref(),
                    credential_password.as_deref(),
                    management_password.as_deref(),
                    touch,
                ),
            },
            Self::Access(access) => match access {
                HsmauthAccessAction::ChangeManagementPassword {
                    management_password,
                    new_management_password,
                    generate,
                } => run_access_change_management_key(
                    dev,
                    scp_params,
                    management_password.as_deref(),
                    new_management_password.as_deref(),
                    generate,
                ),
            },
        }
    }
}

fn open_session(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<HsmAuthSession<Box<dyn yubikit::smartcard::SmartCardConnection + Send>>, CliError> {
    open_smartcard_session(
        dev,
        scp_params,
        Capability::HSMAUTH,
        "YubiHSM Auth",
        HsmAuthSession::new,
        HsmAuthSession::new_with_scp,
    )
}

/// Parse a management password: UTF-8 string (≤16 bytes, null-padded) or hex (32 chars).
fn parse_management_password(value: &str) -> Result<HsmAuthManagementKey, CliError> {
    let encoded = value.as_bytes();
    if encoded.len() <= MANAGEMENT_KEY_LEN {
        let mut key = [0u8; MANAGEMENT_KEY_LEN];
        key[..encoded.len()].copy_from_slice(encoded);
        return HsmAuthManagementKey::new(&key)
            .map_err(|e| CliError(format!("Invalid management password: {e}")));
    }
    if encoded.len() == MANAGEMENT_KEY_LEN * 2
        && let Ok(bytes) = hex::decode(value)
    {
        return HsmAuthManagementKey::new(&bytes)
            .map_err(|e| CliError(format!("Invalid management password: {e}")));
    }
    Err(CliError(
        "Management password must be at most 16 characters, or 32 hex digits.".into(),
    ))
}

/// Get the management password: from CLI arg, or prompt.
fn require_management_password(
    management_password: Option<&str>,
) -> Result<HsmAuthManagementKey, CliError> {
    match management_password {
        Some(p) => parse_management_password(p),
        None => {
            let p = crate::util::prompt_secret("Enter management password")?;
            parse_management_password(&p)
        }
    }
}

/// Get the credential password: from CLI arg, or prompt (with confirmation).
fn require_credential_password(
    credential_password: Option<&str>,
) -> Result<CredentialPassword, CliError> {
    match credential_password {
        Some(p) => Ok(CredentialPassword::from_password(p)),
        None => {
            let p1 = crate::util::prompt_secret("Enter credential password")?;
            let p2 = crate::util::prompt_secret("Confirm credential password")?;
            if p1 != p2 {
                return Err(CliError("Passwords do not match.".into()));
            }
            Ok(CredentialPassword::from_password(&p1))
        }
    }
}

/// Map HsmAuthError to user-friendly messages, matching Python's handle_credential_error.
fn format_credential_error(e: &yubikit::hsmauth::HsmAuthError, default_msg: &str) -> String {
    use yubikit::hsmauth::HsmAuthError;
    use yubikit::smartcard::SmartCardError;
    match e {
        HsmAuthError::InvalidPin(retries) => {
            if *retries > 0 {
                format!("Wrong management password, {retries} attempt(s) remaining.")
            } else {
                "Management password is blocked.".into()
            }
        }
        HsmAuthError::Connection(SmartCardError::Apdu { sw, .. }) => match *sw {
            0x6983 => "A credential with the provided label already exists.".into(),
            0x6A84 => "No space left on the YubiKey for YubiHSM Auth credentials.".into(),
            0x6A82 => "Credential with the provided label was not found.".into(),
            0x6982 => "The device was not touched.".into(),
            0x6985 => "Password does not meet complexity requirement.".into(),
            _ => default_msg.into(),
        },
        _ => default_msg.into(),
    }
}

pub fn run_info(dev: &dyn YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;
    let mut rows = vec![("YubiHSM Auth version", session.version().to_string())];
    if let Ok(retries) = session.get_management_key_retries() {
        rows.push(("Management key retries remaining", format!("{retries}/8")));
    }
    print_table(rows);
    Ok(())
}

pub fn run_reset(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    force: bool,
) -> Result<(), CliError> {
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

pub fn run_credentials_list(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<(), CliError> {
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
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = require_management_password(management_key)?;
    let pw = require_credential_password(credential_password)?;

    let mut session = open_session(dev, scp_params)?;
    session
        .generate_credential_asymmetric(&mgmt, label, &pw, touch)
        .map_err(|e| {
            CliError(format_credential_error(
                &e,
                "Failed to generate credential.",
            ))
        })?;
    eprintln!("Asymmetric credential generated: {label}");
    Ok(())
}

pub fn run_credentials_delete(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    management_key: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    if !force && !confirm(&format!("Delete credential '{label}'?")) {
        return Err(CliError("Aborted.".into()));
    }
    let mgmt = require_management_password(management_key)?;
    let mut session = open_session(dev, scp_params)?;
    session
        .delete_credential(&mgmt, label)
        .map_err(|e| CliError(format_credential_error(&e, "Failed to delete credential.")))?;
    eprintln!("Credential deleted: {label}");
    Ok(())
}

pub fn run_credentials_symmetric(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    enc_key: Option<&str>,
    mac_key: Option<&str>,
    generate: bool,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = require_management_password(management_key)?;
    let pw = require_credential_password(credential_password)?;

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
        .map_err(|e| CliError(format_credential_error(&e, "Failed to store credential.")))?;
    eprintln!("Symmetric credential stored: {label}");
    if generate {
        println!("ENC key: {}", hex::encode(&enc));
        println!("MAC key: {}", hex::encode(&mac));
    }
    Ok(())
}

pub fn run_credentials_derive(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    derivation_password: &str,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = require_management_password(management_key)?;
    let pw = require_credential_password(credential_password)?;

    let mut session = open_session(dev, scp_params)?;
    session
        .put_credential_derived(&mgmt, label, derivation_password, &pw, touch)
        .map_err(|e| CliError(format_credential_error(&e, "Failed to derive credential.")))?;
    eprintln!("Derived credential stored: {label}");
    Ok(())
}

pub fn run_credentials_change_password(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    credential_password: Option<&str>,
    new_credential_password: Option<&str>,
) -> Result<(), CliError> {
    let old_pw = match credential_password {
        Some(p) => CredentialPassword::from_password(p),
        None => {
            let p = crate::util::prompt_secret("Enter current credential password")?;
            CredentialPassword::from_password(&p)
        }
    };
    let new_pw = match new_credential_password {
        Some(p) => CredentialPassword::from_password(p),
        None => {
            let p1 = crate::util::prompt_secret("Enter new credential password")?;
            let p2 = crate::util::prompt_secret("Confirm new credential password")?;
            if p1 != p2 {
                return Err(CliError("Passwords do not match.".into()));
            }
            CredentialPassword::from_password(&p1)
        }
    };

    let mut session = open_session(dev, scp_params)?;
    session
        .change_credential_password(label, &old_pw, &new_pw)
        .map_err(|e| CliError(format_credential_error(&e, "Failed to change password.")))?;
    eprintln!("Credential password changed for: {label}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_credentials_import(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    private_key_file: &str,
    password: Option<&str>,
    credential_password: Option<&str>,
    management_key: Option<&str>,
    touch: bool,
) -> Result<(), CliError> {
    let mgmt = require_management_password(management_key)?;
    let cred_pw = require_credential_password(credential_password)?;

    let data = crate::util::read_file_or_stdin(private_key_file)?;

    // Parse the private key, handling encrypted keys
    let secret_key = parse_ec_private_key(&data, password)?;

    let mut session = open_session(dev, scp_params)?;
    session
        .put_credential_asymmetric(&mgmt, label, &secret_key, &cred_pw, touch)
        .map_err(|e| {
            CliError(format_credential_error(
                &e,
                "Failed to import asymmetric credential.",
            ))
        })?;
    eprintln!("Asymmetric credential imported.");
    Ok(())
}

/// Parse an EC P-256 private key from PEM or DER data, with optional password decryption.
fn parse_ec_private_key(data: &[u8], password: Option<&str>) -> Result<p256::SecretKey, CliError> {
    use elliptic_curve::SecretKey;
    use elliptic_curve::pkcs8::DecodePrivateKey;
    use p256::NistP256;

    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
    {
        if text.contains("ENCRYPTED") {
            let _pw = match password {
                Some(p) => p.to_string(),
                None => crate::util::prompt_secret("Enter password to decrypt key")?,
            };
            // Try parsing as non-encrypted first (some tools wrap non-encrypted keys)
            if let Ok(sk) = SecretKey::<NistP256>::from_pkcs8_pem(text) {
                return Ok(sk);
            }
            return Err(CliError(
                "Cannot decrypt encrypted key in-process. Convert first:\n  \
                 openssl pkey -in key.pem -out key_dec.pem"
                    .into(),
            ));
        }
        // Try PKCS#8 PEM
        if let Ok(sk) = SecretKey::<NistP256>::from_pkcs8_pem(text) {
            return Ok(sk);
        }
        // Try SEC1 PEM (EC PRIVATE KEY)
        if let Ok(sk) = SecretKey::<NistP256>::from_sec1_pem(text) {
            return Ok(sk);
        }
        return Err(CliError(
            "Failed to parse EC P-256 private key from PEM.".into(),
        ));
    }

    // Try PKCS#8 DER
    if let Ok(sk) = SecretKey::<NistP256>::from_pkcs8_der(data) {
        return Ok(sk);
    }
    // Try SEC1 DER
    if let Ok(sk) = SecretKey::<NistP256>::from_sec1_der(data) {
        return Ok(sk);
    }

    Err(CliError(
        "Failed to parse EC P-256 private key. Expected PKCS#8 or SEC1 format.".into(),
    ))
}

pub fn run_credentials_export(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    label: &str,
    output: &str,
    format: CliFormat,
) -> Result<(), CliError> {
    let mut session = open_session(dev, scp_params)?;
    let public_key = session
        .get_public_key(label)
        .map_err(|e| CliError(format_credential_error(&e, "Failed to get public key.")))?;

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

    match format {
        CliFormat::Der => {
            write_file_or_stdout(output, &spki)?;
            if output != "-" {
                eprintln!("Public key exported to {output}.");
            }
        }
        CliFormat::Pem => {
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
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    management_key: Option<&str>,
    new_management_key: Option<&str>,
    generate: bool,
) -> Result<(), CliError> {
    // Resolve old key: prompt if not given
    let old_mgmt = match management_key {
        Some(k) => parse_management_password(k)?,
        None => {
            let p = crate::util::prompt_secret("Enter your current management password")?;
            parse_management_password(&p)?
        }
    };

    let new_key = if generate {
        let mut k = [0u8; 16];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        HsmAuthManagementKey::new(&k)
            .map_err(|e| CliError(format!("Failed to create management password: {e}")))?
    } else if let Some(k) = new_management_key {
        parse_management_password(k)?
    } else {
        let p1 = crate::util::prompt_secret("Enter a new management password")?;
        let p2 = crate::util::prompt_secret("Confirm new management password")?;
        if p1 != p2 {
            return Err(CliError("Passwords do not match.".into()));
        }
        parse_management_password(&p1)?
    };

    let mut session = open_session(dev, scp_params)?;
    session
        .put_management_key(&old_mgmt, &new_key)
        .map_err(|e| {
            CliError(format_credential_error(
                &e,
                "Failed to change management password.",
            ))
        })?;
    if generate {
        eprintln!(
            "Management password changed: {}",
            hex::encode(new_key.expose_secret())
        );
    } else {
        eprintln!("Management password changed.");
    }
    Ok(())
}
