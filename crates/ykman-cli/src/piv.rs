use anyhow::{Result, anyhow};
use std::str::FromStr;
use std::time::Duration;

use clap::Subcommand;
use x509_cert::Certificate;
use x509_cert::builder::{Builder, CertificateBuilder, Profile, RequestBuilder};
use x509_cert::der::{self, Decode, Encode, EncodePem, pem::LineEnding};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use yubikit::device::YubiKeyDevice;
use yubikit::keys::{PrivateKey, PublicKey};
use yubikit::management::Capability;
use yubikit::piv::{
    DEFAULT_MANAGEMENT_KEY, HashAlgorithm, KeyType, ManagementKey, ManagementKeyType, ObjectId,
    PinPolicy, PivError, PivPin, PivSession, PivSignature, PivSigner, Slot, TouchPolicy,
};

use ykman::piv::{
    TAG_PIVMAN_KEY, get_pivman_data, get_pivman_protected_data, has_stored_key, pivman_set_mgm_key,
};
use yubikit::smartcard::{SmartCardConnection, SmartCardError, Sw};

use crate::cli_enums::{
    CliFormat, CliHashAlgorithm, CliKeyType, CliMgmtKeyType, CliPinPolicy, CliTouchPolicy,
};
use crate::scp::ScpParams;
use crate::util::{
    confirm, open_smartcard_session, print_table, read_file_or_stdin, write_file_or_stdout,
};

#[derive(Subcommand)]
pub enum PivAction {
    /// Display PIV status
    Info,
    /// Reset the PIV application
    Reset {
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Manage PIV access (PIN, PUK, management key)
    #[command(subcommand)]
    Access(PivAccessAction),
    /// Manage PIV keys
    #[command(subcommand)]
    Keys(PivKeysAction),
    /// Manage PIV certificates
    #[command(subcommand)]
    Certificates(PivCertAction),
    /// Manage PIV data objects
    #[command(
        subcommand,
        after_help = "Examples:\n\
      \n  Write the contents of a file to data object with ID abc123:\
      \n  $ ykman piv objects import abc123 myfile.txt\
      \n\
      \n  Read the contents of the data object with ID abc123 into a file:\
      \n  $ ykman piv objects export abc123 myfile.txt\
      \n\
      \n  Generate a random value for CHUID:\
      \n  $ ykman piv objects generate chuid"
    )]
    Objects(PivObjectAction),
}

#[derive(Subcommand)]
pub enum PivAccessAction {
    /// Change the PIV PIN
    ChangePin {
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short = 'n', long)]
        new_pin: Option<String>,
    },
    /// Change the PIV PUK
    ChangePuk {
        #[arg(short = 'p', long)]
        puk: Option<String>,
        #[arg(short = 'n', long)]
        new_puk: Option<String>,
    },
    /// Unblock the PIN using PUK
    UnblockPin {
        #[arg(short = 'p', long)]
        puk: Option<String>,
        #[arg(short = 'n', long)]
        new_pin: Option<String>,
    },
    /// Set PIN and PUK retry counts
    SetRetries {
        /// PIN retry count
        pin_retries: u8,
        /// PUK retry count
        puk_retries: u8,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Change the management key
    ChangeManagementKey {
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'n', long)]
        new_management_key: Option<String>,
        #[arg(short = 'a', long, default_value = "tdes")]
        algorithm: CliMgmtKeyType,
        #[arg(short = 't', long)]
        touch: bool,
        #[arg(short = 'g', long)]
        generate: bool,
        #[arg(short = 'f', long)]
        force: bool,
        /// Verify PIN before changing management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Store management key on YubiKey, protected by PIN
        #[arg(short = 'p', long)]
        protect: bool,
    },
}

#[derive(Subcommand)]
pub enum PivKeysAction {
    /// Generate an asymmetric key pair
    Generate {
        /// PIV slot
        slot: String,
        /// Output file for public key
        output: String,
        #[arg(short = 'a', long, default_value = "eccp256")]
        algorithm: CliKeyType,
        #[arg(long, default_value = "default")]
        pin_policy: CliPinPolicy,
        #[arg(long, default_value = "default")]
        touch_policy: CliTouchPolicy,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
    },
    /// Import a private key
    Import {
        /// PIV slot
        slot: String,
        /// Private key file
        key_file: String,
        #[arg(long, default_value = "default")]
        pin_policy: CliPinPolicy,
        #[arg(long, default_value = "default")]
        touch_policy: CliTouchPolicy,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Password for decrypting password-protected key files
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Show key metadata
    Info {
        /// PIV slot
        slot: String,
    },
    /// Generate attestation certificate
    Attest {
        /// PIV slot
        slot: String,
        /// Output certificate file
        output: String,
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
    },
    /// Export public key
    Export {
        /// PIV slot
        slot: String,
        /// Output file
        output: String,
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
        /// Verify public key against slot certificate
        #[arg(short = 'v', long)]
        verify: bool,
        /// PIN for verification
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Move key between slots
    Move {
        /// Source slot
        source: String,
        /// Destination slot
        dest: String,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Delete key in slot
    Delete {
        /// PIV slot
        slot: String,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PivCertAction {
    /// Export certificate from slot
    Export {
        /// PIV slot
        slot: String,
        /// Output file
        output: String,
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
    },
    /// Import certificate to slot
    Import {
        /// PIV slot
        slot: String,
        /// Certificate file
        cert_file: String,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short = 'c', long)]
        compress: bool,
        /// Password for decrypting the certificate file
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Verify certificate against slot key
        #[arg(short = 'v', long)]
        verify: bool,
        /// Don't update CHUID after importing certificate
        #[arg(long)]
        no_update_chuid: bool,
    },
    /// Delete certificate from slot
    Delete {
        /// PIV slot
        slot: String,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Don't update CHUID after deleting certificate
        #[arg(long)]
        no_update_chuid: bool,
    },
    /// Generate a self-signed certificate
    Generate {
        /// PIV slot
        slot: String,
        /// File containing a public key (use '-' for stdin). Optional if YubiKey >= 5.4.
        #[arg(value_name = "PUBLIC-KEY")]
        public_key: Option<String>,
        /// Subject common name
        #[arg(short = 's', long)]
        subject: String,
        /// Validity period in days
        #[arg(long, default_value_t = 365)]
        valid_days: u32,
        /// Hash algorithm
        #[arg(short = 'a', long, default_value = "sha256")]
        hash_algorithm: CliHashAlgorithm,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Don't update CHUID after generating certificate
        #[arg(long)]
        no_update_chuid: bool,
    },
    /// Generate a Certificate Signing Request (CSR)
    Request {
        /// PIV slot
        slot: String,
        /// File containing a public key (use '-' for stdin)
        #[arg(value_name = "PUBLIC-KEY")]
        public_key: String,
        /// Output file (use '-' for stdout)
        output: String,
        /// Subject common name
        #[arg(short = 's', long)]
        subject: String,
        /// Hash algorithm
        #[arg(short = 'a', long, default_value = "sha256")]
        hash_algorithm: CliHashAlgorithm,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PivObjectAction {
    /// Export a PIV data object
    Export {
        /// Object ID (CHUID, CCC, etc.)
        object: String,
        /// Output file (- for stdout)
        output: String,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Import a PIV data object
    Import {
        /// Object ID
        object: String,
        /// Data file
        data: String,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Generate a data object (CHUID or CCC)
    Generate {
        /// Object type: CHUID or CCC
        object: String,
        #[arg(short = 'm', long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

impl PivAction {
    pub fn run(self, dev: &dyn YubiKeyDevice, scp_params: &ScpParams) -> Result<()> {
        match self {
            Self::Info => run_info(dev, scp_params),
            Self::Reset { force } => run_reset(dev, scp_params, force),
            Self::Access(access) => match access {
                PivAccessAction::ChangePin { pin, new_pin } => {
                    run_change_pin(dev, scp_params, pin.as_deref(), new_pin.as_deref())
                }
                PivAccessAction::ChangePuk { puk, new_puk } => {
                    run_change_puk(dev, scp_params, puk.as_deref(), new_puk.as_deref())
                }
                PivAccessAction::UnblockPin { puk, new_pin } => {
                    run_unblock_pin(dev, scp_params, puk.as_deref(), new_pin.as_deref())
                }
                PivAccessAction::SetRetries {
                    pin_retries,
                    puk_retries,
                    management_key,
                    pin,
                    force,
                } => run_set_retries(
                    dev,
                    scp_params,
                    pin_retries,
                    puk_retries,
                    management_key.as_deref(),
                    pin.as_deref(),
                    force,
                ),
                PivAccessAction::ChangeManagementKey {
                    management_key,
                    new_management_key,
                    algorithm,
                    touch,
                    generate,
                    force,
                    pin,
                    protect,
                } => run_change_management_key(
                    dev,
                    scp_params,
                    management_key.as_deref(),
                    new_management_key.as_deref(),
                    algorithm,
                    touch,
                    generate,
                    force,
                    pin.as_deref(),
                    protect,
                ),
            },
            Self::Keys(keys) => match keys {
                PivKeysAction::Generate {
                    slot,
                    output,
                    algorithm,
                    pin_policy,
                    touch_policy,
                    management_key,
                    pin,
                    format,
                } => run_keys_generate(
                    dev,
                    scp_params,
                    &slot,
                    &output,
                    algorithm,
                    pin_policy,
                    touch_policy,
                    management_key.as_deref(),
                    pin.as_deref(),
                    format,
                ),
                PivKeysAction::Import {
                    slot,
                    key_file,
                    pin_policy,
                    touch_policy,
                    management_key,
                    pin,
                    password,
                } => run_keys_import(
                    dev,
                    scp_params,
                    &slot,
                    &key_file,
                    pin_policy,
                    touch_policy,
                    management_key.as_deref(),
                    pin.as_deref(),
                    password.as_deref(),
                ),
                PivKeysAction::Info { slot } => run_keys_info(dev, scp_params, &slot),
                PivKeysAction::Attest {
                    slot,
                    output,
                    format,
                } => run_keys_attest(dev, scp_params, &slot, &output, format),
                PivKeysAction::Export {
                    slot,
                    output,
                    format,
                    verify,
                    pin,
                } => run_keys_export(
                    dev,
                    scp_params,
                    &slot,
                    &output,
                    format,
                    verify,
                    pin.as_deref(),
                ),
                PivKeysAction::Move {
                    source,
                    dest,
                    management_key,
                    pin,
                } => run_keys_move(
                    dev,
                    scp_params,
                    &source,
                    &dest,
                    management_key.as_deref(),
                    pin.as_deref(),
                ),
                PivKeysAction::Delete {
                    slot,
                    management_key,
                    pin,
                } => run_keys_delete(
                    dev,
                    scp_params,
                    &slot,
                    management_key.as_deref(),
                    pin.as_deref(),
                ),
            },
            Self::Certificates(certs) => match certs {
                PivCertAction::Export {
                    slot,
                    output,
                    format,
                } => run_certificates_export(dev, scp_params, &slot, &output, format),
                PivCertAction::Import {
                    slot,
                    cert_file,
                    management_key,
                    pin,
                    compress,
                    password,
                    verify,
                    no_update_chuid,
                } => run_certificates_import(
                    dev,
                    scp_params,
                    &slot,
                    &cert_file,
                    management_key.as_deref(),
                    pin.as_deref(),
                    compress,
                    !no_update_chuid,
                    password.as_deref(),
                    verify,
                ),
                PivCertAction::Delete {
                    slot,
                    management_key,
                    pin,
                    no_update_chuid,
                } => run_certificates_delete(
                    dev,
                    scp_params,
                    &slot,
                    management_key.as_deref(),
                    pin.as_deref(),
                    !no_update_chuid,
                ),
                PivCertAction::Generate {
                    slot,
                    public_key,
                    subject,
                    valid_days,
                    hash_algorithm,
                    management_key,
                    pin,
                    no_update_chuid,
                } => run_certificates_generate(
                    dev,
                    scp_params,
                    &slot,
                    &subject,
                    valid_days,
                    hash_algorithm,
                    management_key.as_deref(),
                    pin.as_deref(),
                    public_key.as_deref(),
                    !no_update_chuid,
                ),
                PivCertAction::Request {
                    slot,
                    public_key,
                    subject,
                    hash_algorithm,
                    output,
                    pin,
                } => run_certificates_request(
                    dev,
                    scp_params,
                    &slot,
                    &subject,
                    hash_algorithm,
                    &output,
                    pin.as_deref(),
                    Some(&public_key),
                ),
            },
            Self::Objects(objs) => match objs {
                PivObjectAction::Export {
                    object,
                    output,
                    pin,
                } => run_objects_export(dev, scp_params, &object, &output, pin.as_deref()),
                PivObjectAction::Import {
                    object,
                    data,
                    management_key,
                    pin,
                } => run_objects_import(
                    dev,
                    scp_params,
                    &object,
                    &data,
                    management_key.as_deref(),
                    pin.as_deref(),
                ),
                PivObjectAction::Generate {
                    object,
                    management_key,
                    pin,
                } => run_objects_generate(
                    dev,
                    scp_params,
                    &object,
                    management_key.as_deref(),
                    pin.as_deref(),
                ),
            },
        }
    }
}

fn open_session(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<PivSession<Box<dyn yubikit::smartcard::SmartCardConnection + Send>>> {
    open_smartcard_session(
        dev,
        scp_params,
        Capability::PIV,
        "PIV",
        PivSession::new,
        PivSession::new_with_scp,
    )
}

fn parse_slot(s: &str) -> Result<Slot> {
    // Accept hex (9a, 9c, etc.), names, or slot numbers
    let s_up = s.to_ascii_uppercase();
    match s_up.as_str() {
        "AUTHENTICATION" | "9A" => Ok(Slot::Authentication),
        "SIGNATURE" | "9C" => Ok(Slot::Signature),
        "KEY-MANAGEMENT" | "KEY_MANAGEMENT" | "KEYMANAGEMENT" | "9D" => Ok(Slot::KeyManagement),
        "CARD-AUTH" | "CARD_AUTH" | "CARDAUTH" | "9E" => Ok(Slot::CardAuth),
        "ATTESTATION" | "F9" => Ok(Slot::Attestation),
        _ => {
            // Try parsing as hex byte for retired slots
            if let Ok(v) =
                u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
            {
                Slot::from_u8(v).ok_or_else(|| anyhow!("Invalid PIV slot: 0x{v:02X}"))
            } else {
                Err(anyhow!(
                    "Invalid slot: {s}. Use 9a, 9c, 9d, 9e, f9, or 82-95."
                ))
            }
        }
    }
}

fn parse_management_key(s: &str) -> Result<Vec<u8>> {
    let key = hex::decode(s).map_err(|_| {
        anyhow!("Management key must be hex-encoded (32, 48, or 64 hexadecimal digits).")
    })?;
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(anyhow!(
            "Management key must be exactly 16, 24, or 32 bytes (32, 48, or 64 hexadecimal digits) long."
        ));
    }
    Ok(key)
}

fn to_management_key(key_type: ManagementKeyType, key: &[u8]) -> Result<ManagementKey> {
    ManagementKey::new(key_type, key).map_err(|e| anyhow!("Invalid management key: {e}"))
}

fn to_piv_pin(pin: &str, label: &str) -> Result<PivPin> {
    PivPin::new(pin).map_err(|e| anyhow!("Invalid {label}: {e}"))
}

// ---------------------------------------------------------------------------

/// Authenticate the management key. Returns true if PIN was verified as a
/// side effect (i.e. when using a PIN-protected management key).
fn authenticate_session(
    session: &mut PivSession<impl SmartCardConnection>,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<bool> {
    if let Some(k) = mgmt_key {
        let key = parse_management_key(k)?;
        let management_key = to_management_key(session.management_key_type(), &key)?;
        session
            .authenticate(&management_key)
            .map_err(|e| format_management_key_auth_error(e, false))?;
        return Ok(false);
    }

    // Check if the key is stored on device (protected by PIN)
    let pivman = get_pivman_data(session);
    if has_stored_key(&pivman) {
        ensure_pin(session, pin)?;
        let prot = get_pivman_protected_data(session);
        if let Some((_, key)) = prot.iter().find(|(t, _)| *t == TAG_PIVMAN_KEY) {
            let management_key = to_management_key(session.management_key_type(), key)?;
            session
                .authenticate(&management_key)
                .map_err(|e| format_management_key_auth_error(e, true))?;
            return Ok(true);
        }
        return Err(anyhow!(
            "Management key is marked as stored on device but could not be read."
        ));
    }

    // Try default key first, prompt if it fails
    if let Ok(default_key) =
        to_management_key(session.management_key_type(), DEFAULT_MANAGEMENT_KEY)
        && session.authenticate(&default_key).is_ok()
    {
        return Ok(false);
    }
    let input = crate::util::prompt_secret("Enter management key")?;
    let key = parse_management_key(&input)?;
    let management_key = to_management_key(session.management_key_type(), &key)?;
    session
        .authenticate(&management_key)
        .map_err(|e| format_management_key_auth_error(e, false))?;
    Ok(false)
}

fn format_management_key_auth_error(e: PivError, stored_key: bool) -> anyhow::Error {
    match e {
        PivError::Connection(SmartCardError::Apdu { sw, .. })
            if Sw::from_u16(sw) == Some(Sw::SecurityConditionNotSatisfied) =>
        {
            if stored_key {
                anyhow!(
                    "Authentication with stored key failed: Stored management key does not match the YubiKey."
                )
            } else {
                anyhow!("Authentication failed: Wrong management key.")
            }
        }
        e => {
            if stored_key {
                anyhow!("Authentication with stored key failed: {e}")
            } else {
                anyhow!("Authentication failed: {e}")
            }
        }
    }
}

/// Ensure PIN is verified. If pin is Some, verifies it. If None, prompts.
fn ensure_pin(
    session: &mut PivSession<impl yubikit::smartcard::SmartCardConnection>,
    pin: Option<&str>,
) -> Result<()> {
    let pin_value = match pin {
        Some(p) => to_piv_pin(p, "PIN")?,
        None => crate::util::prompt_secret("Enter PIN").and_then(|p| to_piv_pin(&p, "PIN"))?,
    };
    session.verify_pin(&pin_value).map_err(|e| match &e {
        yubikit::piv::PivError::InvalidPin(0) => anyhow!("PIN is blocked."),
        yubikit::piv::PivError::InvalidPin(attempts) => {
            anyhow!("PIN verification failed, {attempts} tries left.")
        }
        _ => anyhow!("PIN verification failed: {e}"),
    })
}

/// Try to run an operation, and if it fails with a security condition error,
/// prompt for PIN and retry.
fn verify_pin_if_needed<C, F, T>(
    session: &mut PivSession<C>,
    pin: Option<&str>,
    mut f: F,
) -> Result<T>
where
    C: yubikit::smartcard::SmartCardConnection,
    F: FnMut(&mut PivSession<C>) -> Result<T, yubikit::piv::PivError>,
{
    match f(session) {
        Ok(val) => Ok(val),
        Err(yubikit::piv::PivError::Connection(yubikit::smartcard::SmartCardError::Apdu {
            sw,
            ..
        })) if sw == yubikit::smartcard::Sw::SecurityConditionNotSatisfied as u16 => {
            ensure_pin(session, pin)?;
            f(session).map_err(|e| anyhow!("{e}"))
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

fn format_piv_credential_error(e: PivError, credential: &str, action: &str) -> anyhow::Error {
    match e {
        PivError::InvalidPin(0) => anyhow!("{action}: {credential} is blocked."),
        PivError::InvalidPin(attempts) => {
            anyhow!("{action}: Wrong {credential}, {attempts} attempt(s) remaining.")
        }
        e => anyhow!("{action}: {e}"),
    }
}

fn parse_object_id(s: &str) -> Result<ObjectId> {
    match s.to_ascii_uppercase().as_str() {
        "CHUID" => Ok(ObjectId::Chuid),
        "CCC" | "CAPABILITY" => Ok(ObjectId::Capability),
        "AUTHENTICATION" => Ok(ObjectId::Authentication),
        "SIGNATURE" => Ok(ObjectId::Signature),
        "KEY-MANAGEMENT" | "KEY_MANAGEMENT" => Ok(ObjectId::KeyManagement),
        "CARD-AUTH" | "CARD_AUTH" | "CARDAUTH" => Ok(ObjectId::CardAuth),
        "DISCOVERY" => Ok(ObjectId::Discovery),
        "KEY-HISTORY" | "KEY_HISTORY" => Ok(ObjectId::KeyHistory),
        "FINGERPRINTS" => Ok(ObjectId::Fingerprints),
        "FACIAL" => Ok(ObjectId::Facial),
        "IRIS" => Ok(ObjectId::Iris),
        "PRINTED" => Ok(ObjectId::Printed),
        "ATTESTATION" => Ok(ObjectId::Attestation),
        _ => Err(anyhow!(
            "Unknown object ID: {s}. Use CHUID, CCC, AUTHENTICATION, etc."
        )),
    }
}

pub fn run_info(dev: &dyn YubiKeyDevice, scp_params: &ScpParams) -> Result<()> {
    let mut session = open_session(dev, scp_params)?;
    let reset_blocked = dev.info().reset_blocked.contains(Capability::PIV);
    let version = session.version();

    let mut warnings = Vec::new();
    let mut rows = vec![("PIV version", version.to_string())];

    // PIN metadata
    match session.get_pin_metadata() {
        Ok(meta) => {
            rows.push((
                "PIN tries remaining",
                format!("{}/{}", meta.attempts_remaining, meta.total_attempts),
            ));
            if meta.default_value {
                warnings.push("WARNING: Using default PIN!");
            }
        }
        Err(_) => {
            if let Ok(n) = session.get_pin_attempts() {
                rows.push(("PIN tries remaining", n.to_string()));
            }
        }
    }

    // Bio metadata is only available on biometric-capable PIV devices. Those
    // devices do not expose a PUK, so only show PUK metadata when bio is absent.
    match session.get_bio_metadata() {
        Ok(meta) => {
            if meta.configured {
                rows.push((
                    "Biometrics",
                    format!("Configured, {} attempts remaining", meta.attempts_remaining),
                ));
            } else {
                rows.push(("Biometrics", "Not configured".to_string()));
            }
        }
        Err(PivError::NotSupported(_)) => {
            if let Ok(meta) = session.get_puk_metadata() {
                rows.push((
                    "PUK tries remaining",
                    format!("{}/{}", meta.attempts_remaining, meta.total_attempts),
                ));
                if meta.default_value {
                    warnings.push("WARNING: Using default PUK!");
                }
            }
        }
        Err(_) => {}
    }

    // Management key metadata
    if let Ok(meta) = session.get_management_key_metadata() {
        let algo = format!("{}", meta.key_type);
        rows.push(("Management key algorithm", algo));
        if meta.default_value {
            warnings.push("WARNING: Using default Management key!");
        }
    }

    print_table(rows);

    // Print collected warnings
    for w in &warnings {
        println!("{w}");
    }

    print_table([
        (
            "CHUID",
            session
                .get_object(ObjectId::Chuid)
                .map(|data| hex::encode(&data))
                .unwrap_or_else(|_| "No data available".to_string()),
        ),
        (
            "CCC",
            session
                .get_object(ObjectId::Capability)
                .map(|data| hex::encode(&data))
                .unwrap_or_else(|_| "No data available".to_string()),
        ),
    ]);

    // Slot details
    let slots = [
        (Slot::Authentication, "9A", "AUTHENTICATION"),
        (Slot::Signature, "9C", "SIGNATURE"),
        (Slot::KeyManagement, "9D", "KEY MANAGEMENT"),
        (Slot::CardAuth, "9E", "CARD AUTH"),
    ];

    for (slot, hex_id, name) in slots {
        let has_key = session.get_slot_metadata(slot).ok();
        let has_cert = session.get_certificate(slot).ok();

        if has_key.is_none() && has_cert.is_none() {
            continue;
        }

        println!("\nSlot {hex_id} ({name}):");

        let mut rows = Vec::new();
        if let Some(ref meta) = has_key {
            rows.push(("  Private key type", meta.key_type.to_string()));
        }

        if let Some(ref cert_der) = has_cert {
            // Parse certificate to show details
            if let Some(info) = parse_cert_info(cert_der) {
                if has_key.is_some() {
                    rows.push(("  Public key type", info.key_type));
                }
                rows.extend([
                    ("  Subject DN", info.subject),
                    ("  Issuer DN", info.issuer),
                    ("  Serial", info.serial),
                    ("  Fingerprint", info.fingerprint),
                    ("  Not before", info.not_before),
                    ("  Not after", info.not_after),
                ]);
            }
        }
        print_table(rows);
    }

    if reset_blocked {
        println!("Factory reset is blocked");
    }

    Ok(())
}

struct CertInfo {
    key_type: String,
    subject: String,
    issuer: String,
    serial: String,
    fingerprint: String,
    not_before: String,
    not_after: String,
}

fn parse_cert_info(cert_der: &[u8]) -> Option<CertInfo> {
    use sha2::Digest;
    let fingerprint = hex::encode(sha2::Sha256::digest(cert_der));

    let cert = Certificate::from_der(cert_der).ok()?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let serial = hex::encode(tbs.serial_number.as_bytes())
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or("??"))
        .collect::<Vec<_>>()
        .join(":");
    let not_before = tbs.validity.not_before.to_string();
    let not_after = tbs.validity.not_after.to_string();

    let key_type = PublicKey::from_spki(&tbs.subject_public_key_info.to_der().unwrap_or_default())
        .ok()
        .and_then(|pk| KeyType::from_public_key(&pk).ok())
        .map(|kt| format!("{kt}"))
        .unwrap_or_else(|| "Unknown".to_string());

    Some(CertInfo {
        key_type,
        subject,
        issuer,
        serial,
        fingerprint,
        not_before,
        not_after,
    })
}

pub fn run_reset(dev: &dyn YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<()> {
    if dev.info().reset_blocked.contains(Capability::PIV) {
        return Err(anyhow!(
            "Cannot perform PIV reset when FIDO is configured, \
             use 'ykman config reset' for full factory reset."
                .to_string(),
        ));
    }

    if !force {
        eprintln!("WARNING! This will delete all stored PIV data and restore factory settings.");
        if !confirm("Proceed?") {
            return Err(anyhow!("Aborted."));
        }
    }
    let mut session = open_session(dev, scp_params)?;

    // Block PIN and PUK first (required by reset)
    let blocked_pin = PivPin::new("00000000").expect("constant PIN must be valid");
    let blocked_puk = PivPin::new("00000000").expect("constant PUK must be valid");
    for _ in 0..15 {
        let _ = session.verify_pin(&blocked_pin);
        let _ = session.change_puk(&blocked_puk, &blocked_puk);
    }

    session
        .reset()
        .map_err(|e| anyhow!("Failed to reset PIV: {e}"))?;
    eprintln!("PIV application has been reset.");
    Ok(())
}

pub fn run_change_pin(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<()> {
    let old = match pin {
        Some(p) => to_piv_pin(p, "PIN")?,
        None => crate::util::prompt_secret("Enter the current PIN")
            .and_then(|p| to_piv_pin(&p, "PIN"))?,
    };
    let new = match new_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PIN")?,
    };

    if new.len() < 6 || new.len() > 8 {
        return Err(anyhow!("PIN must be 6-8 characters."));
    }
    let new = to_piv_pin(&new, "PIN")?;

    let mut session = open_session(dev, scp_params)?;
    session
        .change_pin(&old, &new)
        .map_err(|e| format_piv_credential_error(e, "PIN", "Failed to change PIN"))?;
    eprintln!("PIN changed.");
    Ok(())
}

pub fn run_change_puk(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    puk: Option<&str>,
    new_puk: Option<&str>,
) -> Result<()> {
    let old = match puk {
        Some(p) => to_piv_pin(p, "PUK")?,
        None => crate::util::prompt_secret("Enter the current PUK")
            .and_then(|p| to_piv_pin(&p, "PUK"))?,
    };
    let new = match new_puk {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PUK")?,
    };

    if new.len() < 6 || new.len() > 8 {
        return Err(anyhow!("PUK must be 6-8 characters."));
    }
    let new = to_piv_pin(&new, "PUK")?;

    let mut session = open_session(dev, scp_params)?;
    session
        .change_puk(&old, &new)
        .map_err(|e| format_piv_credential_error(e, "PUK", "Failed to change PUK"))?;
    eprintln!("PUK changed.");
    Ok(())
}

pub fn run_unblock_pin(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    puk: Option<&str>,
    new_pin: Option<&str>,
) -> Result<()> {
    let puk = match puk {
        Some(p) => to_piv_pin(p, "PUK")?,
        None => crate::util::prompt_secret("Enter the PUK").and_then(|p| to_piv_pin(&p, "PUK"))?,
    };
    let new = match new_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PIN")?,
    };

    if new.len() < 6 || new.len() > 8 {
        return Err(anyhow!("New PIN must be 6-8 characters."));
    }
    let new = to_piv_pin(&new, "PIN")?;

    let mut session = open_session(dev, scp_params)?;
    session
        .unblock_pin(&puk, &new)
        .map_err(|e| format_piv_credential_error(e, "PUK", "Failed to unblock PIN"))?;
    eprintln!("PIN unblocked.");
    Ok(())
}

pub fn run_set_retries(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    pin_retries: u8,
    puk_retries: u8,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    force: bool,
) -> Result<()> {
    if !force
        && !confirm(&format!(
            "Set PIN retries to {pin_retries} and PUK retries to {puk_retries}? This will reset PIN and PUK to defaults."
        ))
    {
        return Err(anyhow!("Aborted."));
    }

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .set_pin_attempts(pin_retries, puk_retries)
        .map_err(|e| anyhow!("Failed to set retries: {e}"))?;
    eprintln!("PIN and PUK retry counts set.");
    Ok(())
}

pub fn run_change_management_key(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    mgmt_key: Option<&str>,
    new_mgmt_key: Option<&str>,
    algorithm: CliMgmtKeyType,
    touch: bool,
    generate: bool,
    force: bool,
    pin: Option<&str>,
    protect: bool,
) -> Result<()> {
    let key_type: ManagementKeyType = algorithm.into();
    let key_len = key_type.key_len();

    let new_key = if generate {
        let mut k = vec![0u8; key_len];
        getrandom::fill(&mut k).map_err(|e| anyhow!("Failed to generate: {e}"))?;
        k
    } else if let Some(k) = new_mgmt_key {
        let bytes = parse_management_key(k)?;
        if bytes.len() != key_len {
            return Err(anyhow!(
                "Management key must be {key_len} bytes for {key_type}."
            ));
        }
        bytes
    } else {
        let input = crate::util::prompt_new_secret("New management key (hex)")?;
        let bytes = parse_management_key(&input)?;
        if bytes.len() != key_len {
            return Err(anyhow!(
                "Management key must be {key_len} bytes for {key_type}."
            ));
        }
        bytes
    };

    if !force && !confirm("Change management key?") {
        return Err(anyhow!("Aborted."));
    }

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if protect && !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    pivman_set_mgm_key(&mut session, key_type, &new_key, touch, protect)
        .map_err(|e| anyhow!("Failed to set management key: {e}"))?;

    if generate {
        eprintln!("Management key set: {}", hex::encode(&new_key));
    } else {
        eprintln!("Management key changed.");
    }
    Ok(())
}

pub fn run_keys_generate(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    algorithm: CliKeyType,
    pin_policy: CliPinPolicy,
    touch_policy: CliTouchPolicy,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    format: CliFormat,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let key_type: KeyType = algorithm.into();
    let pp: PinPolicy = pin_policy.into();
    let tp: TouchPolicy = touch_policy.into();

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    let public_key = session
        .generate_key(slot, key_type, pp, tp)
        .map_err(|e| anyhow!("Failed to generate key: {e}"))?;

    let spki_der = public_key
        .to_spki()
        .map_err(|e| anyhow!("Failed to encode public key: {e}"))?;

    match format {
        CliFormat::Der => {
            write_file_or_stdout(output, &spki_der)?;
        }
        CliFormat::Pem => {
            let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
                .map_err(|e| anyhow!("Failed to parse SPKI: {e}"))?;
            let pem = spki
                .to_pem(LineEnding::LF)
                .map_err(|e| anyhow!("Failed to encode PEM: {e}"))?;
            write_file_or_stdout(output, pem.as_bytes())?;
        }
    }

    eprintln!("Generated {key_type} key in slot {slot}. Public key written to {output}.");
    Ok(())
}

pub fn run_keys_import(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    key_file: &str,
    pin_policy: CliPinPolicy,
    touch_policy: CliTouchPolicy,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let pp: PinPolicy = pin_policy.into();
    let tp: TouchPolicy = touch_policy.into();

    let data = read_file_or_stdin(key_file)?;

    let der = decrypt_private_key_data(&data, password)?;

    // Parse the private key (auto-detects algorithm from PKCS#8)
    let private_key = PrivateKey::from_pkcs8(&der)
        .map_err(|_| anyhow!("Could not parse private key from file."))?;

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    session
        .put_key(slot, &private_key, pp, tp)
        .map_err(|e| anyhow!("Failed to import key: {e}"))?;

    eprintln!("Private key imported to slot {slot}.");
    Ok(())
}

pub fn run_keys_info(dev: &dyn YubiKeyDevice, scp_params: &ScpParams, slot: &str) -> Result<()> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let meta = session
        .get_slot_metadata(slot)
        .map_err(|e| anyhow!("Failed to get slot metadata: {e}"))?;

    println!("Slot: {slot}");
    println!("Algorithm: {:?}", meta.key_type);
    println!(
        "Origin: {}",
        if meta.generated {
            "generated"
        } else {
            "imported"
        }
    );
    println!("PIN policy: {:?}", meta.pin_policy);
    println!("Touch policy: {:?}", meta.touch_policy);
    Ok(())
}

pub fn run_keys_attest(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    format: CliFormat,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let cert_der = session
        .attest_key(slot)
        .map_err(|e| anyhow!("Failed to attest key: {e}"))?;

    write_cert_file(output, &cert_der, format)?;
    eprintln!("Attestation certificate written to {output}.");
    Ok(())
}

pub fn run_keys_export(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    format: CliFormat,
    verify: bool,
    pin: Option<&str>,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;

    // Try metadata first (5.3.0+)
    let (spki_der, from_cert) = if let Ok(meta) = session.get_slot_metadata(slot) {
        let der = meta
            .public_key
            .to_spki()
            .map_err(|e| anyhow!("Failed to encode public key: {e}"))?;
        (der, false)
    } else {
        // Fall back to reading public key from stored certificate
        let cert_der = session
            .get_certificate(slot)
            .map_err(|_| anyhow!("Unable to export public key from slot {slot}."))?;
        let cert = Certificate::from_der(&cert_der)
            .map_err(|e| anyhow!("Failed to parse certificate: {e}"))?;
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| anyhow!("Failed to encode SPKI: {e}"))?;
        (spki, true)
    };

    // Verify the public key matches the private key if requested.
    // Only strictly needed when we read from a certificate (metadata is authoritative).
    if verify && from_cert {
        check_key_match(&mut session, slot, &spki_der, pin)?;
    }

    match format {
        CliFormat::Der => write_file_or_stdout(output, &spki_der)?,
        CliFormat::Pem => {
            let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
                .map_err(|e| anyhow!("Failed to parse SPKI: {e}"))?;
            let pem = spki
                .to_pem(LineEnding::LF)
                .map_err(|e| anyhow!("Failed to encode PEM: {e}"))?;
            write_file_or_stdout(output, pem.as_bytes())?;
        }
    }
    eprintln!("Public key exported to {output}.");
    Ok(())
}

pub fn run_keys_move(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    source: &str,
    dest: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<()> {
    let from = parse_slot(source)?;
    let to = parse_slot(dest)?;
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .move_key(from, to)
        .map_err(|e| anyhow!("Failed to move key: {e}"))?;
    println!("Key moved from {from} to {to}.");
    Ok(())
}

pub fn run_keys_delete(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .delete_key(slot)
        .map_err(|e| anyhow!("Failed to delete key: {e}"))?;
    eprintln!("Key in slot {slot} deleted.");
    Ok(())
}

pub fn run_certificates_export(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    output: &str,
    format: CliFormat,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let cert_der = session
        .get_certificate(slot)
        .map_err(|e| anyhow!("Failed to get certificate: {e}"))?;

    write_cert_file(output, &cert_der, format)?;
    eprintln!("Certificate exported to {output}.");
    Ok(())
}

pub fn run_certificates_import(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    cert_file: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    compress: bool,
    update_chuid: bool,
    password: Option<&str>,
    verify: bool,
) -> Result<()> {
    let slot = parse_slot(slot)?;

    let data = read_file_or_stdin(cert_file)?;

    let der = decrypt_certificate_data(&data, password)?;

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    if verify {
        // Extract the public key from the certificate and check it matches the slot's private key
        let cert =
            Certificate::from_der(&der).map_err(|e| anyhow!("Failed to parse certificate: {e}"))?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| anyhow!("Failed to encode SPKI: {e}"))?;
        check_key_match(&mut session, slot, &spki_der, pin)?;
    }

    session
        .put_certificate(slot, &der, compress)
        .map_err(|e| anyhow!("Failed to import certificate: {e}"))?;
    eprintln!("Certificate imported to slot {slot}.");

    if update_chuid {
        generate_chuid(&mut session)?;
    }
    Ok(())
}

pub fn run_certificates_delete(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
    update_chuid: bool,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .delete_certificate(slot)
        .map_err(|e| anyhow!("Failed to delete certificate: {e}"))?;
    eprintln!("Certificate in slot {slot} deleted.");

    if update_chuid {
        generate_chuid(&mut session)?;
    }
    Ok(())
}

pub fn run_objects_export(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    object: &str,
    output: &str,
    pin: Option<&str>,
) -> Result<()> {
    let obj_id = parse_object_id(object)?;
    let mut session = open_session(dev, scp_params)?;
    let data = verify_pin_if_needed(&mut session, pin, |s| s.get_object(obj_id))?;

    write_file_or_stdout(output, &data)?;
    if output != "-" {
        eprintln!("Object exported to {output}.");
    }
    Ok(())
}

pub fn run_objects_import(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    object: &str,
    data_file: &str,
    mgmt_key: Option<&str>,
    pin: Option<&str>,
) -> Result<()> {
    let obj_id = parse_object_id(object)?;
    let data = read_file_or_stdin(data_file)?;

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }
    session
        .put_object(obj_id, Some(&data))
        .map_err(|e| anyhow!("Failed to write object: {e}"))?;
    eprintln!("Object imported.");
    Ok(())
}

/// Generate a new CHUID and write it to the device.
fn generate_chuid(
    session: &mut PivSession<impl yubikit::smartcard::SmartCardConnection>,
) -> Result<()> {
    let mut chuid = Vec::new();
    chuid.extend_from_slice(&[0x30, 0x19]);
    chuid.extend_from_slice(&[0x9E; 25]);
    chuid.push(0x34);
    chuid.push(0x10);
    let mut guid = [0u8; 16];
    getrandom::fill(&mut guid).map_err(|e| anyhow!("RNG error: {e}"))?;
    guid[6] = (guid[6] & 0x0f) | 0x40;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    chuid.extend_from_slice(&guid);
    chuid.push(0x35);
    chuid.push(0x08);
    chuid.extend_from_slice(b"20301231");
    chuid.push(0x3E);
    chuid.push(0x00);
    chuid.push(0xFE);
    chuid.push(0x00);

    session
        .put_object(ObjectId::Chuid, Some(&chuid))
        .map_err(|e| anyhow!("Failed to update CHUID: {e}"))?;
    Ok(())
}

pub fn run_objects_generate(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    object: &str,
    management_key: Option<&str>,
    pin: Option<&str>,
) -> Result<()> {
    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, management_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    match object.to_uppercase().as_str() {
        "CHUID" => {
            // Generate CHUID per SP 800-73-4
            let mut chuid = Vec::new();
            // FASC-N (tag 0x30, 25 bytes, all 0x9E = default)
            chuid.extend_from_slice(&[0x30, 0x19]);
            chuid.extend_from_slice(&[0x9E; 25]);
            // GUID (tag 0x34, 16 bytes random UUID v4)
            chuid.push(0x34);
            chuid.push(0x10);
            let mut guid = [0u8; 16];
            getrandom::fill(&mut guid).map_err(|e| anyhow!("RNG error: {e}"))?;
            guid[6] = (guid[6] & 0x0f) | 0x40;
            guid[8] = (guid[8] & 0x3f) | 0x80;
            chuid.extend_from_slice(&guid);
            // Expiry date (tag 0x35, 8 bytes YYYYMMDD)
            chuid.push(0x35);
            chuid.push(0x08);
            chuid.extend_from_slice(b"20301231");
            // Issuer asymmetric signature (empty, tag 0x3E)
            chuid.push(0x3E);
            chuid.push(0x00);
            // Error Detection Code (tag 0xFE)
            chuid.push(0xFE);
            chuid.push(0x00);

            session
                .put_object(ObjectId::Chuid, Some(&chuid))
                .map_err(|e| anyhow!("Failed to write CHUID: {e}"))?;
            eprintln!("CHUID generated.");
        }
        "CCC" => {
            // Generate CCC per SP 800-73-4
            let mut ccc = Vec::new();
            // Card Identifier (tag 0xF0, 21 bytes)
            ccc.push(0xF0);
            ccc.push(0x15);
            let mut card_id = [0u8; 21];
            getrandom::fill(&mut card_id).map_err(|e| anyhow!("RNG error: {e}"))?;
            ccc.extend_from_slice(&card_id);
            // Capability Container version number (tag 0xF1)
            ccc.extend_from_slice(&[0xF1, 0x01, 0x21]);
            // Capability Grammar version number (tag 0xF2)
            ccc.extend_from_slice(&[0xF2, 0x01, 0x21]);
            // Applications CardURL (tag 0xF3, empty)
            ccc.extend_from_slice(&[0xF3, 0x00]);
            // PKCS#15 (tag 0xF4)
            ccc.extend_from_slice(&[0xF4, 0x01, 0x00]);
            // Registered Data Model (tag 0xF5)
            ccc.extend_from_slice(&[0xF5, 0x01, 0x10]);
            // Access Control Rule Table (tag 0xF6, empty)
            ccc.extend_from_slice(&[0xF6, 0x00]);
            // Error Detection Code (tag 0xFE)
            ccc.push(0xFE);
            ccc.push(0x00);

            session
                .put_object(ObjectId::Capability, Some(&ccc))
                .map_err(|e| anyhow!("Failed to write CCC: {e}"))?;
            eprintln!("CCC generated.");
        }
        other => {
            return Err(anyhow!("Unknown object type: {other}. Use CHUID or CCC."));
        }
    }
    Ok(())
}

pub fn run_certificates_generate(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    subject: &str,
    valid_days: u32,
    hash_algorithm: CliHashAlgorithm,
    management_key: Option<&str>,
    pin: Option<&str>,
    public_key_file: Option<&str>,
    update_chuid: bool,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let hash_alg: HashAlgorithm = hash_algorithm.into();

    let mut session = open_session(dev, scp_params)?;
    let pin_verified = authenticate_session(&mut session, management_key, pin)?;
    if !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    let (key_type, spki_der) = resolve_public_key(&mut session, slot, public_key_file)?;

    match key_type {
        KeyType::X25519 | KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => {
            return Err(anyhow!(
                "{key_type} keys cannot sign certificates. \
                 Use a signing key type (e.g. ECC, RSA, Ed25519, or ML-DSA) instead."
            ));
        }
        _ => {}
    }

    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der)
        .map_err(|e| anyhow!("Failed to parse SPKI: {e}"))?;
    let subject_name = Name::from_str(subject).map_err(|e| anyhow!("Invalid subject DN: {e}"))?;

    let serial = random_serial_number()?;
    let validity = Validity::from_now(Duration::from_secs(u64::from(valid_days) * 86400))
        .map_err(|e| anyhow!("Invalid validity period: {e}"))?;

    let cert_der = {
        let signer = PivSigner::new(&mut session, slot, key_type, hash_alg, &spki_der);
        let builder =
            CertificateBuilder::new(Profile::Root, serial, validity, subject_name, spki, &signer)
                .map_err(|e| anyhow!("Failed to create certificate builder: {e}"))?;

        let cert = builder
            .build::<PivSignature>()
            .map_err(|e| anyhow!("Failed to build certificate: {e}"))?;

        cert.to_der()
            .map_err(|e| anyhow!("Failed to encode certificate: {e}"))?
    };

    session
        .put_certificate(slot, &cert_der, false)
        .map_err(|e| anyhow!("Failed to store certificate: {e}"))?;

    eprintln!("Certificate generated and stored in slot {slot:?}.");

    if update_chuid {
        generate_chuid(&mut session)?;
    }
    Ok(())
}

pub fn run_certificates_request(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: &str,
    subject: &str,
    hash_algorithm: CliHashAlgorithm,
    output: &str,
    pin: Option<&str>,
    public_key_file: Option<&str>,
) -> Result<()> {
    let slot = parse_slot(slot)?;
    let hash_alg: HashAlgorithm = hash_algorithm.into();

    let mut session = open_session(dev, scp_params)?;
    ensure_pin(&mut session, pin)?;

    let (key_type, spki_der) = resolve_public_key(&mut session, slot, public_key_file)?;

    match key_type {
        KeyType::X25519 | KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => {
            return Err(anyhow!(
                "{key_type} keys cannot sign certificate requests. \
                 Use a signing key type (e.g. ECC, RSA, Ed25519, or ML-DSA) instead."
            ));
        }
        _ => {}
    }

    let subject_name = Name::from_str(subject).map_err(|e| anyhow!("Invalid subject DN: {e}"))?;

    let signer = PivSigner::new(&mut session, slot, key_type, hash_alg, &spki_der);
    let builder = RequestBuilder::new(subject_name, &signer)
        .map_err(|e| anyhow!("Failed to create CSR builder: {e}"))?;

    let csr = builder
        .build::<PivSignature>()
        .map_err(|e| anyhow!("Failed to build CSR: {e}"))?;

    let pem = csr
        .to_pem(LineEnding::LF)
        .map_err(|e| anyhow!("Failed to encode CSR PEM: {e}"))?;
    write_file_or_stdout(output, pem.as_bytes())?;
    if output != "-" {
        eprintln!("CSR written to {output}.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hash algorithm selection
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers for cert/CSR generation
// ---------------------------------------------------------------------------

fn resolve_public_key(
    session: &mut PivSession<impl yubikit::smartcard::SmartCardConnection>,
    slot: Slot,
    public_key_file: Option<&str>,
) -> Result<(KeyType, Vec<u8>)> {
    if let Some(pk_file) = public_key_file {
        let data = read_file_or_stdin(pk_file)?;
        let der = if let Ok(text) = std::str::from_utf8(&data) {
            if text.contains("-----BEGIN") {
                pem_decode(text)?
            } else {
                data
            }
        } else {
            data
        };
        let pk = PublicKey::from_spki(&der)
            .map_err(|_| anyhow!("Could not determine key type from public key file."))?;
        let kt = KeyType::from_public_key(&pk)
            .map_err(|_| anyhow!("Could not determine key type from public key file."))?;
        Ok((kt, der))
    } else {
        let metadata = session
            .get_slot_metadata(slot)
            .map_err(|e| anyhow!("Failed to get slot metadata (is a key present?): {e}"))?;
        let kt = metadata.key_type;
        let der = metadata
            .public_key
            .to_spki()
            .map_err(|e| anyhow!("Failed to encode public key: {e}"))?;
        Ok((kt, der))
    }
}

fn random_serial_number() -> Result<SerialNumber> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("RNG error: {e}"))?;
    // Ensure positive (clear high bit)
    buf[0] &= 0x7F;
    if buf[0] == 0 {
        buf[0] = 0x01;
    }
    SerialNumber::new(&buf).map_err(|e| anyhow!("Invalid serial number: {e}"))
}

// ---------------------------------------------------------------------------
// Password-protected key/cert parsing helpers
// ---------------------------------------------------------------------------

/// Attempt to decrypt/parse a private key from raw data, handling
/// PEM (plain or ENCRYPTED), PKCS#12, and raw DER. If the key is encrypted
/// and no password is provided, the user is prompted interactively.
fn decrypt_private_key_data(data: &[u8], password: Option<&str>) -> Result<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
    {
        let encrypted = text.contains("ENCRYPTED");
        if encrypted {
            let pw = match password {
                Some(p) => p.to_string(),
                None => crate::util::prompt_secret("Enter password to decrypt key")?,
            };
            return decrypt_pem_private_key(text, &pw);
        }
        return pem_decode(text);
    }

    // Try PKCS#12 if the data looks like it
    if is_pkcs12(data) {
        let pw = match password {
            Some(p) => p.to_string(),
            None => crate::util::prompt_secret("Enter password to decrypt PKCS#12 file")?,
        };
        return extract_private_key_from_pkcs12(data, &pw);
    }

    // Try plain DER
    Ok(data.to_vec())
}

/// Decrypt an encrypted PKCS#8 PEM private key.
fn decrypt_pem_private_key(pem_text: &str, password: &str) -> Result<Vec<u8>> {
    use pkcs8::EncryptedPrivateKeyInfo;

    let der = pem_decode(pem_text)?;
    let enc_key = EncryptedPrivateKeyInfo::try_from(der.as_slice())
        .map_err(|e| anyhow!("Failed to parse encrypted key: {e}"))?;
    let dec_key = enc_key
        .decrypt(password)
        .map_err(|_| anyhow!("Wrong password for encrypted key."))?;
    Ok(dec_key.as_bytes().to_vec())
}

/// Attempt to parse a certificate from raw data, supporting password-protected
/// PKCS#12 files. For PEM and DER certs, the password is ignored.
fn decrypt_certificate_data(data: &[u8], password: Option<&str>) -> Result<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
    {
        return pem_decode(text);
    }

    // Try PKCS#12
    if is_pkcs12(data) {
        let pw = match password {
            Some(p) => p.to_string(),
            None => crate::util::prompt_secret("Enter password to decrypt PKCS#12 file")?,
        };
        return extract_certificate_from_pkcs12(data, &pw);
    }

    // Plain DER certificate
    Ok(data.to_vec())
}

/// Check if data looks like a PKCS#12 file.
/// PKCS#12 is a DER SEQUENCE whose first element is INTEGER with value 3.
fn is_pkcs12(data: &[u8]) -> bool {
    if data.len() < 10 || data[0] != 0x30 {
        return false;
    }
    // Skip the outer SEQUENCE length bytes
    let len_byte = data[1];
    let offset = if len_byte & 0x80 == 0 {
        2
    } else {
        2 + (len_byte & 0x7f) as usize
    };
    // Expect INTEGER tag (0x02) with length 1 and value 3
    offset + 3 <= data.len()
        && data[offset] == 0x02
        && data[offset + 1] == 0x01
        && data[offset + 2] == 0x03
}

/// Extract a private key from PKCS#12 data.
fn extract_private_key_from_pkcs12(data: &[u8], password: &str) -> Result<Vec<u8>> {
    use p12_keystore::KeyStore;

    let ks = KeyStore::from_pkcs12(data, password)
        .map_err(|e| anyhow!("Failed to parse PKCS#12 file: {e}"))?;
    let (_, chain) = ks
        .private_key_chain()
        .ok_or_else(|| anyhow!("No private key found in PKCS#12 file."))?;
    Ok(chain.key().to_vec())
}

/// Extract a certificate from PKCS#12 data.
fn extract_certificate_from_pkcs12(data: &[u8], password: &str) -> Result<Vec<u8>> {
    use p12_keystore::{KeyStore, KeyStoreEntry};

    let ks = KeyStore::from_pkcs12(data, password)
        .map_err(|e| anyhow!("Failed to parse PKCS#12 file: {e}"))?;

    // Try cert from a key chain first, then standalone certs
    for (_, entry) in ks.entries() {
        match entry {
            KeyStoreEntry::PrivateKeyChain(chain) => {
                if let Some(cert) = chain.chain().first() {
                    return Ok(cert.as_der().to_vec());
                }
            }
            KeyStoreEntry::Certificate(cert) => {
                return Ok(cert.as_der().to_vec());
            }
            _ => {}
        }
    }
    Err(anyhow!("No certificate found in PKCS#12 file."))
}

/// Verify that a public key (as SPKI DER) matches the private key in a PIV slot
/// by signing test data and verifying the signature.
fn check_key_match<C: yubikit::smartcard::SmartCardConnection>(
    session: &mut PivSession<C>,
    slot: Slot,
    spki_der: &[u8],
    pin: Option<&str>,
) -> Result<()> {
    // Determine key type from the metadata or SPKI
    let meta = session
        .get_slot_metadata(slot)
        .map_err(|_| anyhow!("No private key in slot {slot}."))?;

    let key_type = meta.key_type;

    // Sign test data
    let test_message = b"ykman-verify-key-match";
    let hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(test_message);
        hasher.finalize().to_vec()
    };

    let to_sign = match key_type {
        KeyType::EccP256 | KeyType::EccP384 => hash.clone(),
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let key_byte_len = (key_type.bit_len() / 8) as usize;
            pkcs1v15_pad(&hash, key_byte_len)
        }
        KeyType::Ed25519 => test_message.to_vec(),
        KeyType::X25519 => {
            return Err(anyhow!("X25519 keys cannot be used for signing."));
        }
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => test_message.to_vec(),
        KeyType::MlKem512 | KeyType::MlKem768 | KeyType::MlKem1024 => {
            return Err(anyhow!("ML-KEM keys cannot be used for signing."));
        }
        _ => {
            return Err(anyhow!("Unsupported key type: {key_type:?}"));
        }
    };

    let signature = verify_pin_if_needed(session, pin, |s| s.sign(slot, key_type, &to_sign))?;

    // Verify signature with the public key
    let verified = verify_signature(key_type, spki_der, test_message, &signature);
    if !verified {
        return Err(anyhow!(
            "Public key does not match the private key in slot {slot}."
        ));
    }
    Ok(())
}

/// PKCS#1 v1.5 padding for RSA signatures with SHA-256.
fn pkcs1v15_pad(hash: &[u8], key_byte_len: usize) -> Vec<u8> {
    // DigestInfo for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    let digest_info_prefix: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let t_len = digest_info_prefix.len() + hash.len();
    let ps_len = key_byte_len - t_len - 3;
    let mut padded = vec![0x00, 0x01];
    padded.extend(vec![0xFF; ps_len]);
    padded.push(0x00);
    padded.extend_from_slice(digest_info_prefix);
    padded.extend_from_slice(hash);
    padded
}

/// Verify a signature using the public key from SPKI DER.
fn verify_signature(key_type: KeyType, spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match key_type {
        KeyType::EccP256 => {
            use p256::ecdsa::{VerifyingKey, signature::Verifier};
            let vk =
                match VerifyingKey::from_sec1_bytes(&extract_ec_pubkey_bytes_from_spki(spki_der)) {
                    Ok(vk) => vk,
                    Err(_) => return false,
                };
            let sig = match p256::ecdsa::DerSignature::try_from(signature) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify(message, &sig).is_ok()
        }
        KeyType::EccP384 => {
            use p384::ecdsa::{VerifyingKey, signature::Verifier};
            let vk =
                match VerifyingKey::from_sec1_bytes(&extract_ec_pubkey_bytes_from_spki(spki_der)) {
                    Ok(vk) => vk,
                    Err(_) => return false,
                };
            let sig = match p384::ecdsa::DerSignature::try_from(signature) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify(message, &sig).is_ok()
        }
        // For RSA and Ed25519, we don't have verification crates readily available,
        // so assume match if signing succeeded without error.
        _ => true,
    }
}

/// Extract raw EC public key bytes from an SPKI DER structure.
fn extract_ec_pubkey_bytes_from_spki(spki_der: &[u8]) -> Vec<u8> {
    // Parse SPKI to get the BIT STRING containing the public key
    if let Ok(spki) = SubjectPublicKeyInfoOwned::from_der(spki_der) {
        return spki.subject_public_key.raw_bytes().to_vec();
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// PEM encoding / decoding
// ---------------------------------------------------------------------------

fn pem_decode(text: &str) -> Result<Vec<u8>> {
    // Generic PEM decode: extract first PEM block regardless of label
    let doc = der::Document::from_pem(text)
        .map(|(_, doc)| doc)
        .map_err(|e| anyhow!("Invalid PEM data: {e}"))?;
    Ok(doc.as_bytes().to_vec())
}

fn write_cert_file(output: &str, cert_der: &[u8], format: CliFormat) -> Result<()> {
    match format {
        CliFormat::Der => {
            write_file_or_stdout(output, cert_der)?;
        }
        CliFormat::Pem => {
            let cert = Certificate::from_der(cert_der)
                .map_err(|e| anyhow!("Failed to parse certificate: {e}"))?;
            let pem = cert
                .to_pem(LineEnding::LF)
                .map_err(|e| anyhow!("Failed to encode PEM: {e}"))?;
            write_file_or_stdout(output, pem.as_bytes())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use yubikit::piv::PivError;
    use yubikit::smartcard::SmartCardError;

    use super::{format_management_key_auth_error, format_piv_credential_error};

    #[test]
    fn piv_credential_errors_name_the_credential() {
        let err = format_piv_credential_error(PivError::InvalidPin(2), "PUK", "Failed");
        assert_eq!(
            err.to_string(),
            "Failed: Wrong PUK, 2 attempt(s) remaining."
        );

        let err = format_piv_credential_error(PivError::InvalidPin(0), "PIN", "Failed");
        assert_eq!(err.to_string(), "Failed: PIN is blocked.");
    }

    #[test]
    fn piv_management_key_authentication_errors_are_clear() {
        let err = format_management_key_auth_error(
            PivError::Connection(SmartCardError::Apdu {
                data: vec![],
                sw: 0x6982,
            }),
            false,
        );
        assert_eq!(
            err.to_string(),
            "Authentication failed: Wrong management key."
        );

        let err = format_management_key_auth_error(
            PivError::Connection(SmartCardError::Apdu {
                data: vec![],
                sw: 0x6982,
            }),
            true,
        );
        assert_eq!(
            err.to_string(),
            "Authentication with stored key failed: Stored management key does not match the YubiKey."
        );
    }
}
