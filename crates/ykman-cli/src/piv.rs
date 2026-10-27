use anyhow::{Result, anyhow};
use std::str::FromStr;
use std::time::Duration;

use clap::{Args, Subcommand};
use x509_cert::Certificate;
use x509_cert::builder::{Builder, CertificateBuilder, Profile, RequestBuilder};
use x509_cert::der::{self, Decode, Encode, EncodePem, pem::LineEnding};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use yubikit::core::Version;
use yubikit::device::YubiKeyDevice;
use yubikit::keys::{PrivateKey, PublicKey};
use yubikit::management::{Capability, DeviceInfo};
use yubikit::piv::{
    DEFAULT_MANAGEMENT_KEY, HashAlgorithm, KeyType, ManagementKey, ManagementKeyType, ObjectId,
    PinPolicy, PivError, PivPin, PivSession, PivSignature, PivSigner, Slot, TouchPolicy,
};
use zeroize::Zeroizing;

use ykman::piv::{
    TAG_PIVMAN_KEY, get_pivman_data, get_pivman_protected_data, has_stored_key, pivman_set_mgm_key,
};
use yubikit::smartcard::{SmartCardConnection, SmartCardError, Sw};

use crate::cli_enums::{
    CliDecryptionPadding, CliFormat, CliHashAlgorithm, CliKeyType, CliLegacyKeyTypeParser,
    CliMgmtKeyType, CliPinPolicy, CliSignaturePadding, CliTouchPolicy,
};
use crate::scp::ScpParams;
use crate::util::{
    ByteFormat, ByteLen, confirm, open_smartcard_session, print_table, prompt_bytes,
    read_file_or_stdin, require_fips_approved, write_file_or_stdout,
};

use yubikit::__internal::{padding, piv_secret};

#[derive(Subcommand)]
pub enum PivAction {
    /// Display PIV status
    Info,
    /// Reset the PIV application
    Reset {
        /// Confirm the reset without prompting
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
        /// Current PIN
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// New PIN
        #[arg(short = 'n', long)]
        new_pin: Option<String>,
    },
    /// Change the PIV PUK
    ChangePuk {
        /// Current PUK
        #[arg(short = 'p', long)]
        puk: Option<String>,
        /// New PUK
        #[arg(short = 'n', long)]
        new_puk: Option<String>,
    },
    /// Unblock the PIN using PUK
    UnblockPin {
        /// Current PUK
        #[arg(short = 'p', long)]
        puk: Option<String>,
        /// New PIN
        #[arg(short = 'n', long)]
        new_pin: Option<String>,
    },
    /// Set PIN and PUK retry counts
    SetRetries {
        /// PIN retry count
        pin_retries: u8,
        /// PUK retry count
        puk_retries: u8,
        /// Current management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Confirm changing retry counters without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Change the management key
    ChangeManagementKey {
        /// Current management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// New management key (hex, 16/24/32 bytes)
        #[arg(short = 'n', long, value_name = "KEY")]
        new_management_key: Option<String>,
        /// Algorithm for the new management key
        #[arg(short = 'a', long, value_name = "ALGORITHM")]
        algorithm: Option<CliMgmtKeyType>,
        /// Require touch when using the new management key
        #[arg(short = 't', long)]
        touch: bool,
        /// Generate a random management key
        #[arg(short = 'g', long)]
        generate: bool,
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
        /// Algorithm for the generated key
        #[arg(short = 'a', long, default_value = "eccp256")]
        algorithm: CliKeyType,
        /// PIN policy for the generated key
        #[arg(long, default_value = "default")]
        pin_policy: CliPinPolicy,
        /// Touch policy for the generated key
        #[arg(long, default_value = "default")]
        touch_policy: CliTouchPolicy,
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Output format (pem or der)
        #[arg(short = 'F', long, default_value = "pem", hide_possible_values = true)]
        format: CliFormat,
    },
    /// Import a private key
    Import {
        /// PIV slot
        slot: String,
        /// Private key file
        key_file: String,
        /// PIN policy for the imported key
        #[arg(long, default_value = "default")]
        pin_policy: CliPinPolicy,
        /// Touch policy for the imported key
        #[arg(long, default_value = "default")]
        touch_policy: CliTouchPolicy,
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Password for decrypting password-protected key files
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Sign a message (ECDSA signatures use DER encoding)
    #[command(mut_arg("algorithm", |arg| arg
        .value_parser(CliLegacyKeyTypeParser)
        .help("Key algorithm for firmware before 5.3")))]
    Sign {
        #[command(flatten)]
        operation: KeyOperation,
        /// RSA/ECDSA hash (default: sha256); unused for Ed25519/ML-DSA
        #[arg(short = 'a', long, value_name = "HASH")]
        hash_algorithm: Option<CliHashAlgorithm>,
        /// Input is already a digest (RSA/ECDSA only)
        #[arg(long)]
        prehashed: bool,
        /// RSA padding (default: pkcs1v15; PSS salt is digest length)
        #[arg(long)]
        padding: Option<CliSignaturePadding>,
        /// ML-DSA context string (at most 255 bytes)
        #[arg(long, conflicts_with = "mu")]
        context: Option<String>,
        /// Input is a precomputed 64-byte ML-DSA mu (external mu)
        #[arg(long, conflicts_with = "compute_mu")]
        mu: bool,
        /// Compute external ML-DSA mu on the host (any message size)
        #[arg(long)]
        compute_mu: bool,
    },
    /// Decrypt RSA ciphertext
    Decrypt {
        #[command(flatten)]
        operation: KeyOperation,
        /// RSA encryption padding
        #[arg(long, default_value = "oaep")]
        padding: CliDecryptionPadding,
        /// OAEP and MGF1 hash (default: sha256; empty label)
        #[arg(short = 'a', long, value_name = "HASH")]
        hash_algorithm: Option<CliHashAlgorithm>,
    },
    /// Decapsulate ML-KEM ciphertext and output the raw shared secret
    Decapsulate {
        #[command(flatten)]
        operation: KeyOperation,
    },
    /// Derive a raw ECDH/X25519 shared secret from a peer public key (PEM/DER)
    Derive {
        #[command(flatten)]
        operation: KeyOperation,
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
        /// Output format (pem or der)
        #[arg(short = 'F', long, default_value = "pem", hide_possible_values = true)]
        format: CliFormat,
    },
    /// Export public key
    Export {
        /// PIV slot
        slot: String,
        /// Output file
        output: String,
        /// Output format (pem or der)
        #[arg(short = 'F', long, default_value = "pem", hide_possible_values = true)]
        format: CliFormat,
        /// Verify that the public key matches the slot's private key
        ///
        /// Uses a signing challenge for certificate-derived keys on firmware before
        /// 5.3. Later firmware exports authoritative public-key metadata.
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
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Delete key in slot
    Delete {
        /// PIV slot
        slot: String,
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

#[derive(Args)]
pub struct KeyOperation {
    /// PIV slot
    slot: String,
    /// Input file, or - for stdin
    input: String,
    /// Output file, or - for binary stdout
    output: String,
    /// PIN (prompted for only if the slot policy requires it)
    #[arg(short = 'P', long)]
    pin: Option<String>,
    /// Key algorithm for devices without slot metadata
    #[arg(long)]
    algorithm: Option<CliKeyType>,
}

#[derive(Subcommand)]
pub enum PivCertAction {
    /// Export certificate from slot
    Export {
        /// PIV slot
        slot: String,
        /// Output file
        output: String,
        /// Output format (pem or der)
        #[arg(short = 'F', long, default_value = "pem", hide_possible_values = true)]
        format: CliFormat,
    },
    /// Import certificate to slot
    Import {
        /// PIV slot
        slot: String,
        /// Certificate file
        cert_file: String,
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// Compress certificate before importing
        #[arg(short = 'c', long)]
        compress: bool,
        /// Password for decrypting the certificate file
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Verify that the certificate's public key matches the slot key
        ///
        /// Uses public-key metadata on firmware 5.3 and later, otherwise a signing
        /// challenge. Does not check certificate signatures, validity, or trust.
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
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
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
        #[arg(long, value_name = "DAYS", default_value_t = 365)]
        valid_days: u32,
        /// Hash algorithm
        #[arg(short = 'a', long, value_name = "HASH", default_value = "sha256")]
        hash_algorithm: CliHashAlgorithm,
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
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
        #[arg(short = 'a', long, value_name = "HASH", default_value = "sha256")]
        hash_algorithm: CliHashAlgorithm,
        /// PIN for signing the CSR
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
        /// PIN for reading PIN-protected objects
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Import a PIV data object
    Import {
        /// Object ID
        object: String,
        /// Data file
        data: String,
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Generate a data object (CHUID or CCC)
    Generate {
        /// Object type: CHUID or CCC
        object: String,
        /// Management key (hex, 16/24/32 bytes)
        #[arg(short = 'm', long, value_name = "KEY")]
        management_key: Option<String>,
        /// PIN for a PIN-protected management key
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
                PivKeysAction::Sign {
                    operation,
                    hash_algorithm,
                    prehashed,
                    padding,
                    context,
                    mu,
                    compute_mu,
                } => run_key_operation(
                    dev,
                    scp_params,
                    &operation,
                    PrivateKeyOperation::Sign {
                        hash_algorithm,
                        prehashed,
                        padding,
                        context,
                        mu,
                        compute_mu,
                    },
                ),
                PivKeysAction::Decrypt {
                    operation,
                    padding,
                    hash_algorithm,
                } => run_key_operation(
                    dev,
                    scp_params,
                    &operation,
                    PrivateKeyOperation::Decrypt {
                        padding,
                        hash_algorithm,
                    },
                ),
                PivKeysAction::Decapsulate { operation } => run_key_operation(
                    dev,
                    scp_params,
                    &operation,
                    PrivateKeyOperation::Decapsulate,
                ),
                PivKeysAction::Derive { operation } => {
                    run_key_operation(dev, scp_params, &operation, PrivateKeyOperation::Derive)
                }
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
    let key_type = session.management_key_type();
    let key = prompt_bytes(
        "Enter the current management key",
        &ByteFormat::hex(ByteLen::Exact(key_type.key_len())).masked(),
    )?;
    let management_key = to_management_key(key_type, &key)?;
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
        PivError::Connection(SmartCardError::Apdu { sw, .. })
            if sw == Sw::ConditionsNotSatisfied as u16 =>
        {
            anyhow!("{action}: {credential} does not meet complexity requirement.")
        }
        e => anyhow!("{action}: {e}"),
    }
}

fn parse_object_id(s: &str) -> Result<u32> {
    match s.to_ascii_uppercase().as_str() {
        "CHUID" => return Ok(ObjectId::Chuid as u32),
        "CCC" | "CAPABILITY" => return Ok(ObjectId::Capability as u32),
        "AUTHENTICATION" => return Ok(ObjectId::Authentication as u32),
        "SIGNATURE" => return Ok(ObjectId::Signature as u32),
        "KEY-MANAGEMENT" | "KEY_MANAGEMENT" => return Ok(ObjectId::KeyManagement as u32),
        "CARD-AUTH" | "CARD_AUTH" | "CARDAUTH" => return Ok(ObjectId::CardAuth as u32),
        "DISCOVERY" => return Ok(ObjectId::Discovery as u32),
        "KEY-HISTORY" | "KEY_HISTORY" => return Ok(ObjectId::KeyHistory as u32),
        "FINGERPRINTS" => return Ok(ObjectId::Fingerprints as u32),
        "FACIAL" => return Ok(ObjectId::Facial as u32),
        "IRIS" => return Ok(ObjectId::Iris as u32),
        "PRINTED" => return Ok(ObjectId::Printed as u32),
        "ATTESTATION" => return Ok(ObjectId::Attestation as u32),
        _ => {}
    }
    // Fall back to a raw hexadecimal object ID (with or without a leading
    // "0x"), so callers can target arbitrary/retired objects not covered by
    // the named aliases above.
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(hex, 16).map_err(|_| {
        anyhow!("Unknown object ID: {s}. Use CHUID, CCC, AUTHENTICATION, etc., or a hex object ID.")
    })
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
    for slot in Slot::key_slots() {
        let has_key = session.get_slot_metadata(slot).ok();
        let has_cert = session.get_certificate(slot).ok();

        if has_key.is_none() && has_cert.is_none() {
            continue;
        }

        println!("\n{}:", slot_heading(slot));

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

fn slot_heading(slot: Slot) -> String {
    let name = match slot {
        Slot::Authentication => "AUTHENTICATION".to_string(),
        Slot::Signature => "SIGNATURE".to_string(),
        Slot::KeyManagement => "KEY MANAGEMENT".to_string(),
        Slot::CardAuth => "CARD AUTH".to_string(),
        _ => format!("{slot:?}").to_ascii_uppercase(),
    };
    format!("Slot {:02X} ({name})", slot as u8)
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
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter the current PIN")?,
    };
    validate_pin_length(dev.info(), &old, "Current PIN", 6)?;
    let old = to_piv_pin(&old, "PIN")?;
    let new = match new_pin {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PIN")?,
    };

    validate_new_pin(dev.info(), &new, "New PIN")?;
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
        Some(p) => p.to_string(),
        None => crate::util::prompt_secret("Enter the current PUK")?,
    };
    validate_pin_length(dev.info(), &old, "Current PUK", 6)?;
    let old = to_piv_pin(&old, "PUK")?;
    let new = match new_puk {
        Some(p) => p.to_string(),
        None => crate::util::prompt_new_secret("New PUK")?,
    };

    validate_new_pin(dev.info(), &new, "New PUK")?;
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

    validate_new_pin(dev.info(), &new, "New PIN")?;
    let new = to_piv_pin(&new, "PIN")?;

    let mut session = open_session(dev, scp_params)?;
    session.unblock_pin(&puk, &new).map_err(|e| match e {
        PivError::Connection(SmartCardError::Apdu { sw, .. })
            if sw == Sw::ConditionsNotSatisfied as u16 =>
        {
            anyhow!("PIN does not meet complexity requirement.")
        }
        e => format_piv_credential_error(e, "PUK", "Failed to unblock PIN"),
    })?;
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
    let mut session = open_session(dev, scp_params)?;
    if dev.info().fips_capable.contains(Capability::PIV) {
        let pin = session
            .get_pin_metadata()
            .map_err(|e| anyhow!("Failed to read PIN metadata: {e}"))?;
        let puk = session
            .get_puk_metadata()
            .map_err(|e| anyhow!("Failed to read PUK metadata: {e}"))?;
        check_fips_retry_change(dev.info(), pin.default_value, puk.default_value)?;
    }
    if !force
        && !confirm(&format!(
            "Set PIN retries to {pin_retries} and PUK retries to {puk_retries}? This will reset PIN and PUK to defaults."
        ))
    {
        return Err(anyhow!("Aborted."));
    }

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
    algorithm: Option<CliMgmtKeyType>,
    touch: bool,
    generate: bool,
    pin: Option<&str>,
    protect: bool,
) -> Result<()> {
    if protect {
        require_fips_approved(dev.info(), Capability::PIV, "prior to using --protect")?;
    }
    let mut session = open_session(dev, scp_params)?;
    let key_type: ManagementKeyType = algorithm
        .map(Into::into)
        .unwrap_or_else(|| session.management_key_type());
    check_management_key_type_supported(
        session.version(),
        dev.info().fips_capable.contains(Capability::PIV),
        key_type,
    )
    .map_err(|e| anyhow!("{e}"))?;

    let key_len = key_type.key_len();

    let provided_new_key = if !generate && let Some(k) = new_mgmt_key {
        let bytes = parse_management_key(k)?;
        if bytes.len() != key_len {
            return Err(anyhow!(
                "Management key must be {key_len} bytes for {key_type}."
            ));
        }
        Some(bytes)
    } else {
        None
    };

    let pin_verified = authenticate_session(&mut session, mgmt_key, pin)?;
    if protect && !pin_verified {
        ensure_pin(&mut session, pin)?;
    }

    let new_key = if generate {
        let mut k = vec![0u8; key_len];
        getrandom::fill(&mut k).map_err(|e| anyhow!("Failed to generate: {e}"))?;
        k
    } else if let Some(k) = provided_new_key {
        k
    } else {
        prompt_bytes(
            &format!(
                "New management key ({})",
                management_key_type_prompt_name(key_type)
            ),
            &ByteFormat::hex(ByteLen::Exact(key_len)).masked(),
        )?
    };

    pivman_set_mgm_key(&mut session, key_type, &new_key, touch, protect)
        .map_err(|e| anyhow!("Failed to set management key: {e}"))?;

    if generate {
        eprintln!("Management key set: {}", hex::encode(&new_key));
    } else {
        eprintln!("Management key changed.");
    }
    Ok(())
}

fn management_key_type_prompt_name(key_type: ManagementKeyType) -> &'static str {
    match key_type {
        ManagementKeyType::Tdes => "TDES",
        ManagementKeyType::Aes128 => "AES-128",
        ManagementKeyType::Aes192 => "AES-192",
        ManagementKeyType::Aes256 => "AES-256",
        _ => "unknown algorithm",
    }
}

fn check_management_key_type_supported(
    version: Version,
    fips_capable: bool,
    key_type: ManagementKeyType,
) -> std::result::Result<(), String> {
    match key_type {
        ManagementKeyType::Tdes if fips_capable => {
            Err("TDES not supported on YubiKey FIPS.".to_string())
        }
        ManagementKeyType::Tdes if version >= Version(6, 0, 0) => {
            Err("TDES management keys are not supported by this YubiKey".to_string())
        }
        ManagementKeyType::Aes128 | ManagementKeyType::Aes192 | ManagementKeyType::Aes256
            if version < Version(5, 4, 0) =>
        {
            Err(format!(
                "{key_type} management keys are not supported by this YubiKey"
            ))
        }
        _ => Ok(()),
    }
}

fn validate_pin_length(info: &DeviceInfo, pin: &str, name: &str, min_len: usize) -> Result<()> {
    let (length, unit) = if info.pin_complexity {
        (pin.chars().count(), "characters")
    } else {
        (pin.len(), "bytes")
    };
    if !(min_len..=8).contains(&length) {
        return Err(if min_len == 8 {
            anyhow!("{name} must be exactly 8 {unit} long.")
        } else {
            anyhow!("{name} must be between {min_len} and 8 {unit} long.")
        });
    }
    Ok(())
}

fn validate_new_pin(info: &DeviceInfo, pin: &str, name: &str) -> Result<()> {
    let min_len = if info.fips_capable.contains(Capability::PIV) {
        8
    } else {
        6
    };
    validate_pin_length(info, pin, name, min_len)
}

fn check_fips_retry_change(info: &DeviceInfo, pin_default: bool, puk_default: bool) -> Result<()> {
    if info.fips_capable.contains(Capability::PIV) && !(pin_default && puk_default) {
        return Err(anyhow!(
            "Retry attempts must be set before PIN/PUK have been changed."
        ));
    }
    Ok(())
}

fn check_key_support_fips(
    info: &DeviceInfo,
    key_type: KeyType,
    pin_policy: PinPolicy,
) -> Result<()> {
    if info.fips_capable.contains(Capability::PIV) {
        if matches!(key_type, KeyType::Rsa1024 | KeyType::X25519) {
            return Err(anyhow!(
                "Key type {key_type} not supported on YubiKey FIPS."
            ));
        }
        if pin_policy == PinPolicy::Never {
            return Err(anyhow!("PIN policy NEVER not supported on YubiKey FIPS."));
        }
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
    require_fips_approved(dev.info(), Capability::PIV, "prior to key generation")?;
    let slot = parse_slot(slot)?;
    let key_type: KeyType = algorithm.into();
    let pp: PinPolicy = pin_policy.into();
    let tp: TouchPolicy = touch_policy.into();
    check_key_support_fips(dev.info(), key_type, pp)?;

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
    require_fips_approved(dev.info(), Capability::PIV, "prior to key import")?;
    let slot = parse_slot(slot)?;
    let pp: PinPolicy = pin_policy.into();
    let tp: TouchPolicy = touch_policy.into();

    let data = read_file_or_stdin(key_file)?;

    let der = decrypt_private_key_data(&data, password)?;

    // Parse the private key (auto-detects algorithm from PKCS#8)
    let private_key = PrivateKey::from_pkcs8(&der)
        .map_err(|_| anyhow!("Could not parse private key from file."))?;
    check_key_support_fips(dev.info(), KeyType::try_from(&private_key.algorithm())?, pp)?;

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

enum PrivateKeyOperation {
    Sign {
        hash_algorithm: Option<CliHashAlgorithm>,
        prehashed: bool,
        padding: Option<CliSignaturePadding>,
        context: Option<String>,
        mu: bool,
        compute_mu: bool,
    },
    Decrypt {
        padding: CliDecryptionPadding,
        hash_algorithm: Option<CliHashAlgorithm>,
    },
    Decapsulate,
    Derive,
}

enum SignRequest {
    Message(Zeroizing<Vec<u8>>),
    Context(String),
    Mu(Zeroizing<Vec<u8>>),
}

fn operation_key_type<C: SmartCardConnection>(
    session: &mut PivSession<C>,
    slot: Slot,
    algorithm: Option<CliKeyType>,
) -> Result<(KeyType, PinPolicy, TouchPolicy, Option<PublicKey>)> {
    if session.version() < Version(5, 3, 0) {
        return algorithm
            .map(|a| {
                (
                    KeyType::from(a),
                    PinPolicy::Default,
                    TouchPolicy::Default,
                    None,
                )
            })
            .ok_or_else(|| anyhow!("Slot metadata is unavailable; specify --algorithm."));
    }
    let metadata = session
        .get_slot_metadata(slot)
        .map_err(|e| anyhow!("Failed to read key metadata for slot {slot}: {e}"))?;
    if let Some(algorithm) = algorithm
        && KeyType::from(algorithm) != metadata.key_type
    {
        return Err(anyhow!(
            "--algorithm does not match the key in slot {slot}."
        ));
    }
    Ok((
        metadata.key_type,
        metadata.pin_policy,
        metadata.touch_policy,
        Some(metadata.public_key),
    ))
}

/// Whether a key's PIN policy is known to require PIN verification in a new session.
fn pin_required(slot: Slot, pin_policy: PinPolicy, version: Version) -> bool {
    match pin_policy {
        PinPolicy::Once | PinPolicy::Always => true,
        // Metadata is unavailable before 5.3, so the policy is not actually known.
        PinPolicy::Default if version >= Version(5, 3, 0) => slot != Slot::CardAuth,
        _ => false,
    }
}

fn peer_key_bytes(key_type: KeyType, input: &[u8]) -> Result<Vec<u8>> {
    let der = if input.starts_with(b"-----BEGIN") {
        pem_decode(std::str::from_utf8(input)?)?
    } else {
        input.to_vec()
    };
    let public_key = PublicKey::from_spki(&der).map_err(|e| {
        anyhow!("Invalid peer public key (expected PEM/DER SubjectPublicKeyInfo): {e}")
    })?;
    Ok(piv_secret::peer_public_key_bytes(key_type, &public_key)?)
}

fn write_secret_output(path: &str, secret: &[u8]) -> Result<()> {
    use std::io::Write;
    if path == "-" {
        return write_file_or_stdout(path, secret);
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        anyhow!("Cannot create secret output '{path}' (must not already exist): {e}")
    })?;
    file.write_all(secret)
        .map_err(|e| anyhow!("Failed to write secret output '{path}': {e}"))
}

fn authorize_key_operation<C, F, T>(
    session: &mut PivSession<C>,
    pin: Option<&str>,
    pin_required: bool,
    touch_policy: TouchPolicy,
    mut operation: F,
) -> Result<T>
where
    C: SmartCardConnection,
    F: FnMut(&mut PivSession<C>) -> Result<T, PivError>,
{
    // Verify the PIN (prompting if needed) before asking for touch, so the
    // prompts appear in the order the YubiKey needs them.
    let pin_verified = pin.is_some() || pin_required;
    if pin_verified {
        ensure_pin(session, pin)?;
    }
    if matches!(touch_policy, TouchPolicy::Always | TouchPolicy::Cached) {
        eprintln!("Touch your YubiKey to authorize the private-key operation.");
    }
    if pin_verified {
        operation(session).map_err(|e| anyhow!("{e}"))
    } else {
        verify_pin_if_needed(session, None, operation)
    }
}

fn run_key_operation(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    operation: &KeyOperation,
    action: PrivateKeyOperation,
) -> Result<()> {
    let slot = parse_slot(&operation.slot)?;
    let input = Zeroizing::new(read_file_or_stdin(&operation.input)?);
    let mut session = open_session(dev, scp_params)?;
    let (key_type, pin_policy, touch_policy, public_key) =
        operation_key_type(&mut session, slot, operation.algorithm)?;
    let pin_required = pin_required(slot, pin_policy, session.version());
    let pin = operation.pin.as_deref();
    let output = match action {
        PrivateKeyOperation::Sign {
            hash_algorithm,
            prehashed,
            padding,
            context,
            mu,
            compute_mu,
        } => {
            let request = if context.is_some() || mu || compute_mu {
                if key_type.algorithm() != yubikit::piv::Algorithm::MlDsa {
                    return Err(anyhow!(
                        "--context, --mu and --compute-mu require an ML-DSA key."
                    ));
                }
                if hash_algorithm.is_some() || prehashed || padding.is_some() {
                    return Err(anyhow!(
                        "ML-DSA signs messages directly; hash, prehashed and padding options are not supported."
                    ));
                }
                let context = context.unwrap_or_default();
                if context.len() > 255 {
                    return Err(anyhow!("--context must be at most 255 bytes."));
                }
                if mu {
                    if input.len() != 64 {
                        return Err(anyhow!("ML-DSA mu input must be exactly 64 bytes."));
                    }
                    SignRequest::Mu(Zeroizing::new(input.to_vec()))
                } else if compute_mu {
                    let Some(PublicKey::MlDsa(public_key)) = public_key else {
                        return Err(anyhow!(
                            "The public key of slot {slot} is needed to compute mu."
                        ));
                    };
                    let mu = padding::ml_dsa_mu(&public_key.key, context.as_bytes(), &input)?;
                    SignRequest::Mu(Zeroizing::new(mu.to_vec()))
                } else {
                    SignRequest::Context(context)
                }
            } else {
                SignRequest::Message(Zeroizing::new(padding::prepare_signature(
                    key_type,
                    &input,
                    hash_algorithm.map(Into::into),
                    prehashed,
                    padding.map(Into::into),
                )?))
            };
            let signature =
                authorize_key_operation(&mut session, pin, pin_required, touch_policy, |s| {
                    match &request {
                        SignRequest::Message(message) => s.sign(slot, key_type, message),
                        SignRequest::Context(context) => {
                            s.sign_with_context(slot, key_type, &input, context.as_bytes())
                        }
                        SignRequest::Mu(mu) => s.sign_external_mu(slot, key_type, mu),
                    }
                })
                .map_err(|e| {
                    if key_type.algorithm() == yubikit::piv::Algorithm::MlDsa
                        && !matches!(request, SignRequest::Mu(_))
                        && input.len() > 4096
                    {
                        anyhow!("Failed to sign: {e} (use --compute-mu for large messages)")
                    } else {
                        anyhow!("Failed to sign: {e}")
                    }
                })?;
            return write_file_or_stdout(&operation.output, &signature);
        }
        PrivateKeyOperation::Decrypt {
            padding,
            hash_algorithm,
        } => {
            if key_type.algorithm() != yubikit::piv::Algorithm::Rsa {
                return Err(anyhow!("Decryption requires an RSA key."));
            }
            if padding == CliDecryptionPadding::Pkcs1v15 && hash_algorithm.is_some() {
                return Err(anyhow!("--hash-algorithm applies only to OAEP decryption."));
            }
            if input.len() != (key_type.bit_len() / 8) as usize {
                return Err(anyhow!(
                    "Ciphertext length must match the RSA modulus size."
                ));
            }
            let block = Zeroizing::new(
                authorize_key_operation(&mut session, pin, pin_required, touch_policy, |s| {
                    s.decrypt(slot, &input)
                })
                .map_err(|e| anyhow!("Failed to decrypt: {e}"))?,
            );
            padding::unpad_rsa(
                &block,
                padding.into(),
                hash_algorithm.map_or(HashAlgorithm::Sha256, Into::into),
            )?
        }
        PrivateKeyOperation::Decapsulate => {
            if piv_secret::ml_kem_ciphertext_len(key_type).is_none() {
                return Err(anyhow!("Decapsulation requires an ML-KEM key."));
            }
            piv_secret::check_secret_input(key_type, &input)?;
            let secret = Zeroizing::new(
                authorize_key_operation(&mut session, pin, pin_required, touch_policy, |s| {
                    s.calculate_secret(slot, key_type, &input)
                })
                .map_err(|e| anyhow!("Failed to decapsulate: {e}"))?,
            );
            piv_secret::check_shared_secret(key_type, &secret)?;
            secret
        }
        PrivateKeyOperation::Derive => {
            if !matches!(
                key_type,
                KeyType::EccP256 | KeyType::EccP384 | KeyType::X25519
            ) {
                return Err(anyhow!("Key agreement requires P-256, P-384, or X25519."));
            }
            let peer = peer_key_bytes(key_type, &input)?;
            let secret = Zeroizing::new(
                authorize_key_operation(&mut session, pin, pin_required, touch_policy, |s| {
                    s.calculate_secret(slot, key_type, &peer)
                })
                .map_err(|e| anyhow!("Failed to derive shared secret: {e}"))?,
            );
            piv_secret::check_shared_secret(key_type, &secret)?;
            secret
        }
    };
    write_secret_output(&operation.output, &output)
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
    if [
        ObjectId::Printed,
        ObjectId::Fingerprints,
        ObjectId::Facial,
        ObjectId::Iris,
    ]
    .iter()
    .any(|object| *object as u32 == obj_id)
    {
        require_fips_approved(dev.info(), Capability::PIV, "to export this object")?;
    }
    let mut session = open_session(dev, scp_params)?;
    let data = verify_pin_if_needed(&mut session, pin, |s| s.get_object_raw(obj_id))?;

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
    authenticate_session(&mut session, mgmt_key, pin)?;
    session
        .put_object_raw(obj_id, Some(&data))
        .map_err(|e| match &e {
            PivError::Connection(SmartCardError::Apdu { sw, .. })
                if Sw::from_u16(*sw) == Some(Sw::WrongLength) =>
            {
                anyhow!(
                    "Failed to write object: data is too large to import ({} bytes)",
                    data.len()
                )
            }
            _ => anyhow!("Failed to write object: {e}"),
        })?;
    eprintln!("Object imported.");
    Ok(())
}

/// Generate a new CHUID and write it to the device.
fn generate_chuid(
    session: &mut PivSession<impl yubikit::smartcard::SmartCardConnection>,
) -> Result<()> {
    let chuid =
        ykman::piv::generate_chuid().map_err(|e| anyhow!("Failed to generate CHUID: {e}"))?;

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
    authenticate_session(&mut session, management_key, pin)?;

    match object.to_uppercase().as_str() {
        "CHUID" => {
            let chuid = ykman::piv::generate_chuid()
                .map_err(|e| anyhow!("Failed to generate CHUID: {e}"))?;
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
/// using metadata, or a signing challenge on firmware before 5.3.
/// Does not check certificate signatures, validity periods, or trust.
fn check_key_match<C: yubikit::smartcard::SmartCardConnection>(
    session: &mut PivSession<C>,
    slot: Slot,
    spki_der: &[u8],
    pin: Option<&str>,
) -> Result<()> {
    let public_key = PublicKey::from_spki(spki_der)?;
    let verified = match session.get_slot_metadata(slot) {
        Ok(metadata) => metadata.public_key == public_key,
        Err(PivError::NotSupported(_)) => {
            let key_type = KeyType::try_from(&public_key.algorithm())?;
            if !matches!(
                key_type,
                KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::EccP256 | KeyType::EccP384
            ) {
                return Err(anyhow!(
                    "Key verification is not supported for {key_type} on this firmware."
                ));
            }
            let test_message = b"ykman-verify-key-match";
            let to_sign = padding::prepare_signature(
                key_type,
                test_message,
                Some(HashAlgorithm::Sha256),
                false,
                None,
            )?;
            let signature =
                verify_pin_if_needed(session, pin, |s| s.sign(slot, key_type, &to_sign))?;
            verify_signature(key_type, spki_der, test_message, &signature)
                .map_err(|e| anyhow!("Failed to verify public key for slot {slot}: {e}"))?
        }
        Err(e) => return Err(anyhow!("Failed to read key metadata for slot {slot}: {e}")),
    };
    if !verified {
        return Err(anyhow!(
            "Public key does not match the private key in slot {slot}."
        ));
    }
    Ok(())
}

/// Verify a legacy RSA/ECDSA challenge signature using the supplied public key.
fn verify_signature(
    key_type: KeyType,
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use elliptic_curve::pkcs8::DecodePublicKey;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use rsa::pkcs8::DecodePublicKey as _;
    use sha2::{Digest, Sha256};

    if !matches!(
        key_type,
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::EccP256 | KeyType::EccP384
    ) {
        return Err(anyhow!(
            "Signature verification is not supported for {key_type}."
        ));
    }
    let public_key = PublicKey::from_spki(spki_der)?;
    if KeyType::try_from(&public_key.algorithm())? != key_type {
        return Ok(false);
    }

    let verified = match key_type {
        KeyType::EccP256 => {
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)?;
            let signature = p256::ecdsa::Signature::from_der(signature)?;
            key.verify_prehash(&Sha256::digest(message), &signature)
                .is_ok()
        }
        KeyType::EccP384 => {
            let key = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)?;
            let signature = p384::ecdsa::Signature::from_der(signature)?;
            key.verify_prehash(&Sha256::digest(message), &signature)
                .is_ok()
        }
        KeyType::Rsa1024 | KeyType::Rsa2048 => {
            let key = rsa::RsaPublicKey::from_public_key_der(spki_der)?;
            key.verify(
                rsa::Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(message),
                signature,
            )
            .is_ok()
        }
        _ => unreachable!(),
    };
    Ok(verified)
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
    use clap::{CommandFactory, ValueEnum};
    use clap_complete::{Shell, generate};
    use yubikit::core::Version;
    use yubikit::keys::PrivateKey;
    use yubikit::piv::{KeyType, ManagementKeyType, PivError, Slot};
    use yubikit::smartcard::SmartCardError;

    use crate::cli_enums::CliKeyType;

    use super::{
        check_management_key_type_supported, decrypt_private_key_data,
        format_management_key_auth_error, format_piv_credential_error,
        management_key_type_prompt_name, slot_heading,
    };

    fn device_info(fips: bool) -> yubikit::management::DeviceInfo {
        let mut info = yubikit::management::DeviceInfo::parse(&[0], Version(5, 7, 4)).unwrap();
        if fips {
            info.fips_capable = yubikit::management::Capability::PIV;
        }
        info
    }

    #[test]
    fn fips_key_restrictions_apply_before_and_after_approval() {
        use yubikit::piv::PinPolicy;
        for approved in [false, true] {
            let mut info = device_info(true);
            if approved {
                info.fips_approved = info.fips_capable;
            }
            for key_type in [KeyType::Rsa1024, KeyType::X25519] {
                assert_eq!(
                    super::check_key_support_fips(&info, key_type, PinPolicy::Default)
                        .unwrap_err()
                        .to_string(),
                    format!("Key type {key_type} not supported on YubiKey FIPS.")
                );
            }
            assert_eq!(
                super::check_key_support_fips(&info, KeyType::EccP256, PinPolicy::Never)
                    .unwrap_err()
                    .to_string(),
                "PIN policy NEVER not supported on YubiKey FIPS."
            );
            super::check_key_support_fips(&info, KeyType::EccP256, PinPolicy::Once).unwrap();
        }
        for key_type in [KeyType::Rsa1024, KeyType::X25519, KeyType::EccP256] {
            super::check_key_support_fips(&device_info(false), key_type, PinPolicy::Never).unwrap();
        }
    }

    #[test]
    fn fips_pin_lengths_use_the_correct_units() {
        let mut info = device_info(true);
        for complexity in [false, true] {
            info.pin_complexity = complexity;
            let unit = if complexity { "characters" } else { "bytes" };
            for name in ["New PIN", "New PUK"] {
                for invalid in ["", "123456", "1234567", "123456789"] {
                    assert_eq!(
                        super::validate_new_pin(&info, invalid, name)
                            .unwrap_err()
                            .to_string(),
                        format!("{name} must be exactly 8 {unit} long.")
                    );
                }
                super::validate_new_pin(&info, "80246397", name).unwrap();
            }
            super::validate_pin_length(&info, "123456", "Current PIN", 6).unwrap();
        }
        info.pin_complexity = true;
        assert!(super::validate_new_pin(&info, "123456\u{e9}", "New PIN").is_err());
        info.pin_complexity = false;
        super::validate_new_pin(&info, "123456\u{e9}", "New PIN").unwrap();
        super::validate_new_pin(&device_info(false), "123456", "New PIN").unwrap();
    }

    #[test]
    fn fips_retry_changes_require_both_default_credentials() {
        for pin in [false, true] {
            for puk in [false, true] {
                assert_eq!(
                    super::check_fips_retry_change(&device_info(true), pin, puk).is_ok(),
                    pin && puk
                );
                super::check_fips_retry_change(&device_info(false), pin, puk).unwrap();
            }
        }
    }

    #[test]
    fn piv_complexity_errors_identify_the_credential() {
        for credential in ["PIN", "PUK"] {
            let error = PivError::Connection(SmartCardError::Apdu {
                sw: 0x6985,
                data: vec![],
            });
            assert_eq!(
                format_piv_credential_error(error, credential, "Failed").to_string(),
                format!("Failed: {credential} does not meet complexity requirement.")
            );
        }
    }

    fn key_command(name: &str) -> clap::Command {
        let mut command = crate::Cli::command();
        command.build();
        command
            .find_subcommand("piv")
            .unwrap()
            .find_subcommand("keys")
            .unwrap()
            .find_subcommand(name)
            .unwrap()
            .clone()
    }

    #[test]
    fn sign_algorithm_accepts_every_key_type_and_alias() {
        for key_type in CliKeyType::value_variants() {
            for name in key_type.to_possible_value().unwrap().get_name_and_aliases() {
                let matches = key_command("sign")
                    .try_get_matches_from(["sign", "9a", "-", "-", "--algorithm", name])
                    .unwrap();
                assert_eq!(
                    KeyType::from(*matches.get_one::<CliKeyType>("algorithm").unwrap()),
                    KeyType::from(*key_type),
                    "{name}"
                );
            }
        }
        assert!(
            key_command("sign")
                .try_get_matches_from(["sign", "9a", "-", "-", "--algorithm", "not-a-key-type"])
                .is_err()
        );
    }

    #[test]
    fn sign_algorithm_only_advertises_legacy_types() {
        let sign = key_command("sign");
        let algorithm = sign
            .get_arguments()
            .find(|arg| arg.get_id() == "algorithm")
            .unwrap();
        let visible: Vec<_> = algorithm
            .get_possible_values()
            .into_iter()
            .filter(|value| !value.is_hide_set())
            .map(|value| value.get_name().to_string())
            .collect();
        assert_eq!(visible, ["rsa1024", "rsa2048", "eccp256", "eccp384"]);

        for name in ["generate", "decrypt", "derive", "decapsulate"] {
            let command = key_command(name);
            let algorithm = command
                .get_arguments()
                .find(|arg| arg.get_id() == "algorithm")
                .unwrap();
            assert_eq!(
                algorithm
                    .get_possible_values()
                    .iter()
                    .filter(|value| !value.is_hide_set())
                    .count(),
                CliKeyType::value_variants().len(),
                "{name}"
            );
        }
    }

    #[test]
    fn sign_algorithm_completions_only_offer_legacy_types() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let mut output = Vec::new();
            generate(shell, &mut key_command("sign"), "ykman-sign", &mut output);
            let completion = String::from_utf8(output).unwrap();
            let mut output = Vec::new();
            generate(
                shell,
                &mut key_command("generate"),
                "ykman-generate",
                &mut output,
            );
            let generation = String::from_utf8(output).unwrap();
            for key_type in CliKeyType::value_variants() {
                let value = key_type.to_possible_value().unwrap();
                assert_eq!(
                    completion.contains(value.get_name()),
                    matches!(
                        key_type,
                        CliKeyType::Rsa1024
                            | CliKeyType::Rsa2048
                            | CliKeyType::Eccp256
                            | CliKeyType::Eccp384
                    ) && generation.contains(value.get_name()),
                    "{shell}: {}",
                    value.get_name()
                );
            }
        }
    }

    #[derive(Debug)]
    struct KeyMatchConnection {
        version: [u8; 3],
        metadata: Vec<u8>,
        metadata_status: u16,
        signature: Vec<u8>,
        expected_challenge: Option<Vec<u8>>,
        command_data: Vec<u8>,
    }

    impl yubikit::core::Connection for KeyMatchConnection {
        type Error = SmartCardError;

        fn close(&mut self) {}
    }

    impl yubikit::smartcard::SmartCardConnection for KeyMatchConnection {
        fn transport(&self) -> yubikit::core::Transport {
            yubikit::core::Transport::Usb
        }

        fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
            use yubikit::__internal::tlv::tlv_encode;
            match apdu[1] {
                0xa4 => Ok((vec![], 0x9000)),
                0xfd => Ok((self.version.to_vec(), 0x9000)),
                0xf7 => {
                    assert!(
                        self.version >= [5, 3, 0],
                        "Legacy verification queried metadata"
                    );
                    if apdu[3] == 0x9b {
                        Ok((vec![0x02, 0x02, 0, 0], 0x9000))
                    } else {
                        Ok((self.metadata.clone(), self.metadata_status))
                    }
                }
                0x87 => {
                    assert!(
                        self.version < [5, 3, 0],
                        "Metadata verification attempted signing"
                    );
                    let (offset, length) = if apdu[4] == 0 {
                        (7, u16::from_be_bytes([apdu[5], apdu[6]]) as usize)
                    } else {
                        (5, apdu[4] as usize)
                    };
                    self.command_data
                        .extend_from_slice(&apdu[offset..offset + length]);
                    if apdu[0] & 0x10 != 0 {
                        return Ok((vec![], 0x9000));
                    }
                    let expected = self
                        .expected_challenge
                        .as_ref()
                        .expect("Unsupported legacy signing");
                    let mut inner = tlv_encode(0x82, &[]);
                    inner.extend(tlv_encode(0x81, expected));
                    assert_eq!(self.command_data, tlv_encode(0x7c, &inner));
                    self.command_data.clear();
                    Ok((tlv_encode(0x7c, &tlv_encode(0x82, &self.signature)), 0x9000))
                }
                _ => panic!("Unexpected key verification APDU: {apdu:?}"),
            }
        }
    }

    fn key_match_session(
        version: [u8; 3],
        key: &[u8],
        signature: &[u8],
    ) -> yubikit::piv::PivSession<KeyMatchConnection> {
        use yubikit::__internal::tlv::tlv_encode;
        use yubikit::keys::PublicKey;
        let public = PublicKey::from_spki(key).unwrap();
        let key_type = KeyType::try_from(&public.algorithm()).unwrap();
        let expected_challenge = if version < [5, 3, 0] && !signature.is_empty() {
            use sha2::{Digest, Sha256};
            Some(match &public {
                PublicKey::Rsa(key) => {
                    // Recover the PKCS#1 block independently from the known signature.
                    let n = rsa::BigUint::from_bytes_be(&key.n);
                    let e = rsa::BigUint::from_bytes_be(&key.e);
                    let encoded = rsa::BigUint::from_bytes_be(signature)
                        .modpow(&e, &n)
                        .to_bytes_be();
                    let mut block = vec![0; key.n.len()];
                    let offset = block.len() - encoded.len();
                    block[offset..].copy_from_slice(&encoded);
                    block
                }
                PublicKey::Ec(_) => Sha256::digest(b"ykman-verify-key-match").to_vec(),
                _ => panic!("Unsupported test signing key"),
            })
        } else {
            None
        };
        let device_key = match public {
            PublicKey::Rsa(key) => [tlv_encode(0x81, &key.n), tlv_encode(0x82, &key.e)].concat(),
            PublicKey::Ec(key) => tlv_encode(0x86, &key.point),
            PublicKey::Ed25519(key) => tlv_encode(0x86, &key.key),
            PublicKey::X25519(key) => tlv_encode(0x86, &key.key),
            PublicKey::MlDsa(key) => tlv_encode(0x87, &key.key),
            PublicKey::MlKem(key) => tlv_encode(0x88, &key.key),
            _ => panic!("Unsupported test public key"),
        };
        let mut metadata = vec![1, 1, key_type as u8, 2, 2, 0, 0, 3, 1, 1];
        metadata.extend(tlv_encode(4, &device_key));
        yubikit::piv::PivSession::new(KeyMatchConnection {
            version,
            metadata,
            metadata_status: 0x9000,
            signature: signature.to_vec(),
            expected_challenge,
            command_data: vec![],
        })
        .unwrap()
    }

    fn assert_challenge_verification(
        key_type: KeyType,
        public_key: &[u8],
        other_key: &[u8],
        signature: &[u8],
    ) {
        let message = b"ykman-verify-key-match";
        assert!(super::verify_signature(key_type, public_key, message, signature).unwrap());
        assert!(!super::verify_signature(key_type, other_key, message, signature).unwrap());
        assert!(
            !super::verify_signature(key_type, public_key, b"wrong message", signature).unwrap()
        );
        let mut corrupt = signature.to_vec();
        corrupt[0] ^= 1;
        assert!(!matches!(
            super::verify_signature(key_type, public_key, message, &corrupt),
            Ok(true)
        ));
        assert!(!matches!(
            super::verify_signature(key_type, public_key, message, &signature[1..]),
            Ok(true)
        ));
        assert!(super::verify_signature(key_type, b"invalid SPKI", message, signature).is_err());
        for other_type in [
            KeyType::Rsa1024,
            KeyType::Rsa2048,
            KeyType::EccP256,
            KeyType::EccP384,
        ] {
            if other_type != key_type {
                assert!(
                    !super::verify_signature(other_type, public_key, message, signature).unwrap()
                );
            }
        }
        let mut legacy = key_match_session([5, 2, 0], public_key, signature);
        super::check_key_match(&mut legacy, Slot::Authentication, public_key, None).unwrap();
        assert!(
            super::check_key_match(&mut legacy, Slot::Authentication, other_key, None).is_err()
        );
        let mut modern = key_match_session([5, 3, 0], public_key, &[]);
        super::check_key_match(&mut modern, Slot::Authentication, public_key, None).unwrap();
        assert!(
            super::check_key_match(&mut modern, Slot::Authentication, other_key, None).is_err()
        );
    }

    #[test]
    fn modern_key_match_uses_metadata_for_new_algorithms() {
        use yubikit::keys::{
            Ed25519PublicKey, MlDsaParameterSet, MlDsaPublicKey, MlKemParameterSet, MlKemPublicKey,
            PublicKey, X25519PublicKey,
        };
        let mut public_keys: Vec<PublicKey> = vec![
            Ed25519PublicKey::new(vec![1; 32]).unwrap().into(),
            X25519PublicKey::new(vec![2; 32]).unwrap().into(),
        ];
        for (parameters, length) in [
            (MlDsaParameterSet::MlDsa44, 1312),
            (MlDsaParameterSet::MlDsa65, 1952),
            (MlDsaParameterSet::MlDsa87, 2592),
        ] {
            public_keys.push(
                MlDsaPublicKey::new(parameters, vec![1; length])
                    .unwrap()
                    .into(),
            );
        }
        for (parameters, length) in [
            (MlKemParameterSet::MlKem512, 800),
            (MlKemParameterSet::MlKem768, 1184),
            (MlKemParameterSet::MlKem1024, 1568),
        ] {
            public_keys.push(
                MlKemPublicKey::new(parameters, vec![1; length])
                    .unwrap()
                    .into(),
            );
        }
        let other = Ed25519PublicKey::new(vec![3; 32])
            .unwrap()
            .to_spki()
            .unwrap();
        for key in public_keys {
            let key = key.to_spki().unwrap();
            let mut session = key_match_session([6, 0, 0], &key, &[]);
            super::check_key_match(&mut session, Slot::Authentication, &key, None).unwrap();
            assert!(
                super::check_key_match(&mut session, Slot::Authentication, &other, None).is_err()
            );

            let mut legacy = key_match_session([5, 2, 0], &key, &[]);
            let error =
                super::check_key_match(&mut legacy, Slot::Authentication, &key, None).unwrap_err();
            assert!(error.to_string().contains("not supported"));
        }
    }

    #[test]
    fn metadata_errors_do_not_fall_back_to_signing() {
        use elliptic_curve::pkcs8::EncodePublicKey;
        let key = p256::SecretKey::from_slice(&[1; 32])
            .unwrap()
            .public_key()
            .to_public_key_der()
            .unwrap();
        for status in [0x6a88, 0x6982, 0x9000] {
            let mut session = key_match_session([5, 3, 0], key.as_bytes(), &[]);
            let mut connection = session.into_connection();
            connection.metadata_status = status;
            connection.metadata.clear();
            session = yubikit::piv::PivSession::new(connection).unwrap();
            let error =
                super::check_key_match(&mut session, Slot::Authentication, key.as_bytes(), None)
                    .unwrap_err();
            assert!(error.to_string().contains("Failed to read key metadata"));
        }
    }

    #[test]
    fn rsa_challenge_signatures_are_verified() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
        use rsa::traits::PublicKeyParts;
        use sha2::{Digest, Sha256};

        for (key_type, pem) in [
            (
                KeyType::Rsa1024,
                include_str!("../../../tests/files/rsa_1024_key.pem"),
            ),
            (
                KeyType::Rsa2048,
                include_str!("../../../tests/files/rsa_2048_key.pem"),
            ),
        ] {
            let key = rsa::RsaPrivateKey::from_pkcs1_pem(pem)
                .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_pem(pem))
                .unwrap();
            let public = key.to_public_key();
            let other = rsa::RsaPublicKey::new(public.n().clone(), 65539u32.into()).unwrap();
            let signature = key
                .sign(
                    rsa::Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(b"ykman-verify-key-match"),
                )
                .unwrap();
            assert_challenge_verification(
                key_type,
                public.to_public_key_der().unwrap().as_bytes(),
                other.to_public_key_der().unwrap().as_bytes(),
                &signature,
            );
        }
    }

    #[test]
    fn ec_challenge_signatures_use_sha256_for_both_curves() {
        use elliptic_curve::pkcs8::EncodePublicKey;
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(b"ykman-verify-key-match");
        let key = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let other = p256::ecdsa::SigningKey::from_slice(&[2; 32]).unwrap();
        let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        assert_challenge_verification(
            KeyType::EccP256,
            key.verifying_key().to_public_key_der().unwrap().as_bytes(),
            other
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
            signature.to_der().as_bytes(),
        );

        let key = p384::ecdsa::SigningKey::from_slice(&[1; 48]).unwrap();
        let other = p384::ecdsa::SigningKey::from_slice(&[2; 48]).unwrap();
        let signature: p384::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        assert_challenge_verification(
            KeyType::EccP384,
            key.verifying_key().to_public_key_der().unwrap().as_bytes(),
            other
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
            signature.to_der().as_bytes(),
        );
    }

    #[test]
    fn unsupported_challenge_verification_fails_explicitly() {
        for key_type in [
            KeyType::Rsa3072,
            KeyType::Rsa4096,
            KeyType::Ed25519,
            KeyType::MlDsa44,
            KeyType::MlDsa65,
            KeyType::MlDsa87,
            KeyType::X25519,
            KeyType::MlKem512,
            KeyType::MlKem768,
            KeyType::MlKem1024,
        ] {
            let error = super::verify_signature(key_type, &[], &[], &[]).unwrap_err();
            assert!(error.to_string().contains("not supported"));
        }
    }

    #[test]
    fn padding_option_names() {
        use crate::cli_enums::{CliDecryptionPadding, CliSignaturePadding};
        use clap::ValueEnum;
        for (padding, name) in [
            (CliSignaturePadding::Pkcs1v15, "pkcs1v15"),
            (CliSignaturePadding::Pss, "pss"),
        ] {
            assert_eq!(padding.to_possible_value().unwrap().get_name(), name);
        }
        for (padding, name) in [
            (CliDecryptionPadding::Pkcs1v15, "pkcs1v15"),
            (CliDecryptionPadding::Oaep, "oaep"),
        ] {
            assert_eq!(padding.to_possible_value().unwrap().get_name(), name);
        }
    }

    #[test]
    fn pin_is_requested_upfront_only_when_policy_requires_it() {
        use yubikit::piv::PinPolicy;
        let v = Version(5, 7, 0);
        assert!(super::pin_required(Slot::Retired1, PinPolicy::Once, v));
        assert!(super::pin_required(Slot::Retired1, PinPolicy::Always, v));
        assert!(super::pin_required(Slot::Signature, PinPolicy::Default, v));
        assert!(!super::pin_required(Slot::CardAuth, PinPolicy::Default, v));
        assert!(!super::pin_required(Slot::Retired1, PinPolicy::Never, v));
        assert!(!super::pin_required(
            Slot::Retired1,
            PinPolicy::MatchOnce,
            v
        ));
        assert!(!super::pin_required(
            Slot::Retired1,
            PinPolicy::Default,
            Version(5, 2, 0)
        ));
    }

    #[test]
    fn secret_output_is_private_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let path = path.to_str().unwrap();
        super::write_secret_output(path, b"secret").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(super::write_secret_output(path, b"replacement").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"secret");
    }

    #[cfg(unix)]
    #[test]
    fn secret_output_does_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(super::write_secret_output(link.to_str().unwrap(), b"secret").is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }

    #[test]
    fn agreement_rejects_wrong_curves_and_invalid_points() {
        let p256 = p256::SecretKey::from_slice(&[1; 32]).unwrap().public_key();
        use p256::pkcs8::EncodePublicKey;
        let der = p256.to_public_key_der().unwrap();
        assert_eq!(
            super::peer_key_bytes(KeyType::EccP256, der.as_bytes())
                .unwrap()
                .len(),
            65
        );
        assert!(super::peer_key_bytes(KeyType::EccP384, der.as_bytes()).is_err());
        assert!(super::peer_key_bytes(KeyType::Rsa2048, der.as_bytes()).is_err());
        assert!(super::peer_key_bytes(KeyType::EccP256, b"not a public key").is_err());
        let mut invalid = der.as_bytes().to_vec();
        let len = invalid.len();
        invalid[len - 64..].fill(0);
        assert!(super::peer_key_bytes(KeyType::EccP256, &invalid).is_err());
    }

    #[test]
    fn piv_info_labels_retired_slots() {
        assert_eq!(
            slot_heading(Slot::Authentication),
            "Slot 9A (AUTHENTICATION)"
        );
        assert_eq!(slot_heading(Slot::Retired1), "Slot 82 (RETIRED1)");
        assert_eq!(slot_heading(Slot::Retired10), "Slot 8B (RETIRED10)");
        assert_eq!(slot_heading(Slot::Retired20), "Slot 95 (RETIRED20)");
    }

    #[test]
    fn openssl_pqc_pem_files_are_accepted_for_import() {
        for (algorithm, key_type) in [
            ("ml-dsa-44", KeyType::MlDsa44),
            ("ml-dsa-65", KeyType::MlDsa65),
            ("ml-dsa-87", KeyType::MlDsa87),
            ("ml-kem-512", KeyType::MlKem512),
            ("ml-kem-768", KeyType::MlKem768),
            ("ml-kem-1024", KeyType::MlKem1024),
        ] {
            for format in ["full", "seed"] {
                let path = format!(
                    "{}/../yubikit/tests/fixtures/pqc/{algorithm}-{format}.pem",
                    env!("CARGO_MANIFEST_DIR")
                );
                let pem = std::fs::read(&path).expect("read OpenSSL key fixture");
                let der = decrypt_private_key_data(&pem, None).expect("decode PEM");
                let key = PrivateKey::from_pkcs8(&der).expect("parse PKCS#8 key");
                assert_eq!(
                    KeyType::try_from(&key.algorithm()).unwrap(),
                    key_type,
                    "{path}"
                );
            }
        }
    }

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
    fn management_key_prompt_names_include_algorithm() {
        assert_eq!(
            management_key_type_prompt_name(ManagementKeyType::Tdes),
            "TDES"
        );
        assert_eq!(
            management_key_type_prompt_name(ManagementKeyType::Aes128),
            "AES-128"
        );
        assert_eq!(
            management_key_type_prompt_name(ManagementKeyType::Aes192),
            "AES-192"
        );
        assert_eq!(
            management_key_type_prompt_name(ManagementKeyType::Aes256),
            "AES-256"
        );
    }

    #[test]
    fn management_key_support_rejects_unsupported_algorithms() {
        assert!(
            check_management_key_type_supported(Version(5, 3, 9), false, ManagementKeyType::Aes192)
                .is_err()
        );
        assert!(
            check_management_key_type_supported(Version(5, 7, 0), true, ManagementKeyType::Tdes)
                .is_err()
        );
        assert!(
            check_management_key_type_supported(Version(6, 0, 0), false, ManagementKeyType::Tdes)
                .is_err()
        );
        assert!(
            check_management_key_type_supported(Version(5, 7, 0), false, ManagementKeyType::Aes192)
                .is_ok()
        );
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
