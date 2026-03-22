use std::process;

use clap::{Parser, Subcommand};
use yubikit_rs::core_types::set_override_version;
use yubikit_rs::device::{list_devices, list_readers, open_reader, YubiKeyDevice};
use yubikit_rs::management::ReleaseType;

mod apdu;
mod config;
mod hsmauth;
mod info;
mod list;
mod oath;
mod openpgp;
mod otp;
mod piv;
mod securitydomain;
mod util;

use util::CliError;

#[derive(Parser)]
#[command(
    name = "ykman-rs",
    about = "Configure your YubiKey via the command line.",
    version,
    after_help = "Examples:\n\
      \n  List connected YubiKeys, only output serial number:\
      \n  $ ykman-rs list --serials\
      \n\
      \n  Show information about YubiKey with serial number 123456:\
      \n  $ ykman-rs --device 123456 info"
)]
struct Cli {
    /// Specify which YubiKey to interact with by serial number
    #[arg(short = 'd', long = "device", global = true)]
    device: Option<u32>,

    /// Specify a YubiKey by smart card reader name
    #[arg(short = 'r', long = "reader", global = true)]
    reader: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List connected YubiKeys
    List {
        /// Output only serial numbers, one per line
        #[arg(short = 's', long)]
        serials: bool,
        /// List available smart card readers
        #[arg(long)]
        readers: bool,
    },
    /// Show general information
    Info,
    /// Enable or disable applications and settings
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Manage the OATH application
    Oath {
        #[command(subcommand)]
        action: OathAction,
    },
    /// Manage the YubiKey OTP application
    Otp {
        #[command(subcommand)]
        action: OtpAction,
    },
    /// Manage the PIV application
    Piv {
        #[command(subcommand)]
        action: PivAction,
    },
    /// Manage the OpenPGP application
    Openpgp {
        #[command(subcommand)]
        action: OpenpgpAction,
    },
    /// Manage the YubiHSM Auth application
    Hsmauth {
        #[command(subcommand)]
        action: HsmauthAction,
    },
    /// Manage the Security Domain
    #[command(name = "sd")]
    SecurityDomain {
        #[command(subcommand)]
        action: SecurityDomainAction,
    },
    /// Send raw APDUs to the YubiKey
    Apdu {
        /// APDUs to send (format: [CLA]INS[P1P2][:DATA][/LE])
        apdus: Vec<String>,
        /// Print only hex output
        #[arg(short = 'x', long)]
        no_pretty: bool,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Configure USB applications
    Usb {
        /// Enable an application (can be repeated)
        #[arg(short = 'e', long = "enable", action = clap::ArgAction::Append)]
        enable: Vec<String>,
        /// Disable an application (can be repeated)
        #[arg(long = "disable", action = clap::ArgAction::Append)]
        disable: Vec<String>,
        /// Enable all supported applications
        #[arg(short = 'a', long)]
        enable_all: bool,
        /// List enabled applications
        #[arg(short = 'l', long)]
        list: bool,
        /// Current lock code (hex)
        #[arg(short = 'L', long = "lock-code")]
        lock_code: Option<String>,
        /// Enable touch-eject
        #[arg(long)]
        touch_eject: bool,
        /// Disable touch-eject
        #[arg(long)]
        no_touch_eject: bool,
        /// Auto-eject timeout in seconds
        #[arg(long)]
        autoeject_timeout: Option<u16>,
        /// Challenge-response timeout in seconds
        #[arg(long)]
        chalresp_timeout: Option<u8>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Configure NFC applications
    Nfc {
        /// Enable an application (can be repeated)
        #[arg(short = 'e', long = "enable", action = clap::ArgAction::Append)]
        enable: Vec<String>,
        /// Disable an application (can be repeated)
        #[arg(long = "disable", action = clap::ArgAction::Append)]
        disable: Vec<String>,
        /// Enable all supported applications
        #[arg(short = 'a', long)]
        enable_all: bool,
        /// Disable all supported applications
        #[arg(short = 'D', long)]
        disable_all: bool,
        /// List enabled applications
        #[arg(short = 'l', long)]
        list: bool,
        /// Current lock code (hex)
        #[arg(short = 'L', long = "lock-code")]
        lock_code: Option<String>,
        /// Disable NFC until next USB power cycle
        #[arg(short = 'R', long)]
        restrict: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Set or change the configuration lock code
    SetLockCode {
        /// Current lock code (hex)
        #[arg(short = 'l', long = "lock-code")]
        lock_code: Option<String>,
        /// New lock code (hex)
        #[arg(short = 'n', long = "new-lock-code")]
        new_lock_code: Option<String>,
        /// Clear the lock code
        #[arg(short = 'c', long)]
        clear: bool,
        /// Generate a random lock code
        #[arg(short = 'g', long)]
        generate: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Set connection mode (for older YubiKeys)
    Mode {
        /// Mode string (e.g., OTP+FIDO+CCID) or number (0-6)
        mode: String,
        /// Enable touch-eject (CCID mode)
        #[arg(long)]
        touch_eject: bool,
        /// Auto-eject timeout in seconds
        #[arg(long)]
        autoeject_timeout: Option<u16>,
        /// Challenge-response timeout in seconds
        #[arg(long)]
        chalresp_timeout: Option<u8>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Factory reset the YubiKey (Bio only)
    Reset {
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum OathAction {
    /// Display general status of the OATH application
    Info {
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Reset the OATH application
    Reset {
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Manage OATH accounts
    #[command(subcommand)]
    Accounts(OathAccountAction),
    /// Manage OATH access (password)
    Access {
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// New password to set
        #[arg(long)]
        new_password: Option<String>,
        /// Remove the password
        #[arg(short, long)]
        clear: bool,
    },
}

#[derive(Subcommand)]
enum OathAccountAction {
    /// List stored OATH accounts
    List {
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
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
    /// Calculate OTP codes
    Code {
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Search filter
        query: Option<String>,
        /// Show hidden accounts
        #[arg(short = 'H', long)]
        show_hidden: bool,
        /// Output single code (for scripting)
        #[arg(short, long)]
        single: bool,
    },
    /// Add an OATH account
    Add {
        /// Account name
        name: String,
        /// Secret key (Base32 encoded)
        #[arg(short, long)]
        secret: Option<String>,
        /// Issuer name
        #[arg(short, long)]
        issuer: Option<String>,
        /// Credential type
        #[arg(short = 'o', long, default_value = "TOTP")]
        oath_type: String,
        /// Number of digits
        #[arg(long, default_value_t = 6)]
        digits: u8,
        /// Hash algorithm
        #[arg(short, long, default_value = "SHA1")]
        algorithm: String,
        /// Initial counter value for HOTP
        #[arg(short, long, default_value_t = 0)]
        counter: u32,
        /// Time period for TOTP (seconds)
        #[arg(short = 'P', long, default_value_t = 30)]
        period: u32,
        /// Require touch for code generation
        #[arg(short, long)]
        touch: bool,
        /// Confirm without prompting
        #[arg(short, long)]
        force: bool,
    },
    /// Delete an OATH account
    Delete {
        /// Account to delete (search query)
        query: String,
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Confirm without prompting
        #[arg(short, long)]
        force: bool,
    },
    /// Rename an OATH account
    Rename {
        /// Account to rename (search query)
        query: String,
        /// New name (issuer:name or just name)
        new_name: String,
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Confirm without prompting
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum OtpAction {
    /// Display OTP slot status
    Info,
    /// Swap the two OTP slot configurations
    Swap {
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Delete an OTP slot configuration
    Delete {
        /// Slot number (1 or 2)
        slot: String,
        /// Access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Configure an NDEF slot
    Ndef {
        /// Slot number (1 or 2)
        slot: String,
        /// URI or text prefix
        #[arg(long)]
        prefix: Option<String>,
        /// NDEF type
        #[arg(long, default_value = "URI")]
        ndef_type: String,
        /// Access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Program a Yubico OTP credential
    Yubiotp {
        /// Slot number (1 or 2)
        slot: String,
        /// Public ID (modhex)
        #[arg(long)]
        public_id: Option<String>,
        /// Private ID (hex)
        #[arg(long)]
        private_id: Option<String>,
        /// AES key (hex)
        #[arg(long)]
        key: Option<String>,
        /// Use serial number as public ID
        #[arg(short = 'S', long)]
        serial_public_id: bool,
        /// Generate random private ID
        #[arg(long)]
        generate_private_id: bool,
        /// Generate random key
        #[arg(long)]
        generate_key: bool,
        /// Append Enter after OTP
        #[arg(long)]
        enter: bool,
        /// Do not append Enter
        #[arg(long, conflicts_with = "enter")]
        no_enter: bool,
        /// Access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Program a static password
    Static {
        /// Slot number (1 or 2)
        slot: String,
        /// Password to store
        password: Option<String>,
        /// Generate a random password
        #[arg(short, long)]
        generate: bool,
        /// Length of generated password
        #[arg(short, long, default_value_t = 38)]
        length: usize,
        /// Keyboard layout
        #[arg(short, long, default_value = "MODHEX")]
        keyboard_layout: String,
        /// Append Enter after password
        #[arg(long)]
        enter: bool,
        /// Do not append Enter
        #[arg(long, conflicts_with = "enter")]
        no_enter: bool,
        /// Access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Program challenge-response (HMAC-SHA1)
    Chalresp {
        /// Slot number (1 or 2)
        slot: String,
        /// HMAC-SHA1 key (hex)
        key: Option<String>,
        /// Use TOTP mode
        #[arg(short, long)]
        totp: bool,
        /// Require touch
        #[arg(short = 'T', long)]
        touch: bool,
        /// Generate random key
        #[arg(short, long)]
        generate: bool,
        /// Access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Perform a challenge-response calculation
    Calculate {
        /// Slot number (1 or 2)
        slot: String,
        /// Challenge (hex)
        challenge: Option<String>,
        /// Use TOTP mode (time-based challenge)
        #[arg(short, long)]
        totp: bool,
        /// Number of digits for TOTP
        #[arg(long, default_value_t = 6)]
        digits: u8,
    },
    /// Program OATH-HOTP credential
    Hotp {
        /// Slot number (1 or 2)
        slot: String,
        /// HMAC key (hex)
        key: Option<String>,
        /// Number of digits (6 or 8)
        #[arg(long, default_value = "6")]
        digits: String,
        /// Initial counter value
        #[arg(long, default_value_t = 0)]
        counter: u32,
        /// Append Enter after code
        #[arg(long)]
        enter: bool,
        /// Do not append Enter
        #[arg(long, conflicts_with = "enter")]
        no_enter: bool,
        /// Access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Update slot settings
    Settings {
        /// Slot number (1 or 2)
        slot: String,
        /// Append Enter after output
        #[arg(long)]
        enter: bool,
        /// Do not append Enter
        #[arg(long, conflicts_with = "enter")]
        no_enter: bool,
        /// Keystroke pacing (0, 20, 40, or 60 ms)
        #[arg(long)]
        pacing: Option<u8>,
        /// Use numeric keypad for digits
        #[arg(long)]
        use_numeric_keypad: bool,
        /// Make serial visible over USB
        #[arg(long)]
        serial_usb_visible: bool,
        /// New access code (hex)
        #[arg(long)]
        new_access_code: Option<String>,
        /// Delete access code
        #[arg(long)]
        delete_access_code: bool,
        /// Current access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum PivAction {
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
    #[command(subcommand)]
    Objects(PivObjectAction),
}

#[derive(Subcommand)]
enum PivAccessAction {
    /// Change the PIV PIN
    ChangePin {
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short, long)]
        new_pin: Option<String>,
    },
    /// Change the PIV PUK
    ChangePuk {
        #[arg(short, long)]
        puk: Option<String>,
        #[arg(short, long)]
        new_puk: Option<String>,
    },
    /// Unblock the PIN using PUK
    UnblockPin {
        #[arg(short, long)]
        puk: Option<String>,
        #[arg(short, long)]
        new_pin: Option<String>,
    },
    /// Set PIN and PUK retry counts
    SetRetries {
        /// PIN retry count
        pin_retries: u8,
        /// PUK retry count
        puk_retries: u8,
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Change the management key
    ChangeManagementKey {
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short, long)]
        new_management_key: Option<String>,
        #[arg(short, long, default_value = "TDES")]
        algorithm: String,
        #[arg(short, long)]
        touch: bool,
        #[arg(short, long)]
        generate: bool,
        #[arg(short = 'f', long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum PivKeysAction {
    /// Generate an asymmetric key pair
    Generate {
        /// PIV slot
        slot: String,
        /// Output file for public key
        output: String,
        #[arg(short, long, default_value = "ECCP256")]
        algorithm: String,
        #[arg(long, default_value = "DEFAULT")]
        pin_policy: String,
        #[arg(long, default_value = "DEFAULT")]
        touch_policy: String,
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short = 'f', long, default_value = "PEM")]
        format: String,
    },
    /// Import a private key
    Import {
        /// PIV slot
        slot: String,
        /// Private key file
        key_file: String,
        #[arg(long, default_value = "DEFAULT")]
        pin_policy: String,
        #[arg(long, default_value = "DEFAULT")]
        touch_policy: String,
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
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
        #[arg(short = 'f', long, default_value = "PEM")]
        format: String,
    },
    /// Export public key
    Export {
        /// PIV slot
        slot: String,
        /// Output file
        output: String,
        #[arg(short = 'f', long, default_value = "PEM")]
        format: String,
    },
    /// Move key between slots
    Move {
        /// Source slot
        source: String,
        /// Destination slot
        dest: String,
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
    /// Delete key in slot
    Delete {
        /// PIV slot
        slot: String,
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

#[derive(Subcommand)]
enum PivCertAction {
    /// Export certificate from slot
    Export {
        /// PIV slot
        slot: String,
        /// Output file
        output: String,
        #[arg(short = 'f', long, default_value = "PEM")]
        format: String,
    },
    /// Import certificate to slot
    Import {
        /// PIV slot
        slot: String,
        /// Certificate file
        cert_file: String,
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short, long)]
        compress: bool,
    },
    /// Delete certificate from slot
    Delete {
        /// PIV slot
        slot: String,
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

#[derive(Subcommand)]
enum PivObjectAction {
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
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

#[derive(Subcommand)]
enum OpenpgpAction {
    /// Display OpenPGP status
    Info,
    /// Reset the OpenPGP application
    Reset {
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Manage access (PINs)
    #[command(subcommand)]
    Access(OpenpgpAccessAction),
    /// Manage keys
    #[command(subcommand)]
    Keys(OpenpgpKeysAction),
    /// Manage certificates
    #[command(subcommand)]
    Certificates(OpenpgpCertAction),
}

#[derive(Subcommand)]
enum OpenpgpAccessAction {
    /// Set PIN retry counts
    SetRetries {
        pin_retries: u8,
        reset_code_retries: u8,
        admin_pin_retries: u8,
        #[arg(short, long)]
        admin_pin: Option<String>,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Change user PIN
    ChangePin {
        #[arg(short = 'P', long)]
        pin: Option<String>,
        #[arg(short, long)]
        new_pin: Option<String>,
    },
    /// Change admin PIN
    ChangeAdminPin {
        #[arg(short, long)]
        admin_pin: Option<String>,
        #[arg(short, long)]
        new_admin_pin: Option<String>,
    },
    /// Change reset code
    ChangeResetCode {
        #[arg(short, long)]
        admin_pin: Option<String>,
        /// New reset code
        reset_code: String,
    },
    /// Unblock PIN
    UnblockPin {
        #[arg(short, long)]
        admin_pin: Option<String>,
        #[arg(long)]
        reset_code: Option<String>,
        #[arg(short, long)]
        new_pin: Option<String>,
    },
    /// Set signature PIN policy
    SetSignaturePolicy {
        /// Policy (once or always)
        policy: String,
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
}

#[derive(Subcommand)]
enum OpenpgpKeysAction {
    /// Show key metadata
    Info {
        /// Key reference (sig, dec, aut, att)
        key: String,
    },
    /// Set touch policy for a key
    SetTouch {
        /// Key reference
        key: String,
        /// Policy (off, on, fixed, cached, cached-fixed)
        policy: String,
        #[arg(short, long)]
        admin_pin: Option<String>,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Import attestation key
    Import {
        /// Key reference
        key: String,
        /// Key file
        key_file: String,
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
    /// Generate attestation certificate
    Attest {
        /// Key reference
        key: String,
        /// Output file
        output: String,
        #[arg(short = 'f', long, default_value = "PEM")]
        format: String,
    },
}

#[derive(Subcommand)]
enum OpenpgpCertAction {
    /// Export certificate
    Export {
        /// Key reference
        key: String,
        /// Output file
        output: String,
        #[arg(short = 'f', long, default_value = "PEM")]
        format: String,
    },
    /// Import certificate
    Import {
        /// Key reference
        key: String,
        /// Certificate file
        cert_file: String,
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
    /// Delete certificate
    Delete {
        /// Key reference
        key: String,
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
}

#[derive(Subcommand)]
enum HsmauthAction {
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
enum HsmauthCredAction {
    /// List credentials
    List,
    /// Generate asymmetric credential
    Generate {
        label: String,
        #[arg(short = 'c', long)]
        credential_password: Option<String>,
        #[arg(short, long)]
        management_key: Option<String>,
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
        #[arg(short, long)]
        management_key: Option<String>,
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
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short, long)]
        touch: bool,
    },
    /// Delete credential
    Delete {
        label: String,
        #[arg(short, long)]
        management_key: Option<String>,
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
        new_credential_password: String,
    },
}

#[derive(Subcommand)]
enum HsmauthAccessAction {
    /// Change management key
    ChangeManagementKey {
        #[arg(short, long)]
        management_key: Option<String>,
        #[arg(short, long)]
        new_management_key: Option<String>,
        #[arg(short, long)]
        generate: bool,
    },
}

#[derive(Subcommand)]
enum SecurityDomainAction {
    /// Display Security Domain info
    Info,
    /// Reset Security Domain
    Reset {
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Manage keys
    #[command(subcommand)]
    Keys(SecurityDomainKeysAction),
}

#[derive(Subcommand)]
enum SecurityDomainKeysAction {
    /// Generate EC key pair
    Generate {
        /// Key ID (hex)
        kid: String,
        /// Key Version Number (hex)
        kvn: String,
        /// Output file for public key
        output: String,
        /// Replace existing KVN
        #[arg(long)]
        replace_kvn: Option<String>,
    },
    /// Export certificate bundle
    Export {
        kid: String,
        kvn: String,
        output: String,
    },
    /// Delete a key
    Delete {
        kid: String,
        kvn: String,
        #[arg(short = 'f', long)]
        force: bool,
    },
}

/// Resolve a YubiKey device based on CLI options.
fn resolve_device(serial: Option<u32>, reader: &Option<String>) -> Result<YubiKeyDevice, CliError> {
    if let Some(reader_name) = reader {
        let readers = list_readers().map_err(|e| CliError(format!("Failed to list readers: {e}")))?;
        let matching: Vec<_> = readers
            .iter()
            .filter(|r| r.to_ascii_lowercase().contains(&reader_name.to_ascii_lowercase()))
            .collect();
        match matching.len() {
            0 => Err(CliError(format!("No reader matching '{reader_name}' found."))),
            1 => open_reader(matching[0])
                .map_err(|e| CliError(format!("Failed to open reader: {e}"))),
            _ => Err(CliError(format!(
                "Multiple readers matching '{reader_name}'. Be more specific."
            ))),
        }
    } else {
        let devices = list_devices()
            .map_err(|e| CliError(format!("Failed to list devices: {e}")))?;
        match (serial, devices.len()) {
            (None, 0) => Err(CliError("No YubiKey detected!".into())),
            (None, 1) => Ok(devices.into_iter().next().unwrap()),
            (None, n) => Err(CliError(format!(
                "Multiple YubiKeys detected ({n}). Use --device SERIAL to specify."
            ))),
            (Some(s), _) => devices
                .into_iter()
                .find(|d| d.serial() == Some(s))
                .ok_or_else(|| CliError(format!("YubiKey with serial {s} not found."))),
        }
    }
}

/// After resolving a device, apply version override if needed.
fn apply_version_override(dev: &YubiKeyDevice) {
    let info = dev.info();
    if info.version_qualifier.release_type != ReleaseType::Final {
        set_override_version(info.version_qualifier.version);
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List { serials, readers } => {
            if cli.device.is_some() {
                return Err(CliError("--device can't be used with 'list'.".into()));
            }
            if cli.reader.is_some() {
                return Err(CliError("--reader can't be used with 'list'.".into()));
            }
            list::run(serials, readers)
        }
        Commands::Info => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            info::run(&dev)
        }
        Commands::Config { action } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            match action {
                ConfigAction::Usb {
                    enable,
                    disable,
                    enable_all,
                    list,
                    lock_code,
                    touch_eject,
                    no_touch_eject,
                    autoeject_timeout,
                    chalresp_timeout,
                    force,
                } => config::run_usb(
                    &dev,
                    &enable,
                    &disable,
                    enable_all,
                    list,
                    lock_code.as_deref(),
                    touch_eject,
                    no_touch_eject,
                    autoeject_timeout,
                    chalresp_timeout,
                    force,
                ),
                ConfigAction::Nfc {
                    enable,
                    disable,
                    enable_all,
                    disable_all,
                    list,
                    lock_code,
                    restrict,
                    force,
                } => config::run_nfc(
                    &dev,
                    &enable,
                    &disable,
                    enable_all,
                    disable_all,
                    list,
                    lock_code.as_deref(),
                    restrict,
                    force,
                ),
                ConfigAction::SetLockCode {
                    lock_code,
                    new_lock_code,
                    clear,
                    generate,
                    force,
                } => config::run_set_lock_code(
                    &dev,
                    lock_code.as_deref(),
                    new_lock_code.as_deref(),
                    clear,
                    generate,
                    force,
                ),
                ConfigAction::Mode {
                    mode,
                    touch_eject,
                    autoeject_timeout,
                    chalresp_timeout,
                    force,
                } => config::run_mode(
                    &dev,
                    &mode,
                    touch_eject,
                    autoeject_timeout,
                    chalresp_timeout,
                    force,
                ),
                ConfigAction::Reset { force } => config::run_reset(&dev, force),
            }
        }
        Commands::Oath { action } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            match action {
                OathAction::Info { password } => {
                    oath::run_info(&dev, password.as_deref())
                }
                OathAction::Reset { force } => oath::run_reset(&dev, force),
                OathAction::Access {
                    password,
                    new_password,
                    clear,
                } => oath::run_access_change(
                    &dev,
                    password.as_deref(),
                    new_password.as_deref(),
                    clear,
                ),
                OathAction::Accounts(acct) => match acct {
                    OathAccountAction::List {
                        password,
                        show_hidden,
                        oath_type,
                        period,
                    } => oath::run_accounts_list(
                        &dev,
                        password.as_deref(),
                        show_hidden,
                        oath_type,
                        period,
                    ),
                    OathAccountAction::Code {
                        password,
                        query,
                        show_hidden,
                        single,
                    } => oath::run_accounts_code(
                        &dev,
                        password.as_deref(),
                        query.as_deref(),
                        show_hidden,
                        single,
                    ),
                    OathAccountAction::Add {
                        name,
                        secret,
                        issuer,
                        oath_type,
                        digits,
                        algorithm,
                        counter,
                        period,
                        touch,
                        force,
                    } => oath::run_accounts_add(
                        &dev,
                        None, // password from parent not available
                        &name,
                        secret.as_deref(),
                        issuer.as_deref(),
                        &oath_type,
                        digits,
                        &algorithm,
                        counter,
                        period,
                        touch,
                        force,
                    ),
                    OathAccountAction::Delete {
                        query,
                        password,
                        force,
                    } => oath::run_accounts_delete(
                        &dev,
                        password.as_deref(),
                        &query,
                        force,
                    ),
                    OathAccountAction::Rename {
                        query,
                        new_name,
                        password,
                        force,
                    } => oath::run_accounts_rename(
                        &dev,
                        password.as_deref(),
                        &query,
                        &new_name,
                        force,
                    ),
                },
            }
        }
        Commands::Otp { action } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            match action {
                OtpAction::Info => otp::run_info(&dev),
                OtpAction::Swap { force } => otp::run_swap(&dev, force),
                OtpAction::Delete {
                    slot,
                    access_code,
                    force,
                } => otp::run_delete(&dev, &slot, access_code.as_deref(), force),
                OtpAction::Ndef {
                    slot,
                    prefix,
                    ndef_type,
                    access_code,
                    force,
                } => otp::run_ndef(
                    &dev,
                    &slot,
                    prefix.as_deref(),
                    &ndef_type,
                    access_code.as_deref(),
                    force,
                ),
                OtpAction::Yubiotp {
                    slot,
                    public_id,
                    private_id,
                    key,
                    serial_public_id,
                    generate_private_id,
                    generate_key,
                    enter,
                    no_enter,
                    access_code,
                    force,
                } => {
                    let enter_flag = if enter {
                        Some(true)
                    } else if no_enter {
                        Some(false)
                    } else {
                        None
                    };
                    otp::run_yubiotp(
                        &dev,
                        &slot,
                        public_id.as_deref(),
                        private_id.as_deref(),
                        key.as_deref(),
                        serial_public_id,
                        generate_private_id,
                        generate_key,
                        enter_flag,
                        access_code.as_deref(),
                        force,
                    )
                }
                OtpAction::Static {
                    slot,
                    password,
                    generate,
                    length,
                    keyboard_layout,
                    enter,
                    no_enter,
                    access_code,
                    force,
                } => {
                    let enter_flag = if enter {
                        Some(true)
                    } else if no_enter {
                        Some(false)
                    } else {
                        None
                    };
                    otp::run_static(
                        &dev,
                        &slot,
                        password.as_deref(),
                        generate,
                        length,
                        &keyboard_layout,
                        enter_flag,
                        access_code.as_deref(),
                        force,
                    )
                }
                OtpAction::Chalresp {
                    slot,
                    key,
                    totp,
                    touch,
                    generate,
                    access_code,
                    force,
                } => otp::run_chalresp(
                    &dev,
                    &slot,
                    key.as_deref(),
                    totp,
                    touch,
                    generate,
                    access_code.as_deref(),
                    force,
                ),
                OtpAction::Calculate {
                    slot,
                    challenge,
                    totp,
                    digits,
                } => otp::run_calculate(
                    &dev,
                    &slot,
                    challenge.as_deref(),
                    totp,
                    digits,
                ),
                OtpAction::Hotp {
                    slot,
                    key,
                    digits,
                    counter,
                    enter,
                    no_enter,
                    access_code,
                    force,
                } => {
                    let enter_flag = if enter {
                        Some(true)
                    } else if no_enter {
                        Some(false)
                    } else {
                        None
                    };
                    otp::run_hotp(
                        &dev,
                        &slot,
                        key.as_deref(),
                        &digits,
                        counter,
                        enter_flag,
                        access_code.as_deref(),
                        force,
                    )
                }
                OtpAction::Settings {
                    slot,
                    enter,
                    no_enter,
                    pacing,
                    use_numeric_keypad,
                    serial_usb_visible,
                    new_access_code,
                    delete_access_code,
                    access_code,
                    force,
                } => {
                    let enter_flag = if enter {
                        Some(true)
                    } else if no_enter {
                        Some(false)
                    } else {
                        None
                    };
                    otp::run_settings(
                        &dev,
                        &slot,
                        enter_flag,
                        pacing,
                        if use_numeric_keypad { Some(true) } else { None },
                        if serial_usb_visible { Some(true) } else { None },
                        new_access_code.as_deref(),
                        delete_access_code,
                        access_code.as_deref(),
                        force,
                    )
                }
            }
        }
        Commands::Piv { action } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            match action {
                PivAction::Info => piv::run_info(&dev),
                PivAction::Reset { force } => piv::run_reset(&dev, force),
                PivAction::Access(access) => match access {
                    PivAccessAction::ChangePin { pin, new_pin } => {
                        piv::run_change_pin(&dev, pin.as_deref(), new_pin.as_deref())
                    }
                    PivAccessAction::ChangePuk { puk, new_puk } => {
                        piv::run_change_puk(&dev, puk.as_deref(), new_puk.as_deref())
                    }
                    PivAccessAction::UnblockPin { puk, new_pin } => {
                        piv::run_unblock_pin(&dev, puk.as_deref(), new_pin.as_deref())
                    }
                    PivAccessAction::SetRetries {
                        pin_retries,
                        puk_retries,
                        management_key,
                        pin,
                        force,
                    } => piv::run_set_retries(
                        &dev,
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
                    } => piv::run_change_management_key(
                        &dev,
                        management_key.as_deref(),
                        new_management_key.as_deref(),
                        &algorithm,
                        touch,
                        generate,
                        force,
                    ),
                },
                PivAction::Keys(keys) => match keys {
                    PivKeysAction::Generate {
                        slot,
                        output,
                        algorithm,
                        pin_policy,
                        touch_policy,
                        management_key,
                        pin,
                        format,
                    } => piv::run_keys_generate(
                        &dev,
                        &slot,
                        &output,
                        &algorithm,
                        &pin_policy,
                        &touch_policy,
                        management_key.as_deref(),
                        pin.as_deref(),
                        &format,
                    ),
                    PivKeysAction::Import {
                        slot,
                        key_file,
                        pin_policy,
                        touch_policy,
                        management_key,
                        pin,
                    } => piv::run_keys_import(
                        &dev,
                        &slot,
                        &key_file,
                        &pin_policy,
                        &touch_policy,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                    PivKeysAction::Info { slot } => piv::run_keys_info(&dev, &slot),
                    PivKeysAction::Attest {
                        slot,
                        output,
                        format,
                    } => piv::run_keys_attest(&dev, &slot, &output, &format),
                    PivKeysAction::Export {
                        slot,
                        output,
                        format,
                    } => piv::run_keys_export(&dev, &slot, &output, &format),
                    PivKeysAction::Move {
                        source,
                        dest,
                        management_key,
                        pin,
                    } => piv::run_keys_move(
                        &dev,
                        &source,
                        &dest,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                    PivKeysAction::Delete {
                        slot,
                        management_key,
                        pin,
                    } => piv::run_keys_delete(
                        &dev,
                        &slot,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                },
                PivAction::Certificates(certs) => match certs {
                    PivCertAction::Export {
                        slot,
                        output,
                        format,
                    } => piv::run_certificates_export(&dev, &slot, &output, &format),
                    PivCertAction::Import {
                        slot,
                        cert_file,
                        management_key,
                        pin,
                        compress,
                    } => piv::run_certificates_import(
                        &dev,
                        &slot,
                        &cert_file,
                        management_key.as_deref(),
                        pin.as_deref(),
                        compress,
                    ),
                    PivCertAction::Delete {
                        slot,
                        management_key,
                        pin,
                    } => piv::run_certificates_delete(
                        &dev,
                        &slot,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                },
                PivAction::Objects(objs) => match objs {
                    PivObjectAction::Export { object, output, pin } => {
                        piv::run_objects_export(&dev, &object, &output, pin.as_deref())
                    }
                    PivObjectAction::Import {
                        object,
                        data,
                        management_key,
                        pin,
                    } => piv::run_objects_import(
                        &dev,
                        &object,
                        &data,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                },
            }
        }
        Commands::Openpgp { action } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            match action {
                OpenpgpAction::Info => openpgp::run_info(&dev),
                OpenpgpAction::Reset { force } => openpgp::run_reset(&dev, force),
                OpenpgpAction::Access(access) => match access {
                    OpenpgpAccessAction::SetRetries {
                        pin_retries,
                        reset_code_retries,
                        admin_pin_retries,
                        admin_pin,
                        force,
                    } => openpgp::run_set_retries(
                        &dev,
                        pin_retries,
                        reset_code_retries,
                        admin_pin_retries,
                        admin_pin.as_deref(),
                        force,
                    ),
                    OpenpgpAccessAction::ChangePin { pin, new_pin } => {
                        openpgp::run_change_pin(&dev, pin.as_deref(), new_pin.as_deref())
                    }
                    OpenpgpAccessAction::ChangeAdminPin {
                        admin_pin,
                        new_admin_pin,
                    } => openpgp::run_change_admin_pin(
                        &dev,
                        admin_pin.as_deref(),
                        new_admin_pin.as_deref(),
                    ),
                    OpenpgpAccessAction::ChangeResetCode {
                        admin_pin,
                        reset_code,
                    } => openpgp::run_change_reset_code(
                        &dev,
                        admin_pin.as_deref(),
                        &reset_code,
                    ),
                    OpenpgpAccessAction::UnblockPin {
                        admin_pin,
                        reset_code,
                        new_pin,
                    } => openpgp::run_unblock_pin(
                        &dev,
                        admin_pin.as_deref(),
                        reset_code.as_deref(),
                        new_pin.as_deref(),
                    ),
                    OpenpgpAccessAction::SetSignaturePolicy { policy, admin_pin } => {
                        openpgp::run_set_signature_policy(
                            &dev,
                            &policy,
                            admin_pin.as_deref(),
                        )
                    }
                },
                OpenpgpAction::Keys(keys) => match keys {
                    OpenpgpKeysAction::Info { key } => openpgp::run_keys_info(&dev, &key),
                    OpenpgpKeysAction::SetTouch {
                        key,
                        policy,
                        admin_pin,
                        force,
                    } => openpgp::run_keys_set_touch(
                        &dev,
                        &key,
                        &policy,
                        admin_pin.as_deref(),
                        force,
                    ),
                    OpenpgpKeysAction::Import {
                        key,
                        key_file,
                        admin_pin,
                    } => openpgp::run_keys_import(
                        &dev,
                        &key,
                        &key_file,
                        admin_pin.as_deref(),
                    ),
                    OpenpgpKeysAction::Attest {
                        key,
                        output,
                        format,
                    } => openpgp::run_keys_attest(&dev, &key, &output, &format),
                },
                OpenpgpAction::Certificates(certs) => match certs {
                    OpenpgpCertAction::Export {
                        key,
                        output,
                        format,
                    } => openpgp::run_certificates_export(&dev, &key, &output, &format),
                    OpenpgpCertAction::Import {
                        key,
                        cert_file,
                        admin_pin,
                    } => openpgp::run_certificates_import(
                        &dev,
                        &key,
                        &cert_file,
                        admin_pin.as_deref(),
                    ),
                    OpenpgpCertAction::Delete { key, admin_pin } => {
                        openpgp::run_certificates_delete(&dev, &key, admin_pin.as_deref())
                    }
                },
            }
        }
        Commands::Hsmauth { action } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            match action {
                HsmauthAction::Info => hsmauth::run_info(&dev),
                HsmauthAction::Reset { force } => hsmauth::run_reset(&dev, force),
                HsmauthAction::Credentials(cred) => match cred {
                    HsmauthCredAction::List => hsmauth::run_credentials_list(&dev),
                    HsmauthCredAction::Generate {
                        label,
                        credential_password,
                        management_key,
                        touch,
                    } => hsmauth::run_credentials_generate(
                        &dev,
                        &label,
                        credential_password.as_deref(),
                        management_key.as_deref(),
                        touch,
                    ),
                    HsmauthCredAction::Symmetric {
                        label,
                        enc_key,
                        mac_key,
                        generate,
                        credential_password,
                        management_key,
                        touch,
                    } => hsmauth::run_credentials_symmetric(
                        &dev,
                        &label,
                        enc_key.as_deref(),
                        mac_key.as_deref(),
                        generate,
                        credential_password.as_deref(),
                        management_key.as_deref(),
                        touch,
                    ),
                    HsmauthCredAction::Derive {
                        label,
                        derivation_password,
                        credential_password,
                        management_key,
                        touch,
                    } => hsmauth::run_credentials_derive(
                        &dev,
                        &label,
                        &derivation_password,
                        credential_password.as_deref(),
                        management_key.as_deref(),
                        touch,
                    ),
                    HsmauthCredAction::Delete {
                        label,
                        management_key,
                        force,
                    } => hsmauth::run_credentials_delete(
                        &dev,
                        &label,
                        management_key.as_deref(),
                        force,
                    ),
                    HsmauthCredAction::ChangePassword {
                        label,
                        credential_password,
                        new_credential_password,
                    } => hsmauth::run_credentials_change_password(
                        &dev,
                        &label,
                        credential_password.as_deref(),
                        &new_credential_password,
                    ),
                },
                HsmauthAction::Access(access) => match access {
                    HsmauthAccessAction::ChangeManagementKey {
                        management_key,
                        new_management_key,
                        generate,
                    } => hsmauth::run_access_change_management_key(
                        &dev,
                        management_key.as_deref(),
                        new_management_key.as_deref(),
                        generate,
                    ),
                },
            }
        }
        Commands::SecurityDomain { action } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apply_version_override(&dev);
            match action {
                SecurityDomainAction::Info => securitydomain::run_info(&dev),
                SecurityDomainAction::Reset { force } => {
                    securitydomain::run_reset(&dev, force)
                }
                SecurityDomainAction::Keys(keys) => {
                    let parse_hex_u8 = |s: &str| -> Result<u8, CliError> {
                        u8::from_str_radix(
                            s.trim_start_matches("0x").trim_start_matches("0X"),
                            16,
                        )
                        .map_err(|_| CliError(format!("Invalid hex value: {s}")))
                    };
                    match keys {
                        SecurityDomainKeysAction::Generate {
                            kid,
                            kvn,
                            output,
                            replace_kvn,
                        } => {
                            let kid = parse_hex_u8(&kid)?;
                            let kvn = parse_hex_u8(&kvn)?;
                            let rkvn = replace_kvn
                                .as_deref()
                                .map(|s| parse_hex_u8(s))
                                .transpose()?;
                            securitydomain::run_keys_generate(&dev, kid, kvn, &output, rkvn)
                        }
                        SecurityDomainKeysAction::Export { kid, kvn, output } => {
                            let kid = parse_hex_u8(&kid)?;
                            let kvn = parse_hex_u8(&kvn)?;
                            securitydomain::run_keys_export(&dev, kid, kvn, &output)
                        }
                        SecurityDomainKeysAction::Delete { kid, kvn, force } => {
                            let kid = parse_hex_u8(&kid)?;
                            let kvn = parse_hex_u8(&kvn)?;
                            securitydomain::run_keys_delete(&dev, kid, kvn, force)
                        }
                    }
                }
            }
        }
        Commands::Apdu { apdus, no_pretty } => {
            let dev = resolve_device(cli.device, &cli.reader)?;
            apdu::run_apdu(&dev, &apdus, no_pretty)
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e.0);
        process::exit(1);
    }
}
