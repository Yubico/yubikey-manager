#![windows_subsystem = "console"]
use std::process;

use clap::{Parser, Subcommand};
use yubikit::core::{Transport, Version, set_override_version};
use yubikit::device::{YubiKeyDevice, list_devices};
use yubikit::management::{Capability, ReleaseType, UsbInterface};

mod apdu;
mod appdata;
mod cli_enums;
mod config;
mod diagnose;
mod hsmauth;
mod info;
mod list;
mod logging;
mod oath;
mod openpgp;
mod otp;
mod piv;
mod scp;
mod securitydomain;
mod util;

use cli_enums::*;

use scp::ScpParams;
use util::{CliError, read_file_or_stdin};

#[derive(Parser)]
#[command(
    name = "ykman",
    about = "Configure your YubiKey via the command line.",
    version,
    after_help = "Examples:\n\
      \n  List connected YubiKeys, only output serial number:\
      \n  $ ykman list --serials\
      \n\
      \n  Show information about YubiKey with serial number 123456:\
      \n  $ ykman --device 123456 info"
)]
struct Cli {
    /// Specify which YubiKey to interact with by serial number
    #[arg(short = 'd', long = "device", global = true)]
    device: Option<u32>,

    /// SCP credentials: private key and cert files, or SCP03 keys as K-ENC:K-MAC[:K-DEK] hex
    #[arg(long = "scp", global = true)]
    scp_cred: Vec<String>,

    /// CA certificate for SCP11 card key verification (PEM/DER file)
    #[arg(long = "scp-ca", global = true)]
    scp_ca: Option<String>,

    /// Card key reference for SCP (KID KVN, hex)
    #[arg(long = "scp-sd", global = true, num_args = 2, value_names = ["KID", "KVN"])]
    scp_sd: Option<Vec<String>>,

    /// OCE key reference for SCP (KID KVN, hex)
    #[arg(long = "scp-oce", global = true, num_args = 2, value_names = ["KID", "KVN"])]
    scp_oce: Option<Vec<String>>,

    /// Password for SCP credential file
    #[arg(long = "scp-password", global = true)]
    scp_password: Option<String>,

    /// Show diagnostic information
    #[arg(long = "diagnose")]
    diagnose: bool,

    /// Enable logging at given verbosity level
    #[arg(short = 'l', long = "log-level")]
    log_level: Option<logging::LogLevel>,

    /// Write log to FILE instead of printing to stderr (requires --log-level)
    #[arg(long = "log-file", value_name = "FILE")]
    log_file: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, clap::ValueEnum)]
enum CliAppName {
    Otp,
    Management,
    Openpgp,
    Oath,
    Piv,
    Fido,
    Hsmauth,
    #[value(name = "secure-domain")]
    SecureDomain,
}

impl CliAppName {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Otp => "otp",
            Self::Management => "management",
            Self::Openpgp => "openpgp",
            Self::Oath => "oath",
            Self::Piv => "piv",
            Self::Fido => "fido",
            Self::Hsmauth => "hsmauth",
            Self::SecureDomain => "secure-domain",
        }
    }
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
    Info {
        /// Check FIPS approved mode status
        #[arg(short = 'c', long)]
        check_fips: bool,
    },
    /// Enable or disable applications and settings
    #[command(after_help = "Examples:\n\
      \n  Disable PIV over NFC:\
      \n  $ ykman config nfc --disable piv\
      \n\
      \n  Enable all applications over USB:\
      \n  $ ykman config usb --enable-all\
      \n\
      \n  Generate and set a random application lock code:\
      \n  $ ykman config set-lock-code --generate")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Manage the OATH application
    #[command(after_help = "Examples:\n\
      \n  Generate codes for accounts starting with 'yubi':\
      \n  $ ykman oath accounts code yubi\
      \n\
      \n  Add an account with the secret key f5up4ub3dw and the name yubico,\
      \n  which requires touch:\
      \n  $ ykman oath accounts add yubico f5up4ub3dw --touch\
      \n\
      \n  Set a password for the OATH application:\
      \n  $ ykman oath access change")]
    Oath {
        #[command(subcommand)]
        action: OathAction,
    },
    /// Manage the YubiKey OTP application
    #[command(after_help = "Examples:\n\
      \n  Swap the configurations between the two slots:\
      \n  $ ykman otp swap\
      \n\
      \n  Program a random challenge-response credential to slot 2:\
      \n  $ ykman otp chalresp --generate 2\
      \n\
      \n  Program a Yubico OTP credential to slot 1, using the serial as public id:\
      \n  $ ykman otp yubiotp 1 --serial-public-id\
      \n\
      \n  Program a random 38 characters long static password to slot 2:\
      \n  $ ykman otp static --generate 2 --length 38\
      \n\
      \n  Remove a currently set access code from slot 2:\
      \n  $ ykman otp --access-code 0123456789ab settings 2 --delete-access-code")]
    Otp {
        /// 6 byte access code (use "-" to prompt for input)
        #[arg(long = "access-code")]
        access_code: Option<String>,
        #[command(subcommand)]
        action: OtpAction,
    },
    /// Manage the PIV application
    #[command(after_help = "Examples:\n\
      \n  Generate an ECC P-256 private key and a self-signed certificate in\
      \n  slot 9a:\
      \n  $ ykman piv keys generate --algorithm eccp256 9a pubkey.pem\
      \n  $ ykman piv certificates generate --subject \"CN=yubico\" 9a pubkey.pem\
      \n\
      \n  Change the PIN from 123456 to 654321:\
      \n  $ ykman piv access change-pin --pin 123456 --new-pin 654321\
      \n\
      \n  Reset all PIV data and restore default settings:\
      \n  $ ykman piv reset")]
    Piv {
        #[command(subcommand)]
        action: PivAction,
    },
    /// Manage the OpenPGP application
    #[command(after_help = "Examples:\n\
      \n  Set the retries for PIN, Reset Code and Admin PIN to 10:\
      \n  $ ykman openpgp access set-retries 10 10 10\
      \n\
      \n  Require touch to use the authentication key:\
      \n  $ ykman openpgp keys set-touch aut on")]
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
    #[command(after_help = "Examples:\n\
      \n  Select the OATH application, send a LIST instruction (0xA1),\
      \n  and make sure we get sw=9000 (these are equivalent):\
      \n  $ ykman apdu a40400:a000000527210101=9000 a1=9000\
      \n    or\
      \n  $ ykman apdu -a oath a1=\
      \n\
      \n  Factory reset the OATH application:\
      \n  $ ykman apdu -a oath 04dead\
      \n    or\
      \n  $ ykman apdu a40400:a000000527210101 04dead\
      \n    or (using full-apdu mode)\
      \n  $ ykman apdu -s 00a4040008a000000527210101 -s 0004dead\
      \n\
      \n  Get 8 random bytes from the OpenPGP application:\
      \n  $ ykman apdu -a openpgp 84/08=")]
    Apdu {
        /// APDUs to send (format: [CLA]INS[P1P2][:DATA][/LE][=EXPECTED_SW])
        apdus: Vec<String>,
        /// Print only hex output
        #[arg(short = 'x', long)]
        no_pretty: bool,
        /// Select application before sending APDUs
        #[arg(short = 'a', long)]
        app: Option<CliAppName>,
        /// Force short APDUs
        #[arg(long)]
        short: bool,
        /// Send full hex APDU strings (alternative to positional)
        #[arg(short = 's', long = "send-apdu")]
        send_apdu: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Configure USB applications
    Usb {
        /// Enable an application (can be repeated)
        #[arg(short = 'e', long = "enable", action = clap::ArgAction::Append)]
        enable: Vec<CliCapability>,
        /// Disable an application (can be repeated)
        #[arg(long = "disable", action = clap::ArgAction::Append)]
        disable: Vec<CliCapability>,
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
        enable: Vec<CliCapability>,
        /// Disable an application (can be repeated)
        #[arg(long = "disable", action = clap::ArgAction::Append)]
        disable: Vec<CliCapability>,
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
    /// Manage connection modes (USB Interfaces).
    ///
    /// This command is generally used with YubiKeys prior to the 5 series.
    /// Use "ykman config usb" for more granular control on YubiKey 5 and later.
    ///
    /// MODE can be a string, such as "OTP+FIDO+CCID", or a shortened form: "o+f+c".
    /// It can also be a mode number.
    #[command(after_help = "Examples:\n\
      \n  Set the OTP and FIDO mode:\
      \n  $ ykman config mode OTP+FIDO\
      \n\
      \n  Set the CCID only mode and use touch to eject the smart card:\
      \n  $ ykman config mode CCID --touch-eject")]
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
    #[command(subcommand)]
    Access(OathAccessAction),
}

#[derive(Subcommand)]
enum OathAccessAction {
    /// Change the password used to protect OATH accounts
    Change {
        /// Current password to unlock OATH
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// New password to set
        #[arg(short = 'n', long)]
        new_password: Option<String>,
        /// Remove the password
        #[arg(short = 'c', long)]
        clear: bool,
        /// Remember the new password on this computer
        #[arg(long)]
        remember: bool,
    },
    /// Remember the password for the current YubiKey on this computer
    Remember {
        /// Password to store
        #[arg(short, long)]
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
enum OathAccountAction {
    /// List stored OATH accounts
    List {
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(long)]
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
    /// Calculate OTP codes
    Code {
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(long)]
        remember: bool,
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
        secret: Option<String>,
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(long)]
        remember: bool,
        /// Issuer name
        #[arg(short, long)]
        issuer: Option<String>,
        /// Credential type
        #[arg(short = 'o', long, default_value = "totp")]
        oath_type: CliOathType,
        /// Number of digits
        #[arg(long, default_value = "6")]
        digits: CliOathDigits,
        /// Hash algorithm
        #[arg(short, long, default_value = "sha1")]
        algorithm: CliOathAlgorithm,
        /// Initial counter value for HOTP
        #[arg(short, long, default_value_t = 0)]
        counter: u32,
        /// Time period for TOTP (seconds)
        #[arg(short = 'P', long, default_value_t = 30)]
        period: u32,
        /// Generate a random credential key
        #[arg(short, long)]
        generate: bool,
        /// Require touch for code generation
        #[arg(short, long)]
        touch: bool,
        /// Confirm without prompting
        #[arg(short, long)]
        force: bool,
    },
    /// Add new account(s) from a PSKC file
    Import {
        /// PSKC file to import
        file: String,
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(long)]
        remember: bool,
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
        /// Remember the password on this computer
        #[arg(long)]
        remember: bool,
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
        /// Remember the password on this computer
        #[arg(long)]
        remember: bool,
        /// Confirm without prompting
        #[arg(short, long)]
        force: bool,
    },
    /// Add account from otpauth:// URI
    Uri {
        /// otpauth:// URI string
        uri: String,
        /// Password to unlock OATH
        #[arg(short, long)]
        password: Option<String>,
        /// Remember the password on this computer
        #[arg(long)]
        remember: bool,
        /// Require touch for code generation
        #[arg(short, long)]
        touch: bool,
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
        slot: CliOtpSlot,
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
        slot: CliOtpSlot,
        /// URI or text prefix
        #[arg(short = 'p', long)]
        prefix: Option<String>,
        /// NDEF type
        #[arg(short = 't', long, default_value = "uri")]
        ndef_type: CliNdefType,
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
        slot: CliOtpSlot,
        /// Public ID (modhex)
        #[arg(short = 'P', long)]
        public_id: Option<String>,
        /// Private ID (hex)
        #[arg(short = 'p', long)]
        private_id: Option<String>,
        /// AES key (hex)
        #[arg(short = 'k', long)]
        key: Option<String>,
        /// Use serial number as public ID
        #[arg(short = 'S', long)]
        serial_public_id: bool,
        /// Generate random private ID
        #[arg(short = 'g', long)]
        generate_private_id: bool,
        /// Generate random key
        #[arg(short = 'G', long)]
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
        /// File path to output configuration
        #[arg(short = 'O', long)]
        config_output: Option<String>,
    },
    /// Program a static password
    Static {
        /// Slot number (1 or 2)
        slot: CliOtpSlot,
        /// Password to store
        password: Option<String>,
        /// Generate a random password
        #[arg(short, long)]
        generate: bool,
        /// Length of generated password
        #[arg(short, long, default_value_t = 38)]
        length: usize,
        /// Keyboard layout
        #[arg(short, long, default_value = "modhex")]
        keyboard_layout: CliKeyboardLayout,
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
        slot: CliOtpSlot,
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
        slot: CliOtpSlot,
        /// Challenge (hex)
        challenge: Option<String>,
        /// Use TOTP mode (time-based challenge)
        #[arg(short, long)]
        totp: bool,
        /// Number of digits for TOTP
        #[arg(long, default_value = "6")]
        digits: CliCalcDigits,
    },
    /// Program OATH-HOTP credential
    Hotp {
        /// Slot number (1 or 2)
        slot: CliOtpSlot,
        /// HMAC key (hex)
        key: Option<String>,
        /// Number of digits (6 or 8)
        #[arg(long, default_value = "6")]
        digits: CliHotpDigits,
        /// Initial counter value
        #[arg(short = 'c', long, default_value_t = 0)]
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
        /// Token identifier string
        #[arg(short = 'i', long)]
        identifier: Option<String>,
    },
    /// Update slot settings
    Settings {
        /// Slot number (1 or 2)
        slot: CliOtpSlot,
        /// Append Enter after output
        #[arg(long)]
        enter: bool,
        /// Do not append Enter
        #[arg(long, conflicts_with = "enter")]
        no_enter: bool,
        /// Keystroke pacing in ms
        #[arg(short = 'p', long)]
        pacing: Option<CliPacing>,
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
        #[arg(short, long, default_value = "tdes")]
        algorithm: CliMgmtKeyType,
        #[arg(short, long)]
        touch: bool,
        #[arg(short, long)]
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
enum PivKeysAction {
    /// Generate an asymmetric key pair
    Generate {
        /// PIV slot
        slot: String,
        /// Output file for public key
        output: String,
        #[arg(short, long, default_value = "eccp256")]
        algorithm: CliKeyType,
        #[arg(long, default_value = "default")]
        pin_policy: CliPinPolicy,
        #[arg(long, default_value = "default")]
        touch_policy: CliTouchPolicy,
        #[arg(short, long)]
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
        #[arg(short, long)]
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
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
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
        #[arg(short, long)]
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
        #[arg(short, long)]
        subject: String,
        /// Validity period in days
        #[arg(long, default_value_t = 365)]
        valid_days: u32,
        /// Hash algorithm
        #[arg(short = 'a', long, default_value = "sha256")]
        hash_algorithm: CliHashAlgorithm,
        #[arg(short, long)]
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
        #[arg(short, long)]
        subject: String,
        /// Hash algorithm
        #[arg(short = 'a', long, default_value = "sha256")]
        hash_algorithm: CliHashAlgorithm,
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
    /// Generate a data object (CHUID or CCC)
    Generate {
        /// Object type: CHUID or CCC
        object: String,
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
        #[arg(short = 'R', long)]
        reset_code: Option<String>,
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
        /// Policy
        policy: CliOpenpgpPinPolicy,
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
}

#[derive(Subcommand)]
enum OpenpgpKeysAction {
    /// Show key metadata
    Info {
        /// Key reference
        key: CliKeyRef,
    },
    /// Set touch policy for a key
    SetTouch {
        /// Key reference
        key: CliKeyRef,
        /// Touch policy
        policy: CliUif,
        #[arg(short, long)]
        admin_pin: Option<String>,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Import attestation key
    Import {
        /// Key reference
        key: CliKeyRef,
        /// Key file
        key_file: String,
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
    /// Generate attestation certificate
    Attest {
        /// Key reference
        key: CliKeyRef,
        /// Output file
        output: String,
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
        /// PIN for attestation
        #[arg(short = 'P', long)]
        pin: Option<String>,
    },
}

#[derive(Subcommand)]
enum OpenpgpCertAction {
    /// Export certificate
    Export {
        /// Key reference
        key: CliKeyRef,
        /// Output file
        output: String,
        #[arg(short = 'F', long, default_value = "pem")]
        format: CliFormat,
    },
    /// Import certificate
    Import {
        /// Key reference
        key: CliKeyRef,
        /// Certificate file
        cert_file: String,
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
    /// Delete certificate
    Delete {
        /// Key reference
        key: CliKeyRef,
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
        management_key: Option<String>,
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
enum HsmauthAccessAction {
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
    /// Import a key (SCP03 static keys or SCP11 certificate/private key)
    Import {
        /// Key ID (hex)
        kid: String,
        /// Key Version Number (hex)
        kvn: String,
        /// Key type
        #[arg(short = 't', long, default_value = "scp11")]
        key_type: CliSdKeyType,
        /// For SCP03: K-ENC:K-MAC:K-DEK hex keys. For SCP11: PEM file with certificate(s) and/or private key
        input: String,
        /// Replace existing KVN
        #[arg(long)]
        replace_kvn: Option<String>,
        /// Password for decrypting private key files
        #[arg(short = 'p', long)]
        password: Option<String>,
    },
    /// Set certificate serial number allowlist
    SetAllowlist {
        /// Key ID (hex)
        kid: String,
        /// Key Version Number (hex)
        kvn: String,
        /// Certificate serial numbers (hex)
        serials: Vec<String>,
    },
}

/// Which transports to scan when resolving a device.
/// Select a single YubiKey from a device list, optionally filtered by serial.
fn select_device(
    devices: Vec<YubiKeyDevice>,
    serial: Option<u32>,
) -> Result<YubiKeyDevice, CliError> {
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

/// Enumerate devices and select one, optionally by serial number.
fn require_device(serial: Option<u32>) -> Result<YubiKeyDevice, CliError> {
    let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
    let devices =
        list_devices(all).map_err(|e| CliError(format!("Failed to list devices: {e}")))?;
    select_device(devices, serial)
}

/// Check that a capability is available and enabled on the device.
///
/// Returns an error distinguishing between "not supported" and "disabled".
fn check_capability(dev: &YubiKeyDevice, capability: Capability) -> Result<(), CliError> {
    let info = dev.info();
    let transport = dev.transport();
    let name = capability_name(capability);

    let supported = info
        .supported_capabilities
        .get(&transport)
        .copied()
        .unwrap_or(Capability::NONE);

    if !supported.contains(capability) {
        return Err(CliError(format!(
            "{name} is not available on this YubiKey."
        )));
    }

    let enabled = info
        .config
        .enabled_capabilities
        .get(&transport)
        .copied()
        .unwrap_or(Capability::NONE);

    if !enabled.contains(capability) {
        let transport_name = match transport {
            Transport::Usb => "USB",
            Transport::Nfc => "NFC",
        };
        return Err(CliError(format!(
            "{name} is currently disabled on this YubiKey over {transport_name}.\n\n\
             Use 'ykman config {transport}' to enable it.",
            transport = match transport {
                Transport::Usb => "usb",
                Transport::Nfc => "nfc",
            }
        )));
    }

    Ok(())
}

fn capability_name(cap: Capability) -> &'static str {
    if cap == Capability::OATH {
        "OATH"
    } else if cap == Capability::PIV {
        "PIV"
    } else if cap == Capability::OPENPGP {
        "OpenPGP"
    } else if cap == Capability::OTP {
        "OTP"
    } else if cap == Capability::HSMAUTH {
        "YubiHSM Auth"
    } else {
        "Application"
    }
}

/// Check that the device firmware version meets a minimum requirement.
fn check_version(dev: &YubiKeyDevice, required: Version, feature: &str) -> Result<(), CliError> {
    let version = dev.info().version;
    if version < required {
        Err(CliError(format!(
            "{feature} requires YubiKey {required} or later (this device has {version}).",
        )))
    } else {
        Ok(())
    }
}

/// Check that the device supports the SCP parameters being used.
fn check_scp_version(dev: &YubiKeyDevice, scp: &ScpParams) -> Result<(), CliError> {
    if scp.scp03_keys.is_some() {
        check_version(dev, Version(5, 3, 0), "SCP03")?;
    }
    if scp.scp11_private_key.is_some()
        || !scp.scp11_certificates.is_empty()
        || scp.sd_ref.is_some()
        || scp.oce_ref.is_some()
        || scp.ca_cert.is_some()
    {
        check_version(dev, Version(5, 7, 2), "SCP11")?;
    }
    Ok(())
}

/// After resolving a device, apply version override if needed.
fn parse_scp_params(cli: &Cli) -> Result<ScpParams, CliError> {
    let mut params = ScpParams::default();

    // Parse --scp-sd
    if let Some(ref sd) = cli.scp_sd {
        let kid = parse_hex_u8(&sd[0])?;
        let kvn = parse_hex_u8(&sd[1])?;
        params.sd_ref = Some((kid, kvn));
    }

    // Parse --scp-oce
    if let Some(ref oce) = cli.scp_oce {
        let kid = parse_hex_u8(&oce[0])?;
        let kvn = parse_hex_u8(&oce[1])?;
        params.oce_ref = Some((kid, kvn));
    }

    // Parse --scp-ca
    if let Some(ref ca_path) = cli.scp_ca {
        let data = read_file_or_stdin(ca_path)?;
        let der = if let Ok(text) = std::str::from_utf8(&data) {
            if text.contains("-----BEGIN") {
                pem_decode_first(text)?
            } else {
                data
            }
        } else {
            data
        };
        params.ca_cert = Some(der);
    }

    // Parse --scp credentials
    if !cli.scp_cred.is_empty() {
        let first = &cli.scp_cred[0];
        // Check if it looks like SCP03 hex keys: K-ENC:K-MAC[:K-DEK]
        let parts: Vec<&str> = first.split(':').collect();
        if (parts.len() == 2 || parts.len() == 3)
            && parts
                .iter()
                .all(|p| p.len() == 32 && p.chars().all(|c| c.is_ascii_hexdigit()))
        {
            // SCP03 keys
            let key_enc =
                hex::decode(parts[0]).map_err(|_| CliError("Invalid SCP03 K-ENC hex.".into()))?;
            let key_mac =
                hex::decode(parts[1]).map_err(|_| CliError("Invalid SCP03 K-MAC hex.".into()))?;
            let key_dek = if parts.len() == 3 {
                Some(
                    hex::decode(parts[2])
                        .map_err(|_| CliError("Invalid SCP03 K-DEK hex.".into()))?,
                )
            } else {
                None
            };
            params.scp03_keys = Some((key_enc, key_mac, key_dek));
        } else {
            // SCP11: files (private key + certificates)
            for path in &cli.scp_cred {
                let data = read_file_or_stdin(path)?;
                let pem_text = std::str::from_utf8(&data).ok();

                if let Some(text) = pem_text {
                    if text.contains("-----BEGIN") {
                        // Could be private key or certificates
                        if text.contains("PRIVATE KEY") {
                            let der = pem_decode_first(text)?;
                            // Extract raw 32-byte key from PKCS#8 or SEC1 DER
                            let raw_key = extract_ec_private_key(&der)?;
                            params.scp11_private_key = Some(raw_key);
                        }
                        // Also extract any certificates
                        for cert_der in pem_decode_all_certs(text)? {
                            params.scp11_certificates.push(cert_der);
                        }
                    } else {
                        // Raw DER — try to detect type
                        params.scp11_certificates.push(data);
                    }
                } else {
                    params.scp11_certificates.push(data);
                }
            }
        }
    }

    Ok(params)
}

fn parse_hex_u8(s: &str) -> Result<u8, CliError> {
    u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|_| CliError(format!("Invalid hex value: {s}")))
}

fn pem_decode_first(text: &str) -> Result<Vec<u8>, CliError> {
    use base64::Engine;
    let mut in_block = false;
    let mut b64 = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| CliError(format!("Invalid PEM data: {e}")))
}

fn pem_decode_all_certs(text: &str) -> Result<Vec<Vec<u8>>, CliError> {
    use base64::Engine;
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            in_cert = true;
            b64.clear();
            continue;
        }
        if line.starts_with("-----END CERTIFICATE") {
            in_cert = false;
            let der = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| CliError(format!("Invalid PEM cert: {e}")))?;
            certs.push(der);
            continue;
        }
        if in_cert {
            b64.push_str(line.trim());
        }
    }
    Ok(certs)
}

fn extract_ec_private_key(der: &[u8]) -> Result<Vec<u8>, CliError> {
    // Very minimal PKCS#8 / SEC1 extraction for P-256 keys
    // PKCS#8: SEQUENCE { version, algorithmIdentifier, OCTET STRING { SEC1 key } }
    // SEC1 EC: SEQUENCE { version, OCTET STRING (privkey), [0] OID, [1] pubkey }
    // We look for a 32-byte octet string which is the raw private key
    if der.len() < 34 {
        return Err(CliError("EC private key too short.".into()));
    }
    // Search for 0x04 0x20 (OCTET STRING, 32 bytes) pattern
    for i in 0..der.len().saturating_sub(33) {
        if der[i] == 0x04 && der[i + 1] == 0x20 {
            return Ok(der[i + 2..i + 34].to_vec());
        }
    }
    Err(CliError(
        "Could not extract EC private key from DER.".into(),
    ))
}

fn apply_version_override(dev: &YubiKeyDevice) {
    let info = dev.info();
    if info.version_qualifier.release_type != ReleaseType::Final {
        set_override_version(info.version_qualifier.version);
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Initialize logging
    if let Some(level) = cli.log_level {
        logging::init_logging(level, cli.log_file.as_deref()).map_err(CliError)?;
        log::info!(
            "System info:\n  ykman:  {}\n  Platform:  {}\n  Arch:      {}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        );
    } else if cli.log_file.is_some() {
        return Err(CliError(
            "--log-file requires specifying --log-level.".into(),
        ));
    }

    // Handle --diagnose
    if cli.diagnose {
        return diagnose::run_diagnose();
    }

    // Parse SCP params before consuming command
    let scp_params = parse_scp_params(&cli)?;

    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            cmd.print_help().ok();
            println!();
            std::process::exit(0);
        }
    };

    match command {
        Commands::List { serials, readers } => {
            if cli.device.is_some() {
                return Err(CliError("--device can't be used with 'list'.".into()));
            }
            list::run(serials, readers)
        }
        Commands::Info { check_fips } => {
            let dev = require_device(cli.device)?;
            apply_version_override(&dev);
            info::run(&dev, check_fips)
        }
        Commands::Config { action } => {
            let dev = require_device(cli.device)?;
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
            let dev = require_device(cli.device)?;
            check_capability(&dev, Capability::OATH)?;
            check_scp_version(&dev, &scp_params)?;
            apply_version_override(&dev);
            match action {
                OathAction::Info { password } => {
                    oath::run_info(&dev, &scp_params, password.as_deref())
                }
                OathAction::Reset { force } => oath::run_reset(&dev, &scp_params, force),
                OathAction::Access(access) => match access {
                    OathAccessAction::Change {
                        password,
                        new_password,
                        clear,
                        remember,
                    } => oath::run_access_change(
                        &dev,
                        &scp_params,
                        password.as_deref(),
                        new_password.as_deref(),
                        clear,
                        remember,
                    ),
                    OathAccessAction::Remember { password } => {
                        oath::run_access_remember(&dev, &scp_params, password.as_deref())
                    }
                    OathAccessAction::Forget { all } => {
                        oath::run_access_forget(&dev, &scp_params, all)
                    }
                },
                OathAction::Accounts(acct) => match acct {
                    OathAccountAction::List {
                        password,
                        remember,
                        show_hidden,
                        oath_type,
                        period,
                    } => oath::run_accounts_list(
                        &dev,
                        &scp_params,
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
                    } => oath::run_accounts_code(
                        &dev,
                        &scp_params,
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
                        generate: _generate,
                        touch,
                        force,
                    } => oath::run_accounts_add(
                        &dev,
                        &scp_params,
                        password.as_deref(),
                        remember,
                        &name,
                        secret.as_deref(),
                        issuer.as_deref(),
                        oath_type,
                        digits,
                        algorithm,
                        counter,
                        period,
                        touch,
                        force,
                    ),
                    OathAccountAction::Delete {
                        query,
                        password,
                        remember,
                        force,
                    } => oath::run_accounts_delete(
                        &dev,
                        &scp_params,
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
                    } => oath::run_accounts_rename(
                        &dev,
                        &scp_params,
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
                    } => oath::run_accounts_uri(
                        &dev,
                        &scp_params,
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
                    } => oath::run_accounts_import(
                        &dev,
                        &scp_params,
                        &file,
                        password.as_deref(),
                        remember,
                        touch,
                        force,
                    ),
                },
            }
        }
        Commands::Otp {
            access_code,
            action,
        } => {
            let dev = require_device(cli.device)?;
            check_capability(&dev, Capability::OTP)?;
            check_scp_version(&dev, &scp_params)?;
            apply_version_override(&dev);
            // access_code from parent command overrides per-subcommand access_code
            let _ = access_code; // available for subcommands that need it
            match action {
                OtpAction::Info => otp::run_info(&dev, &scp_params),
                OtpAction::Swap { force } => otp::run_swap(&dev, &scp_params, force),
                OtpAction::Delete {
                    slot,
                    access_code,
                    force,
                } => otp::run_delete(&dev, &scp_params, slot, access_code.as_deref(), force),
                OtpAction::Ndef {
                    slot,
                    prefix,
                    ndef_type,
                    access_code,
                    force,
                } => otp::run_ndef(
                    &dev,
                    &scp_params,
                    slot,
                    prefix.as_deref(),
                    ndef_type.into(),
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
                    config_output,
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
                        &scp_params,
                        slot,
                        public_id.as_deref(),
                        private_id.as_deref(),
                        key.as_deref(),
                        serial_public_id,
                        generate_private_id,
                        generate_key,
                        enter_flag,
                        access_code.as_deref(),
                        force,
                        config_output.as_deref(),
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
                        &scp_params,
                        slot,
                        password.as_deref(),
                        generate,
                        length,
                        keyboard_layout,
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
                    &scp_params,
                    slot,
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
                } => {
                    otp::run_calculate(&dev, &scp_params, slot, challenge.as_deref(), totp, digits)
                }
                OtpAction::Hotp {
                    slot,
                    key,
                    digits,
                    counter,
                    enter,
                    no_enter,
                    access_code,
                    force,
                    identifier,
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
                        &scp_params,
                        slot,
                        key.as_deref(),
                        digits,
                        counter,
                        enter_flag,
                        access_code.as_deref(),
                        force,
                        identifier.as_deref(),
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
                        &scp_params,
                        slot,
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
            let dev = require_device(cli.device)?;
            check_capability(&dev, Capability::PIV)?;
            check_scp_version(&dev, &scp_params)?;
            apply_version_override(&dev);
            match action {
                PivAction::Info => piv::run_info(&dev, &scp_params),
                PivAction::Reset { force } => piv::run_reset(&dev, &scp_params, force),
                PivAction::Access(access) => match access {
                    PivAccessAction::ChangePin { pin, new_pin } => {
                        piv::run_change_pin(&dev, &scp_params, pin.as_deref(), new_pin.as_deref())
                    }
                    PivAccessAction::ChangePuk { puk, new_puk } => {
                        piv::run_change_puk(&dev, &scp_params, puk.as_deref(), new_puk.as_deref())
                    }
                    PivAccessAction::UnblockPin { puk, new_pin } => {
                        piv::run_unblock_pin(&dev, &scp_params, puk.as_deref(), new_pin.as_deref())
                    }
                    PivAccessAction::SetRetries {
                        pin_retries,
                        puk_retries,
                        management_key,
                        pin,
                        force,
                    } => piv::run_set_retries(
                        &dev,
                        &scp_params,
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
                    } => piv::run_change_management_key(
                        &dev,
                        &scp_params,
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
                        &scp_params,
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
                    } => piv::run_keys_import(
                        &dev,
                        &scp_params,
                        &slot,
                        &key_file,
                        pin_policy,
                        touch_policy,
                        management_key.as_deref(),
                        pin.as_deref(),
                        password.as_deref(),
                    ),
                    PivKeysAction::Info { slot } => piv::run_keys_info(&dev, &scp_params, &slot),
                    PivKeysAction::Attest {
                        slot,
                        output,
                        format,
                    } => piv::run_keys_attest(&dev, &scp_params, &slot, &output, format),
                    PivKeysAction::Export {
                        slot,
                        output,
                        format,
                        verify,
                        pin,
                    } => piv::run_keys_export(
                        &dev,
                        &scp_params,
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
                    } => piv::run_keys_move(
                        &dev,
                        &scp_params,
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
                        &scp_params,
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
                    } => piv::run_certificates_export(&dev, &scp_params, &slot, &output, format),
                    PivCertAction::Import {
                        slot,
                        cert_file,
                        management_key,
                        pin,
                        compress,
                        password,
                        verify,
                        no_update_chuid,
                    } => piv::run_certificates_import(
                        &dev,
                        &scp_params,
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
                    } => piv::run_certificates_delete(
                        &dev,
                        &scp_params,
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
                    } => piv::run_certificates_generate(
                        &dev,
                        &scp_params,
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
                    } => piv::run_certificates_request(
                        &dev,
                        &scp_params,
                        &slot,
                        &subject,
                        hash_algorithm,
                        &output,
                        pin.as_deref(),
                        Some(&public_key),
                    ),
                },
                PivAction::Objects(objs) => match objs {
                    PivObjectAction::Export {
                        object,
                        output,
                        pin,
                    } => {
                        piv::run_objects_export(&dev, &scp_params, &object, &output, pin.as_deref())
                    }
                    PivObjectAction::Import {
                        object,
                        data,
                        management_key,
                        pin,
                    } => piv::run_objects_import(
                        &dev,
                        &scp_params,
                        &object,
                        &data,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                    PivObjectAction::Generate {
                        object,
                        management_key,
                        pin,
                    } => piv::run_objects_generate(
                        &dev,
                        &scp_params,
                        &object,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                },
            }
        }
        Commands::Openpgp { action } => {
            let dev = require_device(cli.device)?;
            check_capability(&dev, Capability::OPENPGP)?;
            check_scp_version(&dev, &scp_params)?;
            apply_version_override(&dev);
            match action {
                OpenpgpAction::Info => openpgp::run_info(&dev, &scp_params),
                OpenpgpAction::Reset { force } => openpgp::run_reset(&dev, &scp_params, force),
                OpenpgpAction::Access(access) => match access {
                    OpenpgpAccessAction::SetRetries {
                        pin_retries,
                        reset_code_retries,
                        admin_pin_retries,
                        admin_pin,
                        force,
                    } => openpgp::run_set_retries(
                        &dev,
                        &scp_params,
                        pin_retries,
                        reset_code_retries,
                        admin_pin_retries,
                        admin_pin.as_deref(),
                        force,
                    ),
                    OpenpgpAccessAction::ChangePin { pin, new_pin } => openpgp::run_change_pin(
                        &dev,
                        &scp_params,
                        pin.as_deref(),
                        new_pin.as_deref(),
                    ),
                    OpenpgpAccessAction::ChangeAdminPin {
                        admin_pin,
                        new_admin_pin,
                    } => openpgp::run_change_admin_pin(
                        &dev,
                        &scp_params,
                        admin_pin.as_deref(),
                        new_admin_pin.as_deref(),
                    ),
                    OpenpgpAccessAction::ChangeResetCode {
                        admin_pin,
                        reset_code,
                    } => openpgp::run_change_reset_code(
                        &dev,
                        &scp_params,
                        admin_pin.as_deref(),
                        reset_code.as_deref(),
                    ),
                    OpenpgpAccessAction::UnblockPin {
                        admin_pin,
                        reset_code,
                        new_pin,
                    } => openpgp::run_unblock_pin(
                        &dev,
                        &scp_params,
                        admin_pin.as_deref(),
                        reset_code.as_deref(),
                        new_pin.as_deref(),
                    ),
                    OpenpgpAccessAction::SetSignaturePolicy { policy, admin_pin } => {
                        openpgp::run_set_signature_policy(
                            &dev,
                            &scp_params,
                            policy,
                            admin_pin.as_deref(),
                        )
                    }
                },
                OpenpgpAction::Keys(keys) => match keys {
                    OpenpgpKeysAction::Info { key } => {
                        openpgp::run_keys_info(&dev, &scp_params, key)
                    }
                    OpenpgpKeysAction::SetTouch {
                        key,
                        policy,
                        admin_pin,
                        force,
                    } => openpgp::run_keys_set_touch(
                        &dev,
                        &scp_params,
                        key,
                        policy,
                        admin_pin.as_deref(),
                        force,
                    ),
                    OpenpgpKeysAction::Import {
                        key,
                        key_file,
                        admin_pin,
                    } => openpgp::run_keys_import(
                        &dev,
                        &scp_params,
                        key,
                        &key_file,
                        admin_pin.as_deref(),
                    ),
                    OpenpgpKeysAction::Attest {
                        key,
                        output,
                        format,
                        pin,
                    } => openpgp::run_keys_attest(
                        &dev,
                        &scp_params,
                        key,
                        &output,
                        format,
                        pin.as_deref(),
                    ),
                },
                OpenpgpAction::Certificates(certs) => match certs {
                    OpenpgpCertAction::Export {
                        key,
                        output,
                        format,
                    } => openpgp::run_certificates_export(&dev, &scp_params, key, &output, format),
                    OpenpgpCertAction::Import {
                        key,
                        cert_file,
                        admin_pin,
                    } => openpgp::run_certificates_import(
                        &dev,
                        &scp_params,
                        key,
                        &cert_file,
                        admin_pin.as_deref(),
                    ),
                    OpenpgpCertAction::Delete { key, admin_pin } => {
                        openpgp::run_certificates_delete(
                            &dev,
                            &scp_params,
                            key,
                            admin_pin.as_deref(),
                        )
                    }
                },
            }
        }
        Commands::Hsmauth { action } => {
            let dev = require_device(cli.device)?;
            check_capability(&dev, Capability::HSMAUTH)?;
            check_scp_version(&dev, &scp_params)?;
            apply_version_override(&dev);
            match action {
                HsmauthAction::Info => hsmauth::run_info(&dev, &scp_params),
                HsmauthAction::Reset { force } => hsmauth::run_reset(&dev, &scp_params, force),
                HsmauthAction::Credentials(cred) => match cred {
                    HsmauthCredAction::List => hsmauth::run_credentials_list(&dev, &scp_params),
                    HsmauthCredAction::Generate {
                        label,
                        credential_password,
                        management_key,
                        touch,
                    } => hsmauth::run_credentials_generate(
                        &dev,
                        &scp_params,
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
                        &scp_params,
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
                        &scp_params,
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
                        &scp_params,
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
                        &scp_params,
                        &label,
                        credential_password.as_deref(),
                        &new_credential_password,
                    ),
                    HsmauthCredAction::Export {
                        label,
                        output,
                        format,
                    } => {
                        hsmauth::run_credentials_export(&dev, &scp_params, &label, &output, format)
                    }
                    HsmauthCredAction::Import {
                        label,
                        private_key,
                        password,
                        credential_password,
                        management_key,
                        touch,
                    } => hsmauth::run_credentials_import(
                        &dev,
                        &scp_params,
                        &label,
                        &private_key,
                        password.as_deref(),
                        credential_password.as_deref(),
                        management_key.as_deref(),
                        touch,
                    ),
                },
                HsmauthAction::Access(access) => match access {
                    HsmauthAccessAction::ChangeManagementPassword {
                        management_password,
                        new_management_password,
                        generate,
                    } => hsmauth::run_access_change_management_key(
                        &dev,
                        &scp_params,
                        management_password.as_deref(),
                        new_management_password.as_deref(),
                        generate,
                    ),
                },
            }
        }
        Commands::SecurityDomain { action } => {
            let dev = require_device(cli.device)?;
            check_version(&dev, Version(5, 3, 0), "Security Domain")?;
            check_scp_version(&dev, &scp_params)?;
            apply_version_override(&dev);
            match action {
                SecurityDomainAction::Info => securitydomain::run_info(&dev, &scp_params),
                SecurityDomainAction::Reset { force } => {
                    securitydomain::run_reset(&dev, &scp_params, force)
                }
                SecurityDomainAction::Keys(keys) => {
                    let parse_hex_u8 = |s: &str| -> Result<u8, CliError> {
                        u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
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
                            let rkvn = replace_kvn.as_deref().map(&parse_hex_u8).transpose()?;
                            securitydomain::run_keys_generate(
                                &dev,
                                &scp_params,
                                kid,
                                kvn,
                                &output,
                                rkvn,
                            )
                        }
                        SecurityDomainKeysAction::Export { kid, kvn, output } => {
                            let kid = parse_hex_u8(&kid)?;
                            let kvn = parse_hex_u8(&kvn)?;
                            securitydomain::run_keys_export(&dev, &scp_params, kid, kvn, &output)
                        }
                        SecurityDomainKeysAction::Delete { kid, kvn, force } => {
                            let kid = parse_hex_u8(&kid)?;
                            let kvn = parse_hex_u8(&kvn)?;
                            securitydomain::run_keys_delete(&dev, &scp_params, kid, kvn, force)
                        }
                        SecurityDomainKeysAction::Import {
                            kid,
                            kvn,
                            key_type,
                            input,
                            replace_kvn,
                            password,
                        } => {
                            let kid = parse_hex_u8(&kid)?;
                            let kvn = parse_hex_u8(&kvn)?;
                            let rkvn = replace_kvn.as_deref().map(&parse_hex_u8).transpose()?;
                            securitydomain::run_keys_import(
                                &dev,
                                &scp_params,
                                kid,
                                kvn,
                                key_type,
                                &input,
                                rkvn,
                                password.as_deref(),
                            )
                        }
                        SecurityDomainKeysAction::SetAllowlist { kid, kvn, serials } => {
                            let kid = parse_hex_u8(&kid)?;
                            let kvn = parse_hex_u8(&kvn)?;
                            securitydomain::run_keys_set_allowlist(
                                &dev,
                                &scp_params,
                                kid,
                                kvn,
                                &serials,
                            )
                        }
                    }
                }
            }
        }
        Commands::Apdu {
            apdus,
            no_pretty,
            app,
            short,
            send_apdu,
        } => {
            let dev = require_device(cli.device)?;
            if dev.reader_name().is_none() {
                return Err(CliError(
                    "The apdu command requires a CCID (smart card) connection.".into(),
                ));
            }
            check_scp_version(&dev, &scp_params)?;
            apdu::run_apdu(
                &dev,
                &scp_params,
                &apdus,
                no_pretty,
                app.map(|a| a.as_str()),
                short,
                &send_apdu,
            )
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e.0);
        process::exit(1);
    }
}
