#![windows_subsystem = "console"]
use std::process;

use clap::{Parser, Subcommand};
use yubikit::core::Version;
use yubikit::management::{Capability, UsbInterface};

mod apdu;
mod cli_enums;
mod config;
mod context;
mod diagnose;
mod fido;
mod hsmauth;
mod info;
mod list;
mod oath;
mod openpgp;
mod otp;
mod piv;
mod scp;
mod securitydomain;
mod util;

// Re-export library modules so binary-internal modules can use them via crate::
use ykman::appdata;
use ykman::cancel;
use ykman::keyboard;
use ykman::logging;

use cli_enums::*;

use context::CommandContext;
use scp::{ScpInputs, ScpParams};
use util::CliError;

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

    /// Show third-party license information
    #[arg(long = "licenses")]
    licenses: bool,

    /// Enable logging at given verbosity level
    #[arg(short = 'l', long = "log-level")]
    log_level: Option<logging::LogLevel>,

    /// Write log to FILE instead of printing to stderr (requires --log-level)
    #[arg(long = "log-file", value_name = "FILE")]
    log_file: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

fn init_logging(cli: &Cli) -> Result<(), CliError> {
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
    Ok(())
}

fn print_licenses() {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    static LICENSES_DEFLATE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/licenses.deflate"));
    let mut text = String::new();
    DeflateDecoder::new(LICENSES_DEFLATE)
        .read_to_string(&mut text)
        .expect("Failed to decompress license data");
    print!("{text}");
}

fn command_or_help(command: Option<Commands>) -> Commands {
    match command {
        Some(command) => command,
        None => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            cmd.print_help().ok();
            println!();
            std::process::exit(0);
        }
    }
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
        action: config::ConfigAction,
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
        action: otp::OtpAction,
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
    /// Manage the FIDO applications
    #[command(after_help = "Examples:\n\
      \n  Reset the FIDO (FIDO2 and U2F) applications:\
      \n  $ ykman fido reset\
      \n\
      \n  Change the FIDO2 PIN from 123456 to 654321:\
      \n  $ ykman fido access change-pin --pin 123456 --new-pin 654321")]
    Fido {
        #[command(subcommand)]
        action: fido::FidoAction,
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
        action: openpgp::OpenpgpAction,
    },
    /// Manage the YubiHSM Auth application
    Hsmauth {
        #[command(subcommand)]
        action: hsmauth::HsmauthAction,
    },
    /// Manage the Security Domain
    #[command(name = "sd")]
    SecurityDomain {
        #[command(subcommand)]
        action: securitydomain::SecurityDomainAction,
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
        /// APDUs to send (format: `[CLA]INS[P1P2][:DATA][/LE][=EXPECTED_SW]`)
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

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();

    init_logging(&cli)?;

    if cli.diagnose {
        return diagnose::run_diagnose();
    }

    if cli.licenses {
        print_licenses();
        return Ok(());
    }

    let scp_params = scp::parse_scp_params(ScpInputs {
        scp_cred: &cli.scp_cred,
        scp_ca: cli.scp_ca.as_deref(),
        scp_sd: cli.scp_sd.as_deref(),
        scp_oce: cli.scp_oce.as_deref(),
        scp_password: cli.scp_password.as_deref(),
    })?;
    let ctx = CommandContext::new(cli.device, scp_params.clone());

    let command = command_or_help(cli.command);

    run_command(command, cli.device, &ctx, &scp_params)
}

fn run_command(
    command: Commands,
    device_filter: Option<u32>,
    ctx: &CommandContext,
    scp_params: &ScpParams,
) -> Result<(), CliError> {
    match command {
        Commands::List { serials, readers } => {
            if device_filter.is_some() {
                return Err(CliError("--device can't be used with 'list'.".into()));
            }
            list::run(serials, readers)
        }
        Commands::Info { check_fips } => {
            let dev = ctx.device()?;
            info::run(&dev, check_fips)
        }
        Commands::Config { action } => {
            let dev = ctx.device()?;
            action.run(dev.as_ref())
        }
        Commands::Oath { action } => {
            let dev = ctx.device_for(Capability::OATH)?;
            match action {
                OathAction::Info { password } => {
                    oath::run_info(&dev, scp_params, password.as_deref())
                }
                OathAction::Reset { force } => oath::run_reset(&dev, scp_params, force),
                OathAction::Access(access) => match access {
                    OathAccessAction::Change {
                        password,
                        new_password,
                        clear,
                        remember,
                    } => oath::run_access_change(
                        &dev,
                        scp_params,
                        password.as_deref(),
                        new_password.as_deref(),
                        clear,
                        remember,
                    ),
                    OathAccessAction::Remember { password } => {
                        oath::run_access_remember(&dev, scp_params, password.as_deref())
                    }
                    OathAccessAction::Forget { all } => {
                        oath::run_access_forget(&dev, scp_params, all)
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
                    } => oath::run_accounts_code(
                        &dev,
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
                        generate: _generate,
                        touch,
                        force,
                    } => oath::run_accounts_add(
                        &dev,
                        scp_params,
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
                    } => oath::run_accounts_rename(
                        &dev,
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
                    } => oath::run_accounts_uri(
                        &dev,
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
                    } => oath::run_accounts_import(
                        &dev,
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
        Commands::Otp {
            access_code: parent_access_code,
            action,
        } => {
            let dev = ctx.device_for(Capability::OTP)?;
            action.run(dev.as_ref(), scp_params, &parent_access_code)
        }
        Commands::Piv { action } => {
            let dev = ctx.device_for(Capability::PIV)?;
            match action {
                PivAction::Info => piv::run_info(&dev, scp_params),
                PivAction::Reset { force } => piv::run_reset(&dev, scp_params, force),
                PivAction::Access(access) => match access {
                    PivAccessAction::ChangePin { pin, new_pin } => {
                        piv::run_change_pin(&dev, scp_params, pin.as_deref(), new_pin.as_deref())
                    }
                    PivAccessAction::ChangePuk { puk, new_puk } => {
                        piv::run_change_puk(&dev, scp_params, puk.as_deref(), new_puk.as_deref())
                    }
                    PivAccessAction::UnblockPin { puk, new_pin } => {
                        piv::run_unblock_pin(&dev, scp_params, puk.as_deref(), new_pin.as_deref())
                    }
                    PivAccessAction::SetRetries {
                        pin_retries,
                        puk_retries,
                        management_key,
                        pin,
                        force,
                    } => piv::run_set_retries(
                        &dev,
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
                    } => piv::run_change_management_key(
                        &dev,
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
                    } => piv::run_keys_import(
                        &dev,
                        scp_params,
                        &slot,
                        &key_file,
                        pin_policy,
                        touch_policy,
                        management_key.as_deref(),
                        pin.as_deref(),
                        password.as_deref(),
                    ),
                    PivKeysAction::Info { slot } => piv::run_keys_info(&dev, scp_params, &slot),
                    PivKeysAction::Attest {
                        slot,
                        output,
                        format,
                    } => piv::run_keys_attest(&dev, scp_params, &slot, &output, format),
                    PivKeysAction::Export {
                        slot,
                        output,
                        format,
                        verify,
                        pin,
                    } => piv::run_keys_export(
                        &dev,
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
                    } => piv::run_keys_move(
                        &dev,
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
                    } => piv::run_keys_delete(
                        &dev,
                        scp_params,
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
                    } => piv::run_certificates_export(&dev, scp_params, &slot, &output, format),
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
                    } => piv::run_certificates_delete(
                        &dev,
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
                    } => piv::run_certificates_generate(
                        &dev,
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
                    } => piv::run_certificates_request(
                        &dev,
                        scp_params,
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
                        piv::run_objects_export(&dev, scp_params, &object, &output, pin.as_deref())
                    }
                    PivObjectAction::Import {
                        object,
                        data,
                        management_key,
                        pin,
                    } => piv::run_objects_import(
                        &dev,
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
                    } => piv::run_objects_generate(
                        &dev,
                        scp_params,
                        &object,
                        management_key.as_deref(),
                        pin.as_deref(),
                    ),
                },
            }
        }
        Commands::Fido { action } => {
            let mut dev = ctx.device_with_scp_check()?;
            action.run(dev.as_mut(), scp_params)
        }
        Commands::Openpgp { action } => {
            let dev = ctx.device_for(Capability::OPENPGP)?;
            action.run(dev.as_ref(), scp_params)
        }
        Commands::Hsmauth { action } => {
            let dev = ctx.device_for(Capability::HSMAUTH)?;
            action.run(dev.as_ref(), scp_params)
        }
        Commands::SecurityDomain { action } => {
            let dev = ctx.device_with_min_version(Version(5, 3, 0), "Security Domain")?;
            action.run(dev.as_ref(), scp_params)
        }
        Commands::Apdu {
            apdus,
            no_pretty,
            app,
            short,
            send_apdu,
        } => {
            let dev = ctx.device()?;
            if !dev.usb_interfaces().contains(UsbInterface::CCID) {
                return Err(CliError(
                    "The apdu command requires a CCID (smart card) connection.".into(),
                ));
            }
            apdu::run_apdu(
                &*dev,
                scp_params,
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

#[cfg(test)]
mod tests {
    use super::otp::effective_access_code;

    #[test]
    fn otp_parent_access_code_overrides_subcommand_access_code() {
        let parent = Some("010203040506".to_string());
        let subcommand = Some("aabbccddeeff".to_string());

        assert_eq!(
            effective_access_code(&parent, &subcommand),
            Some("010203040506")
        );
    }

    #[test]
    fn otp_subcommand_access_code_is_used_without_parent() {
        let parent = None;
        let subcommand = Some("aabbccddeeff".to_string());

        assert_eq!(
            effective_access_code(&parent, &subcommand),
            Some("aabbccddeeff")
        );
    }
}
