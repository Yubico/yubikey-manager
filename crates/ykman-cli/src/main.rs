#![windows_subsystem = "console"]
use std::process;

use clap::{Parser, Subcommand};
use yubikit::core::Version;
use yubikit::management::Capability;

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
    #[arg(short = 'd', long, global = true)]
    device: Option<u32>,

    /// SCP credentials: private key and cert files, or SCP03 keys as K-ENC:K-MAC[:K-DEK] hex
    #[arg(long = "scp", global = true)]
    scp_cred: Vec<String>,

    /// CA certificate for SCP11 card key verification (PEM/DER file)
    #[arg(long, global = true)]
    scp_ca: Option<String>,

    /// Card key reference for SCP (KID KVN, hex)
    #[arg(long, global = true, num_args = 2, value_names = ["KID", "KVN"])]
    scp_sd: Option<Vec<String>>,

    /// OCE key reference for SCP (KID KVN, hex)
    #[arg(long, global = true, num_args = 2, value_names = ["KID", "KVN"])]
    scp_oce: Option<Vec<String>>,

    /// Password for SCP credential file
    #[arg(long, global = true)]
    scp_password: Option<String>,

    /// Show diagnostic information
    #[arg(long)]
    diagnose: bool,

    /// Show third-party license information
    #[arg(long)]
    licenses: bool,

    /// Enable logging at given verbosity level
    #[arg(short = 'l', long, global = true)]
    log_level: Option<logging::LogLevel>,

    /// Write log to FILE instead of printing to stderr (requires --log-level)
    #[arg(long, value_name = "FILE", global = true)]
    log_file: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

fn init_logging(cli: &Cli) -> Result<(), CliError> {
    if let Some(level) = cli.log_level {
        logging::init_logging(level, cli.log_file.as_deref())
            .map_err(|e| CliError(e.to_string()))?;
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
        action: oath::OathAction,
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
        #[arg(long)]
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
        action: piv::PivAction,
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
        #[command(flatten)]
        args: apdu::ApduArgs,
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
            action.run(dev.as_ref(), scp_params)
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
            action.run(dev.as_ref(), scp_params)
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
        Commands::Apdu { args } => {
            let dev = ctx.device()?;
            args.run(dev.as_ref(), scp_params)
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e.0);
        process::exit(1);
    }
}
