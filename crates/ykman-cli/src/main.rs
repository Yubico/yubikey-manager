#![windows_subsystem = "console"]
use anyhow::{Result, anyhow};
use std::process;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::{Shell, generate};

use yubikit::core::Version;
use yubikit::management::Capability;

mod apdu;
mod cli_enums;
mod color;
mod config;
mod context;
mod diagnose;
mod fido;
mod help;
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

#[derive(Parser)]
#[command(
    name = "ykman",
    about = "Configure your YubiKey via the command line.",
    version,
    disable_version_flag = true,
    arg(clap::Arg::new("version")
        .short('V')
        .long("version")
        .action(clap::ArgAction::Version)
        .hide(true)),
    after_help = "Examples:\n\
      \n  List connected YubiKeys, only output serial number:\
      \n  $ ykman list --serials\
      \n\
      \n  Show information about YubiKey with serial number 123456:\
      \n  $ ykman --device 123456 info"
)]
struct Cli {
    /// Use the YubiKey with this serial number
    #[arg(short = 'd', long, global = true, value_name = "SERIAL")]
    device: Option<u32>,

    /// SCP key/cert files, or SCP03 K-ENC:K-MAC[:K-DEK] hex
    #[arg(long = "scp", global = true, value_name = "CRED")]
    scp_cred: Vec<String>,

    /// SCP11 CA file (PEM/DER); alone, requests SCP11b
    #[arg(long, global = true, value_name = "FILE")]
    scp_ca: Option<String>,

    /// SCP card key reference (hex)
    #[arg(long, global = true, num_args = 2, value_names = ["KID", "KVN"])]
    scp_sd: Option<Vec<String>>,

    /// SCP OCE key reference (hex)
    #[arg(long, global = true, num_args = 2, value_names = ["KID", "KVN"])]
    scp_oce: Option<Vec<String>>,

    /// Password for SCP credential file
    #[arg(long, global = true, value_name = "PASSWORD")]
    scp_password: Option<String>,

    /// Show diagnostic information
    #[arg(long, hide = true)]
    diagnose: bool,

    /// Show third-party license information
    #[arg(long, hide = true)]
    licenses: bool,

    /// Generate shell completion
    #[arg(long, value_name = "SHELL", hide = true)]
    completion: Option<Shell>,

    /// Log level: error, warning, info, debug, traffic
    #[arg(
        short = 'l',
        long,
        global = true,
        value_name = "LEVEL",
        hide_possible_values = true
    )]
    log_level: Option<logging::LogLevel>,

    /// Write log to FILE (requires --log-level)
    #[arg(long, value_name = "FILE", global = true)]
    log_file: Option<String>,

    /// Colour output: always, auto, never
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        default_value = "auto",
        hide_default_value = true,
        hide_possible_values = true
    )]
    color: color::ColorChoice,

    /// Disable coloured output (same as --color=never)
    #[arg(long, global = true, conflicts_with = "color", hide = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

fn init_logging(cli: &Cli) -> Result<()> {
    if let Some(level) = cli.log_level {
        logging::init_logging(level, cli.log_file.as_deref())
            .map_err(|e| anyhow!(e.to_string()))?;
        log::info!(
            "System info:\n  ykman:  {}\n  Platform:  {}\n  Arch:      {}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        );
    } else if cli.log_file.is_some() {
        return Err(anyhow!("--log-file requires specifying --log-level."));
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

fn cli_command() -> clap::Command {
    Cli::command()
        .styles(help::STYLES)
        .color(color::help_choice(std::env::args_os().skip(1)))
}

fn print_completion(shell: Shell) {
    use std::io;
    let mut cmd = cli_command();
    let bin_name = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin_name, &mut io::stdout());
}

fn command_or_help(command: Option<Commands>) -> Commands {
    match command {
        Some(command) => command,
        None => {
            let mut cmd = help::configure(cli_command());
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
    /// Show diagnostic information
    Diagnose,
    /// Show the version
    Version,
    /// Show third-party licenses
    Licenses,
    /// Generate shell completion
    #[command(hide = true)]
    Completion {
        /// Shell to generate completion for
        shell: Shell,
    },
}

fn run() -> Result<()> {
    let mut matches = match cli_command().try_get_matches() {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp
                    | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) =>
        {
            help::configure(cli_command()).get_matches()
        }
        Err(error) => error.exit(),
    };
    let cli = Cli::from_arg_matches_mut(&mut matches).unwrap_or_else(|error| error.exit());
    color::init(cli.no_color, cli.color);

    init_logging(&cli)?;

    let command = if cli.diagnose {
        Some(Commands::Diagnose)
    } else if cli.licenses {
        Some(Commands::Licenses)
    } else if let Some(shell) = cli.completion {
        Some(Commands::Completion { shell })
    } else {
        cli.command
    };
    match command {
        Some(Commands::Diagnose) => return diagnose::run_diagnose(),
        Some(Commands::Licenses) => {
            print_licenses();
            return Ok(());
        }
        Some(Commands::Version) => {
            print!("{}", cli_command().render_version());
            return Ok(());
        }
        Some(Commands::Completion { shell }) => {
            print_completion(shell);
            return Ok(());
        }
        _ => {}
    }

    let scp_params = scp::parse_scp_params(ScpInputs {
        scp_cred: &cli.scp_cred,
        scp_ca: cli.scp_ca.as_deref(),
        scp_sd: cli.scp_sd.as_deref(),
        scp_oce: cli.scp_oce.as_deref(),
        scp_password: cli.scp_password.as_deref(),
    })?;
    let ctx = CommandContext::new(cli.device, scp_params.clone());

    let command = command_or_help(command);

    run_command(command, cli.device, &ctx, &scp_params)?;
    Ok(())
}

fn run_command(
    command: Commands,
    device_filter: Option<u32>,
    ctx: &CommandContext,
    scp_params: &ScpParams,
) -> Result<()> {
    match command {
        Commands::Diagnose
        | Commands::Licenses
        | Commands::Version
        | Commands::Completion { .. } => {
            unreachable!("handled in run()")
        }
        Commands::List { serials, readers } => {
            if device_filter.is_some() {
                return Err(anyhow!("--device can't be used with 'list'."));
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
            if let otp::OtpAction::Static {
                list_layouts: true, ..
            } = action
            {
                otp::print_layouts();
                return Ok(());
            }
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
        eprintln!("Error: {e}");
        process::exit(1);
    }
}
