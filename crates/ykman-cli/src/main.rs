#![windows_subsystem = "console"]
use anyhow::{Result, anyhow};
use std::process;

use clap::builder::styling::{Style, Styles};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
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

    /// Disable coloured output (shorthand for `--color=never`)
    #[arg(long, global = true, conflicts_with = "color")]
    no_color: bool,

    /// Control coloured output
    #[arg(long, global = true, value_enum, default_value = "auto")]
    color: color::ColorChoice,

    /// Show diagnostic information
    #[arg(long)]
    diagnose: bool,

    /// Show third-party license information
    #[arg(long)]
    licenses: bool,

    /// Generate shell completion
    #[arg(long)]
    completion: Option<Shell>,

    /// Enable logging at given verbosity level
    #[arg(short = 'l', long, global = true)]
    log_level: Option<logging::LogLevel>,

    /// Write log to FILE instead of printing to stderr (requires --log-level)
    #[arg(long, value_name = "FILE", global = true)]
    log_file: Option<String>,

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

/// Help-screen styling: bold (no underline) section headers/usage line, and
/// plain (not bold) command/flag names, matching the look of tools such as
/// `gh --help`.
const HELP_STYLES: Styles = Styles::styled()
    .header(Style::new().bold())
    .usage(Style::new().bold())
    .literal(Style::new());

/// Renders `text` wrapped in the same bold style used for clap's own
/// section headings (see [`HELP_STYLES`]), for use in literal template
/// text/`after_help` strings that clap itself never styles.
fn styled_heading(text: &str) -> String {
    format!(
        "{}{text}{}",
        HELP_STYLES.get_header().render(),
        HELP_STYLES.get_header().render_reset()
    )
}

/// Builds a per-command help template with our own uppercase, colon-free
/// section headings ("USAGE", "ARGUMENTS", "OPTIONS", "COMMANDS") baked in
/// as literal (pre-styled) text, using clap's heading-less `{usage}`/
/// `{positionals}`/`{options}`/`{subcommands}` template tags for the body of
/// each section. This avoids fighting clap's own hardcoded heading text
/// (e.g. `write_args()`/`usage.rs` always emit "Options"/"Usage" with a
/// trailing colon with no public override), unlike `{all-args}` though,
/// these tags don't omit their heading when a command has no args of that
/// kind, so each section here is only included if `cmd` actually has one
/// (e.g. leaf commands with no subcommands get no "COMMANDS" section).
fn build_help_template(cmd: &clap::Command) -> String {
    let mut template = format!(
        "{{before-help}}{{about-with-newline}}\n{}\n  {{usage}}\n\n",
        styled_heading("USAGE")
    );
    if cmd.get_positionals().any(|arg| !arg.is_hide_set()) {
        template.push_str(&format!(
            "{}\n{{positionals}}\n\n",
            styled_heading("ARGUMENTS")
        ));
    }
    if cmd.get_subcommands().any(|sub| !sub.is_hide_set()) {
        template.push_str(&format!(
            "{}\n{{subcommands}}\n\n",
            styled_heading("COMMANDS")
        ));
    }
    // Every command has at least `-h`/`--help`, so OPTIONS is unconditional.
    template.push_str(&format!("{}\n{{options}}", styled_heading("OPTIONS")));
    // `{after-help}` (used for our own "EXAMPLES" section) already inserts
    // its own leading blank line when present, so nothing more is added
    // after OPTIONS here to avoid doubling it up.
    template.push_str("{after-help}");
    template
}

/// Determines the `--no-color`/`--color` choice by scanning raw `argv`
/// directly, so it can be applied to clap's own [`clap::Command::color`]
/// (which governs whether *its* help/error output, including our
/// hand-styled headings, gets its ANSI codes stripped). This is otherwise
/// unreachable for `-h`/`--help`: clap handles those internally and exits
/// during `get_matches()`, before our `Cli` struct (and its `color` field)
/// is ever populated. `NO_COLOR` and tty auto-detection don't need
/// duplicating here — clap's default `ColorChoice::Auto` already handles
/// both via `anstream`, matching [`color::resolve`]'s fallback behaviour;
/// only the explicit-override cases need to be pre-parsed by hand.
fn detect_color_choice() -> clap::ColorChoice {
    let mut choice = clap::ColorChoice::Auto;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        let value = if arg == "--no-color" {
            Some("never")
        } else if let Some(value) = arg.strip_prefix("--color=") {
            Some(value)
        } else if arg == "--color" {
            args.peek().map(String::as_str)
        } else {
            None
        };
        if let Some(parsed) = value.and_then(|v| color::ColorChoice::from_str(v, true).ok()) {
            choice = match parsed {
                color::ColorChoice::Always => clap::ColorChoice::Always,
                color::ColorChoice::Auto => clap::ColorChoice::Auto,
                color::ColorChoice::Never => clap::ColorChoice::Never,
            };
        }
    }
    choice
}

/// Builds the CLI's [`clap::Command`], applying [`HELP_STYLES`], the
/// detected [`detect_color_choice`], and a per-node help template (see
/// [`build_help_template`]) throughout the entire command tree (every
/// subcommand, recursively) — none of this is propagated automatically by
/// clap for nested subcommands, except `color()` which is a global setting.
fn build_cli_command() -> clap::Command {
    let mut cmd = Cli::command()
        .styles(HELP_STYLES)
        .color(detect_color_choice());
    // Propagates each subcommand's full "ykman <path>" bin name (used in its
    // USAGE line) before we render/bake help text below; without this, each
    // subcommand only knows its own short name (e.g. "fido" instead of
    // "ykman fido") since that propagation normally only happens later,
    // during arg parsing.
    cmd.build();
    finalize_help(&mut cmd);
    cmd
}

/// Strips ANSI escape sequences, used only to compare otherwise-plain text
/// (e.g. matching a heading) since the "raw" rendered help text has styling
/// codes baked directly into it. Delegates to `anstream`'s (already a
/// transitive dependency of clap, for the same tty/`--no-color` stripping
/// it does at print time) escape-sequence parser rather than a hand-rolled
/// one.
fn strip_ansi(s: &str) -> String {
    anstream::adapter::strip_str(s).to_string()
}

/// Applies `transform` to each line within a named section of rendered help
/// text — from the line matching `heading` (ignoring baked-in ANSI codes) up
/// to, but not including, the next blank line — leaving everything else
/// untouched. `transform` returns `None` to leave a line as-is. Factors out
/// the "find this heading, then walk its lines" boilerplate shared by
/// [`add_command_colons`] and [`lowercase_usage`].
fn transform_section(
    text: &str,
    heading: &str,
    transform: impl Fn(&str) -> Option<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_section = false;
    for line in text.split_inclusive('\n') {
        let content = line.trim_end_matches('\n');
        if in_section {
            if content.trim().is_empty() {
                in_section = false;
            } else if let Some(replacement) = transform(content) {
                out.push_str(&replacement);
                out.push('\n');
                continue;
            }
        }
        if strip_ansi(content) == heading {
            in_section = true;
        }
        out.push_str(line);
    }
    out
}

/// Adds a trailing colon after each subcommand name in the "COMMANDS"
/// section (matching the style used by `gh <command> --help`), e.g.
/// "  info     Show general information" becomes
/// "  info:    Show general information". Consumes one space of the
/// existing alignment padding for the colon so the description column
/// stays aligned.
fn add_command_colons(text: &str) -> String {
    transform_section(text, "COMMANDS", |content| {
        let rest = content.strip_prefix("  ")?;
        let gap = rest.find(|c: char| c.is_whitespace())?;
        let (name, after) = rest.split_at(gap);
        let padding = after.len() - after.trim_start().len();
        // Only rewrite if there's padding to spare for the colon, i.e. this
        // really is a "name<spaces>description" row.
        (padding > 1).then(|| {
            let description = &after[padding..];
            format!("  {name}:{}{description}", " ".repeat(padding - 1))
        })
    })
}

/// Lowercases the "USAGE" section's example line(s) (e.g.
/// "ykman fido [OPTIONS] <COMMAND>" becomes "ykman fido [options] <command>"),
/// matching the lowercase placeholders used by tools like `gh`.
/// Command/binary names are already lowercase, so this only affects clap's
/// uppercase `[OPTIONS]`/`<COMMAND>`-style placeholders.
fn lowercase_usage(text: &str) -> String {
    transform_section(text, "USAGE", |content| Some(content.to_lowercase()))
}

fn finalize_help(cmd: &mut clap::Command) {
    let taken = std::mem::replace(cmd, clap::Command::new(""));
    let template = build_help_template(&taken);
    let mut taken = taken.help_template(template);

    // We render in compact/short-form below to keep OPTIONS to one line per
    // arg, but clap's short-form always uses the short `about` text over a
    // richer `long_about` (from a multi-paragraph doc comment). Substitute
    // it in so we still get the compact arg layout without losing that text
    // on a command's own `--help` page (e.g. `config set-lock-code --help`).
    if let Some(long_about) = taken.get_long_about().cloned() {
        taken = taken.about(long_about);
    }

    let rendered = taken
        .render_help()
        .ansi()
        .to_string()
        // Our `after_help` strings all start with "Examples:\n\n<first item>"
        // (a blank line before the first example), so this also swallows
        // that blank line to keep the heading flush with its content, like
        // the other headings (which are baked into our own help template,
        // see `build_help_template`). "Examples:" itself is our own literal
        // `after_help` text and is never styled by clap, so it's bolded
        // manually here to match.
        .replace(
            "Examples:\n\n",
            &format!("{}\n", styled_heading("EXAMPLES")),
        )
        // We always bake the compact/short-form help (see comment above), so
        // the built-in help text's own "--help shows more" hint no longer
        // applies since --help now renders identically to -h.
        .replace("Print help (see more with '--help')", "Print help");
    let rendered = lowercase_usage(&add_command_colons(&rendered));
    taken = taken.override_help(rendered);

    for sub in taken.get_subcommands_mut() {
        finalize_help(sub);
    }
    *cmd = taken;
}

fn print_completion(shell: Shell) {
    use std::io;
    let mut cmd = build_cli_command();
    let bin_name = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin_name, &mut io::stdout());
}

fn command_or_help(command: Option<Commands>) -> Commands {
    match command {
        Some(command) => command,
        None => {
            let mut cmd = build_cli_command();
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

fn run() -> Result<()> {
    let mut matches = build_cli_command().get_matches();
    let cli = Cli::from_arg_matches_mut(&mut matches).unwrap_or_else(|e| e.exit());

    color::init(cli.no_color, cli.color);
    init_logging(&cli)?;

    if cli.diagnose {
        diagnose::run_diagnose()?;
        return Ok(());
    }

    if cli.licenses {
        print_licenses();
        return Ok(());
    }

    if let Some(shell) = cli.completion {
        print_completion(shell);
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
