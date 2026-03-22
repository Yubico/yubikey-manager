use std::process;

use clap::{Parser, Subcommand};
use yubikit_rs::core_types::set_override_version;
use yubikit_rs::device::{list_devices, list_readers, open_reader, YubiKeyDevice};
use yubikit_rs::management::ReleaseType;

mod info;
mod list;
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
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e.0);
        process::exit(1);
    }
}
