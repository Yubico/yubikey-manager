use std::process;

use clap::{Parser, Subcommand};
use yubikit_rs::core_types::set_override_version;
use yubikit_rs::device::{list_devices, list_readers, open_reader, YubiKeyDevice};
use yubikit_rs::management::ReleaseType;

mod config;
mod info;
mod list;
mod oath;
mod otp;
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
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e.0);
        process::exit(1);
    }
}
