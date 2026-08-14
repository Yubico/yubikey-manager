use anyhow::{Result, anyhow};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use yubikit::core::Connection;
use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::oath::parse_b32_key;
use yubikit::otp::{modhex_decode, modhex_encode};
use yubikit::yubiotp::{
    ACC_CODE_SIZE, AccessCode, ConfigState, HmacKey, KEY_SIZE, NdefType, Slot, SlotConfiguration,
    UID_SIZE, YubiOtpSession,
};

use crate::cancel;
use crate::cli_enums::{CliCalcDigits, CliHotpDigits, CliOtpSlot, CliPacing};
use crate::keyboard::{KeyboardLayout, LayoutSelection};
use crate::scp::{self, ScpParams};
use crate::util::{
    self, b32_encode, confirm, format_session_error, format_smartcard_connection_error,
};

pub fn effective_access_code<'a>(
    parent_access_code: &'a Option<String>,
    subcommand_access_code: &'a Option<String>,
) -> Option<&'a str> {
    parent_access_code
        .as_deref()
        .or(subcommand_access_code.as_deref())
}

#[cfg(test)]
mod tests {
    use super::{effective_access_code, format_otp_write_error, generate_static_pw};
    use crate::keyboard::LayoutSelection;

    #[test]
    fn parent_access_code_overrides_subcommand_access_code() {
        let parent = Some("010203040506".to_string());
        let subcommand = Some("aabbccddeeff".to_string());

        assert_eq!(
            effective_access_code(&parent, &subcommand),
            Some("010203040506")
        );
    }

    #[test]
    fn subcommand_access_code_is_used_without_parent() {
        let parent = None;
        let subcommand = Some("aabbccddeeff".to_string());

        assert_eq!(
            effective_access_code(&parent, &subcommand),
            Some("aabbccddeeff")
        );
    }

    #[test]
    fn otp_write_error_mentions_possible_access_code() {
        let err = format_otp_write_error("Connection error: Command rejected: No data");
        assert_eq!(
            err.to_string(),
            "Failed to write to the YubiKey. Slot(s) may be protected with an access code."
        );
    }

    #[test]
    fn generated_modhex_static_pw_uses_both_cases() {
        // A long generated password should contain both upper and lower case
        // modhex characters. The probability of an all-single-case result is
        // negligible (~2 * 2^-256).
        let pw = generate_static_pw(256, LayoutSelection::modhex()).unwrap();
        assert!(
            pw.chars()
                .all(|c| "cbdefghijklnrtuv".contains(c.to_ascii_lowercase()))
        );
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
    }
}

#[derive(Args, Clone, Copy)]
pub struct EnterArgs {
    /// Append Enter after output
    #[arg(long)]
    enter: bool,
    /// Do not append Enter
    #[arg(long, conflicts_with = "enter")]
    no_enter: bool,
}

#[derive(Subcommand)]
pub enum OtpAction {
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
        ndef_type: crate::cli_enums::CliNdefType,
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
        /// Public ID (modhex, 0-16 bytes)
        #[arg(short = 'P', long)]
        public_id: Option<String>,
        /// Private ID (hex, 6 bytes)
        #[arg(short = 'p', long)]
        private_id: Option<String>,
        /// AES key (hex, 16 bytes)
        #[arg(short = 'k', long)]
        key: Option<String>,
        /// Use serial number as public ID
        #[arg(short = 'S', long, conflicts_with = "public_id")]
        serial_public_id: bool,
        /// Generate random private ID
        #[arg(short = 'g', long, conflicts_with = "private_id")]
        generate_private_id: bool,
        /// Generate random key
        #[arg(short = 'G', long, conflicts_with = "key")]
        generate_key: bool,
        #[command(flatten)]
        enter: EnterArgs,
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
        #[arg(required_unless_present = "list_layouts")]
        slot: Option<CliOtpSlot>,
        /// Password to store
        password: Option<String>,
        /// Generate a random password
        #[arg(short = 'g', long, conflicts_with = "password")]
        generate: bool,
        /// Length of generated password
        #[arg(short = 'L', long, default_value_t = 38)]
        length: usize,
        /// Keyboard layout as 'layout' or 'layout:variant' (see --list-layouts)
        #[arg(short = 'k', long, default_value = "modhex")]
        keyboard_layout: LayoutSelection,
        /// List the available keyboard layouts (and variants) and exit
        #[arg(long, conflicts_with_all = ["password", "generate"])]
        list_layouts: bool,
        #[command(flatten)]
        enter: EnterArgs,
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
        #[arg(short = 't', long)]
        totp: bool,
        /// Require touch
        #[arg(short = 'T', long)]
        touch: bool,
        /// Generate random key
        #[arg(short = 'g', long, conflicts_with = "key")]
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
        #[arg(short = 't', long)]
        totp: bool,
        /// Number of digits for TOTP
        #[arg(long, default_value = "6")]
        digits: CliCalcDigits,
    },
    /// Program OATH-HOTP credential
    Hotp {
        /// Slot number (1 or 2)
        slot: CliOtpSlot,
        /// HMAC key (hex, or Base32 with --totp)
        key: Option<String>,
        /// Number of digits (6 or 8)
        #[arg(long, default_value = "6")]
        digits: CliHotpDigits,
        /// Initial counter value
        #[arg(short = 'c', long, default_value_t = 0)]
        counter: u32,
        #[command(flatten)]
        enter: EnterArgs,
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
        #[command(flatten)]
        enter: EnterArgs,
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
        #[arg(long, conflicts_with = "new_access_code", requires = "access_code")]
        delete_access_code: bool,
        /// Current access code (hex)
        #[arg(short = 'A', long)]
        access_code: Option<String>,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
}

impl OtpAction {
    pub fn run(
        self,
        dev: &dyn YubiKeyDevice,
        scp_params: &ScpParams,
        parent_access_code: &Option<String>,
    ) -> Result<()> {
        match self {
            Self::Info => run_info(dev, scp_params),
            Self::Swap { force } => run_swap(dev, scp_params, force),
            Self::Delete {
                slot,
                access_code,
                force,
            } => run_delete(
                dev,
                scp_params,
                slot,
                effective_access_code(parent_access_code, &access_code),
                force,
            ),
            Self::Ndef {
                slot,
                prefix,
                ndef_type,
                access_code,
                force,
            } => run_ndef(
                dev,
                scp_params,
                slot,
                prefix.as_deref(),
                ndef_type.into(),
                effective_access_code(parent_access_code, &access_code),
                force,
            ),
            Self::Yubiotp {
                slot,
                public_id,
                private_id,
                key,
                serial_public_id,
                generate_private_id,
                generate_key,
                enter,
                access_code,
                force,
                config_output,
            } => run_yubiotp(
                dev,
                scp_params,
                YubiOtpOptions {
                    slot,
                    public_id: public_id.as_deref(),
                    private_id: private_id.as_deref(),
                    key: key.as_deref(),
                    serial_public_id,
                    generate_private_id,
                    generate_key,
                    enter: enter.value(),
                    access_code: effective_access_code(parent_access_code, &access_code),
                    force,
                    config_output: config_output.as_deref(),
                },
            ),
            Self::Static {
                slot,
                password,
                generate,
                length,
                keyboard_layout,
                list_layouts,
                enter,
                access_code,
                force,
            } => {
                if list_layouts {
                    print_layouts();
                    return Ok(());
                }
                let slot = slot.expect("slot is required unless --list-layouts is set");
                run_static(
                    dev,
                    scp_params,
                    StaticOptions {
                        slot,
                        password: password.as_deref(),
                        generate,
                        length,
                        keyboard_layout,
                        enter: enter.value(),
                        access_code: effective_access_code(parent_access_code, &access_code),
                        force,
                    },
                )
            }
            Self::Chalresp {
                slot,
                key,
                totp,
                touch,
                generate,
                access_code,
                force,
            } => run_chalresp(
                dev,
                scp_params,
                slot,
                key.as_deref(),
                totp,
                touch,
                generate,
                effective_access_code(parent_access_code, &access_code),
                force,
            ),
            Self::Calculate {
                slot,
                challenge,
                totp,
                digits,
            } => run_calculate(dev, scp_params, slot, challenge.as_deref(), totp, digits),
            Self::Hotp {
                slot,
                key,
                digits,
                counter,
                enter,
                access_code,
                force,
                identifier,
            } => run_hotp(
                dev,
                scp_params,
                HotpOptions {
                    slot,
                    key: key.as_deref(),
                    digits,
                    counter,
                    enter: enter.value(),
                    access_code: effective_access_code(parent_access_code, &access_code),
                    force,
                    identifier: identifier.as_deref(),
                },
            ),
            Self::Settings {
                slot,
                enter,
                pacing,
                use_numeric_keypad,
                serial_usb_visible,
                new_access_code,
                delete_access_code,
                access_code,
                force,
            } => run_settings(
                dev,
                scp_params,
                SettingsOptions {
                    slot,
                    enter: enter.value(),
                    pacing,
                    use_numeric: if use_numeric_keypad { Some(true) } else { None },
                    serial_usb_visible: if serial_usb_visible { Some(true) } else { None },
                    new_access_code: new_access_code.as_deref(),
                    delete_access_code,
                    access_code: effective_access_code(parent_access_code, &access_code),
                    force,
                },
            ),
        }
    }
}

impl EnterArgs {
    pub fn value(self) -> Option<bool> {
        if self.enter {
            Some(true)
        } else if self.no_enter {
            Some(false)
        } else {
            None
        }
    }
}

/// Trait for operations that can be run on any [`YubiOtpSession`].
trait YubiOtpOp<R> {
    fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<R>;
}

/// Open an OTP session (preferring HID, falling back to SmartCard) and run `op`.
fn with_otp_session<F: YubiOtpOp<R>, R>(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    f: F,
) -> Result<R> {
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::OTP)?;

    // If SCP is needed or NFC, must use SmartCard
    if scp_config.is_some() || scp::is_nfc(dev) {
        return with_otp_sc(dev, scp_config, f);
    }

    // Try OTP HID first
    if let Ok(conn) = dev.open_otp()
        && let Ok(mut session) = YubiOtpSession::new_otp(conn)
    {
        return f.run(&mut session);
    }

    // Fall back to SmartCard
    with_otp_sc(dev, scp_config, f)
}

fn with_otp_sc<F: YubiOtpOp<R>, R>(
    dev: &dyn YubiKeyDevice,
    scp_config: Option<yubikit::smartcard::ScpKeyParams>,
    f: F,
) -> Result<R> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| format_smartcard_connection_error("OTP", e))?;
    match scp_config {
        None => {
            let mut session =
                YubiOtpSession::new(conn).map_err(|(e, _)| format_session_error("OTP", e))?;
            f.run(&mut session)
        }
        Some(params) => {
            let mut session = YubiOtpSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| format_session_error("OTP", e))?;
            f.run(&mut session)
        }
    }
}

/// Prints the available keyboard layouts, one per line, e.g.
/// `de - German (variants: deadacute, dvorak)`.
pub fn print_layouts() {
    for layout in KeyboardLayout::all() {
        let variants = layout.variants();
        if variants.is_empty() {
            println!("{} - {}", layout.name(), layout.description());
        } else {
            let names: Vec<&str> = variants.iter().map(|v| v.name()).collect();
            println!(
                "{} - {} (variants: {})",
                layout.name(),
                layout.description(),
                names.join(", ")
            );
        }
    }
}

fn encode_password(password: &str, layout: LayoutSelection) -> Result<Vec<u8>> {
    let map = layout.scancodes();
    password
        .chars()
        .map(|c| {
            map.get(&c)
                .copied()
                .ok_or_else(|| anyhow!("Character '{c}' not supported in {} layout", layout.name()))
        })
        .collect()
}

fn generate_static_pw(length: usize, layout: LayoutSelection) -> Result<String> {
    let chars: Vec<char> = layout
        .scancodes()
        .keys()
        .copied()
        .filter(|c| !"\t\n ".contains(*c))
        .collect();
    let mut pw = String::with_capacity(length);
    let mut rand_bytes = vec![0u8; length];
    getrandom::fill(&mut rand_bytes).map_err(|e| anyhow!("Failed to generate random: {e}"))?;
    for b in rand_bytes {
        pw.push(chars[b as usize % chars.len()]);
    }
    Ok(pw)
}

fn parse_access_code(s: &str) -> Result<[u8; ACC_CODE_SIZE]> {
    let bytes = hex::decode(s).map_err(|_| anyhow!("Access code must be hex-encoded."))?;
    if bytes.len() != ACC_CODE_SIZE {
        return Err(anyhow!(
            "Access code must be {ACC_CODE_SIZE} bytes ({} hex chars).",
            ACC_CODE_SIZE * 2
        ));
    }
    let mut arr = [0u8; ACC_CODE_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn to_access_code(code: &[u8; ACC_CODE_SIZE]) -> Result<AccessCode> {
    AccessCode::new(code.as_slice()).map_err(|e| anyhow!("Invalid access code: {e}"))
}

fn format_otp_write_error<E: std::fmt::Display>(e: E) -> anyhow::Error {
    if e.to_string().contains("Command rejected: No data") {
        anyhow!("Failed to write to the YubiKey. Slot(s) may be protected with an access code.")
    } else {
        anyhow!("Failed to write to the YubiKey: {e}")
    }
}

fn confirm_slot_overwrite<C: Connection + 'static>(session: &YubiOtpSession<C>, slot: Slot) {
    let state = session.get_config_state();
    if state.is_configured(slot).unwrap_or(false)
        && !confirm(&format!(
            "Slot {} is already configured. Overwrite configuration?",
            slot.map(1, 2)
        ))
    {
        std::process::exit(1);
    }
}

fn format_oath_code(response: &[u8], digits: u8) -> String {
    let offs = (response[response.len() - 1] & 0xF) as usize;
    let code = u32::from_be_bytes([
        response[offs] & 0x7F,
        response[offs + 1],
        response[offs + 2],
        response[offs + 3],
    ]);
    let modulus = 10u32.pow(digits as u32);
    format!("{:0>width$}", code % modulus, width = digits as usize)
}

fn parse_hex_key(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|_| anyhow!("Key must be hex-encoded."))
}

fn prompt_for_touch() {
    eprintln!("Touch your YubiKey...");
}

pub fn run_info(dev: &dyn YubiKeyDevice, scp_params: &ScpParams) -> Result<()> {
    struct Info;
    impl YubiOtpOp<()> for Info {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            let state = session.get_config_state();
            for slot in [Slot::One, Slot::Two] {
                let num = slot.map(1, 2);
                let configured = state.is_configured(slot).map_or("unknown".into(), |b| {
                    if b {
                        "programmed".to_string()
                    } else {
                        "empty".to_string()
                    }
                });
                println!("Slot {num}: {configured}");
            }
            Ok(())
        }
    }
    with_otp_session(dev, scp_params, Info)
}

pub fn run_swap(dev: &dyn YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<()> {
    if !force && !confirm("Swap the two slot configurations?") {
        return Err(anyhow!("Aborted."));
    }
    struct Swap;
    impl YubiOtpOp<()> for Swap {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            session.swap_slots().map_err(format_otp_write_error)?;
            eprintln!("Slot configurations swapped.");
            Ok(())
        }
    }
    with_otp_session(dev, scp_params, Swap)
}

pub fn run_delete(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    access_code: Option<&str>,
    force: bool,
) -> Result<()> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    if !force {
        struct CheckEmpty;
        impl YubiOtpOp<ConfigState> for CheckEmpty {
            fn run<C: Connection + 'static>(
                self,
                session: &mut YubiOtpSession<C>,
            ) -> Result<ConfigState> {
                Ok(session.get_config_state())
            }
        }
        let state = with_otp_session(dev, scp_params, CheckEmpty)?;
        if matches!(state.is_configured(slot), Ok(false)) {
            return Err(anyhow!("Not possible to delete an empty slot."));
        }
        if !confirm(&format!("Delete slot {}?", slot.map(1, 2))) {
            return Err(anyhow!("Aborted."));
        }
    }

    struct Delete {
        slot: Slot,
        acc: Option<[u8; ACC_CODE_SIZE]>,
    }
    impl YubiOtpOp<()> for Delete {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            let acc = self.acc.as_ref().map(to_access_code).transpose()?;
            session
                .delete_slot(self.slot, acc.as_ref())
                .map_err(format_otp_write_error)?;
            eprintln!("Configuration slot {} deleted.", self.slot.map(1, 2));
            Ok(())
        }
    }
    with_otp_session(dev, scp_params, Delete { slot, acc })
}

pub fn run_ndef(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    prefix: Option<&str>,
    ndef_type: NdefType,
    access_code: Option<&str>,
    force: bool,
) -> Result<()> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;
    let nt = ndef_type;
    if !force
        && !confirm(&format!(
            "Configure slot {} for NDEF ({ndef_type:?})?",
            slot.map(1, 2)
        ))
    {
        return Err(anyhow!("Aborted."));
    }
    struct Ndef {
        slot: Slot,
        prefix: Option<String>,
        acc: Option<[u8; ACC_CODE_SIZE]>,
        nt: NdefType,
    }
    impl YubiOtpOp<()> for Ndef {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            session
                .set_ndef_configuration(
                    self.slot,
                    self.prefix.as_deref(),
                    self.acc.as_ref().map(|a| a.as_slice()),
                    self.nt,
                )
                .map_err(|e| anyhow!("Failed to configure NDEF: {e}"))?;
            eprintln!("NDEF configuration updated.");
            Ok(())
        }
    }
    with_otp_session(
        dev,
        scp_params,
        Ndef {
            slot,
            prefix: prefix.map(String::from),
            acc,
            nt,
        },
    )
}

pub struct YubiOtpOptions<'a> {
    pub slot: CliOtpSlot,
    pub public_id: Option<&'a str>,
    pub private_id: Option<&'a str>,
    pub key: Option<&'a str>,
    pub serial_public_id: bool,
    pub generate_private_id: bool,
    pub generate_key: bool,
    pub enter: Option<bool>,
    pub access_code: Option<&'a str>,
    pub force: bool,
    pub config_output: Option<&'a str>,
}

pub fn run_yubiotp(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    options: YubiOtpOptions<'_>,
) -> Result<()> {
    let YubiOtpOptions {
        slot,
        public_id,
        private_id,
        key,
        serial_public_id,
        generate_private_id,
        generate_key,
        enter,
        access_code,
        force,
        config_output,
    } = options;
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    // Resolve public ID
    let pub_id_bytes: Vec<u8> = if serial_public_id {
        struct GetSerial;
        impl YubiOtpOp<u32> for GetSerial {
            fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<u32> {
                session
                    .get_serial()
                    .map_err(|e| anyhow!("Failed to get serial: {e}"))
            }
        }
        let serial = with_otp_session(dev, scp_params, GetSerial)?;
        let mut id = vec![0xffu8, 0x00];
        id.extend_from_slice(&serial.to_be_bytes());
        eprintln!("Using YubiKey serial as public ID: {}", modhex_encode(&id));
        id
    } else if let Some(pid) = public_id {
        modhex_decode(pid).map_err(|_| anyhow!("Invalid modhex public ID."))?
    } else if force {
        return Err(anyhow!(
            "Public ID not given. Remove the --force flag, or add the --serial-public-id flag or --public-id option."
        ));
    } else {
        util::prompt_bytes(
            "Enter public ID",
            &util::ByteFormat::modhex(util::ByteLen::Range(0, 16)),
        )?
    };

    // Resolve private ID
    let priv_id: [u8; UID_SIZE] = if generate_private_id {
        let mut id = [0u8; UID_SIZE];
        getrandom::fill(&mut id).map_err(|e| anyhow!("Failed to generate: {e}"))?;
        eprintln!("Using a randomly generated private ID: {}", hex::encode(id));
        id
    } else if let Some(pid) = private_id {
        let bytes = hex::decode(pid).map_err(|_| anyhow!("Private ID must be hex-encoded."))?;
        if bytes.len() != UID_SIZE {
            return Err(anyhow!(
                "Private ID must be {UID_SIZE} bytes ({} hex chars).",
                UID_SIZE * 2
            ));
        }
        let mut arr = [0u8; UID_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    } else if force {
        return Err(anyhow!(
            "Private ID not given. Remove the --force flag, or add the --generate-private-id flag or --private-id option."
        ));
    } else {
        let bytes = util::prompt_bytes(
            "Enter private ID",
            &util::ByteFormat::hex(util::ByteLen::Exact(UID_SIZE)).masked(),
        )?;
        let mut arr = [0u8; UID_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    };

    // Resolve key
    let key_bytes: [u8; KEY_SIZE] = if generate_key {
        let mut k = [0u8; KEY_SIZE];
        getrandom::fill(&mut k).map_err(|e| anyhow!("Failed to generate: {e}"))?;
        eprintln!("Using a randomly generated secret key: {}", hex::encode(k));
        k
    } else if let Some(k) = key {
        let bytes = hex::decode(k).map_err(|_| anyhow!("Key must be hex-encoded."))?;
        if bytes.len() != KEY_SIZE {
            return Err(anyhow!(
                "Key must be {KEY_SIZE} bytes ({} hex chars).",
                KEY_SIZE * 2
            ));
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    } else if force {
        return Err(anyhow!(
            "Secret key not given. Remove the --force flag, or add the --generate-key flag or --key option."
        ));
    } else {
        let bytes = util::prompt_bytes(
            "Enter secret key",
            &util::ByteFormat::hex(util::ByteLen::Exact(KEY_SIZE)).masked(),
        )?;
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    };

    if !force
        && !confirm(&format!(
            "Program a YubiOTP credential in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(anyhow!("Aborted."));
    }

    let mut config = SlotConfiguration::yubiotp(&pub_id_bytes, &priv_id, &key_bytes)
        .map_err(|e| anyhow!("Invalid configuration: {e}"))?;
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }

    let need_serial = config_output.is_some();
    let output_path = config_output.map(String::from);

    struct ProgramYubiOtp {
        slot: Slot,
        config: SlotConfiguration,
        acc: Option<[u8; ACC_CODE_SIZE]>,
        need_serial: bool,
    }
    impl YubiOtpOp<Option<u32>> for ProgramYubiOtp {
        fn run<C: Connection + 'static>(
            self,
            session: &mut YubiOtpSession<C>,
        ) -> Result<Option<u32>> {
            let acc = self.acc.as_ref().map(to_access_code).transpose()?;
            session
                .put_configuration(self.slot, &self.config, acc.as_ref(), None)
                .map_err(format_otp_write_error)?;
            if self.need_serial {
                let serial = session
                    .get_serial()
                    .map_err(|e| anyhow!("Failed to get serial: {e}"))?;
                Ok(Some(serial))
            } else {
                Ok(None)
            }
        }
    }
    let serial = with_otp_session(
        dev,
        scp_params,
        ProgramYubiOtp {
            slot,
            config,
            acc,
            need_serial,
        },
    )?;

    if let Some(output_path) = output_path {
        let serial = serial.unwrap();
        let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        let access_code_hex = acc.as_ref().map_or(String::new(), hex::encode);
        let csv_line = format!(
            "{},{},{},{},{},{},",
            serial,
            modhex_encode(&pub_id_bytes),
            hex::encode(priv_id),
            hex::encode(key_bytes),
            access_code_hex,
            timestamp,
        );
        util::write_file_or_stdout(&output_path, (csv_line + "\n").as_bytes())?;
        eprintln!("Configuration parameters written to {output_path}.");
    }

    Ok(())
}

pub struct StaticOptions<'a> {
    pub slot: CliOtpSlot,
    pub password: Option<&'a str>,
    pub generate: bool,
    pub length: usize,
    pub keyboard_layout: LayoutSelection,
    pub enter: Option<bool>,
    pub access_code: Option<&'a str>,
    pub force: bool,
}

pub fn run_static(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    options: StaticOptions<'_>,
) -> Result<()> {
    let StaticOptions {
        slot,
        password,
        generate,
        length,
        keyboard_layout,
        enter,
        access_code,
        force,
    } = options;
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    let pw = if let Some(p) = password {
        if p.len() > 38 {
            return Err(anyhow!(
                "Password too long (maximum length is 38 characters)."
            ));
        }
        p.to_string()
    } else if generate {
        generate_static_pw(length, keyboard_layout)?
    } else {
        util::prompt_new_secret("Static password")?
    };

    let scan_codes = encode_password(&pw, keyboard_layout)?;

    let mut config = SlotConfiguration::static_password(&scan_codes)
        .map_err(|e| anyhow!("Invalid configuration: {e}"))?;
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }

    struct ProgramStatic {
        slot: Slot,
        config: SlotConfiguration,
        acc: Option<[u8; ACC_CODE_SIZE]>,
        force: bool,
    }
    impl YubiOtpOp<()> for ProgramStatic {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            if !self.force {
                confirm_slot_overwrite(session, self.slot);
            }
            let acc = self.acc.as_ref().map(to_access_code).transpose()?;
            session
                .put_configuration(self.slot, &self.config, acc.as_ref(), None)
                .map_err(format_otp_write_error)?;
            eprintln!("Static password stored in slot {}.", self.slot.map(1, 2));
            Ok(())
        }
    }
    with_otp_session(
        dev,
        scp_params,
        ProgramStatic {
            slot,
            config,
            acc,
            force,
        },
    )
}

pub fn run_chalresp(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    key: Option<&str>,
    totp: bool,
    touch: bool,
    generate: bool,
    access_code: Option<&str>,
    force: bool,
) -> Result<()> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    let key_bytes: Vec<u8> = if let Some(k) = key {
        if totp {
            parse_b32_key(k).map_err(|_| anyhow!("Invalid Base32-encoded key."))?
        } else {
            parse_hex_key(k)?
        }
    } else if generate {
        let mut k = vec![0u8; 20];
        getrandom::fill(&mut k).map_err(|e| anyhow!("Failed to generate: {e}"))?;
        if totp {
            eprintln!(
                "Using a randomly generated key (base32): {}",
                b32_encode(&k)
            );
        } else {
            eprintln!("Using a randomly generated key (hex): {}", hex::encode(&k));
        }
        k
    } else if force {
        return Err(anyhow!(
            "No secret key given. Remove the --force flag, set the KEY argument or set the --generate flag."
        ));
    } else if totp {
        loop {
            match util::prompt_bytes(
                "Enter a secret key",
                &util::ByteFormat::base32(util::ByteLen::Any).masked(),
            ) {
                Ok(k) => break k,
                Err(e) => eprintln!("{e}"),
            }
        }
    } else {
        util::prompt_bytes(
            "Enter a secret key",
            &util::ByteFormat::hex(util::ByteLen::Any).masked(),
        )?
    };

    let cred_type = if totp { "TOTP" } else { "challenge-response" };
    if !force
        && !confirm(&format!(
            "Program a {cred_type} credential in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(anyhow!("Aborted."));
    }

    let hmac_key = HmacKey::new(&key_bytes).map_err(|e| anyhow!("Invalid key: {e}"))?;
    let mut config =
        SlotConfiguration::hmac_sha1(&hmac_key).map_err(|e| anyhow!("Invalid key: {e}"))?;
    if touch {
        config = config.require_touch(true);
    }

    struct ProgramChalResp {
        slot: Slot,
        config: SlotConfiguration,
        acc: Option<[u8; ACC_CODE_SIZE]>,
        cred_type: String,
    }
    impl YubiOtpOp<()> for ProgramChalResp {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            let acc = self.acc.as_ref().map(to_access_code).transpose()?;
            session
                .put_configuration(self.slot, &self.config, acc.as_ref(), None)
                .map_err(format_otp_write_error)?;
            eprintln!(
                "{} credential stored in slot {}.",
                self.cred_type,
                self.slot.map(1, 2)
            );
            Ok(())
        }
    }
    with_otp_session(
        dev,
        scp_params,
        ProgramChalResp {
            slot,
            config,
            acc,
            cred_type: cred_type.to_string(),
        },
    )
}

pub fn run_calculate(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    challenge: Option<&str>,
    totp: bool,
    digits: CliCalcDigits,
) -> Result<()> {
    let slot: Slot = slot.into();
    let digits = digits.as_u8();

    let challenge_bytes: Vec<u8> = if totp {
        if let Some(c) = challenge {
            let ts: u64 = c
                .parse()
                .map_err(|_| anyhow!("Timestamp challenge for TOTP must be an integer."))?;
            (ts / 30).to_be_bytes().to_vec()
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            (now / 30).to_be_bytes().to_vec()
        }
    } else if let Some(c) = challenge {
        hex::decode(c).map_err(|_| anyhow!("Challenge must be hex-encoded."))?
    } else {
        util::prompt_bytes(
            "Enter a challenge",
            &util::ByteFormat::hex(util::ByteLen::Any),
        )?
    };

    struct Calculate {
        slot: Slot,
        challenge_bytes: Vec<u8>,
        totp: bool,
        digits: u8,
    }
    impl YubiOtpOp<()> for Calculate {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            // Check that slot is configured
            if matches!(
                session.get_config_state().is_configured(self.slot),
                Ok(false)
            ) {
                return Err(anyhow!(
                    "Cannot perform challenge-response on an empty slot."
                ));
            }

            // Set up Ctrl+C cancellation
            cancel::clear();
            let prompted = AtomicBool::new(false);
            let on_keepalive = |status: u8| {
                if status == 2 && !prompted.swap(true, Ordering::Relaxed) {
                    prompt_for_touch();
                }
            };

            let result = session
                .calculate_hmac_sha1_with_cancel(
                    self.slot,
                    &self.challenge_bytes,
                    Some(&cancel::is_cancelled),
                    Some(&on_keepalive),
                )
                .map_err(|e| anyhow!("Failed to calculate: {e}"))?;

            if self.totp {
                println!("{}", format_oath_code(&result, self.digits));
            } else {
                println!("{}", hex::encode(&result));
            }
            Ok(())
        }
    }
    with_otp_session(
        dev,
        scp_params,
        Calculate {
            slot,
            challenge_bytes,
            totp,
            digits,
        },
    )
}

pub struct HotpOptions<'a> {
    pub slot: CliOtpSlot,
    pub key: Option<&'a str>,
    pub digits: CliHotpDigits,
    pub counter: u32,
    pub enter: Option<bool>,
    pub access_code: Option<&'a str>,
    pub force: bool,
    pub identifier: Option<&'a str>,
}

pub fn run_hotp(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    options: HotpOptions<'_>,
) -> Result<()> {
    let HotpOptions {
        slot,
        key,
        digits,
        counter,
        enter,
        access_code,
        force,
        identifier,
    } = options;
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    let key_bytes = if let Some(k) = key {
        parse_hex_key(k)?
    } else {
        loop {
            match util::prompt_bytes(
                "Enter a secret key",
                &util::ByteFormat::hex(util::ByteLen::Any).masked(),
            ) {
                Ok(k) => break k,
                Err(e) => eprintln!("{e}"),
            }
        }
    };

    // Parse token identifier
    let (token_id, mh1, mh2) = if let Some(ident) = identifier {
        let ident = if ident == "-" { "ubhe" } else { ident };
        let ident = match ident.len() {
            4 => {
                struct GetSerial;
                impl YubiOtpOp<u32> for GetSerial {
                    fn run<C: Connection + 'static>(
                        self,
                        session: &mut YubiOtpSession<C>,
                    ) -> Result<u32> {
                        session
                            .get_serial()
                            .map_err(|e| anyhow!("Failed to get serial: {e}"))
                    }
                }
                let serial = with_otp_session(dev, scp_params, GetSerial)?;
                format!("{ident}{serial:08}")
            }
            8 => format!("ubhe{ident}"),
            12 => ident.to_string(),
            _ => return Err(anyhow!("Incorrect length for token identifier.")),
        };

        let (omp_m, omp) = parse_modhex_or_bcd(&ident[..2])?;
        let (tt_m, tt) = parse_modhex_or_bcd(&ident[2..4])?;
        let (mui_m, mui) = parse_modhex_or_bcd(&ident[4..])?;

        if tt_m && !omp_m {
            return Err(anyhow!("TT can only be modhex encoded if OMP is as well."));
        }
        if mui_m && !(omp_m && tt_m) {
            return Err(anyhow!(
                "MUI can only be modhex encoded if OMP and TT are as well."
            ));
        }

        let mut tid = Vec::new();
        tid.extend_from_slice(&omp);
        tid.extend_from_slice(&tt);
        tid.extend_from_slice(&mui);

        let mh1 = if mui_m { true } else { omp_m && !tt_m };
        let mh2 = mui_m || tt_m;
        (tid, mh1, mh2)
    } else {
        (vec![], false, false)
    };

    if !force
        && !confirm(&format!(
            "Program a HOTP credential in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(anyhow!("Aborted."));
    }

    let hmac_key = HmacKey::new(&key_bytes).map_err(|e| anyhow!("Invalid key: {e}"))?;
    let mut config = SlotConfiguration::hotp(&hmac_key).map_err(|e| anyhow!("Invalid key: {e}"))?;
    if matches!(digits, CliHotpDigits::Eight) {
        config = config.digits8(true);
    }
    if counter > 0 {
        config = config
            .imf(counter)
            .map_err(|e| anyhow!("Invalid counter: {e}"))?;
    }
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }
    if !token_id.is_empty() {
        config = config
            .token_id(&token_id, mh1, mh2)
            .map_err(|e| anyhow!("Invalid token identifier: {e}"))?;
    }

    struct ProgramHotp {
        slot: Slot,
        config: SlotConfiguration,
        acc: Option<[u8; ACC_CODE_SIZE]>,
    }
    impl YubiOtpOp<()> for ProgramHotp {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            let acc = self.acc.as_ref().map(to_access_code).transpose()?;
            session
                .put_configuration(self.slot, &self.config, acc.as_ref(), None)
                .map_err(format_otp_write_error)?;
            eprintln!("HOTP credential stored in slot {}.", self.slot.map(1, 2));
            Ok(())
        }
    }
    with_otp_session(dev, scp_params, ProgramHotp { slot, config, acc })
}

pub struct SettingsOptions<'a> {
    pub slot: CliOtpSlot,
    pub enter: Option<bool>,
    pub pacing: Option<CliPacing>,
    pub use_numeric: Option<bool>,
    pub serial_usb_visible: Option<bool>,
    pub new_access_code: Option<&'a str>,
    pub delete_access_code: bool,
    pub access_code: Option<&'a str>,
    pub force: bool,
}

pub fn run_settings(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    options: SettingsOptions<'_>,
) -> Result<()> {
    let SettingsOptions {
        slot,
        enter,
        pacing,
        use_numeric,
        serial_usb_visible,
        new_access_code,
        delete_access_code,
        access_code,
        force,
    } = options;
    let slot: Slot = slot.into();
    let cur_acc = access_code.map(parse_access_code).transpose()?;

    if delete_access_code && access_code.is_none() {
        return Err(anyhow!(
            "--delete-access-code used without providing an access code (see \"ykman otp --help\" for more info)."
        ));
    }

    {
        struct CheckConfigured;
        impl YubiOtpOp<ConfigState> for CheckConfigured {
            fn run<C: Connection + 'static>(
                self,
                session: &mut YubiOtpSession<C>,
            ) -> Result<ConfigState> {
                Ok(session.get_config_state())
            }
        }
        let state = with_otp_session(dev, scp_params, CheckConfigured)?;
        if matches!(state.is_configured(slot), Ok(false)) {
            return Err(anyhow!("Not possible to update settings on an empty slot."));
        }
    }

    let new_acc = if delete_access_code {
        None
    } else if let Some(nac) = new_access_code {
        Some(parse_access_code(nac)?)
    } else {
        cur_acc
    };

    if !force
        && !confirm(&format!(
            "Update the settings for slot {}? All existing settings will be overwritten.",
            slot.map(1, 2)
        ))
    {
        return Err(anyhow!("Aborted."));
    }

    let mut config = SlotConfiguration::update();
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }
    if let Some(p) = pacing {
        let p = p.as_u8();
        config = config.pacing(p >= 20, p >= 40);
    }
    if let Some(v) = use_numeric {
        config = config.use_numeric(v);
    }
    if let Some(v) = serial_usb_visible {
        config = config.serial_usb_visible(v);
    }

    struct UpdateSettings {
        slot: Slot,
        config: SlotConfiguration,
        new_acc: Option<[u8; ACC_CODE_SIZE]>,
        cur_acc: Option<[u8; ACC_CODE_SIZE]>,
    }
    impl YubiOtpOp<()> for UpdateSettings {
        fn run<C: Connection + 'static>(self, session: &mut YubiOtpSession<C>) -> Result<()> {
            let new_acc = self.new_acc.as_ref().map(to_access_code).transpose()?;
            let cur_acc = self.cur_acc.as_ref().map(to_access_code).transpose()?;
            session
                .update_configuration(self.slot, &self.config, new_acc.as_ref(), cur_acc.as_ref())
                .map_err(format_otp_write_error)?;
            eprintln!("Settings for slot {} updated.", self.slot.map(1, 2));
            Ok(())
        }
    }
    with_otp_session(
        dev,
        scp_params,
        UpdateSettings {
            slot,
            config,
            new_acc,
            cur_acc,
        },
    )
}

/// Parse a value as modhex or BCD (decimal digits encoded as hex).
/// Returns (is_modhex, decoded_bytes).
fn parse_modhex_or_bcd(value: &str) -> Result<(bool, Vec<u8>)> {
    if let Ok(bytes) = modhex_decode(value) {
        return Ok((true, bytes));
    }
    // Try to parse as decimal digits (BCD)
    if value.chars().all(|c| c.is_ascii_digit()) {
        let bytes = hex::decode(value).map_err(|_| anyhow!("Value must be modhex or decimal."))?;
        return Ok((false, bytes));
    }
    Err(anyhow!("Value must be modhex or decimal."))
}
