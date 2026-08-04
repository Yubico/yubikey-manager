use anyhow::{Result, anyhow};
use clap::Subcommand;
use yubikit::core::Connection;
use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::{
    Capability, DeviceConfig, DeviceFlag, ManagementError, ManagementSession,
};

use crate::cli_enums::CliCapability;
use crate::util::{
    confirm, format_session_error, format_smartcard_connection_error, prompt_new_secret,
    prompt_secret,
};

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Configure USB applications
    Usb {
        /// Enable an application (can be repeated)
        #[arg(short = 'e', long, action = clap::ArgAction::Append)]
        enable: Vec<CliCapability>,
        /// Disable an application (can be repeated)
        #[arg(short = 'x', long, action = clap::ArgAction::Append)]
        disable: Vec<CliCapability>,
        /// Enable all supported applications
        #[arg(short = 'a', long)]
        enable_all: bool,
        /// Current lock code as 32 hex characters (16 bytes)
        #[arg(short = 'L', long, value_name = "HEX")]
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
        #[arg(short = 'e', long, action = clap::ArgAction::Append)]
        enable: Vec<CliCapability>,
        /// Disable an application (can be repeated)
        #[arg(short = 'x', long, action = clap::ArgAction::Append)]
        disable: Vec<CliCapability>,
        /// Enable all supported applications
        #[arg(short = 'a', long)]
        enable_all: bool,
        /// Disable all supported applications
        #[arg(short = 'X', long)]
        disable_all: bool,
        /// Current lock code as 32 hex characters (16 bytes)
        #[arg(short = 'L', long, value_name = "HEX")]
        lock_code: Option<String>,
        /// Disable NFC until next USB power cycle
        #[arg(short = 'R', long)]
        restrict: bool,
        /// Confirm without prompting
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Set or change the configuration lock code
    ///
    /// A lock code may be used to protect the application configuration. It must be exactly
    /// 32 hexadecimal characters, representing 16 bytes.
    SetLockCode {
        /// Current lock code as 32 hex characters (16 bytes)
        #[arg(short = 'L', long, value_name = "HEX")]
        lock_code: Option<String>,
        /// New lock code as 32 hex characters (16 bytes)
        #[arg(short = 'n', long, value_name = "HEX", conflicts_with = "generate")]
        new_lock_code: Option<String>,
        /// Clear the lock code
        #[arg(short = 'c', long, conflicts_with_all = ["new_lock_code", "generate"])]
        clear: bool,
        /// Generate a random 32-character hex lock code
        #[arg(short = 'g', long, conflicts_with = "new_lock_code")]
        generate: bool,
        /// Confirm the action without prompting
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

impl ConfigAction {
    pub fn run(self, dev: &dyn YubiKeyDevice) -> Result<()> {
        match self {
            Self::Usb {
                enable,
                disable,
                enable_all,
                lock_code,
                touch_eject,
                no_touch_eject,
                autoeject_timeout,
                chalresp_timeout,
                force,
            } => run_usb(
                dev,
                &enable,
                &disable,
                enable_all,
                lock_code.as_deref(),
                touch_eject,
                no_touch_eject,
                autoeject_timeout,
                chalresp_timeout,
                force,
            ),
            Self::Nfc {
                enable,
                disable,
                enable_all,
                disable_all,
                lock_code,
                restrict,
                force,
            } => run_nfc(
                dev,
                &enable,
                &disable,
                enable_all,
                disable_all,
                lock_code.as_deref(),
                restrict,
                force,
            ),
            Self::SetLockCode {
                lock_code,
                new_lock_code,
                clear,
                generate,
                force,
            } => run_set_lock_code(
                dev,
                lock_code.as_deref(),
                new_lock_code.as_deref(),
                clear,
                generate,
                force,
            ),
            Self::Mode {
                mode,
                touch_eject,
                autoeject_timeout,
                chalresp_timeout,
                force,
            } => run_mode(
                dev,
                &mode,
                touch_eject,
                autoeject_timeout,
                chalresp_timeout,
                force,
            ),
            Self::Reset { force } => run_reset(dev, force),
        }
    }
}

/// Open a management session on any available transport and run a generic function.
///
/// Tries SmartCard first, then OTP HID, then FIDO HID.
fn with_management_session<F, R>(dev: &dyn YubiKeyDevice, f: F) -> Result<R>
where
    F: ManagementOp<R>,
{
    if let Ok(conn) = dev.open_smartcard() {
        let mut session =
            ManagementSession::new(conn).map_err(|(e, _)| format_session_error("management", e))?;
        return f.run(&mut session);
    }
    if let Ok(conn) = dev.open_otp() {
        let mut session = ManagementSession::new_otp(conn)
            .map_err(|(e, _)| format_session_error("management", e))?;
        return f.run(&mut session);
    }
    if let Ok(conn) = dev.open_fido() {
        let mut session = ManagementSession::new_fido(conn)
            .map_err(|(e, _)| format_session_error("management", e))?;
        return f.run(&mut session);
    }
    Err(anyhow!(
        "Couldn't connect to the YubiKey. Command requires CCID, OTP, or FIDO access to be enabled."
    ))
}

/// Trait for operations that can be run on any [`ManagementSession`].
trait ManagementOp<R> {
    fn run<C: Connection + 'static>(self, session: &mut ManagementSession<C>) -> Result<R>;
}

fn write_config(
    dev: &dyn YubiKeyDevice,
    config: &DeviceConfig,
    reboot: bool,
    lock_code: Option<&[u8]>,
    new_lock_code: Option<&[u8]>,
) -> Result<()> {
    struct WriteConfig<'a> {
        config: &'a DeviceConfig,
        reboot: bool,
        lock_code: Option<&'a [u8]>,
        new_lock_code: Option<&'a [u8]>,
    }
    impl ManagementOp<()> for WriteConfig<'_> {
        fn run<C: Connection + 'static>(self, session: &mut ManagementSession<C>) -> Result<()> {
            session
                .write_device_config(self.config, self.reboot, self.lock_code, self.new_lock_code)
                .map_err(format_write_config_error)
        }
    }
    with_management_session(
        dev,
        WriteConfig {
            config,
            reboot,
            lock_code,
            new_lock_code,
        },
    )
}

fn format_write_config_error<E: std::fmt::Debug + std::fmt::Display>(
    error: ManagementError<E>,
) -> anyhow::Error {
    let message = error.to_string();
    if message.contains("SW=0x63C0") {
        anyhow!("Failed to write config: Wrong lock code provided")
    } else if message.contains("SW=0x6983") {
        anyhow!("Failed to write config: Lock code blocked. Remove and re-insert the YubiKey.")
    } else {
        anyhow!("Failed to write config: {error}")
    }
}

fn parse_lock_code(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!(
            "Lock code has the wrong format. It must be 32 hexadecimal characters."
        ));
    }
    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect();
    let bytes = bytes.map_err(|_| {
        anyhow!("Lock code has the wrong format. It must be 32 hexadecimal characters.")
    })?;
    if bytes.len() != 16 {
        return Err(anyhow!(
            "Lock code has the wrong format. It must be 32 hexadecimal characters."
        ));
    }
    Ok(bytes)
}

fn current_lock_code(
    is_locked: bool,
    lock_code: Option<&str>,
    prompt: &str,
) -> Result<Option<Vec<u8>>> {
    if is_locked {
        let code = match lock_code {
            Some(code) => code.to_string(),
            None => prompt_secret(prompt)?,
        };
        Ok(Some(parse_lock_code(&code)?))
    } else {
        reject_lock_code_if_unlocked(is_locked, lock_code)?;
        Ok(None)
    }
}

fn reject_lock_code_if_unlocked(is_locked: bool, lock_code: Option<&str>) -> Result<()> {
    if !is_locked && lock_code.is_some() {
        Err(anyhow!(
            "Lock code provided, but configuration is not locked."
        ))
    } else {
        Ok(())
    }
}

/// Compute capability changes for a transport and confirm with the user.
///
/// Returns the new enabled capabilities set and a list of change descriptions.
/// The caller is responsible for checking whether the overall changes list is empty.
fn compute_capability_changes(
    transport_name: &str,
    supported: Capability,
    enabled: Capability,
    enable: &[CliCapability],
    disable: &[CliCapability],
    enable_all: bool,
    disable_all: bool,
    allow_disable_all: bool,
) -> Result<(Capability, Vec<String>)> {
    let mut new_enabled = enabled;
    let mut changes = Vec::new();

    if enable_all {
        for &cap in Capability::ALL {
            if supported.contains(cap) && !enabled.contains(cap) {
                new_enabled |= cap;
                changes.push(format!("Enable {}", cap.display_name()));
            }
        }
    }
    if disable_all {
        for &cap in Capability::ALL {
            if supported.contains(cap) && enabled.contains(cap) {
                new_enabled = Capability(new_enabled.0 & !cap.0);
                changes.push(format!("Disable {}", cap.display_name()));
            }
        }
    }

    for name in enable {
        let cap: Capability = (*name).into();
        if !supported.contains(cap) {
            return Err(anyhow!(
                "{} is not supported on {transport_name}.",
                cap.display_name()
            ));
        }
        if !enabled.contains(cap) {
            new_enabled |= cap;
            changes.push(format!("Enable {}", cap.display_name()));
        }
    }
    for name in disable {
        let cap: Capability = (*name).into();
        if enabled.contains(cap) {
            new_enabled = Capability(new_enabled.0 & !cap.0);
            changes.push(format!("Disable {}", cap.display_name()));
        }
    }

    if !allow_disable_all && new_enabled.is_empty() {
        return Err(anyhow!("Cannot disable all {transport_name} applications."));
    }

    Ok((new_enabled, changes))
}

/// Confirm configuration changes with the user, or proceed if `force` is set.
fn confirm_config_changes(transport_name: &str, changes: &[String], force: bool) -> Result<()> {
    if !force {
        eprintln!("{transport_name} configuration changes:");
        for c in changes {
            eprintln!("  {c}");
        }
        if !confirm("Proceed?") {
            return Err(anyhow!("Aborted by user."));
        }
    }
    Ok(())
}

pub fn run_usb(
    dev: &dyn YubiKeyDevice,
    enable: &[CliCapability],
    disable: &[CliCapability],
    enable_all: bool,
    lock_code: Option<&str>,
    touch_eject: bool,
    no_touch_eject: bool,
    autoeject_timeout: Option<u16>,
    chalresp_timeout: Option<u8>,
    force: bool,
) -> Result<()> {
    let info = dev.info();
    let usb_supported = info
        .supported_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);
    let usb_enabled = info
        .config
        .enabled_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);

    reject_lock_code_if_unlocked(info.is_locked, lock_code)?;

    let (new_enabled, mut changes) = compute_capability_changes(
        "USB",
        usb_supported,
        usb_enabled,
        enable,
        disable,
        enable_all,
        false,
        false,
    )?;

    if touch_eject {
        changes.push("Enable touch-eject".into());
    }
    if no_touch_eject {
        changes.push("Disable touch-eject".into());
    }
    if let Some(t) = autoeject_timeout {
        changes.push(format!("Set auto-eject timeout to {t}"));
    }
    if let Some(t) = chalresp_timeout {
        changes.push(format!("Set challenge-response timeout to {t}"));
    }

    if changes.is_empty() {
        return Err(anyhow!("No configuration changes specified."));
    }

    let reboot = new_enabled != usb_enabled;
    if reboot {
        changes.push("The YubiKey will reboot".into());
    }

    let lc = current_lock_code(
        info.is_locked,
        lock_code,
        "Enter lock code (32 hex characters)",
    )?;

    confirm_config_changes("USB", &changes, force)?;

    let mut config = DeviceConfig::default();
    config
        .enabled_capabilities
        .insert(Transport::Usb, new_enabled);
    if touch_eject || autoeject_timeout.is_some() {
        config.device_flags = Some(DeviceFlag::EJECT);
    } else if no_touch_eject {
        config.device_flags = Some(DeviceFlag::NONE);
    }
    config.auto_eject_timeout = autoeject_timeout;
    config.challenge_response_timeout = chalresp_timeout;

    write_config(dev, &config, reboot, lc.as_deref(), None)?;

    eprintln!("USB application configuration updated.");
    Ok(())
}

pub fn run_nfc(
    dev: &dyn YubiKeyDevice,
    enable: &[CliCapability],
    disable: &[CliCapability],
    enable_all: bool,
    disable_all: bool,
    lock_code: Option<&str>,
    restrict: bool,
    force: bool,
) -> Result<()> {
    let info = dev.info();
    let nfc_supported = info
        .supported_capabilities
        .get(&Transport::Nfc)
        .copied()
        .ok_or_else(|| anyhow!("NFC is not supported on this YubiKey."))?;
    let nfc_enabled = info
        .config
        .enabled_capabilities
        .get(&Transport::Nfc)
        .copied()
        .unwrap_or(Capability::NONE);

    reject_lock_code_if_unlocked(info.is_locked, lock_code)?;

    if restrict {
        let config = DeviceConfig {
            nfc_restricted: Some(true),
            ..Default::default()
        };
        let lc = current_lock_code(
            info.is_locked,
            lock_code,
            "Enter lock code (32 hex characters)",
        )?;
        confirm_config_changes(
            "NFC",
            &["Disable NFC until next USB power cycle".into()],
            force,
        )?;
        write_config(dev, &config, false, lc.as_deref(), None)?;
        println!(
            "YubiKey NFC disabled. It will be re-enabled automatically the next time it is connected to USB power."
        );
        return Ok(());
    }

    let (new_enabled, changes) = compute_capability_changes(
        "NFC",
        nfc_supported,
        nfc_enabled,
        enable,
        disable,
        enable_all,
        disable_all,
        true,
    )?;

    if changes.is_empty() {
        return Err(anyhow!("No configuration changes specified."));
    }

    let lc = current_lock_code(
        info.is_locked,
        lock_code,
        "Enter lock code (32 hex characters)",
    )?;

    confirm_config_changes("NFC", &changes, force)?;

    let mut config = DeviceConfig::default();
    config
        .enabled_capabilities
        .insert(Transport::Nfc, new_enabled);
    write_config(dev, &config, false, lc.as_deref(), None)?;

    eprintln!("NFC application configuration updated.");
    Ok(())
}

pub fn run_set_lock_code(
    dev: &dyn YubiKeyDevice,
    lock_code: Option<&str>,
    new_lock_code: Option<&str>,
    clear: bool,
    generate: bool,
    force: bool,
) -> Result<()> {
    let is_locked = dev.info().is_locked;
    if clear && !is_locked {
        eprintln!("No lock code is currently set.");
        return Ok(());
    }

    let cur = if is_locked {
        current_lock_code(true, lock_code, "Current lock code (32 hex characters)")?
    } else {
        lock_code.map(parse_lock_code).transpose()?
    };

    let new = if clear {
        Some(vec![0u8; 16])
    } else if generate {
        let mut code = vec![0u8; 16];
        getrandom::fill(&mut code).map_err(|e| anyhow!("Failed to generate random: {e}"))?;
        let hex: String = code.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("Using a randomly generated lock code: {hex}");
        if !force && !confirm("Lock configuration with this lock code?") {
            return Err(anyhow!("Aborted by user."));
        }
        Some(code)
    } else {
        Some(parse_lock_code(
            match new_lock_code {
                Some(code) => code.to_string(),
                None => prompt_new_secret("New lock code (32 hex characters)")?,
            }
            .as_str(),
        )?)
    };

    let config = DeviceConfig::default();
    write_config(dev, &config, false, cur.as_deref(), new.as_deref())?;

    eprintln!("Lock code updated.");
    Ok(())
}

pub fn run_reset(dev: &dyn YubiKeyDevice, force: bool) -> Result<()> {
    if !force {
        eprintln!("WARNING! This will delete all stored data and restore factory settings.");
        if !confirm("Proceed?") {
            return Err(anyhow!("Aborted by user."));
        }
    }
    eprintln!("Resetting YubiKey data...");
    let conn = dev
        .open_smartcard()
        .map_err(|e| format_smartcard_connection_error("management", e))?;
    let mut session =
        ManagementSession::new(conn).map_err(|(e, _)| format_session_error("management", e))?;
    session
        .device_reset()
        .map_err(|e| anyhow!("Failed to reset device: {e}"))?;

    eprintln!("Reset complete. All data has been cleared from the YubiKey.");
    Ok(())
}

pub fn run_mode(
    dev: &dyn YubiKeyDevice,
    mode_str: &str,
    touch_eject: bool,
    autoeject_timeout: Option<u16>,
    chalresp_timeout: Option<u8>,
    force: bool,
) -> Result<()> {
    let info = dev.info();
    if info.version >= yubikit::core::Version(5, 0, 0) && !force {
        return Err(anyhow!(
            "Mode switching is not supported on YubiKey 5 and later.\n\
             Use \"ykman config usb\" for more granular control."
        ));
    }

    // Parse mode string (e.g., "OTP+FIDO+CCID" or number 0-6)
    let mode_code: u8 = if let Ok(n) = mode_str.parse::<u8>() {
        if n > 6 {
            return Err(anyhow!("Invalid mode code: {n} (must be 0-6)"));
        }
        n
    } else {
        let parts: Vec<&str> = mode_str.split('+').collect();
        let mut iface = 0u8;
        for p in &parts {
            match p.trim().to_ascii_uppercase().as_str() {
                "OTP" | "O" => iface |= 0x01,
                "CCID" | "C" => iface |= 0x02,
                "FIDO" | "U2F" | "F" => iface |= 0x04,
                _ => return Err(anyhow!("Unknown interface: {p}")),
            }
        }
        // Map interface flags to mode code
        match iface {
            0x01 => 0, // OTP
            0x02 => 1, // CCID
            0x03 => 2, // OTP+CCID
            0x04 => 3, // FIDO
            0x05 => 4, // OTP+FIDO
            0x06 => 5, // FIDO+CCID
            0x07 => 6, // OTP+FIDO+CCID
            _ => return Err(anyhow!("Invalid mode combination.")),
        }
    };

    let code = if touch_eject || autoeject_timeout.is_some() {
        mode_code | 0x80
    } else {
        mode_code
    };

    if !force && !confirm(&format!("Set mode of YubiKey to {mode_str}?")) {
        return Err(anyhow!("Aborted by user."));
    }

    struct SetMode {
        code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    }
    impl ManagementOp<()> for SetMode {
        fn run<C: Connection + 'static>(self, session: &mut ManagementSession<C>) -> Result<()> {
            session
                .set_mode(self.code, self.chalresp_timeout, self.auto_eject_timeout)
                .map_err(|e| anyhow!("Failed to set mode: {e}"))
        }
    }
    with_management_session(
        dev,
        SetMode {
            code,
            chalresp_timeout: chalresp_timeout.unwrap_or(0),
            auto_eject_timeout: autoeject_timeout.unwrap_or(0),
        },
    )?;

    println!(
        "Mode set! You must remove and re-insert your YubiKey for this change to take effect."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{current_lock_code, format_write_config_error};
    use yubikit::management::ManagementError;

    const LOCK_CODE: &str = "01020304050607080102030405060708";

    #[test]
    fn config_lock_code_rejects_code_when_unlocked() {
        let err = current_lock_code(false, Some(LOCK_CODE), "Lock code").unwrap_err();
        assert!(err.to_string().contains("configuration is not locked"));
    }

    #[test]
    fn config_lock_code_accepts_code_when_locked() {
        let code = current_lock_code(true, Some(LOCK_CODE), "Lock code")
            .unwrap()
            .unwrap();
        assert_eq!(code, [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn config_lock_code_is_optional_when_unlocked() {
        assert!(
            current_lock_code(false, None, "Lock code")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn lock_code_change_formats_wrong_current_code_error() {
        let err = format_write_config_error(ManagementError::Connection("APDU error: SW=0x63C0"));
        assert_eq!(
            err.to_string(),
            "Failed to write config: Wrong lock code provided"
        );
    }

    #[test]
    fn lock_code_change_formats_too_many_attempts_error() {
        let err = format_write_config_error(ManagementError::Connection("APDU error: SW=0x6983"));
        assert_eq!(
            err.to_string(),
            "Failed to write config: Lock code blocked. Remove and re-insert the YubiKey."
        );
    }
}
