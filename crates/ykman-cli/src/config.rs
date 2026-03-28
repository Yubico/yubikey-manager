use std::io::{self, Write};

use yubikit::device::YubiKeyDevice;
use yubikit::management::{
    Capability, DeviceConfig, DeviceFlag, ManagementCcidSession, ManagementFidoSession,
    ManagementOtpSession, ManagementSession,
};
use yubikit::smartcard::Transport;

use crate::cli_enums::CliCapability;
use crate::util::CliError;

/// Open a management session, trying SmartCard first, then OTP HID, then FIDO HID.
fn write_config(
    dev: &YubiKeyDevice,
    config: &DeviceConfig,
    reboot: bool,
    lock_code: Option<&[u8]>,
    new_lock_code: Option<&[u8]>,
) -> Result<(), CliError> {
    if let Ok(conn) = dev.open_smartcard() {
        let mut session = ManagementCcidSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open management session: {e}")))?;
        session
            .write_device_config(config, reboot, lock_code, new_lock_code)
            .map_err(|e| CliError(format!("Failed to write config: {e}")))?;
    } else if let Ok(conn) = dev.open_otp() {
        let mut session = ManagementOtpSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open OTP management session: {e}")))?;
        session
            .write_device_config(config, reboot, lock_code, new_lock_code)
            .map_err(|e| CliError(format!("Failed to write config: {e}")))?;
    } else if let Ok(conn) = dev.open_fido() {
        let mut session = ManagementFidoSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open FIDO management session: {e}")))?;
        session
            .write_device_config(config, reboot, lock_code, new_lock_code)
            .map_err(|e| CliError(format!("Failed to write config: {e}")))?;
    } else {
        return Err(CliError(
            "Failed to open connection: No SmartCard, OTP, or FIDO connection available.".into(),
        ));
    }
    Ok(())
}

fn parse_lock_code(hex: &str) -> Result<Vec<u8>, CliError> {
    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect();
    let bytes = bytes.map_err(|_| CliError("Invalid hex in lock code.".into()))?;
    if bytes.len() != 16 {
        return Err(CliError(
            "Lock code must be exactly 16 bytes (32 hex characters).".into(),
        ));
    }
    Ok(bytes)
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub fn run_usb(
    dev: &YubiKeyDevice,
    enable: &[CliCapability],
    disable: &[CliCapability],
    enable_all: bool,
    list: bool,
    lock_code: Option<&str>,
    touch_eject: bool,
    no_touch_eject: bool,
    autoeject_timeout: Option<u16>,
    chalresp_timeout: Option<u8>,
    force: bool,
) -> Result<(), CliError> {
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

    if list {
        for &cap in Capability::ALL {
            if usb_supported.contains(cap) {
                let status = if usb_enabled.contains(cap) {
                    "Enabled"
                } else {
                    "Disabled"
                };
                println!("{}: {status}", cap.display_name());
            }
        }
        return Ok(());
    }

    let mut new_enabled = usb_enabled;
    let mut changes = Vec::new();

    if enable_all {
        for &cap in Capability::ALL {
            if usb_supported.contains(cap) && !usb_enabled.contains(cap) {
                new_enabled |= cap;
                changes.push(format!("Enable {}", cap.display_name()));
            }
        }
    }

    for name in enable {
        let cap: Capability = (*name).into();
        if !usb_supported.contains(cap) {
            return Err(CliError(format!(
                "{} is not supported on USB.",
                cap.display_name()
            )));
        }
        if !usb_enabled.contains(cap) {
            new_enabled |= cap;
            changes.push(format!("Enable {}", cap.display_name()));
        }
    }

    for name in disable {
        let cap: Capability = (*name).into();
        if usb_enabled.contains(cap) {
            new_enabled = Capability(new_enabled.0 & !cap.0);
            changes.push(format!("Disable {}", cap.display_name()));
        }
    }

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
        return Err(CliError("No configuration changes specified.".into()));
    }

    if new_enabled.is_empty() {
        return Err(CliError("Cannot disable all USB applications.".into()));
    }

    let reboot = new_enabled != usb_enabled;
    if reboot {
        changes.push("The YubiKey will reboot".into());
    }

    if !force {
        eprintln!("USB configuration changes:");
        for c in &changes {
            eprintln!("  {c}");
        }
        if !confirm("Proceed?") {
            return Err(CliError("Aborted by user.".into()));
        }
    }

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

    let lc = lock_code.map(parse_lock_code).transpose()?;
    write_config(dev, &config, reboot, lc.as_deref(), None)?;

    eprintln!("USB application configuration updated.");
    Ok(())
}

pub fn run_nfc(
    dev: &YubiKeyDevice,
    enable: &[CliCapability],
    disable: &[CliCapability],
    enable_all: bool,
    disable_all: bool,
    list: bool,
    lock_code: Option<&str>,
    restrict: bool,
    force: bool,
) -> Result<(), CliError> {
    let info = dev.info();
    let nfc_supported = info
        .supported_capabilities
        .get(&Transport::Nfc)
        .copied()
        .ok_or_else(|| CliError("NFC is not supported on this YubiKey.".into()))?;
    let nfc_enabled = info
        .config
        .enabled_capabilities
        .get(&Transport::Nfc)
        .copied()
        .unwrap_or(Capability::NONE);

    if list {
        for &cap in Capability::ALL {
            if nfc_supported.contains(cap) {
                let status = if nfc_enabled.contains(cap) {
                    "Enabled"
                } else {
                    "Disabled"
                };
                println!("{}: {status}", cap.display_name());
            }
        }
        return Ok(());
    }

    if restrict {
        let config = DeviceConfig {
            nfc_restricted: Some(true),
            ..Default::default()
        };
        let lc = lock_code.map(parse_lock_code).transpose()?;
        if !force {
            eprintln!("NFC configuration changes:");
            eprintln!("  Disable NFC until next USB power cycle");
            if !confirm("Proceed?") {
                return Err(CliError("Aborted by user.".into()));
            }
        }
        write_config(dev, &config, false, lc.as_deref(), None)?;
        println!(
            "YubiKey NFC disabled. It will be re-enabled automatically the next time it is connected to USB power."
        );
        return Ok(());
    }

    let mut new_enabled = nfc_enabled;
    let mut changes = Vec::new();

    if enable_all {
        for &cap in Capability::ALL {
            if nfc_supported.contains(cap) && !nfc_enabled.contains(cap) {
                new_enabled |= cap;
                changes.push(format!("Enable {}", cap.display_name()));
            }
        }
    }
    if disable_all {
        for &cap in Capability::ALL {
            if nfc_supported.contains(cap) && nfc_enabled.contains(cap) {
                new_enabled = Capability(new_enabled.0 & !cap.0);
                changes.push(format!("Disable {}", cap.display_name()));
            }
        }
    }

    for name in enable {
        let cap: Capability = (*name).into();
        if !nfc_supported.contains(cap) {
            return Err(CliError(format!(
                "{} is not supported on NFC.",
                cap.display_name()
            )));
        }
        if !nfc_enabled.contains(cap) {
            new_enabled |= cap;
            changes.push(format!("Enable {}", cap.display_name()));
        }
    }
    for name in disable {
        let cap: Capability = (*name).into();
        if nfc_enabled.contains(cap) {
            new_enabled = Capability(new_enabled.0 & !cap.0);
            changes.push(format!("Disable {}", cap.display_name()));
        }
    }

    if changes.is_empty() {
        return Err(CliError("No configuration changes specified.".into()));
    }

    if !force {
        eprintln!("NFC configuration changes:");
        for c in &changes {
            eprintln!("  {c}");
        }
        if !confirm("Proceed?") {
            return Err(CliError("Aborted by user.".into()));
        }
    }

    let mut config = DeviceConfig::default();
    config
        .enabled_capabilities
        .insert(Transport::Nfc, new_enabled);
    let lc = lock_code.map(parse_lock_code).transpose()?;
    write_config(dev, &config, false, lc.as_deref(), None)?;

    eprintln!("NFC application configuration updated.");
    Ok(())
}

pub fn run_set_lock_code(
    dev: &YubiKeyDevice,
    lock_code: Option<&str>,
    new_lock_code: Option<&str>,
    clear: bool,
    generate: bool,
    force: bool,
) -> Result<(), CliError> {
    let cur = lock_code.map(parse_lock_code).transpose()?;
    let new = if clear {
        Some(vec![0u8; 16])
    } else if generate {
        let mut code = vec![0u8; 16];
        getrandom::fill(&mut code)
            .map_err(|e| CliError(format!("Failed to generate random: {e}")))?;
        let hex: String = code.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("Using a randomly generated lock code: {hex}");
        if !force && !confirm("Lock configuration with this lock code?") {
            return Err(CliError("Aborted by user.".into()));
        }
        Some(code)
    } else {
        new_lock_code.map(parse_lock_code).transpose()?
    };

    let config = DeviceConfig::default();
    write_config(dev, &config, false, cur.as_deref(), new.as_deref())?;

    eprintln!("Lock code updated.");
    Ok(())
}

pub fn run_reset(dev: &YubiKeyDevice, force: bool) -> Result<(), CliError> {
    if !force {
        eprintln!("WARNING! This will delete all stored data and restore factory settings.");
        if !confirm("Proceed?") {
            return Err(CliError("Aborted by user.".into()));
        }
    }
    eprintln!("Resetting YubiKey data...");
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    let mut session = ManagementCcidSession::new(conn)
        .map_err(|e| CliError(format!("Failed to open management session: {e}")))?;
    session
        .device_reset()
        .map_err(|e| CliError(format!("Failed to reset device: {e}")))?;

    eprintln!("Reset complete. All data has been cleared from the YubiKey.");
    Ok(())
}

pub fn run_mode(
    dev: &YubiKeyDevice,
    mode_str: &str,
    touch_eject: bool,
    autoeject_timeout: Option<u16>,
    chalresp_timeout: Option<u8>,
    force: bool,
) -> Result<(), CliError> {
    let info = dev.info();
    if info.version >= yubikit::core::Version(5, 0, 0) && !force {
        return Err(CliError(
            "Mode switching is not supported on YubiKey 5 and later.\n\
             Use \"ykman config usb\" for more granular control."
                .into(),
        ));
    }

    // Parse mode string (e.g., "OTP+FIDO+CCID" or number 0-6)
    let mode_code: u8 = if let Ok(n) = mode_str.parse::<u8>() {
        if n > 6 {
            return Err(CliError(format!("Invalid mode code: {n} (must be 0-6)")));
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
                _ => return Err(CliError(format!("Unknown interface: {p}"))),
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
            _ => return Err(CliError("Invalid mode combination.".into())),
        }
    };

    let code = if touch_eject || autoeject_timeout.is_some() {
        mode_code | 0x80
    } else {
        mode_code
    };

    if !force && !confirm(&format!("Set mode of YubiKey to {mode_str}?")) {
        return Err(CliError("Aborted by user.".into()));
    }

    if let Ok(conn) = dev.open_smartcard() {
        let mut session = ManagementCcidSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open management session: {e}")))?;
        session
            .set_mode(
                code,
                chalresp_timeout.unwrap_or(0),
                autoeject_timeout.unwrap_or(0),
            )
            .map_err(|e| CliError(format!("Failed to set mode: {e}")))?;
    } else if let Ok(conn) = dev.open_otp() {
        let mut session = ManagementOtpSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open OTP management session: {e}")))?;
        session
            .set_mode(
                code,
                chalresp_timeout.unwrap_or(0),
                autoeject_timeout.unwrap_or(0),
            )
            .map_err(|e| CliError(format!("Failed to set mode: {e}")))?;
    } else if let Ok(conn) = dev.open_fido() {
        let mut session = ManagementFidoSession::new(conn)
            .map_err(|e| CliError(format!("Failed to open FIDO management session: {e}")))?;
        session
            .set_mode(
                code,
                chalresp_timeout.unwrap_or(0),
                autoeject_timeout.unwrap_or(0),
            )
            .map_err(|e| CliError(format!("Failed to set mode: {e}")))?;
    } else {
        return Err(CliError(
            "Failed to open connection: No SmartCard, OTP, or FIDO connection available.".into(),
        ));
    }

    println!(
        "Mode set! You must remove and re-insert your YubiKey for this change to take effect."
    );
    Ok(())
}
