use yubikit_rs::device::{list_devices, list_readers};
use yubikit_rs::management::{ManagementSession, ReleaseType};

use crate::util::CliError;

pub fn run_diagnose() -> Result<(), CliError> {
    println!("ykman-rs:         {}", env!("CARGO_PKG_VERSION"));
    println!("Platform:         {}", std::env::consts::OS);
    println!("Arch:             {}", std::env::consts::ARCH);

    // PC/SC readers
    println!();
    print!("Detected PC/SC readers:");
    match list_readers() {
        Ok(readers) => {
            if readers.is_empty() {
                println!(" (none)");
            } else {
                println!();
                for r in &readers {
                    println!("  {r}");
                }
            }
        }
        Err(e) => println!(" Error: {e}"),
    }

    // YubiKey devices
    println!();
    print!("Detected YubiKeys:");
    match list_devices() {
        Ok(devices) => {
            if devices.is_empty() {
                println!(" (none)");
            } else {
                println!();
                for dev in &devices {
                    println!(
                        "  {} (serial: {})",
                        dev.reader_name().unwrap_or("unknown"),
                        dev.serial()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "N/A".into()),
                    );

                    // Management info
                    if let Ok(conn) = dev.open_smartcard() {
                        if let Ok(mut mgmt) = ManagementSession::new(conn) {
                            let info = mgmt.read_device_info();
                            match info {
                                Ok(di) => {
                                    println!("    Device info:");
                                    println!(
                                        "      Serial:          {}",
                                        di.serial.map(|s| s.to_string()).unwrap_or("N/A".into())
                                    );
                                    println!("      Firmware:        {}", di.version);
                                    println!("      Form factor:     {:?}", di.form_factor);
                                    if let Some(ref pn) = di.part_number {
                                        println!("      Part number:     {pn}");
                                    }
                                    println!("      FIPS capable:    0x{:04X}", di.fips_capable.0);
                                    println!("      FIPS approved:   0x{:04X}", di.fips_approved.0);
                                    println!("      PIN complexity:  {}", di.pin_complexity);
                                    if di.version_qualifier.release_type != ReleaseType::Final {
                                        println!(
                                            "      Version qualifier: {} {:?} #{}",
                                            di.version_qualifier.version,
                                            di.version_qualifier.release_type,
                                            di.version_qualifier.iteration
                                        );
                                    }
                                    // Capabilities
                                    if let Some(usb) = di
                                        .config
                                        .enabled_capabilities
                                        .get(&yubikit_rs::iso7816::Transport::Usb)
                                    {
                                        println!("      USB enabled:     0x{:04X}", usb.0);
                                    }
                                    if let Some(nfc) = di
                                        .config
                                        .enabled_capabilities
                                        .get(&yubikit_rs::iso7816::Transport::Nfc)
                                    {
                                        println!("      NFC enabled:     0x{:04X}", nfc.0);
                                    }
                                    if let Some(usb) = di
                                        .supported_capabilities
                                        .get(&yubikit_rs::iso7816::Transport::Usb)
                                    {
                                        println!("      USB supported:   0x{:04X}", usb.0);
                                    }
                                    if let Some(nfc) = di
                                        .supported_capabilities
                                        .get(&yubikit_rs::iso7816::Transport::Nfc)
                                    {
                                        println!("      NFC supported:   0x{:04X}", nfc.0);
                                    }
                                }
                                Err(e) => println!("    Management: Error: {e}"),
                            }
                        }
                    }

                    // OTP info
                    if let Ok(conn) = dev.open_otp() {
                        if let Ok(session) = yubikit_rs::yubiotp::YubiOtpOtpSession::new(conn) {
                            let state = session.get_config_state();
                            println!("    OTP:");
                            println!("      Version:  {}", session.version());
                            for slot in [
                                yubikit_rs::yubiotp::Slot::One,
                                yubikit_rs::yubiotp::Slot::Two,
                            ] {
                                let num = slot.map(1, 2);
                                let configured =
                                    state.is_configured(slot).map_or("unknown".into(), |b| {
                                        if b { "programmed" } else { "empty" }.to_string()
                                    });
                                println!("      Slot {num}: {configured}");
                            }
                        }
                    }
                }
            }
        }
        Err(e) => println!(" Error: {e}"),
    }

    println!();
    println!("End of diagnostics");
    Ok(())
}
