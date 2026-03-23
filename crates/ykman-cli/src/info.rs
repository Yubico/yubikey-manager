use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::iso7816::Transport;
use yubikit_rs::management::Capability;

use crate::util::CliError;

pub fn run(dev: &YubiKeyDevice, check_fips: bool) -> Result<(), CliError> {
    let info = dev.info();

    println!("Device type: {}", dev.name());
    if let Some(serial) = info.serial {
        println!("Serial number: {serial}");
    }
    if info.version != yubikit_rs::core_types::Version(0, 0, 0) {
        println!("Firmware version: {}", info.version_name());
    } else {
        println!("Firmware version: Uncertain, re-run with only one YubiKey connected");
    }
    if info.form_factor != yubikit_rs::management::FormFactor::Unknown {
        println!("Form factor: {}", info.form_factor);
    }

    let usb_ifaces = dev.usb_interfaces();
    if usb_ifaces.0 != 0 {
        println!("Enabled USB interfaces: {usb_ifaces}");
    }

    // NFC status
    if info.supported_capabilities.contains_key(&Transport::Nfc) {
        let nfc_status = match info.config.nfc_restricted {
            Some(true) => "restricted",
            _ => {
                if info
                    .config
                    .enabled_capabilities
                    .get(&Transport::Nfc)
                    .is_some_and(|c| !c.is_empty())
                {
                    "enabled"
                } else {
                    "disabled"
                }
            }
        };
        println!("NFC transport is {nfc_status}");
    }
    if info.pin_complexity {
        println!("PIN complexity is enforced");
    }
    if info.is_locked {
        println!("Configured capabilities are protected by a lock code");
    }

    println!();
    print_app_status_table(
        &info.supported_capabilities,
        &info.config.enabled_capabilities,
    );

    if !info.fips_capable.is_empty() {
        println!();
        println!("FIPS approved applications");
        for &cap in Capability::ALL {
            if info.fips_capable.contains(cap) {
                let approved = info.fips_approved.contains(cap);
                println!(
                    "  {}: {}",
                    cap.display_name(),
                    if approved { "Yes" } else { "No" }
                );
            }
        }
    }

    if check_fips {
        println!();
        if info.fips_capable.is_empty() {
            println!("FIPS approved mode: Not applicable (device is not FIPS capable)");
        } else {
            let all_approved = Capability::ALL
                .iter()
                .all(|&cap| !info.fips_capable.contains(cap) || info.fips_approved.contains(cap));
            println!(
                "FIPS approved mode: {}",
                if all_approved { "Yes" } else { "No" }
            );
        }
    }

    Ok(())
}

fn print_app_status_table(
    supported: &std::collections::HashMap<Transport, Capability>,
    enabled: &std::collections::HashMap<Transport, Capability>,
) {
    let usb_supported = supported
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);
    let usb_enabled = enabled
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);
    let nfc_supported = supported.get(&Transport::Nfc).copied();
    let nfc_enabled = enabled
        .get(&Transport::Nfc)
        .copied()
        .unwrap_or(Capability::NONE);

    let has_nfc = nfc_supported.is_some();
    let nfc_supported = nfc_supported.unwrap_or(Capability::NONE);

    // Build rows
    struct Row {
        app: &'static str,
        usb: &'static str,
        nfc: &'static str,
    }

    let mut rows = Vec::new();
    for &cap in Capability::ALL {
        let usb_status = if usb_supported.contains(cap) {
            if usb_enabled.contains(cap) {
                "Enabled"
            } else {
                "Disabled"
            }
        } else {
            "Not available"
        };
        let nfc_status = if nfc_supported.contains(cap) {
            if nfc_enabled.contains(cap) {
                "Enabled"
            } else {
                "Disabled"
            }
        } else {
            "Not available"
        };
        // Only show capabilities that are supported on at least one transport
        if usb_supported.contains(cap) || (has_nfc && nfc_supported.contains(cap)) {
            rows.push(Row {
                app: cap.display_name(),
                usb: usb_status,
                nfc: nfc_status,
            });
        }
    }

    // Calculate column widths
    let app_w = rows.iter().map(|r| r.app.len()).max().unwrap_or(12).max(12);
    let usb_w = rows.iter().map(|r| r.usb.len()).max().unwrap_or(3).max(3);

    if has_nfc {
        let nfc_w = rows.iter().map(|r| r.nfc.len()).max().unwrap_or(3).max(3);
        println!(
            "{:<app_w$}\t{:<usb_w$}\t{:<nfc_w$}",
            "Applications", "USB", "NFC"
        );
        for row in &rows {
            println!(
                "{:<app_w$}\t{:<usb_w$}\t{:<nfc_w$}",
                row.app, row.usb, row.nfc
            );
        }
    } else {
        println!("{:<app_w$}", "Applications");
        for row in &rows {
            println!("{:<app_w$}\t{:<usb_w$}", row.app, row.usb);
        }
    }
}
