use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;

use crate::util::{CliError, print_table};

pub fn run(dev: &dyn YubiKeyDevice, check_fips: bool) -> Result<(), CliError> {
    let info = dev.info();

    let mut rows = vec![("Device type", dev.name())];
    if let Some(serial) = info.serial {
        rows.push(("Serial number", serial.to_string()));
    }
    if info.version != yubikit::core::Version(0, 0, 0) {
        rows.push(("Firmware version", info.version_name()));
    } else {
        rows.push((
            "Firmware version",
            "Uncertain, re-run with only one YubiKey connected".to_string(),
        ));
    }
    if info.form_factor != yubikit::management::FormFactor::Unknown {
        rows.push(("Form factor", info.form_factor.to_string()));
    }

    // Show USB interfaces only when connected via USB
    let is_usb = dev.transport() == Transport::Usb;
    if is_usb {
        let usb_ifaces = dev.usb_interfaces();
        if usb_ifaces.0 != 0 {
            rows.push(("Enabled USB interfaces", usb_ifaces.to_string()));
        }
    }
    print_table(rows);

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
        let mut rows = Vec::new();
        for &cap in Capability::ALL {
            if info.fips_capable.contains(cap) {
                let approved = info.fips_approved.contains(cap);
                rows.push((
                    format!("  {}", cap.display_name()),
                    if approved {
                        "Yes".to_string()
                    } else {
                        "No".to_string()
                    },
                ));
            }
        }
        print_table(rows);
    }

    if check_fips {
        println!();
        if info.fips_capable.is_empty() {
            println!("FIPS approved mode: Not applicable (device is not FIPS capable)");
        } else {
            let all_approved = Capability::ALL
                .iter()
                .all(|&cap| !info.fips_capable.contains(cap) || info.fips_approved.contains(cap));
            print_table([(
                "FIPS approved mode",
                if all_approved { "Yes" } else { "No" }.to_string(),
            )]);
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

    let mut rows = Vec::new();
    if has_nfc {
        rows.push(vec!["Applications", "USB", "NFC"]);
    } else {
        rows.push(vec!["Applications", "USB"]);
    }
    for &cap in Capability::ALL {
        let usb_status = if usb_supported.contains(cap) {
            if usb_enabled.contains(cap) {
                // FIDO_CCID is "Inactive" when FIDO2 is not also enabled
                if cap == Capability::FIDOCCID && !usb_enabled.contains(Capability::FIDO2) {
                    "Inactive"
                } else {
                    "Enabled"
                }
            } else {
                "Disabled"
            }
        } else {
            "Not available"
        };
        // FIDO_CCID is USB-only; show "N/A" for NFC
        let nfc_status = if cap == Capability::FIDOCCID {
            "N/A"
        } else if nfc_supported.contains(cap) {
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
            if has_nfc {
                rows.push(vec![cap.display_name(), usb_status, nfc_status]);
            } else {
                rows.push(vec![cap.display_name(), usb_status]);
            }
        }
    }

    print_table(rows);
}
