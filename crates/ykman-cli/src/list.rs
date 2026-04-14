use yubikit::core::Transport;
use yubikit::device::{
    YubiKeyDevice, get_name, list_devices, list_readers, name_from_pid, scan_usb_devices,
    usb_interfaces_from_pid,
};
use yubikit::management::UsbInterface;

use crate::util::CliError;

/// Format a device description like: `YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 123`
pub fn describe_device(dev: &YubiKeyDevice) -> String {
    let info = dev.info();
    let name = get_name(info);
    let version = info.version_name();
    let ifaces = dev.usb_interfaces();
    let ifaces_str = format_interfaces(ifaces);
    let serial_str = match dev.serial() {
        Some(s) => format!(" Serial: {s}"),
        None => String::new(),
    };
    let reader_str = match dev.transport() {
        Transport::Nfc => match dev.reader_name() {
            Some(name) => format!(" [{name}]"),
            None => String::new(),
        },
        Transport::Usb => String::new(),
    };
    format!("{name} ({version}){ifaces_str}{serial_str}{reader_str}")
}

fn format_interfaces(ifaces: UsbInterface) -> String {
    if ifaces.0 != 0 {
        let mut parts = Vec::new();
        if ifaces.0 & UsbInterface::OTP.0 != 0 {
            parts.push("OTP");
        }
        if ifaces.0 & UsbInterface::FIDO.0 != 0 {
            parts.push("FIDO");
        }
        if ifaces.0 & UsbInterface::CCID.0 != 0 {
            parts.push("CCID");
        }
        format!(" [{}]", parts.join("+"))
    } else {
        String::new()
    }
}

pub fn run(serials: bool, readers: bool) -> Result<(), CliError> {
    if readers {
        let reader_list =
            list_readers().map_err(|e| CliError(format!("Failed to list readers: {e}")))?;
        for r in &reader_list {
            println!("{r}");
        }
        return Ok(());
    }

    let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
    let devices =
        list_devices(all).map_err(|e| CliError(format!("Failed to list devices: {e}")))?;

    // Collect PIDs of devices that were fully enumerated
    let listed_pids: std::collections::HashSet<u16> =
        devices.iter().filter_map(|d| d.pid()).collect();

    if devices.is_empty() && !serials {
        // Check for devices that are visible but not accessible
        let (scan_pids, _) = scan_usb_devices();
        let blocked: Vec<u16> = scan_pids
            .keys()
            .filter(|pid| !listed_pids.contains(pid))
            .copied()
            .collect();

        if blocked.is_empty() {
            println!("No YubiKeys detected.");
        } else {
            for pid in &blocked {
                print_blocked_device(*pid);
            }
        }
        return Ok(());
    }

    for dev in &devices {
        if serials {
            if let Some(s) = dev.serial() {
                println!("{s}");
            }
        } else {
            println!("{}", describe_device(dev));
        }
    }

    // Show any devices found by scan but not fully accessible
    if !serials {
        let (scan_pids, _) = scan_usb_devices();
        for pid in scan_pids.keys() {
            if !listed_pids.contains(pid) {
                print_blocked_device(*pid);
            }
        }
    }

    Ok(())
}

fn print_blocked_device(pid: u16) {
    let name = name_from_pid(pid);
    let ifaces = usb_interfaces_from_pid(pid);
    let ifaces_str = format_interfaces(ifaces);
    println!("{name}{ifaces_str} <access denied>");
}
