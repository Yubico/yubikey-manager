use yubikit::device::{YubiKeyDevice, get_name};
use yubikit::management::UsbInterface;
#[cfg(feature = "hardware")]
use yubikit::platform::device::{name_from_pid, scan_usb_devices, usb_interfaces_from_pid};
#[cfg(feature = "hardware")]
use yubikit::platform::pcsc::list_readers;

use crate::util::CliError;

/// Format a device description like: `YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 123`
pub fn describe_device(dev: &dyn YubiKeyDevice) -> String {
    let info = dev.info();
    let name = get_name(info);
    let version = info.version_name();
    let ifaces = dev.usb_interfaces();
    let ifaces_str = format_interfaces(ifaces);
    let serial_str = match info.serial {
        Some(s) => format!(" Serial: {s}"),
        None => String::new(),
    };
    format!("{name} ({version}){ifaces_str}{serial_str}")
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
        #[cfg(feature = "hardware")]
        {
            let reader_list =
                list_readers().map_err(|e| CliError(format!("Failed to list readers: {e}")))?;
            for r in &reader_list {
                println!("{r}");
            }
            return Ok(());
        }
        #[cfg(not(feature = "hardware"))]
        {
            return Err(CliError(
                "Listing readers requires hardware access (built without 'hardware' feature)."
                    .into(),
            ));
        }
    }

    let mut source = ykman::device::get_device_source();
    let devices = source
        .list_devices()
        .map_err(|e| CliError(format!("Failed to list devices: {e}")))?;

    if devices.is_empty() && !serials && !source.is_service() {
        // Check for devices that are visible but not accessible
        #[cfg(feature = "hardware")]
        {
            let (scan_pids, _) = scan_usb_devices();
            if scan_pids.is_empty() {
                println!("No YubiKeys detected.");
            } else {
                for pid in scan_pids.keys() {
                    print_blocked_device(*pid);
                }
            }
        }
        #[cfg(not(feature = "hardware"))]
        {
            println!("No YubiKeys detected.");
        }
        return Ok(());
    }

    if devices.is_empty() && !serials {
        println!("No YubiKeys detected.");
        return Ok(());
    }

    for dev in &devices {
        if serials {
            if let Some(s) = dev.info().serial {
                println!("{s}");
            }
        } else {
            println!("{}", describe_device(dev.as_ref()));
        }
    }

    Ok(())
}

#[cfg(feature = "hardware")]
fn print_blocked_device(pid: u16) {
    let name = name_from_pid(pid);
    let ifaces = usb_interfaces_from_pid(pid);
    let ifaces_str = format_interfaces(ifaces);
    println!("{name}{ifaces_str} <access denied>");
}
