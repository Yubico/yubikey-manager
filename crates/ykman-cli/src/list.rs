use yubikit::core::Transport;
use yubikit::device::{
    LocalYubiKeyDevice, YubiKeyDevice, get_name, list_devices, list_readers, name_from_pid,
    scan_usb_devices, usb_interfaces_from_pid,
};
use yubikit::management::UsbInterface;

use crate::util::CliError;

/// Format a device description like: `YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 123`
pub fn describe_device(dev: &LocalYubiKeyDevice) -> String {
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

    // On Windows, prefer listing devices via the service.
    #[cfg(target_os = "windows")]
    if list_via_service(serials)? {
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

/// Try to list devices via the ykman-svc service.
/// Returns Ok(true) if devices were successfully listed from service,
/// Ok(false) if service is unavailable (caller should fall back to local listing).
#[cfg(target_os = "windows")]
fn list_via_service(serials: bool) -> Result<bool, CliError> {
    use serde_json::json;

    let mut client = match ykman::rpc::client::RpcClient::connect_pipe() {
        Ok(c) => c,
        Err(_) => return Ok(false),
    };

    let _ = client.call("update_children", &[], json!({}), None, false);
    let root = match client.get(&[]) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let children = match root.body.get("children").and_then(|v| v.as_object()) {
        Some(c) if !c.is_empty() => c.clone(),
        _ => {
            println!("No YubiKeys detected.");
            return Ok(true);
        }
    };

    for (name, info) in &children {
        if serials {
            // Device names are serial numbers when available
            if info.get("serial").and_then(|v| v.as_u64()).is_some() {
                println!("{name}");
            }
        } else {
            println!("{}", describe_svc_device(name, info));
        }
    }

    Ok(true)
}

/// Format a service device description from its children JSON data.
#[cfg(target_os = "windows")]
pub(crate) fn describe_svc_device(name: &str, info: &serde_json::Value) -> String {
    let dev_name = info
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("YubiKey");

    let version = if let Some(arr) = info.get("version").and_then(|v| v.as_array())
        && arr.len() == 3
    {
        format!(
            "{}.{}.{}",
            arr[0].as_u64().unwrap_or(0),
            arr[1].as_u64().unwrap_or(0),
            arr[2].as_u64().unwrap_or(0)
        )
    } else {
        "?.?.?".to_string()
    };

    let ifaces_str = if let Some(raw) = info.get("usb_interfaces").and_then(|v| v.as_u64()) {
        format_interfaces(UsbInterface(raw as u8))
    } else {
        String::new()
    };

    let serial_str = if let Some(serial) = info.get("serial").and_then(|v| v.as_u64()) {
        format!(" Serial: {serial}")
    } else {
        format!(" [{name}]")
    };

    format!("{dev_name} ({version}){ifaces_str}{serial_str}")
}

fn print_blocked_device(pid: u16) {
    let name = name_from_pid(pid);
    let ifaces = usb_interfaces_from_pid(pid);
    let ifaces_str = format_interfaces(ifaces);
    println!("{name}{ifaces_str} <access denied>");
}
