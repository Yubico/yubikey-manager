use yubikit::core::Transport;
use yubikit::device::{
    get_name, list_devices, list_devices_ccid, list_devices_fido, list_devices_otp, list_readers,
};

use crate::util::CliError;

pub fn run(serials: bool, readers: bool) -> Result<(), CliError> {
    if readers {
        let reader_list =
            list_readers().map_err(|e| CliError(format!("Failed to list readers: {e}")))?;
        for r in &reader_list {
            println!("{r}");
        }
        return Ok(());
    }

    let devices = list_devices(&[list_devices_ccid, list_devices_otp, list_devices_fido])
        .map_err(|e| CliError(format!("Failed to list devices: {e}")))?;

    if devices.is_empty() && !serials {
        println!("No YubiKeys detected.");
        return Ok(());
    }

    for dev in &devices {
        if serials {
            if let Some(s) = dev.serial() {
                println!("{s}");
            }
        } else {
            let info = dev.info();
            let name = get_name(info);
            let version = &info.version_name();
            let ifaces = dev.usb_interfaces();
            let ifaces_str = if ifaces.0 != 0 {
                let mut parts = Vec::new();
                if ifaces.0 & yubikit::management::UsbInterface::OTP.0 != 0 {
                    parts.push("OTP");
                }
                if ifaces.0 & yubikit::management::UsbInterface::FIDO.0 != 0 {
                    parts.push("FIDO");
                }
                if ifaces.0 & yubikit::management::UsbInterface::CCID.0 != 0 {
                    parts.push("CCID");
                }
                format!(" [{}]", parts.join("+"))
            } else {
                String::new()
            };
            let serial_str = match dev.serial() {
                Some(s) => format!(" Serial: {s}"),
                None => String::new(),
            };
            let reader_str = if dev.transport() == Transport::Nfc {
                if let Some(name) = dev.reader_name() {
                    format!(" [{name}]")
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            println!("{name} ({version}){ifaces_str}{serial_str}{reader_str}");
        }
    }

    Ok(())
}
