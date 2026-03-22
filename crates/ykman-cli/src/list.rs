use yubikit_rs::device::{get_name, list_devices, list_readers};

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

    let devices =
        list_devices().map_err(|e| CliError(format!("Failed to list devices: {e}")))?;

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
            let serial_str = match dev.serial() {
                Some(s) => format!(" Serial: {s}"),
                None => String::new(),
            };
            println!("{name} ({version}){serial_str}");
        }
    }

    Ok(())
}
