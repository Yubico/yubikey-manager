//! List all connected YubiKeys and display their information.

use yubikit::device::{list_devices, list_devices_ccid_all, list_devices_fido, list_devices_otp};

fn main() {
    match list_devices(&[list_devices_ccid_all, list_devices_otp, list_devices_fido]) {
        Ok(devices) => {
            println!("Found {} YubiKey(s):", devices.len());
            for dev in &devices {
                println!(
                    "  {} (serial: {:?}, version: {})",
                    dev.name(),
                    dev.serial(),
                    dev.version()
                );
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
