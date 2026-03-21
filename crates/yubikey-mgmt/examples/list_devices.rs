//! List all connected YubiKeys and display their information.

use yubikey_mgmt::device::list_devices;

fn main() {
    match list_devices() {
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
