//! List all connected YubiKeys and display their information.

use yubikit::device::list_devices;
use yubikit::management::UsbInterface;

fn main() {
    let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
    match list_devices(all) {
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
