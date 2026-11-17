//! List all connected YubiKeys and display their information.

use yubikit::management::UsbInterface;
use yubikit::platform::device::list_devices;

fn main() {
    let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
    match list_devices(all) {
        Ok(devices) => {
            println!("Found {} YubiKey(s):", devices.len());
            for dev in &devices {
                println!(
                    "  {} (serial: {:?}, version: {})",
                    dev.name(),
                    dev.info().serial,
                    dev.info().version
                );
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
