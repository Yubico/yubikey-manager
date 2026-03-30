//! Read detailed device information from the first connected YubiKey.

use yubikit::core::Transport;
use yubikit::device::{list_devices, list_devices_ccid_all, list_devices_fido, list_devices_otp};

fn main() {
    let devices = list_devices(&[list_devices_ccid_all, list_devices_otp, list_devices_fido])
        .expect("Failed to enumerate devices");
    let dev = devices.first().expect("No YubiKey found");
    let info = dev.info();

    println!("Device: {}", dev.name());
    println!("Serial: {:?}", info.serial);
    println!("Version: {}", info.version);
    println!("Form factor: {}", info.form_factor);
    println!("FIPS: {}", info.is_fips);
    println!("SKY: {}", info.is_sky);
    println!("PIN complexity: {}", info.pin_complexity);

    println!("Supported capabilities:");
    for transport in [Transport::Usb, Transport::Nfc] {
        if let Some(cap) = info.supported_capabilities.get(&transport) {
            println!("  {transport:?}: {cap}");
        }
    }

    println!("Enabled capabilities:");
    for transport in [Transport::Usb, Transport::Nfc] {
        if let Some(cap) = info.config.enabled_capabilities.get(&transport) {
            println!("  {transport:?}: {cap}");
        }
    }

    println!("Version qualifier: {}", info.version_qualifier);
}
