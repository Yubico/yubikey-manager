//! Read detailed device information from the first connected YubiKey.

use yubikey_mgmt::device::list_devices;
use yubikey_mgmt::iso7816::Transport;

fn main() {
    let devices = list_devices().expect("Failed to enumerate devices");
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
