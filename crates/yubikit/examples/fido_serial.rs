//! Read the serial number from a YubiKey over FIDO HID.
//!
//! This example only requires the `hid` feature.

use yubikit::management::ManagementSession;
use yubikit::platform::hidapi::{HidFidoConnection, list_fido_devices};

fn main() {
    let devices = list_fido_devices().expect("Failed to list FIDO devices");
    let dev = devices.first().expect("No FIDO device found");
    println!("Using FIDO device: {}", dev.path);

    let conn = HidFidoConnection::open(dev).expect("Failed to open FIDO connection");
    let mut session = ManagementSession::new_fido(conn)
        .unwrap_or_else(|(e, _)| panic!("Management session: {e}"));
    let info = session
        .read_device_info()
        .expect("Failed to read device info");
    println!("Serial: {:?}", info.serial);
}
