//! Read the serial number from a YubiKey over PC/SC (SmartCard).
//!
//! This example only requires the `pcsc` feature.

use yubikit::management::ManagementSession;
use yubikit::platform::pcsc::{PcscSmartCardConnection, list_readers};

fn main() {
    let readers = list_readers().expect("Failed to list PC/SC readers");
    let reader = readers.first().expect("No PC/SC reader found");
    println!("Using reader: {reader}");

    let conn = PcscSmartCardConnection::open(reader).expect("Failed to open connection");
    let mut session =
        ManagementSession::new(conn).unwrap_or_else(|(e, _)| panic!("Management session: {e}"));
    let info = session
        .read_device_info()
        .expect("Failed to read device info");
    println!("Serial: {:?}", info.serial);
}
