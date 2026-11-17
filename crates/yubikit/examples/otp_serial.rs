//! Read the serial number from a YubiKey over OTP HID.
//!
//! This example only requires the `hid` feature.

use yubikit::management::ManagementSession;
use yubikit::platform::hidapi::{HidOtpConnection, list_otp_devices};

fn main() {
    let devices = list_otp_devices().expect("Failed to list OTP devices");
    let dev = devices.first().expect("No OTP device found");
    println!("Using OTP device: {}", dev.path);

    let conn = HidOtpConnection::new(&dev.path).expect("Failed to open OTP connection");
    let mut session =
        ManagementSession::new_otp(conn).unwrap_or_else(|(e, _)| panic!("Management session: {e}"));
    let info = session
        .read_device_info()
        .expect("Failed to read device info");
    println!("Serial: {:?}", info.serial);
}
