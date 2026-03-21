//! List OATH accounts on the first connected YubiKey.

use yubikit_rs::device::list_devices;
use yubikit_rs::oath::OathSession;

fn main() {
    let devices = list_devices().expect("Failed to enumerate devices");
    let dev = devices.first().expect("No YubiKey found");

    let conn = dev.open_smartcard().expect("Failed to open connection");
    let mut session = OathSession::new(conn).expect("Failed to open OATH session");

    println!("OATH accounts on {}:", dev.name());
    let creds = session
        .list_credentials()
        .expect("Failed to list credentials");
    for cred in &creds {
        println!("  {cred:?}");
    }
}
