//! Demonstrate the YubiKey reinsert flow.
//!
//! Lists connected YubiKeys, picks the first one, and asks the user to
//! remove and reinsert it.

use yubikit::device::{
    ReinsertStatus, list_devices, list_devices_ccid, list_devices_fido, list_devices_otp,
};

const ENUMERATORS: &[yubikit::device::EnumerateFn] =
    &[list_devices_ccid, list_devices_otp, list_devices_fido];

fn main() {
    let mut devices = list_devices(ENUMERATORS).expect("Failed to enumerate YubiKeys");

    if devices.is_empty() {
        eprintln!("No YubiKeys detected.");
        std::process::exit(1);
    }

    let dev = &mut devices[0];
    println!(
        "Found: {} (serial: {:?}, version: {})",
        dev.name(),
        dev.serial(),
        dev.version(),
    );
    println!();

    if let Err(e) = dev.reinsert(
        ENUMERATORS,
        &|status| match status {
            ReinsertStatus::Remove => {
                println!("Remove the YubiKey from the USB port...");
            }
            ReinsertStatus::Reinsert => {
                println!("Now reinsert the YubiKey...");
            }
            ReinsertStatus::RemoveFromReader => {
                println!("Remove the YubiKey from the NFC reader...");
            }
            ReinsertStatus::PlaceOnReader => {
                println!("Place the YubiKey on the NFC reader again...");
            }
        },
        &|| false,
    ) {
        eprintln!("Reinsert failed: {e}");
        std::process::exit(1);
    }

    println!();
    println!(
        "YubiKey reconnected: {} (serial: {:?})",
        dev.name(),
        dev.serial(),
    );
}
