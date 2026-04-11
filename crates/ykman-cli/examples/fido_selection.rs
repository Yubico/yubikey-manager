// Example: FIDO2 authenticatorSelection with cancel
//
// Opens a FIDO connection over HID (preferred) or PC/SC, initializes CTAP2,
// then calls selection() while a background thread cancels after 3 seconds.
//
// Usage: cargo run -p ykman-cli --example fido_selection

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Session, CtapStatus};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::transport::pcsc::{PcscSmartCardConnection, list_readers};

// --- Main ---

fn run_selection_hid(conn: HidFidoConnection) {
    println!("=== Testing selection over HID ===");

    let ctap = match CtapSession::new_fido(conn) {
        Ok(c) => c,
        Err((e, _)) => {
            eprintln!("Failed to init CTAP: {e}");
            return;
        }
    };
    let mut ctap2 = match Ctap2Session::new(ctap) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to init CTAP2: {e}");
            return;
        }
    };

    println!("CTAP2 initialized, AAGUID: {}", ctap2.info().aaguid);
    run_selection_inner(&mut ctap2);
}

fn run_selection_smartcard(conn: PcscSmartCardConnection, reader: &str) {
    println!("=== Testing selection over PC/SC ({reader}) ===");

    let ctap = match CtapSession::new(conn) {
        Ok(c) => c,
        Err((e, _)) => {
            eprintln!("Failed to init CTAP: {e}");
            return;
        }
    };

    if !ctap.has_ctap2() {
        eprintln!("  FIDO2 not available on this device");
        return;
    }

    let mut ctap2 = match Ctap2Session::new(ctap) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to init CTAP2: {e}");
            return;
        }
    };

    println!("CTAP2 initialized, AAGUID: {}", ctap2.info().aaguid);
    run_selection_inner(&mut ctap2);
}

fn run_selection_inner<C: yubikit::core::Connection + 'static>(ctap2: &mut Ctap2Session<C>) {
    println!("Starting selection (will cancel after 3 seconds)...");

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_thread = cancel.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        println!("  [cancel thread] Setting cancel flag");
        cancel_thread.store(true, Ordering::Relaxed);
    });

    let is_cancelled = || cancel.load(Ordering::Relaxed);
    let result = ctap2.selection(
        Some(&mut |status| {
            println!("  [keepalive] status={status:#04x}");
        }),
        Some(&is_cancelled),
    );

    handle.join().unwrap();

    match result {
        Ok(()) => println!("Selection succeeded (user touched the device)"),
        Err(ref e) => match e {
            yubikit::ctap2::Ctap2Error::StatusError(CtapStatus::KeepaliveCancel) => {
                println!("Selection was cancelled (expected)")
            }
            _ => println!("Selection failed: {e}"),
        },
    }
    println!();
}

fn main() {
    // Try HID first
    if let Ok(devices) = list_fido_devices() {
        for dev_info in &devices {
            println!(
                "Found HID FIDO device: {} (pid={:#06x})",
                dev_info.path, dev_info.pid
            );
            match HidFidoConnection::open(dev_info) {
                Ok(conn) => run_selection_hid(conn),
                Err(e) => eprintln!("Failed to open HID device: {e}"),
            }
        }
    }

    // Try PCSC
    if let Ok(readers) = list_readers() {
        for reader in &readers {
            println!("Found PC/SC reader: {reader}");
            match PcscSmartCardConnection::open(reader) {
                Ok(conn) => run_selection_smartcard(conn, reader),
                Err(e) => eprintln!("  Failed to connect: {e}"),
            }
        }
    }
}
