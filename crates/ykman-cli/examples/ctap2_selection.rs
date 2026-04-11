// Example: CTAP2 authenticatorSelection using yubikit's CtapSession + Ctap2Session
//
// Lists attached YubiKeys, then for each device:
//   - If it has a FIDO HID interface, opens a Ctap2Session over HID and calls selection()
//   - If it has a CCID interface, opens a Ctap2Session over SmartCard and calls selection()
//
// A background thread cancels selection after 5 seconds if the user hasn't touched the key.
//
// Usage: cargo run -p ykman-cli --example ctap2_selection

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Error, Ctap2Session, CtapStatus};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::transport::pcsc::{PcscSmartCardConnection, list_readers};

const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

fn run_selection<C, E>(mut session: Ctap2Session<C>, transport: &str)
where
    C: yubikit::core::Connection<Error = E> + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    println!("  Starting selection over {transport}...");
    println!("  Touch the YubiKey to confirm (auto-cancel in {CANCEL_TIMEOUT:?})");

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(CANCEL_TIMEOUT);
        cancel_clone.store(true, Ordering::Relaxed);
    });

    let result = session.selection(
        Some(&mut |status| {
            println!("  [keepalive] status=0x{status:02X}");
        }),
        Some(&|| cancel.load(Ordering::Relaxed)),
    );

    handle.join().unwrap();

    match &result {
        Ok(()) => println!("  ✓ Selection succeeded (user touched the device)"),
        Err(Ctap2Error::StatusError(CtapStatus::KeepaliveCancel)) => {
            println!("  ✗ Selection was cancelled (timeout)")
        }
        Err(Ctap2Error::StatusError(CtapStatus::InvalidCommand)) => {
            println!("  ⚠ Selection not supported (CTAP 2.1+ required)")
        }
        Err(e) => println!("  ✗ Selection failed: {e}"),
    }
    println!();
}

fn is_yubico_reader(reader: &str) -> bool {
    reader.contains("Yubico") || reader.contains("YubiKey")
}

fn main() {
    let mut found_any = false;

    // Discover FIDO HID devices
    let fido_devs = list_fido_devices().unwrap_or_default();
    // Discover CCID readers (filter to Yubico)
    let readers: Vec<String> = list_readers()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| is_yubico_reader(r))
        .collect();

    if fido_devs.is_empty() && readers.is_empty() {
        eprintln!("No YubiKeys found.");
        return;
    }

    // FIDO HID
    for dev in &fido_devs {
        found_any = true;
        println!(
            "Found FIDO HID device: {} (PID=0x{:04X})",
            dev.path, dev.pid
        );

        let conn = match HidFidoConnection::open(dev) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  Failed to open: {e}");
                continue;
            }
        };
        println!(
            "  Device version: {}.{}.{}, capabilities: 0x{:02X}",
            conn.device_version().0,
            conn.device_version().1,
            conn.device_version().2,
            conn.capabilities().raw(),
        );

        let ctap = match CtapSession::new_fido(conn) {
            Ok(s) => s,
            Err((e, _)) => {
                eprintln!("  Failed to open CTAP session: {e}");
                continue;
            }
        };
        let ctap2 = Ctap2Session::new(ctap);
        run_selection(ctap2, "FIDO HID");
    }

    // CCID / SmartCard
    for reader in &readers {
        found_any = true;
        println!("Found CCID reader: {reader}");

        let conn = match PcscSmartCardConnection::open(reader) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  Failed to connect: {e}");
                continue;
            }
        };

        let ctap = match CtapSession::new(conn) {
            Ok(s) => s,
            Err((e, _)) => {
                eprintln!("  FIDO not available: {e}");
                continue;
            }
        };

        if !ctap.has_ctap2() {
            println!("  Skipping: no CTAP2 support (CTAP1 only)");
            continue;
        }

        let ctap2 = Ctap2Session::new(ctap);
        run_selection(ctap2, &format!("CCID ({reader})"));
    }

    if !found_any {
        eprintln!("No YubiKeys found.");
    }
}
