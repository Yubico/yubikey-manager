// Example: CTAP2 authenticatorSelection using yubikit's CtapSession + Ctap2Session
//
// Lists attached YubiKeys, then for each device:
//   - If it has a FIDO HID interface, opens a Ctap2Session over HID and calls selection()
//   - If it has a CCID interface, opens a Ctap2Session over SmartCard and calls selection()
//
// A background thread cancels selection after 5 seconds if the user hasn't touched the key.
//
// Usage: cargo run -p yubikit --example ctap2_selection

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Error, Ctap2Session, CtapStatus};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::transport::pcsc::{PcscSmartCardConnection, list_readers};

const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

fn run_demo<C, E>(mut session: Ctap2Session<C>, transport: &str)
where
    C: yubikit::core::Connection<Error = E> + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    // --- selection ---
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

    let selection_ok = match &result {
        Ok(()) => {
            println!("  ✓ Selection succeeded (user touched the device)");
            true
        }
        Err(Ctap2Error::StatusError(CtapStatus::KeepaliveCancel)) => {
            println!("  ✗ Selection was cancelled (timeout)");
            false
        }
        Err(Ctap2Error::StatusError(CtapStatus::InvalidCommand)) => {
            println!("  ⚠ Selection not supported (CTAP 2.1+ required)");
            true // still call get_info
        }
        Err(e) => {
            println!("  ✗ Selection failed: {e}");
            false
        }
    };

    // --- get_info ---
    if selection_ok {
        println!("  Calling get_info...");
        match session.get_info() {
            Ok(info) => print_info(&info),
            Err(e) => println!("  ✗ get_info failed: {e}"),
        }
    }

    println!();
}

fn print_info(info: &yubikit::ctap2::Info) {
    println!("  Authenticator Info:");
    println!("    Versions:    {:?}", info.versions);
    println!("    AAGUID:      {}", info.aaguid);
    if !info.extensions.is_empty() {
        println!("    Extensions:  {:?}", info.extensions);
    }
    if !info.options.is_empty() {
        println!("    Options:     {:?}", info.options);
    }
    println!("    Max msg:     {} bytes", info.max_msg_size);
    if !info.pin_uv_protocols.is_empty() {
        println!("    PIN/UV:      {:?}", info.pin_uv_protocols);
    }
    if let Some(fw) = info.firmware_version {
        println!("    Firmware:    {fw}");
    }
    if !info.transports.is_empty() {
        println!("    Transports:  {:?}", info.transports);
    }
    if !info.algorithms.is_empty() {
        let algs: Vec<_> = info.algorithms.iter().map(|a| a.alg).collect();
        println!("    Algorithms:  {:?}", algs);
    }
    if let Some(n) = info.remaining_disc_creds {
        println!("    Remaining discoverable credentials: {n}");
    }
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
        let ctap2 = match Ctap2Session::new(ctap) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  Failed to get info: {e}");
                continue;
            }
        };
        run_demo(ctap2, "FIDO HID");
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

        let ctap2 = match Ctap2Session::new(ctap) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  Failed to get info: {e}");
                continue;
            }
        };
        run_demo(ctap2, &format!("CCID ({reader})"));
    }

    if !found_any {
        eprintln!("No YubiKeys found.");
    }
}
