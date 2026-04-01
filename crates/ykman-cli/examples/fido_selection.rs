// Example: FIDO2 authenticatorSelection with cancel
//
// Opens a FIDO connection over HID (preferred) or PC/SC, initializes CTAP2,
// then calls selection() while a background thread cancels after 3 seconds.
//
// Usage: cargo run -p ykman-cli --example fido_selection

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fido2_client::ctap::{self, CtapDevice, CtapError};
use fido2_client::ctap2::Ctap2;
use yubikit::smartcard::{SmartCardConnection, SmartCardError, SmartCardProtocol};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::transport::pcsc::{PcscSmartCardConnection, list_readers};

const AID_FIDO: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
const SW_KEEPALIVE: u16 = 0x9100;

// --- HID adapter ---

struct HidCtapDevice {
    conn: HidFidoConnection,
}

impl CtapDevice for HidCtapDevice {
    fn call(
        &self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, CtapError> {
        self.conn
            .call_with_keepalive(cmd, data, on_keepalive, cancel)
            .map_err(|e| CtapError::TransportError(e.to_string()))
    }

    fn capabilities(&self) -> u8 {
        self.conn.capabilities().raw()
    }

    fn close(&mut self) {
        self.conn.close();
    }
}

// --- SmartCard (PCSC) adapter ---

struct SmartCardCtapDevice<C: SmartCardConnection> {
    protocol: RefCell<SmartCardProtocol<C>>,
    capabilities: u8,
}

impl<C: SmartCardConnection> SmartCardCtapDevice<C> {
    fn open(connection: C) -> Result<Self, CtapError> {
        let mut protocol = SmartCardProtocol::new(connection);
        let resp = protocol
            .select(AID_FIDO)
            .map_err(|e| CtapError::TransportError(format!("FIDO select failed: {e}")))?;

        let mut capabilities = 0u8;
        if resp == b"U2F_V2" {
            capabilities |= ctap::capability::NMSG;
        }

        let protocol = RefCell::new(protocol);
        // Probe for CTAP2
        {
            let mut proto = protocol.borrow_mut();
            if proto.send_apdu(0x80, 0x10, 0x80, 0x00, b"\x04").is_ok() {
                capabilities |= ctap::capability::CBOR;
            }
        }

        Ok(Self {
            protocol,
            capabilities,
        })
    }

    fn call_cbor(
        &self,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, CtapError> {
        let resp = {
            let mut protocol = self.protocol.borrow_mut();
            match protocol.send_apdu(0x80, 0x10, 0x80, 0x00, data) {
                Ok(resp) => return Ok(resp),
                Err(SmartCardError::Apdu { data, sw }) if sw == SW_KEEPALIVE => data,
                Err(SmartCardError::Apdu { sw, .. }) => {
                    return Err(CtapError::TransportError(format!(
                        "NFCCTAP error: SW={sw:04X}"
                    )));
                }
                Err(e) => return Err(CtapError::TransportError(e.to_string())),
            }
        };

        let mut last_ka: Option<u8> = None;
        if !resp.is_empty() {
            last_ka = Some(resp[0]);
            on_keepalive(resp[0]);
        }

        loop {
            std::thread::sleep(Duration::from_millis(100));
            let p1 = if cancel.is_some_and(|f| f.load(Ordering::Relaxed)) {
                0x11
            } else {
                0x00
            };
            let mut protocol = self.protocol.borrow_mut();
            match protocol.send_apdu(0x80, 0x11, p1, 0x00, &[]) {
                Ok(resp) => return Ok(resp),
                Err(SmartCardError::Apdu { data, sw }) if sw == SW_KEEPALIVE => {
                    if let Some(&status) = data.first()
                        && last_ka != Some(status)
                    {
                        last_ka = Some(status);
                        on_keepalive(status);
                    }
                }
                Err(SmartCardError::Apdu { sw, .. }) => {
                    return Err(CtapError::TransportError(format!(
                        "NFCCTAP error: SW={sw:04X}"
                    )));
                }
                Err(e) => return Err(CtapError::TransportError(e.to_string())),
            }
        }
    }
}

impl<C: SmartCardConnection> CtapDevice for SmartCardCtapDevice<C> {
    fn call(
        &self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, CtapError> {
        match cmd {
            ctap::cmd::CBOR => self.call_cbor(data, on_keepalive, cancel),
            _ => Err(CtapError::StatusError(ctap::CtapStatus::InvalidCommand)),
        }
    }

    fn capabilities(&self) -> u8 {
        self.capabilities
    }

    fn close(&mut self) {}
}

// --- Main ---

fn run_selection(device: &dyn CtapDevice, transport_name: &str) {
    println!("=== Testing selection over {transport_name} ===");

    let ctap2 = match Ctap2::new(device, false) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to init CTAP2: {e}");
            return;
        }
    };

    println!("CTAP2 initialized, AAGUID: {:?}", ctap2.info().aaguid);
    println!("Starting selection (will cancel after 3 seconds)...");

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_thread = cancel.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        println!("  [cancel thread] Setting cancel flag");
        cancel_thread.store(true, Ordering::Relaxed);
    });

    let result = ctap2.selection(
        &mut |status| {
            println!("  [keepalive] status={status:#04x}");
        },
        Some(&cancel),
    );

    handle.join().unwrap();

    match result {
        Ok(()) => println!("Selection succeeded (user touched the device)"),
        Err(ref e) if e.get_status() == Some(ctap::CtapStatus::KeepaliveCancel) => {
            println!("Selection was cancelled (expected)")
        }
        Err(e) => println!("Selection failed: {e}"),
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
                Ok(conn) => {
                    let device = HidCtapDevice { conn };
                    run_selection(&device, "HID");
                }
                Err(e) => eprintln!("Failed to open HID device: {e}"),
            }
        }
    }

    // Try PCSC
    if let Ok(readers) = list_readers() {
        for reader in &readers {
            println!("Found PC/SC reader: {reader}");
            match PcscSmartCardConnection::open(reader) {
                Ok(conn) => match SmartCardCtapDevice::open(conn) {
                    Ok(device) => run_selection(&device, &format!("PC/SC ({reader})")),
                    Err(e) => eprintln!("  FIDO not available: {e}"),
                },
                Err(e) => eprintln!("  Failed to connect: {e}"),
            }
        }
    }
}
