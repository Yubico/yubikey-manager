//! Test controller abstraction for automating user interaction with YubiKeys.
//!
//! Different transports require different mechanisms to satisfy user presence,
//! power cycle the device, etc. The [`Controller`] trait provides a unified
//! interface, with implementations for NFC (automated via PCSC) and a fallback
//! that prints instructions to the user (for USB).

use std::io::{self, Write};
use std::time::Duration;

/// Abstraction over physical interactions required during FIDO tests.
pub trait Controller: Send + Sync {
    /// Press the YubiKey sensor (satisfy user presence).
    ///
    /// For NFC this is never needed (presence is implicit), so calling this
    /// on [`NfcController`] will panic.
    fn touch(&self);

    /// Release the YubiKey sensor after a long touch.
    ///
    /// Must only be called after [`touch()`](Controller::touch). For NFC this
    /// is never needed, so calling this on [`NfcController`] will panic.
    fn release(&self);

    /// Disconnect and re-connect the YubiKey (power cycle).
    ///
    /// On NFC this is done via PCSC. On USB this requires physical
    /// disconnection and reconnection.
    fn reinsert(&self);
}

/// Controller for NFC-attached YubiKeys.
///
/// User presence is implicit (card on reader), so `touch`/`release` are
/// invalid operations. `reinsert` performs an NFC power cycle via PCSC.
pub struct NfcController {
    reader_name: String,
}

impl NfcController {
    pub fn new(reader_name: &str) -> Self {
        Self {
            reader_name: reader_name.to_string(),
        }
    }
}

impl Controller for NfcController {
    fn touch(&self) {
        panic!("NfcController::touch() called — UP is implicit over NFC, this should not happen");
    }

    fn release(&self) {
        panic!("NfcController::release() called — UP is implicit over NFC, this should not happen");
    }

    fn reinsert(&self) {
        power_cycle_nfc(&self.reader_name).expect("NFC power cycle failed");
    }
}

/// Controller that prints instructions to the user for manual interaction.
///
/// Used when tests run over USB and physical actions cannot be automated.
pub struct PrintController;

impl Controller for PrintController {
    fn touch(&self) {
        eprint!("\n\x1b[1;36m>>> Touch the YubiKey sensor now...\x1b[0m");
        io::stderr().flush().ok();
    }

    fn release(&self) {
        eprintln!("\n\x1b[1;36m>>> Release the YubiKey sensor now.\x1b[0m");
    }

    fn reinsert(&self) {
        eprintln!("\x1b[1;36m>>> Disconnect and reconnect the YubiKey, then press Enter.\x1b[0m");
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).ok();
    }
}

/// Controller for a Pi Pico-based USB test fixture.
///
/// Controls power and touch on a YubiKey via HTTP endpoints on a Pi Pico W.
/// The Pico exposes `/usbN/power/{on,off}` and `/usbN/touch/{on,off}` endpoints.
pub struct PicoController {
    base_url: String,
    port: u8,
}

impl PicoController {
    pub fn new(base_url: &str, port: u8) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            port,
        }
    }

    fn get(&self, path: &str) {
        let url = format!("{}{}", self.base_url, path);
        eprintln!("PicoController: GET {url}");
        ureq::get(&url)
            .call()
            .unwrap_or_else(|e| panic!("PicoController request failed: {url}: {e}"));
    }
}

impl Controller for PicoController {
    fn touch(&self) {
        // Ensure touch is off first so the authenticator sees a fresh press
        self.get(&format!("/usb{}/touch/off", self.port));
        std::thread::sleep(Duration::from_millis(200));
        self.get(&format!("/usb{}/touch/on", self.port));
        // Give the authenticator time to register the touch
        std::thread::sleep(Duration::from_millis(300));
    }

    fn release(&self) {
        self.get(&format!("/usb{}/touch/off", self.port));
    }

    fn reinsert(&self) {
        // Release touch before power cycling
        self.get(&format!("/usb{}/touch/off", self.port));
        self.get(&format!("/usb{}/power/off", self.port));
        std::thread::sleep(Duration::from_millis(500));
        self.get(&format!("/usb{}/power/on", self.port));
        // Wait for the YubiKey to enumerate on the USB bus
        std::thread::sleep(Duration::from_millis(2000));
    }
}

/// Determine the appropriate controller based on transport and environment.
///
/// - NFC: always returns [`NfcController`]
/// - USB: checks the `CONTROLLER` environment variable:
///   - Not set: returns `None` (test should be skipped)
///   - `"interactive"`: returns [`PrintController`]
///   - URL (e.g. `"http://192.168.7.1"`): returns [`PicoController`]
///
/// The `PICO_PORT` environment variable selects the USB port on the Pico
/// fixture (1–12, default 1).
pub fn get_controller(
    transport: yubikit::core::Transport,
    reader_name: Option<&str>,
) -> Option<Box<dyn Controller>> {
    match transport {
        yubikit::core::Transport::Nfc => {
            let name = reader_name.expect("NFC device must have a reader name");
            Some(Box::new(NfcController::new(name)))
        }
        yubikit::core::Transport::Usb => {
            let env_val = std::env::var("CONTROLLER").ok()?;
            if env_val.eq_ignore_ascii_case("interactive") {
                Some(Box::new(PrintController))
            } else {
                let port: u8 = std::env::var("PICO_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(6); // Default port 6, closest to the controller on the fixture
                Some(Box::new(PicoController::new(&env_val, port)))
            }
        }
    }
}

/// Power-cycle the NFC card using PCSC so the "recently powered up"
/// window is reset for commands like FIDO reset.
pub fn power_cycle_nfc(reader_name: &str) -> Result<(), String> {
    use pcsc::{Context, Disposition, Protocols, Scope, ShareMode};
    use std::ffi::CString;

    let c_reader = CString::new(reader_name).map_err(|e| e.to_string())?;
    let ctx = Context::establish(Scope::User).map_err(|e| e.to_string())?;

    eprintln!("FIDO setup: power-cycling NFC card via PCSC...");

    // Try UnpowerCard (cold reset / field off) first.
    {
        let card = ctx
            .connect(&c_reader, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| e.to_string())?;
        card.disconnect(Disposition::UnpowerCard)
            .map_err(|(_, e)| e.to_string())?;
    }
    std::thread::sleep(Duration::from_millis(1000));

    // Reconnect to confirm the card came back; use ResetCard to also
    // ensure the card goes through its ATR sequence (warm reset).
    {
        let mut card = ctx
            .connect(&c_reader, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| e.to_string())?;
        card.reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard)
            .map_err(|e| e.to_string())?;
        card.disconnect(Disposition::LeaveCard)
            .map_err(|(_, e)| e.to_string())?;
    }
    std::thread::sleep(Duration::from_millis(200));

    eprintln!("FIDO setup: NFC card power-cycled");
    Ok(())
}
