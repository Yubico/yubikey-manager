//! Test controller abstraction for automating user interaction with YubiKeys.
//!
//! Different transports require different mechanisms to satisfy user presence,
//! power cycle the device, etc. The [`Controller`] trait provides a unified
//! interface, with implementations for NFC (automated via PCSC) and a fallback
//! that prints instructions to the user (for USB).

use std::io::{self, Write};
use std::sync::{Mutex, Once, OnceLock};
use std::time::Duration;

static PICO_CLEANUP_TARGETS: OnceLock<Mutex<Vec<(String, u8)>>> = OnceLock::new();
static REGISTER_PICO_CLEANUP: Once = Once::new();

extern "C" fn cleanup_pico_touch() {
    if let Some(targets) = PICO_CLEANUP_TARGETS.get()
        && let Ok(targets) = targets.lock()
    {
        for (base_url, port) in targets.iter() {
            let url = format!("{base_url}/usb{port}/touch/off");
            eprintln!("PicoController cleanup: GET {url}");
            let _ = ureq::get(&url).call();
        }
    }
}

fn register_pico_cleanup(base_url: &str, port: u8) {
    let targets = PICO_CLEANUP_TARGETS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut targets) = targets.lock() {
        let target = (base_url.to_string(), port);
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    REGISTER_PICO_CLEANUP.call_once(|| unsafe {
        unsafe extern "C" {
            fn atexit(cb: extern "C" fn()) -> i32;
        }
        let _ = atexit(cleanup_pico_touch);
    });
}

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

    /// Remove/disconnect the YubiKey (first half of a power cycle).
    ///
    /// On USB this powers off the port. On NFC this disconnects via PCSC.
    fn remove(&self);

    /// Insert/reconnect the YubiKey (second half of a power cycle).
    ///
    /// On USB this powers on the port and waits for enumeration.
    /// On NFC this reconnects via PCSC and resets the card.
    fn insert(&self);
}

/// Controller for NFC-attached YubiKeys.
///
/// User presence is implicit (card on reader), so `touch`/`release` are
/// invalid operations. `remove`/`insert` perform an NFC power cycle via PCSC.
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

    fn remove(&self) {
        use pcsc::{Context, Disposition, Protocols, Scope, ShareMode};
        use std::ffi::CString;

        let c_reader = CString::new(self.reader_name.as_str()).expect("invalid reader name");
        let ctx = Context::establish(Scope::User).expect("PCSC context failed");

        eprintln!("NfcController: removing card (UnpowerCard)...");
        let card = ctx
            .connect(&c_reader, ShareMode::Shared, Protocols::ANY)
            .expect("NFC remove: connect failed");
        if let Err((_, e)) = card.disconnect(Disposition::UnpowerCard) {
            panic!("NFC remove: disconnect failed: {e}");
        }

        std::thread::sleep(Duration::from_millis(1000));
    }

    fn insert(&self) {
        use pcsc::{Context, Disposition, Protocols, Scope, ShareMode};
        use std::ffi::CString;

        let c_reader = CString::new(self.reader_name.as_str()).expect("invalid reader name");
        let ctx = Context::establish(Scope::User).expect("PCSC context failed");

        eprintln!("NfcController: inserting card (ResetCard)...");
        let mut card = ctx
            .connect(&c_reader, ShareMode::Shared, Protocols::ANY)
            .expect("NFC insert: connect failed");
        card.reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard)
            .expect("NFC insert: reconnect failed");
        if let Err((_, e)) = card.disconnect(Disposition::LeaveCard) {
            panic!("NFC insert: disconnect failed: {e}");
        }

        std::thread::sleep(Duration::from_millis(200));
        eprintln!("NfcController: card power-cycled");
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

    fn remove(&self) {
        eprintln!("\x1b[1;36m>>> Disconnect the YubiKey now.\x1b[0m");
    }

    fn insert(&self) {
        eprintln!("\x1b[1;36m>>> Reconnect the YubiKey now.\x1b[0m");
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
        let base_url = base_url.trim_end_matches('/').to_string();
        register_pico_cleanup(&base_url, port);
        Self { base_url, port }
    }

    fn format_url(&self, action: &str) -> String {
        format!("{}/usb{}/{}", self.base_url, self.port, action)
    }

    fn get(&self, path: &str) {
        let url = self.format_url(path);
        eprintln!("PicoController: GET {url}");
        ureq::get(&url)
            .call()
            .unwrap_or_else(|e| panic!("PicoController request failed: {url}: {e}"));
    }
}

impl Controller for PicoController {
    fn touch(&self) {
        // Turn touch off first then back on in a background thread so that
        // the NFCCTAP keepalive polling loop isn't starved. The authenticator
        // needs to see a fresh off→on transition to register user presence.
        let url_off = self.format_url("touch/off");
        let url_on = self.format_url("touch/on");
        std::thread::spawn(move || {
            eprintln!("PicoController: GET {url_off}");
            let _ = ureq::get(&url_off).call();
            std::thread::sleep(Duration::from_millis(200));
            eprintln!("PicoController: GET {url_on}");
            let _ = ureq::get(&url_on).call();
        });
    }

    fn release(&self) {
        self.get("touch/off");
    }

    fn remove(&self) {
        self.get("touch/off");
        self.get("power/off");
    }

    fn insert(&self) {
        self.get("power/on");
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
