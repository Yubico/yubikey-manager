//! Test controller abstraction for automating user interaction with YubiKeys.
//!
//! Different transports require different mechanisms to satisfy user presence,
//! power cycle the device, etc. The [`Controller`] trait provides a unified
//! interface, with implementations for NFC (automated via PCSC) and a fallback
//! that prints instructions to the user (for USB).

use std::io::{self, Write};

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
    std::thread::sleep(std::time::Duration::from_millis(1000));

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
    std::thread::sleep(std::time::Duration::from_millis(200));

    eprintln!("FIDO setup: NFC card power-cycled");
    Ok(())
}
