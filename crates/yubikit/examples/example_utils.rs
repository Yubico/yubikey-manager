// Shared utilities for WebAuthn examples.
//
// Provides console-based UserInteraction, a simple ClientDataCollector,
// device discovery, and helper functions used across all examples.

use std::io::{self, Write};

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Session, Info, Permissions};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::webauthn::{
    ClientDataCollector, CollectedClientData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, UserInteraction, WebAuthnClient,
};

pub const ORIGIN: &str = "https://example.com";
pub const RP_ID: &str = "example.com";

// ---------------------------------------------------------------------------
// UserInteraction – console-based prompts
// ---------------------------------------------------------------------------

pub struct ConsoleInteraction;

impl UserInteraction for ConsoleInteraction {
    fn prompt_up(&self) {
        println!("\n👆 Touch your security key...");
    }

    fn request_pin(&self, _permissions: Permissions, _rp_id: Option<&str>) -> Option<String> {
        print!("🔑 Enter PIN: ");
        io::stdout().flush().ok();
        let mut pin = String::new();
        io::stdin().read_line(&mut pin).ok()?;
        let pin = pin.trim().to_string();
        if pin.is_empty() { None } else { Some(pin) }
    }

    fn request_uv(&self, _permissions: Permissions, _rp_id: Option<&str>) -> bool {
        println!("🔒 Biometric verification requested – proceeding");
        true
    }
}

// ---------------------------------------------------------------------------
// ClientDataCollector – simple implementation for "example.com"
// ---------------------------------------------------------------------------

pub struct SimpleCollector;

impl ClientDataCollector for SimpleCollector {
    fn collect_create(
        &self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let rp_id = options.rp.id.clone().unwrap_or_else(|| RP_ID.to_string());
        let cd = CollectedClientData::create("webauthn.create", &options.challenge, ORIGIN, false);
        Ok((cd, rp_id))
    }

    fn collect_get(
        &self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let rp_id = options.rp_id.clone().unwrap_or_else(|| RP_ID.to_string());
        let cd = CollectedClientData::create("webauthn.get", &options.challenge, ORIGIN, false);
        Ok((cd, rp_id))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a non-cryptographic random challenge for demo purposes.
pub fn random_challenge() -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    let a = h.finish().to_le_bytes();
    let mut h2 = DefaultHasher::new();
    a.hash(&mut h2);
    42u64.hash(&mut h2);
    let b = h2.finish().to_le_bytes();
    [a, b, a, b].concat()
}

/// Format bytes as a hex string.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Discover a FIDO HID device and create a [`WebAuthnClient`].
///
/// Returns the client and the authenticator [`Info`].
/// Prints device information and exits the process if no device is found.
pub fn open_client() -> (
    WebAuthnClient<HidFidoConnection, ConsoleInteraction, SimpleCollector>,
    Info,
) {
    let devices = list_fido_devices().expect("failed to list HID devices");
    let dev = devices.first().unwrap_or_else(|| {
        eprintln!("No FIDO HID devices found. Insert a security key and try again.");
        std::process::exit(1);
    });

    println!("Using device: {} (PID=0x{:04X})", dev.path, dev.pid);

    let conn = HidFidoConnection::open(dev).expect("failed to open HID connection");
    let ctap = match CtapSession::new_fido(conn) {
        Ok(s) => s,
        Err((e, _)) => {
            eprintln!("CTAP session error: {e}");
            std::process::exit(1);
        }
    };
    let session = match Ctap2Session::new(ctap) {
        Ok(s) => s,
        Err((e, _)) => {
            eprintln!("CTAP2 init failed: {e}");
            std::process::exit(1);
        }
    };
    let info = session.info().clone();

    (
        WebAuthnClient::new(session, ConsoleInteraction, SimpleCollector),
        info,
    )
}
