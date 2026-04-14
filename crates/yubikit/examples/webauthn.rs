// Example: WebAuthn registration + authentication using a FIDO2 security key.
//
// Demonstrates:
//   1. Discovering a FIDO HID device
//   2. Creating a WebAuthnClient with simple console-based interaction
//   3. Performing a registration ceremony (make_credential)
//   4. Using the resulting credential to perform authentication (get_assertion)
//
// The credential is created as a non-resident key for "example.com".
// PIN entry is prompted on stdin when required.
//
// Usage: cargo run -p yubikit --example webauthn
//
// ⚠ This example creates a (non-resident) credential on the authenticator.
// It does NOT delete it afterwards.

use std::io::{self, Write};

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Session, Permissions};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::webauthn::{
    ClientDataCollector, CollectedClientData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, UserInteraction, UserVerificationRequirement, WebAuthnClient,
};

// ---------------------------------------------------------------------------
// UserInteraction – console-based prompts
// ---------------------------------------------------------------------------

struct ConsoleInteraction;

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

const ORIGIN: &str = "https://example.com";
const RP_ID: &str = "example.com";

struct SimpleCollector;

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
// Helper: generate a random challenge
// ---------------------------------------------------------------------------

fn random_challenge() -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    // Simple (non-cryptographic!) challenge for demo purposes
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

// ---------------------------------------------------------------------------
// Helper: format bytes as hex
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    // 1. Find a FIDO HID device
    let devices = list_fido_devices().expect("failed to list HID devices");
    let dev = match devices.first() {
        Some(d) => d,
        None => {
            eprintln!("No FIDO HID devices found. Insert a security key and try again.");
            std::process::exit(1);
        }
    };

    println!("Using device: {} (PID=0x{:04X})", dev.path, dev.pid);

    // 2. Open CTAP2 session
    let conn = HidFidoConnection::open(dev).expect("failed to open HID connection");
    let ctap = match CtapSession::new_fido(conn) {
        Ok(s) => s,
        Err((e, _)) => {
            eprintln!("Failed to open CTAP session: {e}");
            std::process::exit(1);
        }
    };
    let session = Ctap2Session::new(ctap).expect("failed to initialise CTAP2 session");

    println!("CTAP2 session established.");
    println!("  Authenticator: {:?}", session.info().versions);

    // 3. Create WebAuthn client
    let mut client = WebAuthnClient::new(session, ConsoleInteraction, SimpleCollector);

    // 4. Registration ceremony
    println!("\n━━━ Registration ━━━");
    let create_options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: "Example RP".to_string(),
            id: Some(RP_ID.to_string()),
        },
        user: PublicKeyCredentialUserEntity {
            id: b"user-1234".to_vec(),
            name: Some("alice@example.com".to_string()),
            display_name: Some("Alice".to_string()),
        },
        challenge: random_challenge(),
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -8, // EdDSA
            },
        ],
        timeout: Some(60_000),
        exclude_credentials: None,
        authenticator_selection: None,
        hints: None,
        attestation: None,
        attestation_formats: None,
        extensions: None,
    };

    let reg = match client.make_credential(&create_options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Registration failed: {e}");
            std::process::exit(1);
        }
    };

    println!("✅ Registration succeeded!");
    println!("  Credential ID: {} ({} bytes)", hex(&reg.id), reg.id.len());
    println!(
        "  Attestation object: {} bytes",
        reg.response.attestation_object.len()
    );

    // 5. Authentication ceremony
    println!("\n━━━ Authentication ━━━");
    let get_options = PublicKeyCredentialRequestOptions {
        challenge: random_challenge(),
        timeout: Some(60_000),
        rp_id: Some(RP_ID.to_string()),
        allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: reg.id.clone(),
            transports: None,
        }]),
        user_verification: Some(UserVerificationRequirement::Discouraged),
        hints: None,
        extensions: None,
    };

    let assertions = match client.get_assertion(&get_options) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Authentication failed: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "✅ Authentication succeeded! ({} assertion(s))",
        assertions.len()
    );
    for (i, assertion) in assertions.iter().enumerate() {
        println!("  Assertion {i}:");
        println!("    Credential ID: {}", hex(&assertion.id));
        println!(
            "    Signature: {} bytes",
            assertion.response.signature.len()
        );
        println!(
            "    Auth data: {} bytes",
            assertion.response.authenticator_data.len()
        );
        if let Some(ref handle) = assertion.response.user_handle {
            println!("    User handle: {}", hex(handle));
        }
    }

    // Release the session
    let _session = client.into_session();
    println!("\nDone.");
}
