// Example: WebAuthn PRF extension – derive symmetric secrets from a credential.
//
// Demonstrates:
//   1. Registering a credential with `prf` extension enabled
//   2. Deriving a secret during authentication using `eval` salts
//   3. Verifying that the same salts produce the same secret
//
// The PRF extension wraps the CTAP2 hmac-secret extension.  The client
// hashes application-supplied inputs through
//   SHA-256("WebAuthn PRF\0" || input)
// before sending them to the authenticator as HMAC salts.
//
// Usage: cargo run -p yubikit --example webauthn_prf
//
// ⚠ This example creates a credential on the authenticator.

use std::io::{self, Write};

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Session, Permissions};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::webauthn::extensions::{
    AuthenticationExtensionInputs, RegistrationExtensionInputs,
    prf::{AuthenticationInput, PrfEval, RegistrationInput},
};
use yubikit::webauthn::{
    ClientDataCollector, CollectedClientData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, UserInteraction, UserVerificationRequirement, WebAuthnClient,
};

// ---------------------------------------------------------------------------
// Shared helpers (same as webauthn.rs)
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
    fn request_uv(&self, _p: Permissions, _rp: Option<&str>) -> bool {
        true
    }
}

const ORIGIN: &str = "https://example.com";
const RP_ID: &str = "example.com";

struct SimpleCollector;

impl ClientDataCollector for SimpleCollector {
    fn collect_create(
        &self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let rp_id = options.rp.id.clone().unwrap_or_else(|| RP_ID.to_string());
        Ok((
            CollectedClientData::create("webauthn.create", &options.challenge, ORIGIN, false),
            rp_id,
        ))
    }
    fn collect_get(
        &self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let rp_id = options.rp_id.clone().unwrap_or_else(|| RP_ID.to_string());
        Ok((
            CollectedClientData::create("webauthn.get", &options.challenge, ORIGIN, false),
            rp_id,
        ))
    }
}

fn random_challenge() -> Vec<u8> {
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let devices = list_fido_devices().expect("failed to list HID devices");
    let dev = devices.first().unwrap_or_else(|| {
        eprintln!("No FIDO HID devices found.");
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
    let session = Ctap2Session::new(ctap).expect("CTAP2 init failed");

    let info = session.info();
    if !info.extensions.iter().any(|e| e == "hmac-secret") {
        eprintln!("Authenticator does not support hmac-secret / PRF.");
        std::process::exit(1);
    }
    println!("✓ hmac-secret extension supported");

    let mut client = WebAuthnClient::new(session, ConsoleInteraction, SimpleCollector);

    // -- Registration with PRF enabled --
    println!("\n━━━ Registration (PRF) ━━━");
    let create_options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: "PRF Example".to_string(),
            id: Some(RP_ID.to_string()),
        },
        user: PublicKeyCredentialUserEntity {
            id: b"prf-user".to_vec(),
            name: Some("prf@example.com".to_string()),
            display_name: Some("PRF User".to_string()),
        },
        challenge: random_challenge(),
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
            type_: PublicKeyCredentialType::PublicKey,
            alg: -7,
        }],
        timeout: Some(60_000),
        exclude_credentials: None,
        authenticator_selection: None,
        hints: None,
        attestation: None,
        attestation_formats: None,
        extensions: Some(RegistrationExtensionInputs {
            prf: Some(RegistrationInput { eval: None }),
            ..Default::default()
        }),
    };

    let reg = match client.make_credential(&create_options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Registration failed: {e}");
            std::process::exit(1);
        }
    };

    println!("✅ Credential registered: {}", hex(&reg.id));
    if let Some(ref ext) = reg.client_extension_results
        && let Some(ref prf) = ext.prf
    {
        println!("  PRF enabled: {}", prf.enabled);
    }

    // -- Authentication with PRF eval --
    println!("\n━━━ Authentication (PRF eval) ━━━");

    let salt_input = b"example PRF salt input".to_vec();

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
        extensions: Some(AuthenticationExtensionInputs {
            prf: Some(AuthenticationInput {
                eval: Some(PrfEval {
                    first: salt_input.clone(),
                    second: None,
                }),
                eval_by_credential: Default::default(),
            }),
            ..Default::default()
        }),
    };

    let assertions = match client.get_assertion(&get_options) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Authentication failed: {e}");
            std::process::exit(1);
        }
    };

    let first = &assertions[0];
    println!("✅ Authentication succeeded");
    if let Some(ref ext) = first.client_extension_results
        && let Some(ref prf) = ext.prf
    {
        println!("  PRF first:  {}", hex(&prf.results.first));
        if let Some(ref second) = prf.results.second {
            println!("  PRF second: {}", hex(second));
        }
    }

    // -- Second authentication with same salt → same secret --
    println!("\n━━━ Verify determinism (same salt → same secret) ━━━");

    let get_options2 = PublicKeyCredentialRequestOptions {
        challenge: random_challenge(),
        extensions: Some(AuthenticationExtensionInputs {
            prf: Some(AuthenticationInput {
                eval: Some(PrfEval {
                    first: salt_input,
                    second: None,
                }),
                eval_by_credential: Default::default(),
            }),
            ..Default::default()
        }),
        ..get_options
    };

    let assertions2 = match client.get_assertion(&get_options2) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Second auth failed: {e}");
            std::process::exit(1);
        }
    };

    let ext1 = first.client_extension_results.as_ref().unwrap();
    let ext2 = assertions2[0].client_extension_results.as_ref().unwrap();
    let s1 = &ext1.prf.as_ref().unwrap().results.first;
    let s2 = &ext2.prf.as_ref().unwrap().results.first;

    if s1 == s2 {
        println!("✅ Same salt produced the same secret ({} bytes)", s1.len());
    } else {
        println!("❌ Secrets differ – this is unexpected!");
    }

    let _session = client.into_session();
    println!("\nDone.");
}
