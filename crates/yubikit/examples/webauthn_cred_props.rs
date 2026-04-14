// Example: WebAuthn credProps + minPinLength extensions.
//
// credProps (credential properties):
//   A client-side extension that tells the relying party whether the
//   credential was actually stored as a resident (discoverable) key.
//   The authenticator does not participate – the client fills this in.
//
// minPinLength:
//   Requests the authenticator to report the minimum PIN length it
//   enforces.  The RP can use this to guide users.
//
// Usage: cargo run -p yubikit --example webauthn_cred_props
//
// ⚠ This example creates credentials on the authenticator.

use std::io::{self, Write};

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Session, Permissions};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::webauthn::extensions::RegistrationExtensionInputs;
use yubikit::webauthn::{
    AuthenticatorSelectionCriteria, ClientDataCollector, CollectedClientData,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, ResidentKeyRequirement, UserInteraction, WebAuthnClient,
};

// ---------------------------------------------------------------------------
// Shared helpers
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
    let has_min_pin = info.extensions.iter().any(|e| e == "minPinLength");
    println!("✓ credProps: always available (client-side)");
    println!(
        "{} minPinLength: {}",
        if has_min_pin { "✓" } else { "✗" },
        if has_min_pin {
            "supported"
        } else {
            "not supported"
        }
    );

    let mut client = WebAuthnClient::new(session, ConsoleInteraction, SimpleCollector);

    // -- Non-resident credential with credProps --
    println!("\n━━━ Non-resident credential (credProps) ━━━");
    let create_options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: "CredProps Example".to_string(),
            id: Some(RP_ID.to_string()),
        },
        user: PublicKeyCredentialUserEntity {
            id: b"props-user-nr".to_vec(),
            name: Some("props@example.com".to_string()),
            display_name: Some("Props User".to_string()),
        },
        challenge: random_challenge(),
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
            type_: PublicKeyCredentialType::PublicKey,
            alg: -7,
        }],
        timeout: Some(60_000),
        exclude_credentials: None,
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            user_verification: None,
        }),
        hints: None,
        attestation: None,
        attestation_formats: None,
        extensions: Some(RegistrationExtensionInputs {
            cred_props: Some(true),
            min_pin_length: if has_min_pin { Some(true) } else { None },
            ..Default::default()
        }),
    };

    match client.make_credential(&create_options) {
        Ok(reg) => {
            println!("✅ Credential: {}", hex(&reg.id));
            if let Some(ref ext) = reg.client_extension_results {
                if let Some(ref cp) = ext.cred_props {
                    println!("  Discoverable (rk): {}", cp.rk);
                }
                if let Some(ref mp) = ext.min_pin_length {
                    println!("  Min PIN length: {}", mp.length);
                }
            }
        }
        Err(e) => eprintln!("❌ Failed: {e}"),
    }

    // -- Resident credential with credProps --
    println!("\n━━━ Resident credential (credProps) ━━━");
    let create_options_rk = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: "CredProps Example".to_string(),
            id: Some(RP_ID.to_string()),
        },
        user: PublicKeyCredentialUserEntity {
            id: b"props-user-rk".to_vec(),
            name: Some("props-rk@example.com".to_string()),
            display_name: Some("Props RK User".to_string()),
        },
        challenge: random_challenge(),
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
            type_: PublicKeyCredentialType::PublicKey,
            alg: -7,
        }],
        timeout: Some(60_000),
        exclude_credentials: None,
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: Some(ResidentKeyRequirement::Required),
            user_verification: None,
        }),
        hints: None,
        attestation: None,
        attestation_formats: None,
        extensions: Some(RegistrationExtensionInputs {
            cred_props: Some(true),
            min_pin_length: if has_min_pin { Some(true) } else { None },
            ..Default::default()
        }),
    };

    match client.make_credential(&create_options_rk) {
        Ok(reg) => {
            println!("✅ Credential: {}", hex(&reg.id));
            if let Some(ref ext) = reg.client_extension_results {
                if let Some(ref cp) = ext.cred_props {
                    println!("  Discoverable (rk): {}", cp.rk);
                }
                if let Some(ref mp) = ext.min_pin_length {
                    println!("  Min PIN length: {}", mp.length);
                }
            }
        }
        Err(e) => eprintln!("❌ Failed: {e}"),
    }

    let _session = client.into_session();
    println!("\nDone.");
}
