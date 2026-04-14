// Example: WebAuthn largeBlob extension – read and write large blobs.
//
// Demonstrates:
//   1. Creating a credential with `largeBlob.support = "required"`
//   2. Writing arbitrary data to the large blob associated with the credential
//   3. Reading the data back in a subsequent authentication
//
// Unlike credBlob (which is limited to ~32 bytes), largeBlob can store
// much larger data using the authenticator's dedicated blob storage.
//
// Usage: cargo run -p yubikit --example webauthn_large_blob
//
// ⚠ This example creates a credential and writes to large blob storage.

use std::io::{self, Write};

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Session, Permissions};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::webauthn::extensions::{
    AuthenticationExtensionInputs, RegistrationExtensionInputs,
    large_blob::{AuthenticationInput, LargeBlobSupport, RegistrationInput},
};
use yubikit::webauthn::{
    AuthenticatorSelectionCriteria, ClientDataCollector, CollectedClientData,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, ResidentKeyRequirement,
    UserInteraction, UserVerificationRequirement, WebAuthnClient,
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
    if info.options.get("largeBlobs") != Some(&true) {
        eprintln!("Authenticator does not support largeBlobs.");
        std::process::exit(1);
    }
    println!("✓ largeBlobs supported");

    let mut client = WebAuthnClient::new(session, ConsoleInteraction, SimpleCollector);

    // -- Registration with largeBlob support required --
    // largeBlob requires a resident key (discoverable credential)
    println!("\n━━━ Registration (largeBlob: required) ━━━");

    let create_options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: "LargeBlob Example".to_string(),
            id: Some(RP_ID.to_string()),
        },
        user: PublicKeyCredentialUserEntity {
            id: b"largeblob-user".to_vec(),
            name: Some("largeblob@example.com".to_string()),
            display_name: Some("LargeBlob User".to_string()),
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
            large_blob: Some(RegistrationInput {
                support: LargeBlobSupport::Required,
            }),
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

    println!("✅ Credential: {}", hex(&reg.id));
    if let Some(ref ext) = reg.client_extension_results
        && let Some(ref lb) = ext.large_blob
    {
        println!("  largeBlob supported: {}", lb.supported);
    }

    // -- Write a blob --
    let blob_data = b"This is a larger piece of data stored via the largeBlob extension. \
        It can hold more than the 32 bytes credBlob is limited to."
        .to_vec();
    println!(
        "\n━━━ Authentication: write blob ({} bytes) ━━━",
        blob_data.len()
    );

    let write_options = PublicKeyCredentialRequestOptions {
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
            large_blob: Some(AuthenticationInput::write(blob_data.clone())),
            ..Default::default()
        }),
    };

    let assertions = match client.get_assertion(&write_options) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Write failed: {e}");
            std::process::exit(1);
        }
    };

    if let Some(ref ext) = assertions[0].client_extension_results
        && let Some(ref lb) = ext.large_blob
    {
        println!("✅ Blob written: {:?}", lb.written);
    }

    // -- Read the blob back --
    println!("\n━━━ Authentication: read blob ━━━");

    let read_options = PublicKeyCredentialRequestOptions {
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
            large_blob: Some(AuthenticationInput::read()),
            ..Default::default()
        }),
    };

    let assertions = match client.get_assertion(&read_options) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Read failed: {e}");
            std::process::exit(1);
        }
    };

    if let Some(ref ext) = assertions[0].client_extension_results
        && let Some(ref lb) = ext.large_blob
    {
        if let Some(ref data) = lb.blob {
            println!("✅ Read {} bytes", data.len());
            match std::str::from_utf8(data) {
                Ok(s) => println!("  Content: \"{s}\""),
                Err(_) => println!("  Content: {}", hex(data)),
            }
            if *data == blob_data {
                println!("  ✅ Data matches what was written!");
            } else {
                println!("  ❌ Data does not match!");
            }
        } else {
            println!("  (no blob data returned)");
        }
    }

    let _session = client.into_session();
    println!("\nDone.");
}
