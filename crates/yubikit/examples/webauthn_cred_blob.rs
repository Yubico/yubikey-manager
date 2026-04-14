// Example: WebAuthn credBlob extension – store and retrieve a small blob.
//
// Demonstrates:
//   1. Creating a credential with `credBlob` to store a small secret
//   2. Authenticating with `getCredBlob: true` to read the blob back
//
// credBlob stores data directly in the credential (typically max 32 bytes).
// It is simpler than largeBlob but limited in size.
//
// Usage: cargo run -p yubikit --example webauthn_cred_blob
//
// ⚠ This example creates a credential on the authenticator.

#[path = "example_utils.rs"]
mod example_utils;
use example_utils::{RP_ID, hex, open_client, random_challenge};

use yubikit::webauthn::extensions::{
    AuthenticationExtensionInputs, RegistrationExtensionInputs, cred_blob::RegistrationInput,
};
use yubikit::webauthn::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, UserVerificationRequirement,
};

fn main() {
    let (mut client, info) = open_client();

    if !info.extensions.iter().any(|e| e == "credBlob") {
        eprintln!("Authenticator does not support credBlob.");
        std::process::exit(1);
    }
    let max_len = info.max_cred_blob_length.unwrap_or(0);
    println!("✓ credBlob supported (max {max_len} bytes)");

    // -- Registration: store a blob --
    let blob_data = b"hello, credBlob!".to_vec();
    println!(
        "\n━━━ Registration (credBlob: {} bytes) ━━━",
        blob_data.len()
    );

    let create_options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: "CredBlob Example".to_string(),
            id: Some(RP_ID.to_string()),
        },
        user: PublicKeyCredentialUserEntity {
            id: b"blob-user".to_vec(),
            name: Some("blob@example.com".to_string()),
            display_name: Some("Blob User".to_string()),
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
            cred_blob: Some(RegistrationInput { blob: blob_data }),
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
        && let Some(ref cb) = ext.cred_blob
    {
        println!("  Blob stored: {}", cb.stored);
    }

    // -- Authentication: retrieve the blob --
    println!("\n━━━ Authentication (getCredBlob) ━━━");

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
            get_cred_blob: Some(true),
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

    println!("✅ Authentication succeeded");
    if let Some(ref ext) = assertions[0].client_extension_results
        && let Some(ref cb) = ext.cred_blob
    {
        println!("  Retrieved blob: {}", hex(&cb.blob));
        match std::str::from_utf8(&cb.blob) {
            Ok(s) => println!("  As UTF-8: \"{s}\""),
            Err(_) => println!("  (not valid UTF-8)"),
        }
    }

    let _session = client.into_session();
    println!("\nDone.");
}
