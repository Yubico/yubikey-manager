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

#[path = "example_utils.rs"]
mod example_utils;
use example_utils::{RP_ID, hex, open_client, random_challenge};

use yubikit::webauthn::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, UserVerificationRequirement,
};

fn main() {
    let (mut client, _info) = open_client();

    // -- Registration --
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

    // -- Authentication --
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

    let _session = client.into_session();
    println!("\nDone.");
}
