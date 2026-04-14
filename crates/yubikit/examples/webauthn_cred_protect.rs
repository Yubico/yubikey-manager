// Example: WebAuthn credProtect extension – set credential protection level.
//
// Demonstrates creating a credential with each of the three credProtect
// protection levels and inspecting the echoed policy in the response.
//
// Protection levels:
//   Level 1 – userVerificationOptional (default, no extra protection)
//   Level 2 – userVerificationOptionalWithCredentialIDList
//              (credential usable without UV only if its ID is provided)
//   Level 3 – userVerificationRequired
//              (UV always required to use the credential)
//
// Usage: cargo run -p yubikit --example webauthn_cred_protect
//
// ⚠ This example creates credentials on the authenticator.

#[path = "example_utils.rs"]
mod example_utils;
use example_utils::{RP_ID, hex, open_client, random_challenge};

use yubikit::webauthn::extensions::{
    RegistrationExtensionInputs,
    cred_protect::{CredProtectPolicy, RegistrationInput},
};
use yubikit::webauthn::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity,
};

fn main() {
    let mut client = open_client();

    let info = client.info().clone();
    if !info.extensions.iter().any(|e| e == "credProtect") {
        eprintln!("Authenticator does not support credProtect.");
        std::process::exit(1);
    }
    println!("✓ credProtect extension supported\n");

    let policies = [
        (
            CredProtectPolicy::UserVerificationOptional,
            "Level 1 - userVerificationOptional",
        ),
        (
            CredProtectPolicy::UserVerificationOptionalWithCredentialIDList,
            "Level 2 - userVerificationOptionalWithCredentialIDList",
        ),
        (
            CredProtectPolicy::UserVerificationRequired,
            "Level 3 - userVerificationRequired",
        ),
    ];

    for (policy, label) in &policies {
        println!("━━━ {label} ━━━");

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "CredProtect Example".to_string(),
                id: Some(RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: format!("user-cp-{}", *policy as u32).into_bytes(),
                name: Some("credprotect@example.com".to_string()),
                display_name: Some("CredProtect User".to_string()),
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
                cred_protect: Some(RegistrationInput {
                    policy: *policy,
                    enforce: true,
                }),
                ..Default::default()
            }),
        };

        match client.make_credential(&create_options) {
            Ok(reg) => {
                println!("  ✅ Credential: {}", hex(&reg.id));
                if let Some(ref ext) = reg.client_extension_results {
                    if let Some(ref cp) = ext.cred_protect {
                        println!("  Echoed policy: {:?}\n", cp.policy);
                    } else {
                        println!("  (no credProtect in response)\n");
                    }
                } else {
                    println!("  (no extension results)\n");
                }
            }
            Err(e) => {
                eprintln!("  ❌ Failed: {e}\n");
            }
        }
    }

    let _session = client.into_session();
    println!("Done.");
}
