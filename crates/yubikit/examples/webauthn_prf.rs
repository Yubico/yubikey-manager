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

#[path = "example_utils.rs"]
mod example_utils;
use example_utils::{RP_ID, hex, open_client, random_challenge};

use yubikit::webauthn::extensions::{
    AuthenticationExtensionInputs, RegistrationExtensionInputs,
    prf::{AuthenticationInput, PrfEval, RegistrationInput},
};
use yubikit::webauthn::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, UserVerificationRequirement,
};

fn main() {
    let mut client = open_client();

    let info = client.info().clone();
    if !info.extensions.iter().any(|e| e == "hmac-secret") {
        eprintln!("Authenticator does not support hmac-secret / PRF.");
        std::process::exit(1);
    }
    println!("✓ hmac-secret extension supported");

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
