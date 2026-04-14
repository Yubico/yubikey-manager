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

#[path = "example_utils.rs"]
mod example_utils;
use example_utils::{RP_ID, hex, open_client, random_challenge};

use yubikit::webauthn::extensions::RegistrationExtensionInputs;
use yubikit::webauthn::{
    AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, ResidentKeyRequirement,
};

fn main() {
    let mut client = open_client();

    let info = client.info().clone();
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
