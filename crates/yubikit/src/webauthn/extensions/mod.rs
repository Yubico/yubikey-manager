// Copyright (c) 2026 Yubico AB
// All rights reserved.
//
//   Redistribution and use in source and binary forms, with or
//   without modification, are permitted provided that the following
//   conditions are met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//    2. Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! WebAuthn extension types and CBOR encoding/decoding.
//!
//! Each sub-module defines extension-specific input/output types with JSON
//! serialization. The aggregate [`RegistrationExtensionInputs`](crate::webauthn::extensions::RegistrationExtensionInputs) and
//! [`AuthenticationExtensionInputs`](crate::webauthn::extensions::AuthenticationExtensionInputs) structs are used in the WebAuthn
//! options, while the output types appear in ceremony responses.

use serde::{Deserialize, Serialize};

use crate::cbor::{self, Value};

/// Credential Blob extension (`credBlob`).
pub mod cred_blob;
/// Credential Properties extension (`credProps`).
pub mod cred_props;
/// Credential Protection extension (`credProtect`).
pub mod cred_protect;
/// Large Blob extension (`largeBlob`).
pub mod large_blob;
/// Minimum PIN Length extension (`minPinLength`).
pub mod min_pin_length;
/// Pseudo-Random Function extension (`prf` / `hmac-secret`).
pub mod prf;

// Re-export key types
/// Credential protection policy level.
pub use cred_protect::CredProtectPolicy;
/// Level of large blob support requested during registration.
pub use large_blob::LargeBlobSupport;
/// PRF evaluation inputs and derived results.
pub use prf::{PrfEval, PrfResults};

// ---------------------------------------------------------------------------
// Registration (makeCredential)
// ---------------------------------------------------------------------------

/// Extension inputs for a registration ceremony.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationExtensionInputs {
    /// PRF extension input — enables hmac-secret and optionally evaluates salts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<prf::RegistrationInput>,

    /// credProtect — uses flattened JSON fields (`credentialProtectionPolicy`,
    /// `enforceCredentialProtectionPolicy`).
    #[serde(default, skip_serializing_if = "Option::is_none", flatten)]
    pub cred_protect: Option<cred_protect::RegistrationInput>,

    /// credBlob — stores a small data blob with the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<cred_blob::RegistrationInput>,

    /// largeBlob — requests a large blob key for the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<large_blob::RegistrationInput>,

    /// credProps — client-side only, no CTAP2 extension is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,

    /// minPinLength — requests the authenticator's minimum PIN length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
}

/// Extension outputs from a registration ceremony.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationExtensionOutputs {
    /// PRF extension output — whether hmac-secret is enabled and optional results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<prf::RegistrationOutput>,

    /// credProtect output — the effective credential protection policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<cred_protect::RegistrationOutput>,

    /// credBlob output — whether the blob was successfully stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<cred_blob::RegistrationOutput>,

    /// largeBlob output — whether large blob storage is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<large_blob::RegistrationOutput>,

    /// credProps output — credential properties (e.g. whether it is discoverable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<cred_props::RegistrationOutput>,

    /// minPinLength output — the authenticator's minimum PIN length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<min_pin_length::RegistrationOutput>,
}

// ---------------------------------------------------------------------------
// Authentication (getAssertion)
// ---------------------------------------------------------------------------

/// Extension inputs for an authentication ceremony.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionInputs {
    /// PRF extension input — evaluates salts to derive symmetric secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<prf::AuthenticationInput>,

    /// Whether to retrieve a previously stored credBlob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get_cred_blob: Option<bool>,

    /// largeBlob — reads or writes large blob data associated with a credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<large_blob::AuthenticationInput>,
}

/// Extension outputs from an authentication ceremony.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionOutputs {
    /// PRF extension output — derived symmetric secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<prf::AuthenticationOutput>,

    /// credBlob output — the retrieved blob data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<cred_blob::AuthenticationOutput>,

    /// largeBlob output — blob data read or write status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<large_blob::AuthenticationOutput>,
}

// ---------------------------------------------------------------------------
// Authenticator data extension parsing
// ---------------------------------------------------------------------------

/// Parse the extensions CBOR map from raw authenticator data.
///
/// Authenticator data layout:
/// `rpIdHash(32) + flags(1) + counter(4) + [attestedCredData] + [extensions]`
///
/// If the ED flag (0x80) is set, extensions are a CBOR map at the end of
/// the authenticator data, after any attested credential data.
pub(crate) fn parse_auth_data_extensions(auth_data: &[u8]) -> Option<Vec<(String, Value)>> {
    if auth_data.len() < 37 {
        return None;
    }

    let flags = auth_data[32];
    if flags & 0x80 == 0 {
        // ED flag not set
        return None;
    }

    // Skip past attested credential data if present (AT flag = 0x40)
    let mut offset = 37; // rpIdHash(32) + flags(1) + counter(4)
    if flags & 0x40 != 0 {
        // attestedCredData: aaguid(16) + credIdLen(2) + credId + credPubKey
        if auth_data.len() < offset + 18 {
            return None;
        }
        let cred_id_len = u16::from_be_bytes([auth_data[offset + 16], auth_data[offset + 17]]);
        offset += 18 + cred_id_len as usize;

        // Skip the credential public key (CBOR-encoded)
        let key_bytes = &auth_data[offset..];
        let key_len = cbor_item_length(key_bytes)?;
        offset += key_len;
    }

    if offset >= auth_data.len() {
        return None;
    }

    // Decode the extensions CBOR map
    let ext_bytes = &auth_data[offset..];
    let value = cbor::decode(ext_bytes).ok()?;

    let map = value.as_map()?;
    let mut result = Vec::new();
    for (k, v) in map {
        if let Some(key) = k.as_text() {
            result.push((key.to_string(), v.clone()));
        }
    }
    Some(result)
}

/// Determine the byte length of a CBOR item (for skipping over it).
fn cbor_item_length(data: &[u8]) -> Option<usize> {
    let (_value, remaining) = cbor::decode_from(data).ok()?;
    Some(data.len() - remaining.len())
}

// ---------------------------------------------------------------------------
// CBOR input builder
// ---------------------------------------------------------------------------

/// Build a CBOR `Value::Map` from extension entries for the CTAP2 extensions parameter.
pub(crate) fn build_extensions_cbor(entries: Vec<(String, Value)>) -> Option<Value> {
    if entries.is_empty() {
        return None;
    }
    let map: Vec<(Value, Value)> = entries
        .into_iter()
        .map(|(k, v)| (Value::Text(k), v))
        .collect();
    Some(Value::Map(map))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_inputs_json_empty() {
        let inputs = RegistrationExtensionInputs::default();
        let json = serde_json::to_string(&inputs).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_registration_inputs_json_cred_protect() {
        let json = r#"{"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":true}"#;
        let inputs: RegistrationExtensionInputs = serde_json::from_str(json).unwrap();
        let cp = inputs.cred_protect.unwrap();
        assert_eq!(cp.policy, CredProtectPolicy::UserVerificationRequired);
        assert!(cp.enforce);
    }

    #[test]
    fn test_authentication_inputs_json() {
        let json = r#"{"getCredBlob":true}"#;
        let inputs: AuthenticationExtensionInputs = serde_json::from_str(json).unwrap();
        assert_eq!(inputs.get_cred_blob, Some(true));
    }

    #[test]
    fn test_build_extensions_cbor() {
        let entries = vec![
            ("credProtect".into(), Value::Int(3)),
            ("minPinLength".into(), Value::Bool(true)),
        ];
        let cbor = build_extensions_cbor(entries).unwrap();
        let map = cbor.as_map().unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_build_extensions_cbor_empty() {
        assert!(build_extensions_cbor(vec![]).is_none());
    }

    #[test]
    fn test_parse_auth_data_no_extensions() {
        // Minimal auth_data: 37 bytes, no ED flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // UP only
        assert!(parse_auth_data_extensions(&auth_data).is_none());
    }

    #[test]
    fn test_parse_auth_data_with_extensions() {
        // Build auth_data with ED flag and a simple extension map
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x80; // ED flag only (no AT)

        // Append CBOR map: {"credProtect": 3}
        let ext_map = Value::Map(vec![(Value::Text("credProtect".into()), Value::Int(3))]);
        auth_data.extend_from_slice(&cbor::encode(&ext_map));

        let exts = parse_auth_data_extensions(&auth_data).unwrap();
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].0, "credProtect");
        assert_eq!(exts[0].1.as_int(), Some(3));
    }

    #[test]
    fn test_parse_auth_data_with_at_and_ed() {
        // Build auth_data with both AT and ED flags
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0xC0; // AT + ED

        // Attested credential data: aaguid(16) + credIdLen(2) + credId(4)
        auth_data.extend_from_slice(&[0u8; 16]); // aaguid
        auth_data.extend_from_slice(&[0x00, 0x04]); // credIdLen = 4
        auth_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // credId

        // Minimal COSE key (CBOR map)
        let cose_key = Value::Map(vec![
            (Value::Int(1), Value::Int(2)),  // kty: EC2
            (Value::Int(-1), Value::Int(1)), // crv: P-256
        ]);
        auth_data.extend_from_slice(&cbor::encode(&cose_key));

        // Extension map
        let ext_map = Value::Map(vec![(Value::Text("minPinLength".into()), Value::Int(8))]);
        auth_data.extend_from_slice(&cbor::encode(&ext_map));

        let exts = parse_auth_data_extensions(&auth_data).unwrap();
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].0, "minPinLength");
        assert_eq!(exts[0].1.as_int(), Some(8));
    }

    #[test]
    fn test_outputs_default_empty() {
        let out = RegistrationExtensionOutputs::default();
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(json, "{}");
    }
}
