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

//! PRF extension (Pseudo-Random Function).
//!
//! WebAuthn wrapper around the CTAP2 `hmac-secret` extension. Derives
//! symmetric secrets from credentials using HMAC-SHA-256 with user-provided
//! inputs, hashed through `SHA-256("WebAuthn PRF" || 0x00 || input)`.

use std::collections::HashMap;

use base64::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::ctap2::PinProtocol;

const HMAC_SECRET_ID: &str = "hmac-secret";
const HMAC_SECRET_MC_ID: &str = "hmac-secret-mc";

/// PRF evaluation inputs — first and optional second.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrfEval {
    /// First PRF input (base64url-encoded in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub first: Vec<u8>,
    /// Optional second PRF input (base64url-encoded in JSON).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "b64_opt_ser",
        deserialize_with = "b64_opt_de"
    )]
    /// Optional second input value for the PRF (base64url-encoded in JSON).
    pub second: Option<Vec<u8>>,
}

/// Registration input for PRF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInput {
    /// Optional evaluation inputs to compute PRF results during registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<PrfEval>,
}

/// Registration output for PRF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutput {
    /// Whether the authenticator supports PRF (hmac-secret) for this credential.
    pub enabled: bool,
    /// PRF evaluation results, if `eval` was provided in the input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<PrfResults>,
}

/// Authentication input for PRF.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInput {
    /// Default evaluation inputs applied when no credential-specific eval matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<PrfEval>,
    /// Per-credential evaluation inputs, keyed by base64url credential ID.
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "eval_by_cred_ser",
        deserialize_with = "eval_by_cred_de"
    )]
    /// Per-credential evaluation inputs, keyed by credential ID.
    pub eval_by_credential: HashMap<Vec<u8>, PrfEval>,
}

/// Authentication output for PRF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOutput {
    /// The derived PRF secrets.
    pub results: PrfResults,
}

/// Derived PRF results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrfResults {
    /// First 32-byte derived secret (base64url-encoded in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub first: Vec<u8>,
    /// Optional second 32-byte derived secret (base64url-encoded in JSON).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "b64_opt_ser",
        deserialize_with = "b64_opt_de"
    )]
    /// Optional second 32-byte derived secret (base64url-encoded in JSON).
    pub second: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Salt transformation: WebAuthn PRF input → CTAP2 hmac-secret salt
// ---------------------------------------------------------------------------

/// Hash a PRF input into a 32-byte hmac-secret salt.
fn prf_salt(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"WebAuthn PRF");
    hasher.update(b"\x00");
    hasher.update(input);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Shared secret state for hmac-secret crypto
// ---------------------------------------------------------------------------

/// Holds the ECDH key agreement state needed for hmac-secret.
/// Created by performing key agreement with the authenticator.
pub(crate) struct HmacSecretState {
    /// The platform's COSE public key (sent to the authenticator).
    pub key_agreement: Value,
    /// The derived shared secret (used for encrypt/decrypt).
    shared_secret: Zeroizing<Vec<u8>>,
    /// The PIN protocol used for the key agreement.
    pub protocol: PinProtocol,
}

impl HmacSecretState {
    /// Create state by performing ECDH key agreement.
    pub fn new(protocol: PinProtocol, authenticator_key: &Value) -> Result<Self, String> {
        let (platform_key, shared_secret) = protocol.encapsulate(authenticator_key)?;
        Ok(Self {
            key_agreement: platform_key,
            shared_secret: Zeroizing::new(shared_secret),
            protocol,
        })
    }

    /// Encrypt salts and compute authentication tag.
    pub fn encrypt_salts(&self, salts: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let enc = self.protocol.encrypt(&self.shared_secret, salts);
        let auth = self.protocol.authenticate(&self.shared_secret, &enc);
        (enc, auth)
    }

    /// Decrypt the authenticator's response.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        self.protocol
            .decrypt(&self.shared_secret, ciphertext)
            .map(Zeroizing::new)
    }
}

// ---------------------------------------------------------------------------
// CBOR building
// ---------------------------------------------------------------------------

/// Build the CBOR input for hmac-secret (enable only, for makeCredential).
pub(crate) fn make_credential_enable_cbor() -> (String, Value) {
    (HMAC_SECRET_ID.into(), Value::Bool(true))
}

/// Build the CBOR input for hmac-secret-mc (makeCredential with salts).
pub(crate) fn make_credential_salts_cbor(
    eval: &PrfEval,
    state: &HmacSecretState,
) -> Vec<(String, Value)> {
    let salt1 = prf_salt(&eval.first);
    let salt2_data = eval.second.as_ref().map(|s| prf_salt(s));

    let mut salts = salt1;
    if let Some(s2) = &salt2_data {
        salts.extend_from_slice(s2);
    }

    let (enc, auth) = state.encrypt_salts(&salts);

    let mc_map = Value::Map(vec![
        (Value::Int(1), state.key_agreement.clone()),
        (Value::Int(2), Value::Bytes(enc)),
        (Value::Int(3), Value::Bytes(auth)),
        (Value::Int(4), Value::Int(state.protocol.version() as i64)),
    ]);

    vec![
        (HMAC_SECRET_ID.into(), Value::Bool(true)),
        (HMAC_SECRET_MC_ID.into(), mc_map),
    ]
}

/// Build the CBOR input for hmac-secret getAssertion.
pub(crate) fn get_assertion_cbor(eval: &PrfEval, state: &HmacSecretState) -> (String, Value) {
    let salt1 = prf_salt(&eval.first);
    let salt2_data = eval.second.as_ref().map(|s| prf_salt(s));

    let mut salts = salt1;
    if let Some(s2) = &salt2_data {
        salts.extend_from_slice(s2);
    }

    let (enc, auth) = state.encrypt_salts(&salts);

    let map = Value::Map(vec![
        (Value::Int(1), state.key_agreement.clone()),
        (Value::Int(2), Value::Bytes(enc)),
        (Value::Int(3), Value::Bytes(auth)),
        (Value::Int(4), Value::Int(state.protocol.version() as i64)),
    ]);

    (HMAC_SECRET_ID.into(), map)
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Parse hmac-secret output from makeCredential authenticator data extensions.
pub(crate) fn make_credential_from_auth_data(
    extensions: &[(String, Value)],
    state: Option<&HmacSecretState>,
) -> Result<Option<RegistrationOutput>, String> {
    // Check hmac-secret-mc first (returns encrypted secrets)
    let mc_output = extensions
        .iter()
        .find(|(k, _)| k == HMAC_SECRET_MC_ID)
        .map(|(_, v)| v);

    if let (Some(ciphertext), Some(state)) = (mc_output, state) {
        let ct = ciphertext
            .as_bytes()
            .ok_or("hmac-secret-mc output is not bytes")?;
        let decrypted = state.decrypt(ct)?;
        let results = split_secrets(&decrypted)?;
        return Ok(Some(RegistrationOutput {
            enabled: true,
            results: Some(results),
        }));
    }

    // Fall back to hmac-secret (just a boolean)
    let hs_output = extensions
        .iter()
        .find(|(k, _)| k == HMAC_SECRET_ID)
        .map(|(_, v)| v);

    if let Some(val) = hs_output
        && val.as_bool() == Some(true)
    {
        return Ok(Some(RegistrationOutput {
            enabled: true,
            results: None,
        }));
    }

    Ok(None)
}

/// Parse hmac-secret output from getAssertion authenticator data extensions.
pub(crate) fn get_assertion_from_auth_data(
    extensions: &[(String, Value)],
    state: &HmacSecretState,
) -> Result<Option<PrfResults>, String> {
    let output = extensions
        .iter()
        .find(|(k, _)| k == HMAC_SECRET_ID)
        .map(|(_, v)| v);

    let Some(ciphertext) = output else {
        return Ok(None);
    };

    let ct = ciphertext
        .as_bytes()
        .ok_or("hmac-secret output is not bytes")?;
    let decrypted = state.decrypt(ct)?;
    split_secrets(&decrypted).map(Some)
}

/// Split decrypted secrets into first (32 bytes) and optional second (32 bytes).
fn split_secrets(data: &[u8]) -> Result<PrfResults, String> {
    if data.len() != 32 && data.len() != 64 {
        return Err(format!(
            "hmac-secret output must be 32 or 64 bytes, got {}",
            data.len()
        ));
    }
    let first = data[..32].to_vec();
    let second = if data.len() == 64 {
        Some(data[32..].to_vec())
    } else {
        None
    };
    Ok(PrfResults { first, second })
}

/// Select the PRF eval to use for a given credential ID.
pub(crate) fn select_eval<'a>(
    input: &'a AuthenticationInput,
    credential_id: Option<&[u8]>,
) -> Option<&'a PrfEval> {
    if let Some(cred_id) = credential_id
        && let Some(eval) = input.eval_by_credential.get(cred_id)
    {
        return Some(eval);
    }
    input.eval.as_ref()
}

// ---------------------------------------------------------------------------
// Serde helpers for base64url byte fields
// ---------------------------------------------------------------------------

fn b64_ser<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

fn b64_de<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    BASE64_URL_SAFE_NO_PAD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

fn b64_opt_ser<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(b) => s.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(b)),
        None => s.serialize_none(),
    }
}

fn b64_opt_de<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let opt = Option::<String>::deserialize(d)?;
    match opt {
        Some(s) => BASE64_URL_SAFE_NO_PAD
            .decode(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

fn eval_by_cred_ser<S: Serializer>(
    map: &HashMap<Vec<u8>, PrfEval>,
    s: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut m = s.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        m.serialize_entry(&BASE64_URL_SAFE_NO_PAD.encode(k), v)?;
    }
    m.end()
}

fn eval_by_cred_de<'de, D: Deserializer<'de>>(d: D) -> Result<HashMap<Vec<u8>, PrfEval>, D::Error> {
    let string_map: HashMap<String, PrfEval> = HashMap::deserialize(d)?;
    string_map
        .into_iter()
        .map(|(k, v)| {
            BASE64_URL_SAFE_NO_PAD
                .decode(&k)
                .map(|decoded| (decoded, v))
                .map_err(serde::de::Error::custom)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_salt() {
        let input = b"test input";
        let salt = prf_salt(input);
        assert_eq!(salt.len(), 32);

        // Verify deterministic
        assert_eq!(salt, prf_salt(input));

        // Different inputs produce different salts
        let salt2 = prf_salt(b"other input");
        assert_ne!(salt, salt2);
    }

    #[test]
    fn test_split_secrets_32() {
        let data = vec![0x42u8; 32];
        let result = split_secrets(&data).unwrap();
        assert_eq!(result.first.len(), 32);
        assert!(result.second.is_none());
    }

    #[test]
    fn test_split_secrets_64() {
        let mut data = vec![0x42u8; 32];
        data.extend_from_slice(&[0x43u8; 32]);
        let result = split_secrets(&data).unwrap();
        assert_eq!(result.first, vec![0x42u8; 32]);
        assert_eq!(result.second.unwrap(), vec![0x43u8; 32]);
    }

    #[test]
    fn test_split_secrets_invalid() {
        assert!(split_secrets(&[0u8; 16]).is_err());
        assert!(split_secrets(&[0u8; 48]).is_err());
    }

    #[test]
    fn test_registration_input_json() {
        let input = RegistrationInput { eval: None };
        let json = serde_json::to_string(&input).unwrap();
        let parsed: RegistrationInput = serde_json::from_str(&json).unwrap();
        assert!(parsed.eval.is_none());
    }

    #[test]
    fn test_select_eval_default() {
        let eval = PrfEval {
            first: vec![1, 2, 3],
            second: None,
        };
        let input = AuthenticationInput {
            eval: Some(eval),
            eval_by_credential: HashMap::new(),
        };
        let selected = select_eval(&input, None);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().first, vec![1, 2, 3]);
    }

    #[test]
    fn test_select_eval_by_credential() {
        let default_eval = PrfEval {
            first: vec![1, 2, 3],
            second: None,
        };
        let cred_eval = PrfEval {
            first: vec![4, 5, 6],
            second: None,
        };
        let cred_id = vec![0xAA, 0xBB];
        let mut by_cred = HashMap::new();
        by_cred.insert(cred_id.clone(), cred_eval);

        let input = AuthenticationInput {
            eval: Some(default_eval),
            eval_by_credential: by_cred,
        };

        // Matching credential → use credential-specific eval
        let selected = select_eval(&input, Some(&cred_id));
        assert_eq!(selected.unwrap().first, vec![4, 5, 6]);

        // Non-matching credential → fall back to default
        let selected = select_eval(&input, Some(&[0xCC]));
        assert_eq!(selected.unwrap().first, vec![1, 2, 3]);
    }
}
