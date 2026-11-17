// Copyright 2026 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Signing extension (previewSign) version 4.
//!
//! Allows a Relying Party to sign arbitrary data using an asymmetric key pair
//! associated with a credential but different from the credential key pair.
//! Registration creates the signing key pair and emits the signing public key;
//! authentication ceremonies use the signing private key to sign arbitrary data.

use base64::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cbor::Value;

/// CTAP2 extension identifier for previewSign.
pub const EXTENSION_ID: &str = "previewSign";

// CBOR map keys for authenticator extension input/output (integer aliases from CDDL)
const KEY_KH: i64 = 2;
const KEY_ALG: i64 = 3;
const KEY_FLAGS: i64 = 4;
const KEY_TBS: i64 = 6;
const KEY_ATT_OBJ: i64 = 7;
#[allow(dead_code)]
const KEY_ARGS: i64 = 7; // same as ATT_OBJ but used in authentication context

/// Flags for signing key pair user presence/verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignFlags {
    /// Signatures do not require user presence or user verification.
    Unattended = 0b000,
    /// Signatures require user presence but not user verification.
    RequireUp = 0b001,
    /// Signatures require user presence and user verification.
    RequireUv = 0b101,
}

// ---------------------------------------------------------------------------
// Registration types
// ---------------------------------------------------------------------------

/// Registration input for previewSign — requests key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationInput {
    /// Key generation parameters.
    pub generate_key: GenerateKeyInput,
}

/// Parameters for signing key pair generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyInput {
    /// Acceptable signature algorithms, ordered most preferred first.
    pub algorithms: Vec<i64>,
}

/// Registration output for previewSign.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationOutput {
    /// The generated signing key pair information.
    pub generated_key: GeneratedKey,
}

/// Information about the generated signing key pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedKey {
    /// The key handle for the signing private key (base64url in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub key_handle: Vec<u8>,
    /// The signing public key in COSE_Key format (base64url in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub public_key: Vec<u8>,
    /// The COSE algorithm identifier chosen by the authenticator.
    pub algorithm: i64,
    /// Attestation object for the signing key pair (base64url in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub attestation_object: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Authentication types
// ---------------------------------------------------------------------------

/// Authentication input for previewSign — requests signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInput {
    /// Per-credential signing inputs, keyed by base64url credential ID.
    pub sign_by_credential: std::collections::HashMap<String, SignInput>,
}

/// Signing input for a specific credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInput {
    /// The key handle for the signing private key (base64url in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub key_handle: Vec<u8>,
    /// Data to be signed (base64url in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub tbs: Vec<u8>,
    /// Optional additional arguments to the signing algorithm (base64url CBOR in JSON).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "b64_opt_ser",
        deserialize_with = "b64_opt_de"
    )]
    pub additional_args: Option<Vec<u8>>,
}

/// Authentication output for previewSign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOutput {
    /// The generated signature (base64url in JSON).
    #[serde(serialize_with = "b64_ser", deserialize_with = "b64_de")]
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// CBOR building
// ---------------------------------------------------------------------------

/// Build the CBOR input for previewSign during makeCredential.
///
/// Authenticator extension input (registration):
/// ```text
/// { 3: [alg, ...], 4: flags }
/// ```
pub(crate) fn make_credential_to_cbor(
    input: &RegistrationInput,
    user_verification_required: bool,
) -> (String, Value) {
    let alg_array = Value::Array(
        input
            .generate_key
            .algorithms
            .iter()
            .map(|&a| Value::Int(a))
            .collect(),
    );
    let flags: i64 = if user_verification_required {
        0b101
    } else {
        0b001
    };

    let map = Value::Map(vec![
        (Value::Int(KEY_ALG), alg_array),
        (Value::Int(KEY_FLAGS), Value::Int(flags)),
    ]);

    (EXTENSION_ID.into(), map)
}

/// Build the CBOR input for previewSign during getAssertion.
///
/// Authenticator extension input (authentication):
/// ```text
/// { 2: kh, 6: tbs, ?7: args }
/// ```
pub(crate) fn get_assertion_to_cbor(sign_input: &SignInput) -> (String, Value) {
    let mut entries = vec![
        (
            Value::Int(KEY_KH),
            Value::Bytes(sign_input.key_handle.clone()),
        ),
        (Value::Int(KEY_TBS), Value::Bytes(sign_input.tbs.clone())),
    ];

    if let Some(ref args) = sign_input.additional_args {
        entries.push((Value::Int(KEY_ARGS), Value::Bytes(args.clone())));
    }

    (EXTENSION_ID.into(), Value::Map(entries))
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Parse previewSign output from makeCredential authenticator data extensions
/// and unsigned extension outputs.
///
/// From auth_data extensions: `"previewSign" -> { 3: alg }`
/// From unsigned extension outputs: `"previewSign" -> { 7: att-obj }`
///
/// The att-obj is a CBOR byte string containing a CBOR map:
/// `{ 1: fmt, 2: authData, 3: attStmt }`
///
/// The inner authData contains attested credential data with:
/// - credentialId = key handle
/// - credentialPublicKey = signing public key
pub(crate) fn make_credential_from_outputs(
    auth_data_extensions: &[(String, Value)],
    unsigned_ext_outputs: Option<&Value>,
) -> Result<Option<RegistrationOutput>, String> {
    // Get algorithm from signed extension output in auth_data
    let sign_ext = auth_data_extensions
        .iter()
        .find(|(k, _)| k == EXTENSION_ID)
        .map(|(_, v)| v);

    let Some(sign_ext_map) = sign_ext else {
        return Ok(None);
    };

    let algorithm = sign_ext_map
        .map_get_int(KEY_ALG)
        .and_then(|v| v.as_int())
        .ok_or("previewSign: missing alg in extension output")?;

    // Get att-obj from unsigned extension outputs
    let unsigned_sign = unsigned_ext_outputs
        .and_then(|v| v.as_map())
        .and_then(|map| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(EXTENSION_ID))
                .map(|(_, v)| v)
        });

    let Some(unsigned_map) = unsigned_sign else {
        return Err("previewSign: missing unsigned extension outputs".into());
    };

    let att_obj_bytes = unsigned_map
        .map_get_int(KEY_ATT_OBJ)
        .and_then(|v| v.as_bytes())
        .ok_or("previewSign: missing att-obj in unsigned outputs")?;

    // Parse the inner attestation object: { 1: fmt, 2: authData, 3: attStmt }
    let inner_att_obj = crate::cbor::decode(att_obj_bytes)
        .map_err(|e| format!("previewSign: failed to decode att-obj: {e}"))?;

    let inner_auth_data = inner_att_obj
        .map_get_int(2)
        .and_then(|v| v.as_bytes())
        .ok_or("previewSign: missing authData in att-obj")?;

    // Extract credentialId (key handle) and credentialPublicKey from inner authData
    let (key_handle, public_key) = extract_attested_credential_data(inner_auth_data)?;

    // Reconstruct the attestation object in standard WebAuthn format:
    // { "fmt": ..., "authData": ..., "attStmt": ... }
    let fmt = inner_att_obj
        .map_get_int(1)
        .cloned()
        .unwrap_or(Value::Text("none".into()));
    let att_stmt = inner_att_obj
        .map_get_int(3)
        .cloned()
        .unwrap_or(Value::Map(Vec::new()));

    let att_obj_webauthn = Value::Map(vec![
        (Value::Text("fmt".into()), fmt),
        (
            Value::Text("authData".into()),
            Value::Bytes(inner_auth_data.to_vec()),
        ),
        (Value::Text("attStmt".into()), att_stmt),
    ]);
    let attestation_object = crate::cbor::encode(&att_obj_webauthn);

    Ok(Some(RegistrationOutput {
        generated_key: GeneratedKey {
            key_handle,
            public_key,
            algorithm,
            attestation_object,
        },
    }))
}

/// Parse previewSign output from getAssertion authenticator data extensions.
///
/// From auth_data extensions: `"previewSign" -> { 6: sig }`
pub(crate) fn get_assertion_from_auth_data(
    extensions: &[(String, Value)],
) -> Result<Option<AuthenticationOutput>, String> {
    let sign_ext = extensions
        .iter()
        .find(|(k, _)| k == EXTENSION_ID)
        .map(|(_, v)| v);

    let Some(sign_ext_map) = sign_ext else {
        return Ok(None);
    };

    // sig is at key 6 in the authentication output CDDL
    let sig = sign_ext_map
        .map_get_int(6)
        .and_then(|v| v.as_bytes())
        .ok_or("previewSign: missing sig in extension output")?;

    Ok(Some(AuthenticationOutput {
        signature: sig.to_vec(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract credentialId and credentialPublicKey from attested credential data
/// within an authenticator data structure.
///
/// AuthData layout: rpIdHash(32) + flags(1) + counter(4) + attestedCredData
/// AttCredData: aaguid(16) + credIdLen(2) + credId(credIdLen) + credPubKey(CBOR)
fn extract_attested_credential_data(auth_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let offset = 37; // rpIdHash(32) + flags(1) + counter(4)
    if auth_data.len() < offset + 18 {
        return Err("previewSign: inner authData too short for attested cred data".into());
    }

    let cred_id_len = u16::from_be_bytes([auth_data[offset + 16], auth_data[offset + 17]]) as usize;
    let cred_id_start = offset + 18;
    let cred_id_end = cred_id_start + cred_id_len;

    if auth_data.len() < cred_id_end {
        return Err("previewSign: inner authData too short for credentialId".into());
    }

    let key_handle = auth_data[cred_id_start..cred_id_end].to_vec();

    // The credential public key is CBOR-encoded starting after the credential ID
    let pub_key_bytes = &auth_data[cred_id_end..];
    // We need to figure out the length of the CBOR item to extract just the key
    let (_decoded, remaining) = crate::cbor::decode_from(pub_key_bytes)
        .map_err(|e| format!("previewSign: failed to decode public key CBOR: {e}"))?;
    let pub_key_len = pub_key_bytes.len() - remaining.len();
    let public_key = pub_key_bytes[..pub_key_len].to_vec();

    Ok((key_handle, public_key))
}

// ---------------------------------------------------------------------------
// Extension processor implementation
// ---------------------------------------------------------------------------

use crate::ctap2::Info;
use crate::webauthn::extensions::{
    AuthenticationExtensionOutputs, AuthenticationProcessor, Ctap2Extension, ExtensionContext,
    OutputContext, RegistrationExtensionOutputs, RegistrationProcessor,
};
use crate::webauthn::types::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
};

/// The previewSign extension definition.
pub struct PreviewSignExtension;

impl Ctap2Extension for PreviewSignExtension {
    fn make_credential(
        &self,
        info: &Info,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<Option<Box<dyn RegistrationProcessor>>, String> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        let sign_input = match &ext.preview_sign {
            Some(si) => si.clone(),
            None => return Ok(None),
        };
        if !info.extensions.iter().any(|e| e == EXTENSION_ID) {
            return Ok(None);
        }
        let uv_required = options.authenticator_selection.as_ref().is_some_and(|sel| {
            sel.user_verification == Some(UserVerificationRequirement::Required)
        });
        Ok(Some(Box::new(PreviewSignRegistrationProcessor {
            input: sign_input,
            uv_required,
        })))
    }

    fn get_assertion(
        &self,
        info: &Info,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<Option<Box<dyn AuthenticationProcessor>>, String> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        let sign_input = match &ext.preview_sign {
            Some(si) => si.clone(),
            None => return Ok(None),
        };
        if !info.extensions.iter().any(|e| e == EXTENSION_ID) {
            return Ok(None);
        }
        Ok(Some(Box::new(PreviewSignAuthenticationProcessor {
            input: sign_input,
        })))
    }
}

struct PreviewSignRegistrationProcessor {
    input: RegistrationInput,
    uv_required: bool,
}

impl RegistrationProcessor for PreviewSignRegistrationProcessor {
    fn prepare_inputs(&self, _ctx: &mut ExtensionContext) -> Result<Vec<(String, Value)>, String> {
        Ok(vec![make_credential_to_cbor(&self.input, self.uv_required)])
    }

    fn prepare_outputs(&self, ctx: &OutputContext<'_>, outputs: &mut RegistrationExtensionOutputs) {
        if let Some(exts) = ctx.auth_data_extensions {
            match make_credential_from_outputs(exts, ctx.unsigned_extension_outputs) {
                Ok(Some(sign_out)) => {
                    outputs.preview_sign = Some(sign_out);
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!("previewSign output parse error: {e}");
                }
            }
        }
    }
}

struct PreviewSignAuthenticationProcessor {
    input: AuthenticationInput,
}

impl AuthenticationProcessor for PreviewSignAuthenticationProcessor {
    fn prepare_inputs(
        &self,
        selected_cred_id: Option<&[u8]>,
        _ctx: &mut ExtensionContext,
    ) -> Result<Vec<(String, Value)>, String> {
        let Some(cred_id) = selected_cred_id else {
            return Ok(vec![]);
        };
        let cred_id_b64 = BASE64_URL_SAFE_NO_PAD.encode(cred_id);
        if let Some(si) = self.input.sign_by_credential.get(&cred_id_b64) {
            Ok(vec![get_assertion_to_cbor(si)])
        } else {
            Ok(vec![])
        }
    }

    fn prepare_outputs(
        &self,
        ctx: &OutputContext<'_>,
        outputs: &mut AuthenticationExtensionOutputs,
    ) {
        if let Some(exts) = ctx.auth_data_extensions {
            match get_assertion_from_auth_data(exts) {
                Ok(Some(sign_out)) => {
                    outputs.preview_sign = Some(sign_out);
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!("previewSign output parse error: {e}");
                }
            }
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_credential_cbor_up() {
        let input = RegistrationInput {
            generate_key: GenerateKeyInput {
                algorithms: vec![-65539],
            },
        };
        let (key, val) = make_credential_to_cbor(&input, false);
        assert_eq!(key, "previewSign");
        let map = val.as_map().unwrap();
        // alg (key 3) should be [-65539]
        let alg = map
            .iter()
            .find(|(k, _)| k.as_int() == Some(3))
            .unwrap()
            .1
            .clone();
        let arr = alg.as_array().unwrap();
        assert_eq!(arr[0].as_int(), Some(-65539));
        // flags (key 4) should be 1 (require-up)
        let flags = map
            .iter()
            .find(|(k, _)| k.as_int() == Some(4))
            .unwrap()
            .1
            .clone();
        assert_eq!(flags.as_int(), Some(0b001));
    }

    #[test]
    fn test_make_credential_cbor_uv() {
        let input = RegistrationInput {
            generate_key: GenerateKeyInput {
                algorithms: vec![-7, -65539],
            },
        };
        let (key, val) = make_credential_to_cbor(&input, true);
        assert_eq!(key, "previewSign");
        let map = val.as_map().unwrap();
        // flags should be 5 (require-uv)
        let flags = map
            .iter()
            .find(|(k, _)| k.as_int() == Some(4))
            .unwrap()
            .1
            .clone();
        assert_eq!(flags.as_int(), Some(0b101));
    }

    #[test]
    fn test_get_assertion_cbor() {
        let input = SignInput {
            key_handle: vec![1, 2, 3],
            tbs: vec![4, 5, 6],
            additional_args: None,
        };
        let (key, val) = get_assertion_to_cbor(&input);
        assert_eq!(key, "previewSign");
        let map = val.as_map().unwrap();
        // kh (key 2)
        let kh = map
            .iter()
            .find(|(k, _)| k.as_int() == Some(2))
            .unwrap()
            .1
            .clone();
        assert_eq!(kh.as_bytes(), Some(&[1, 2, 3][..]));
        // tbs (key 6)
        let tbs = map
            .iter()
            .find(|(k, _)| k.as_int() == Some(6))
            .unwrap()
            .1
            .clone();
        assert_eq!(tbs.as_bytes(), Some(&[4, 5, 6][..]));
        // No args key
        assert!(map.iter().find(|(k, _)| k.as_int() == Some(7)).is_none());
    }

    #[test]
    fn test_get_assertion_cbor_with_args() {
        let input = SignInput {
            key_handle: vec![1],
            tbs: vec![2],
            additional_args: Some(vec![0xA0]), // empty CBOR map
        };
        let (_, val) = get_assertion_to_cbor(&input);
        let map = val.as_map().unwrap();
        let args = map
            .iter()
            .find(|(k, _)| k.as_int() == Some(7))
            .unwrap()
            .1
            .clone();
        assert_eq!(args.as_bytes(), Some(&[0xA0][..]));
    }
}
