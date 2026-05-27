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

//! Credential Blob extension (credBlob).
//!
//! Stores and retrieves small data blobs with credentials.

use base64::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cbor::Value;

/// CTAP2 extension identifier for credBlob.
pub const EXTENSION_ID: &str = "credBlob";

/// Registration input for credBlob — the blob data to store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInput {
    /// The blob data to store with the credential (base64url-encoded in JSON).
    #[serde(
        rename = "credBlob",
        serialize_with = "b64_ser",
        deserialize_with = "b64_de"
    )]
    /// The blob data to store with the credential (base64url-encoded in JSON).
    pub blob: Vec<u8>,
}

/// Registration output for credBlob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutput {
    /// Whether the authenticator successfully stored the blob.
    #[serde(rename = "credBlob")]
    pub stored: bool,
}

/// Authentication output for credBlob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOutput {
    /// The blob data retrieved from the credential (base64url-encoded in JSON).
    #[serde(
        rename = "credBlob",
        serialize_with = "b64_ser",
        deserialize_with = "b64_de"
    )]
    /// The blob data retrieved from the credential (base64url-encoded in JSON).
    pub blob: Vec<u8>,
}

// CBOR helpers

pub(crate) fn make_credential_to_cbor(blob: &[u8]) -> (String, Value) {
    (EXTENSION_ID.into(), Value::Bytes(blob.to_vec()))
}

pub(crate) fn get_assertion_to_cbor() -> (String, Value) {
    (EXTENSION_ID.into(), Value::Bool(true))
}

pub(crate) fn make_credential_from_cbor(value: &Value) -> Option<bool> {
    value.as_bool()
}

pub(crate) fn get_assertion_from_cbor(value: &Value) -> Option<Vec<u8>> {
    value.as_bytes().map(|b| b.to_vec())
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
};

/// The credBlob extension definition.
pub struct CredBlobExtension;

impl Ctap2Extension for CredBlobExtension {
    fn make_credential(
        &self,
        info: &Info,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<Option<Box<dyn RegistrationProcessor>>, String> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        let blob = match &ext.cred_blob {
            Some(cb) => cb.blob.clone(),
            None => return Ok(None),
        };
        if !info.extensions.iter().any(|e| e == EXTENSION_ID) {
            return Ok(None);
        }
        if let Some(max_len) = info.max_cred_blob_length.filter(|&max| blob.len() > max) {
            return Err(format!("credBlob too large: {} > {}", blob.len(), max_len));
        }
        Ok(Some(Box::new(CredBlobRegistrationProcessor { blob })))
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
        if ext.get_cred_blob != Some(true) {
            return Ok(None);
        }
        if !info.extensions.iter().any(|e| e == EXTENSION_ID) {
            return Ok(None);
        }
        Ok(Some(Box::new(CredBlobAuthenticationProcessor)))
    }
}

struct CredBlobRegistrationProcessor {
    blob: Vec<u8>,
}

impl RegistrationProcessor for CredBlobRegistrationProcessor {
    fn prepare_inputs(&self, _ctx: &mut ExtensionContext) -> Result<Vec<(String, Value)>, String> {
        Ok(vec![make_credential_to_cbor(&self.blob)])
    }

    fn prepare_outputs(&self, ctx: &OutputContext<'_>, outputs: &mut RegistrationExtensionOutputs) {
        if let Some((_, val)) = ctx
            .auth_data_extensions
            .and_then(|exts| exts.iter().find(|(k, _)| k == EXTENSION_ID))
            && let Some(stored) = make_credential_from_cbor(val)
        {
            outputs.cred_blob = Some(RegistrationOutput { stored });
        }
    }
}

struct CredBlobAuthenticationProcessor;

impl AuthenticationProcessor for CredBlobAuthenticationProcessor {
    fn prepare_inputs(
        &self,
        _selected_cred_id: Option<&[u8]>,
        _ctx: &mut ExtensionContext,
    ) -> Result<Vec<(String, Value)>, String> {
        Ok(vec![get_assertion_to_cbor()])
    }

    fn prepare_outputs(
        &self,
        ctx: &OutputContext<'_>,
        outputs: &mut AuthenticationExtensionOutputs,
    ) {
        if let Some((_, val)) = ctx
            .auth_data_extensions
            .and_then(|exts| exts.iter().find(|(k, _)| k == EXTENSION_ID))
            && let Some(blob) = get_assertion_from_cbor(val)
        {
            outputs.cred_blob = Some(AuthenticationOutput { blob });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor_make_credential() {
        let blob = vec![1, 2, 3, 4];
        let (key, val) = make_credential_to_cbor(&blob);
        assert_eq!(key, "credBlob");
        assert_eq!(val.as_bytes(), Some(blob.as_slice()));
    }

    #[test]
    fn test_cbor_get_assertion() {
        let (key, val) = get_assertion_to_cbor();
        assert_eq!(key, "credBlob");
        assert_eq!(val.as_bool(), Some(true));
    }
}
