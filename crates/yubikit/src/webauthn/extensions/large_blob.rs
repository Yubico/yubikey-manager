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

//! Large Blob extension (largeBlob).
//!
//! Associates large data blobs with credentials. During registration,
//! requests a `largeBlobKey` from the authenticator. During authentication,
//! uses the key to read/write blobs via the Large Blobs API.

use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::cbor::Value;

const LARGE_BLOB_KEY_EXT_ID: &str = "largeBlobKey";

/// Level of large blob support requested during registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LargeBlobSupport {
    /// The RP requires large blob support; registration fails without it.
    Required,
    /// The RP prefers large blob support but does not require it.
    Preferred,
}

/// Registration input for largeBlob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInput {
    /// Level of large blob support requested.
    pub support: LargeBlobSupport,
}

/// Registration output for largeBlob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutput {
    /// Whether the authenticator supports large blob storage for this credential.
    pub supported: bool,
}

/// Authentication input for largeBlob.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInput {
    /// Set to `true` to read the large blob associated with the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    /// Data to write as the large blob (mutually exclusive with `read`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "b64_opt_ser",
        deserialize_with = "b64_opt_de"
    )]
    /// Data to write as the large blob (base64url-encoded in JSON).
    pub write: Option<Vec<u8>>,
}

impl AuthenticationInput {
    /// Create an input that reads the large blob.
    pub fn read() -> Self {
        Self {
            read: Some(true),
            write: None,
        }
    }

    /// Create an input that writes `data` as the large blob.
    pub fn write(data: Vec<u8>) -> Self {
        Self {
            read: None,
            write: Some(data),
        }
    }
}

/// Authentication output for largeBlob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOutput {
    /// The blob data read from the authenticator, if a read was requested.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "b64_opt_ser",
        deserialize_with = "b64_opt_de"
    )]
    /// The blob data read from the authenticator, if a read was requested.
    pub blob: Option<Vec<u8>>,
    /// Whether the write operation succeeded, if a write was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
}

// CBOR helpers — sends the `largeBlobKey` extension to the authenticator

pub(crate) fn to_cbor() -> (String, Value) {
    (LARGE_BLOB_KEY_EXT_ID.into(), Value::Bool(true))
}

// ---------------------------------------------------------------------------
// Extension processor implementation
// ---------------------------------------------------------------------------

use crate::ctap2::{Info, Permissions};
use crate::webauthn::extensions::{
    AuthenticationExtensionOutputs, AuthenticationProcessor, Ctap2Extension, ExtensionContext,
    OutputContext, RegistrationExtensionOutputs, RegistrationProcessor,
};
use crate::webauthn::types::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};

/// The largeBlob extension definition.
pub struct LargeBlobExtension;

impl Ctap2Extension for LargeBlobExtension {
    fn make_credential(
        &self,
        info: &Info,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<Option<Box<dyn RegistrationProcessor>>, String> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        let lb = match &ext.large_blob {
            Some(lb) => lb,
            None => return Ok(None),
        };
        let supported = info.extensions.iter().any(|e| e == LARGE_BLOB_KEY_EXT_ID);
        if lb.support == LargeBlobSupport::Required && !supported {
            return Err("largeBlob not supported by authenticator".into());
        }
        if !supported {
            return Ok(None);
        }
        Ok(Some(Box::new(LargeBlobRegistrationProcessor)))
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
        let lb = match &ext.large_blob {
            Some(lb) => lb,
            None => return Ok(None),
        };
        if !info.extensions.iter().any(|e| e == LARGE_BLOB_KEY_EXT_ID) {
            return Ok(None);
        }
        let needs_write = lb.write.is_some();
        Ok(Some(Box::new(LargeBlobAuthenticationProcessor {
            needs_write,
        })))
    }
}

struct LargeBlobRegistrationProcessor;

impl RegistrationProcessor for LargeBlobRegistrationProcessor {
    fn prepare_inputs(&self, _ctx: &mut ExtensionContext) -> Result<Vec<(String, Value)>, String> {
        Ok(vec![to_cbor()])
    }

    fn prepare_outputs(&self, ctx: &OutputContext<'_>, outputs: &mut RegistrationExtensionOutputs) {
        outputs.large_blob = Some(RegistrationOutput {
            supported: ctx.has_large_blob_key,
        });
    }
}

struct LargeBlobAuthenticationProcessor {
    needs_write: bool,
}

impl AuthenticationProcessor for LargeBlobAuthenticationProcessor {
    fn permissions(&self) -> Permissions {
        if self.needs_write {
            Permissions::LARGE_BLOB_WRITE
        } else {
            Permissions::new(0)
        }
    }

    fn prepare_inputs(
        &self,
        _selected_cred_id: Option<&[u8]>,
        _ctx: &mut ExtensionContext,
    ) -> Result<Vec<(String, Value)>, String> {
        Ok(vec![to_cbor()])
    }

    fn prepare_outputs(
        &self,
        _ctx: &OutputContext<'_>,
        _outputs: &mut AuthenticationExtensionOutputs,
    ) {
        // Large blob read/write is handled separately by the client after
        // get_assertion, since it needs session access. The output is written
        // by the client's process_large_blob method.
    }
}

fn b64_opt_ser<S: serde::Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(b) => s.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(b)),
        None => s.serialize_none(),
    }
}

fn b64_opt_de<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
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
    fn test_support_json() {
        let input = RegistrationInput {
            support: LargeBlobSupport::Required,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"required\""));
    }

    #[test]
    fn test_auth_input_json() {
        let read = AuthenticationInput::read();
        let json = serde_json::to_string(&read).unwrap();
        assert!(json.contains("\"read\":true"));
        assert!(!json.contains("write"));
    }

    #[test]
    fn test_cbor() {
        let (key, val) = to_cbor();
        assert_eq!(key, "largeBlobKey");
        assert_eq!(val.as_bool(), Some(true));
    }
}
