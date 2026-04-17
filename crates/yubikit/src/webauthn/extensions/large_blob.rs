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
