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
