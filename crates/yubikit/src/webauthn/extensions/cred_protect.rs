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

//! Credential Protection extension (credProtect).
//!
//! Controls when user verification is required to use a credential.

use serde::{Deserialize, Serialize};

use crate::cbor::Value;

/// CTAP2 extension identifier for credProtect.
pub const EXTENSION_ID: &str = "credProtect";

/// Credential protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredProtectPolicy {
    /// No protection — credential can be used without UV.
    UserVerificationOptional = 1,
    /// UV required for discoverable credential assertions without a credential ID.
    UserVerificationOptionalWithCredentialIDList = 2,
    /// UV always required to use the credential.
    UserVerificationRequired = 3,
}

impl CredProtectPolicy {
    /// Construct a policy from its CTAP2 integer value (1, 2, or 3).
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::UserVerificationOptional),
            2 => Some(Self::UserVerificationOptionalWithCredentialIDList),
            3 => Some(Self::UserVerificationRequired),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::UserVerificationOptional => "userVerificationOptional",
            Self::UserVerificationOptionalWithCredentialIDList => {
                "userVerificationOptionalWithCredentialIDList"
            }
            Self::UserVerificationRequired => "userVerificationRequired",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "userVerificationOptional" => Some(Self::UserVerificationOptional),
            "userVerificationOptionalWithCredentialIDList" => {
                Some(Self::UserVerificationOptionalWithCredentialIDList)
            }
            "userVerificationRequired" => Some(Self::UserVerificationRequired),
            _ => None,
        }
    }
}

impl Serialize for CredProtectPolicy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CredProtectPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_str(&s).ok_or_else(|| serde::de::Error::custom("invalid credProtect policy"))
    }
}

/// Registration input for credProtect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInput {
    /// The requested credential protection level.
    #[serde(rename = "credentialProtectionPolicy")]
    pub policy: CredProtectPolicy,
    /// Whether the RP requires the authenticator to support credProtect.
    #[serde(
        rename = "enforceCredentialProtectionPolicy",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    /// Whether to fail registration if the authenticator does not support credProtect.
    pub enforce: bool,
}

/// Registration output for credProtect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutput {
    /// The effective credential protection policy set by the authenticator.
    #[serde(rename = "credentialProtectionPolicy")]
    pub policy: CredProtectPolicy,
}

// CBOR helpers

pub(crate) fn to_cbor(policy: CredProtectPolicy) -> (String, Value) {
    (EXTENSION_ID.into(), Value::Int(policy as i64))
}

pub(crate) fn from_cbor(value: &Value) -> Option<CredProtectPolicy> {
    value
        .as_int()
        .and_then(|v| CredProtectPolicy::from_u32(v as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_json_roundtrip() {
        let input = RegistrationInput {
            policy: CredProtectPolicy::UserVerificationRequired,
            enforce: true,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("userVerificationRequired"));
        assert!(json.contains("enforceCredentialProtectionPolicy"));
        let parsed: RegistrationInput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy, CredProtectPolicy::UserVerificationRequired);
        assert!(parsed.enforce);
    }

    #[test]
    fn test_policy_cbor() {
        let (key, val) = to_cbor(CredProtectPolicy::UserVerificationOptionalWithCredentialIDList);
        assert_eq!(key, "credProtect");
        assert_eq!(val.as_int(), Some(2));

        let parsed = from_cbor(&val).unwrap();
        assert_eq!(
            parsed,
            CredProtectPolicy::UserVerificationOptionalWithCredentialIDList
        );
    }
}
