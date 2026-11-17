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
    fn from_u32(v: u32) -> Option<Self> {
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

// ---------------------------------------------------------------------------
// Extension processor implementation
// ---------------------------------------------------------------------------

use crate::ctap2::Info;
use crate::webauthn::extensions::{
    Ctap2Extension, ExtensionContext, OutputContext, RegistrationExtensionOutputs,
    RegistrationProcessor,
};
use crate::webauthn::types::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};

/// The credProtect extension definition.
pub struct CredProtectExtension;

impl Ctap2Extension for CredProtectExtension {
    fn make_credential(
        &self,
        info: &Info,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<Option<Box<dyn RegistrationProcessor>>, String> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        let cp = match &ext.cred_protect {
            Some(cp) => cp.clone(),
            None => return Ok(None),
        };
        if cp.enforce && !info.extensions.iter().any(|e| e == EXTENSION_ID) {
            return Err("credProtect not supported by authenticator".into());
        }
        Ok(Some(Box::new(CredProtectRegistrationProcessor {
            policy: cp.policy,
        })))
    }

    fn get_assertion(
        &self,
        _info: &Info,
        _options: &PublicKeyCredentialRequestOptions,
    ) -> Result<Option<Box<dyn super::AuthenticationProcessor>>, String> {
        Ok(None)
    }
}

struct CredProtectRegistrationProcessor {
    policy: CredProtectPolicy,
}

impl RegistrationProcessor for CredProtectRegistrationProcessor {
    fn prepare_inputs(&self, _ctx: &mut ExtensionContext) -> Result<Vec<(String, Value)>, String> {
        Ok(vec![to_cbor(self.policy)])
    }

    fn prepare_outputs(&self, ctx: &OutputContext<'_>, outputs: &mut RegistrationExtensionOutputs) {
        if let Some((_, val)) = ctx
            .auth_data_extensions
            .and_then(|exts| exts.iter().find(|(k, _)| k == EXTENSION_ID))
            && let Some(policy) = from_cbor(val)
        {
            outputs.cred_protect = Some(RegistrationOutput { policy });
        }
    }
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
