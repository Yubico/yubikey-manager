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

//! Minimum PIN Length extension (minPinLength).
//!
//! Returns the minimum PIN length enforced by the authenticator.
//! Registration only.

use serde::{Deserialize, Serialize};

use crate::cbor::Value;
use crate::ctap2::Info;
use crate::webauthn::extensions::{
    Ctap2Extension, ExtensionContext, OutputContext, RegistrationExtensionOutputs,
    RegistrationProcessor,
};
use crate::webauthn::types::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};

/// CTAP2 extension identifier for minPinLength.
pub const EXTENSION_ID: &str = "minPinLength";

/// Registration output for minPinLength.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutput {
    /// The minimum PIN length enforced by the authenticator.
    #[serde(rename = "minPinLength")]
    pub length: u32,
}

// CBOR helpers

pub(crate) fn to_cbor() -> (String, Value) {
    (EXTENSION_ID.into(), Value::Bool(true))
}

pub(crate) fn from_cbor(value: &Value) -> Option<u32> {
    value.as_int().map(|v| v as u32)
}

// ---------------------------------------------------------------------------
// Extension processor implementation
// ---------------------------------------------------------------------------

/// The minPinLength extension definition.
pub struct MinPinLengthExtension;

impl Ctap2Extension for MinPinLengthExtension {
    fn make_credential(
        &self,
        info: &Info,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<Option<Box<dyn RegistrationProcessor>>, String> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        if ext.min_pin_length != Some(true) {
            return Ok(None);
        }
        if !info.extensions.iter().any(|e| e == EXTENSION_ID) {
            return Ok(None);
        }
        Ok(Some(Box::new(MinPinLengthRegistrationProcessor)))
    }

    fn get_assertion(
        &self,
        _info: &Info,
        _options: &PublicKeyCredentialRequestOptions,
    ) -> Result<Option<Box<dyn super::AuthenticationProcessor>>, String> {
        Ok(None)
    }
}

struct MinPinLengthRegistrationProcessor;

impl RegistrationProcessor for MinPinLengthRegistrationProcessor {
    fn prepare_inputs(&self, _ctx: &mut ExtensionContext) -> Result<Vec<(String, Value)>, String> {
        Ok(vec![to_cbor()])
    }

    fn prepare_outputs(&self, ctx: &OutputContext<'_>, outputs: &mut RegistrationExtensionOutputs) {
        if let Some((_, val)) = ctx
            .auth_data_extensions
            .and_then(|exts| exts.iter().find(|(k, _)| k == EXTENSION_ID))
            && let Some(length) = from_cbor(val)
        {
            outputs.min_pin_length = Some(RegistrationOutput { length });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbor() {
        let (key, val) = to_cbor();
        assert_eq!(key, "minPinLength");
        assert_eq!(val.as_bool(), Some(true));

        let out = from_cbor(&Value::Int(8));
        assert_eq!(out, Some(8));
    }
}
