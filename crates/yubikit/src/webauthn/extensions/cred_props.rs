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

//! Credential Properties extension (credProps).
//!
//! Client-side extension that reports whether a created credential is
//! discoverable (resident key). No CTAP2 extension is sent to the
//! authenticator — the result is computed by the client.

use serde::{Deserialize, Serialize};

use crate::ctap2::Info;
use crate::webauthn::extensions::{
    Ctap2Extension, ExtensionContext, OutputContext, RegistrationExtensionOutputs,
    RegistrationProcessor,
};
use crate::webauthn::types::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions, ResidentKeyRequirement,
};

/// Registration output for credProps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutput {
    /// Whether the created credential is discoverable (resident).
    pub rk: bool,
}

/// The credProps extension definition.
pub struct CredPropsExtension;

impl Ctap2Extension for CredPropsExtension {
    fn make_credential(
        &self,
        _info: &Info,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<Option<Box<dyn RegistrationProcessor>>, String> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        if ext.cred_props != Some(true) {
            return Ok(None);
        }
        let rk = options.authenticator_selection.as_ref().is_some_and(|sel| {
            matches!(
                sel.resident_key,
                Some(ResidentKeyRequirement::Required | ResidentKeyRequirement::Preferred)
            )
        });
        Ok(Some(Box::new(CredPropsRegistrationProcessor { rk })))
    }

    fn get_assertion(
        &self,
        _info: &Info,
        _options: &PublicKeyCredentialRequestOptions,
    ) -> Result<Option<Box<dyn super::AuthenticationProcessor>>, String> {
        Ok(None)
    }
}

struct CredPropsRegistrationProcessor {
    rk: bool,
}

impl RegistrationProcessor for CredPropsRegistrationProcessor {
    fn prepare_inputs(
        &self,
        _ctx: &mut ExtensionContext,
    ) -> Result<Vec<(String, crate::cbor::Value)>, String> {
        // credProps is client-side only — no authenticator input
        Ok(vec![])
    }

    fn prepare_outputs(
        &self,
        _ctx: &OutputContext<'_>,
        outputs: &mut RegistrationExtensionOutputs,
    ) {
        outputs.cred_props = Some(RegistrationOutput { rk: self.rk });
    }
}
