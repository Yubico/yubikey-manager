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

use std::collections::BTreeMap;

use crate::cbor::{self, Value};
use crate::core::Connection;

use super::pin_protocol::PinProtocol;
use super::session::Ctap2Session;
use super::{Ctap2Error, cmd};

/// CredentialManagement sub-command identifiers (§6.8).
mod cred_mgmt_cmd {
    pub const GET_CREDS_METADATA: u8 = 0x01;
    pub const ENUMERATE_RPS_BEGIN: u8 = 0x02;
    pub const ENUMERATE_RPS_NEXT: u8 = 0x03;
    pub const ENUMERATE_CREDS_BEGIN: u8 = 0x04;
    pub const ENUMERATE_CREDS_NEXT: u8 = 0x05;
    pub const DELETE_CREDENTIAL: u8 = 0x06;
    pub const UPDATE_USER_INFO: u8 = 0x07;
}

/// CredentialManagement response map keys (§6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CredMgmtResult {
    ExistingCredCount = 0x01,
    MaxRemainingCount = 0x02,
    Rp = 0x03,
    RpIdHash = 0x04,
    TotalRps = 0x05,
    User = 0x06,
    CredentialId = 0x07,
    PublicKey = 0x08,
    TotalCredentials = 0x09,
    CredProtect = 0x0A,
    LargeBlobKey = 0x0B,
}

/// CTAP2 CredentialManagement operations (§6.8).
///
/// Provides credential enumeration, deletion, and user info updates.
/// Owns a [`Ctap2Session`] and a [`PinProtocol`] for authenticated commands.
pub struct CredentialManagement<C: Connection> {
    session: Ctap2Session<C>,
    protocol: PinProtocol,
    pin_token: Vec<u8>,
    use_legacy: bool,
}

impl<C: Connection + 'static> CredentialManagement<C> {
    /// Create a new `CredentialManagement` from a `Ctap2Session` and a PIN token.
    ///
    /// The PIN token must have the `CREDENTIAL_MGMT` permission.
    /// Automatically determines whether to use the standard (0x0A) or
    /// legacy preview (0x41) command byte based on the authenticator's
    /// reported capabilities.
    pub fn new(
        session: Ctap2Session<C>,
        protocol: PinProtocol,
        pin_token: Vec<u8>,
    ) -> Result<Self, Ctap2Error<C::Error>> {
        let info = &session.cached_info;
        let has_cred_mgmt = info.options.get("credMgmt") == Some(&true);
        let has_preview = info.versions.contains(&"FIDO_2_1_PRE".to_string())
            && info.options.get("credentialMgmtPreview") == Some(&true);

        if !has_cred_mgmt && !has_preview {
            return Err(Ctap2Error::InvalidResponse(
                "Authenticator does not support credentialManagement".into(),
            ));
        }

        let use_legacy = !has_cred_mgmt && has_preview;

        Ok(Self {
            session,
            protocol,
            pin_token,
            use_legacy,
        })
    }

    /// Consume this `CredentialManagement`, returning the underlying `Ctap2Session`.
    pub fn into_session(self) -> Ctap2Session<C> {
        self.session
    }

    /// Whether the `update_user_info` sub-command is supported.
    ///
    /// Only available with the standard (non-preview) command.
    pub fn is_update_supported(&self) -> bool {
        !self.use_legacy
    }

    fn cmd_byte(&self) -> u8 {
        if self.use_legacy {
            cmd::CREDENTIAL_MGMT_PRE
        } else {
            cmd::CREDENTIAL_MGMT
        }
    }

    fn call(
        &mut self,
        sub_cmd: u8,
        sub_cmd_params: Option<&Value>,
        auth: bool,
    ) -> Result<BTreeMap<u32, Value>, Ctap2Error<C::Error>> {
        let mut params: Vec<(Value, Value)> = Vec::new();
        params.push((Value::Int(0x01), Value::Int(sub_cmd as i64)));
        if let Some(p) = sub_cmd_params {
            params.push((Value::Int(0x02), p.clone()));
        }
        if auth {
            // pinUvAuthParam = authenticate(pinToken, [subCmd] ++ serialize(subCmdParams))
            let mut msg = vec![sub_cmd];
            if let Some(p) = sub_cmd_params {
                msg.extend_from_slice(&cbor::encode(p));
            }
            let pin_uv_param = self.protocol.authenticate(&self.pin_token, &msg);
            params.push((Value::Int(0x03), Value::Int(self.protocol.version() as i64)));
            params.push((Value::Int(0x04), Value::Bytes(pin_uv_param)));
        }

        let data = cbor::encode(&Value::Map(params));
        let response = self
            .session
            .send_cbor(self.cmd_byte(), Some(&data), None, None)?;

        if response.is_empty() {
            return Ok(BTreeMap::new());
        }

        let value = cbor::decode(&response)
            .map_err(|e| Ctap2Error::InvalidResponse(format!("CBOR decode error: {e}")))?;
        let map = value
            .as_map()
            .ok_or_else(|| Ctap2Error::InvalidResponse("Expected CBOR map".into()))?;

        let mut result = BTreeMap::new();
        for (k, v) in map {
            if let Some(key) = k.as_int() {
                result.insert(key as u32, v.clone());
            }
        }
        Ok(result)
    }

    /// Get credential storage metadata.
    ///
    /// Returns `(existing_credential_count, max_possible_remaining_credentials)`.
    pub fn get_metadata(&mut self) -> Result<(u32, u32), Ctap2Error<C::Error>> {
        let resp = self.call(cred_mgmt_cmd::GET_CREDS_METADATA, None, true)?;
        let existing = resp
            .get(&(CredMgmtResult::ExistingCredCount as u32))
            .and_then(|v| v.as_int())
            .ok_or_else(|| {
                Ctap2Error::InvalidResponse("missing existingResidentCredentialsCount".into())
            })? as u32;
        let remaining = resp
            .get(&(CredMgmtResult::MaxRemainingCount as u32))
            .and_then(|v| v.as_int())
            .ok_or_else(|| {
                Ctap2Error::InvalidResponse(
                    "missing maxPossibleRemainingResidentCredentialsCount".into(),
                )
            })? as u32;
        Ok((existing, remaining))
    }

    /// Enumerate all relying parties with stored credentials.
    pub fn enumerate_rps(&mut self) -> Result<Vec<BTreeMap<u32, Value>>, Ctap2Error<C::Error>> {
        let first = self.call(cred_mgmt_cmd::ENUMERATE_RPS_BEGIN, None, true)?;
        let total = first
            .get(&(CredMgmtResult::TotalRps as u32))
            .and_then(|v| v.as_int())
            .unwrap_or(0) as usize;

        if total == 0 {
            return Ok(Vec::new());
        }

        let mut results = Vec::with_capacity(total);
        results.push(first);
        for _ in 1..total {
            let next = self.call(cred_mgmt_cmd::ENUMERATE_RPS_NEXT, None, false)?;
            results.push(next);
        }
        Ok(results)
    }

    /// Enumerate all credentials for a given RP ID hash.
    pub fn enumerate_creds(
        &mut self,
        rp_id_hash: &[u8],
    ) -> Result<Vec<BTreeMap<u32, Value>>, Ctap2Error<C::Error>> {
        let params = Value::Map(vec![(Value::Int(0x01), Value::Bytes(rp_id_hash.to_vec()))]);
        let first = self.call(cred_mgmt_cmd::ENUMERATE_CREDS_BEGIN, Some(&params), true)?;
        let total = first
            .get(&(CredMgmtResult::TotalCredentials as u32))
            .and_then(|v| v.as_int())
            .unwrap_or(0) as usize;

        if total == 0 {
            return Ok(Vec::new());
        }

        let mut results = Vec::with_capacity(total);
        results.push(first);
        for _ in 1..total {
            let next = self.call(cred_mgmt_cmd::ENUMERATE_CREDS_NEXT, None, false)?;
            results.push(next);
        }
        Ok(results)
    }

    /// Delete a credential by its credential ID.
    pub fn delete_cred(&mut self, credential_id: &Value) -> Result<(), Ctap2Error<C::Error>> {
        let params = Value::Map(vec![(Value::Int(0x02), credential_id.clone())]);
        self.call(cred_mgmt_cmd::DELETE_CREDENTIAL, Some(&params), true)?;
        Ok(())
    }

    /// Update user information for a credential.
    ///
    /// Only supported with the standard (non-preview) command variant.
    pub fn update_user_info(
        &mut self,
        credential_id: &Value,
        user: &Value,
    ) -> Result<(), Ctap2Error<C::Error>> {
        if self.use_legacy {
            return Err(Ctap2Error::InvalidResponse(
                "updateUserInfo not supported in preview mode".into(),
            ));
        }
        let params = Value::Map(vec![
            (Value::Int(0x02), credential_id.clone()),
            (Value::Int(0x03), user.clone()),
        ]);
        self.call(cred_mgmt_cmd::UPDATE_USER_INFO, Some(&params), true)?;
        Ok(())
    }
}
