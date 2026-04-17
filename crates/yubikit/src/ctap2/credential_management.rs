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

//! CTAP2 Credential Management — enumerate and delete resident credentials.

use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::core::Connection;

use super::pin_protocol::PinProtocol;
use super::session::Ctap2Session;
use super::types::{CredentialInfo, RpInfo};
use super::{Ctap2Error, build_args_map, ctap2_cmd};
use crate::webauthn::types::{PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity};

/// CredentialManagement sub-command identifiers (§6.8).
mod cred_mgmt_cmd {
    /// Get credential storage metadata.
    pub(super) const GET_CREDS_METADATA: u8 = 0x01;
    /// Begin enumerating relying parties.
    pub(super) const ENUMERATE_RPS_BEGIN: u8 = 0x02;
    /// Get next relying party in enumeration.
    pub(super) const ENUMERATE_RPS_NEXT: u8 = 0x03;
    /// Begin enumerating credentials for a relying party.
    pub(super) const ENUMERATE_CREDS_BEGIN: u8 = 0x04;
    /// Get next credential in enumeration.
    pub(super) const ENUMERATE_CREDS_NEXT: u8 = 0x05;
    /// Delete a resident credential.
    pub(super) const DELETE_CREDENTIAL: u8 = 0x06;
    /// Update user information for a credential.
    pub(super) const UPDATE_USER_INFO: u8 = 0x07;
}

/// Response map key constants for internal parsing.
mod cred_mgmt_result_key {
    /// Number of existing discoverable credentials stored.
    pub(super) const EXISTING_CRED_COUNT: i64 = 0x01;
    /// Maximum number of additional credentials that can be stored.
    pub(super) const MAX_REMAINING_COUNT: i64 = 0x02;
    /// Total number of relying parties with stored credentials.
    pub(super) const TOTAL_RPS: i64 = 0x05;
    /// Total number of credentials for the current relying party.
    pub(super) const TOTAL_CREDENTIALS: i64 = 0x09;
}

/// CTAP2 CredentialManagement operations (§6.8).
///
/// Provides credential enumeration, deletion, and user info updates.
/// Owns a [`Ctap2Session`](crate::ctap2::Ctap2Session) and a [`PinProtocol`](crate::ctap2::PinProtocol) for authenticated commands.
pub struct CredentialManagement<C: Connection> {
    session: Ctap2Session<C>,
    protocol: PinProtocol,
    pin_token: Zeroizing<Vec<u8>>,
    use_legacy: bool,
}

impl<C: Connection + 'static> CredentialManagement<C> {
    /// Whether the authenticator supports credential management.
    ///
    /// Returns `true` if the standard `credMgmt` option is set, or if the
    /// device supports the `credentialMgmtPreview` prototype.
    pub fn is_supported(info: &super::Info) -> bool {
        if info.options.get("credMgmt") == Some(&true) {
            return true;
        }
        info.versions.contains(&"FIDO_2_1_PRE".to_string())
            && info.options.get("credentialMgmtPreview") == Some(&true)
    }

    /// Whether the authenticator supports read-only credential management
    /// (enumeration with PIN/UV auth for the credential management read-only permission).
    pub fn is_readonly_supported(info: &super::Info) -> bool {
        info.options.get("perCredMgmtRO") == Some(&true)
    }

    /// Create a new `CredentialManagement` from a `Ctap2Session` and a PIN token.
    ///
    /// The PIN token must have the `CREDENTIAL_MGMT` permission.
    /// Automatically determines whether to use the standard (0x0A) or
    /// legacy preview (0x41) command byte based on the authenticator's
    /// reported capabilities.
    /// On failure, returns the session alongside the error.
    #[allow(clippy::result_large_err)]
    pub fn new(
        session: Ctap2Session<C>,
        protocol: PinProtocol,
        pin_token: Vec<u8>,
    ) -> Result<Self, (Ctap2Error<C::Error>, Ctap2Session<C>)> {
        let info = &session.cached_info;
        if !Self::is_supported(info) {
            return Err((
                Ctap2Error::InvalidResponse(
                    "Authenticator does not support credentialManagement".into(),
                ),
                session,
            ));
        }

        let use_legacy = info.options.get("credMgmt") != Some(&true);

        Ok(Self {
            session,
            protocol,
            pin_token: Zeroizing::new(pin_token),
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
            ctap2_cmd::CREDENTIAL_MGMT_PRE
        } else {
            ctap2_cmd::CREDENTIAL_MGMT
        }
    }

    fn call(
        &mut self,
        sub_cmd: u8,
        sub_cmd_params: Option<&Value>,
        auth: bool,
    ) -> Result<Value, Ctap2Error<C::Error>> {
        let (protocol_ver, pin_uv_param) = if auth {
            let mut msg = vec![sub_cmd];
            if let Some(p) = sub_cmd_params {
                msg.extend_from_slice(&cbor::encode(p));
            }
            let param = self.protocol.authenticate(&self.pin_token, &msg);
            (
                Some(Value::Int(self.protocol.version() as i64)),
                Some(Value::Bytes(param)),
            )
        } else {
            (None, None)
        };

        let data = build_args_map(&[
            Some(Value::Int(sub_cmd as i64)), // 0x01
            sub_cmd_params.cloned(),          // 0x02
            protocol_ver,                     // 0x03
            pin_uv_param,                     // 0x04
        ]);
        self.session
            .send_cbor(self.cmd_byte(), Some(&data), None, None)
    }

    /// Get credential storage metadata.
    ///
    /// Returns `(existing_credential_count, max_possible_remaining_credentials)`.
    pub fn get_metadata(&mut self) -> Result<(u32, u32), Ctap2Error<C::Error>> {
        let resp = self.call(cred_mgmt_cmd::GET_CREDS_METADATA, None, true)?;
        let existing = resp
            .map_get_int(cred_mgmt_result_key::EXISTING_CRED_COUNT)
            .and_then(|v| v.as_int())
            .ok_or_else(|| {
                Ctap2Error::InvalidResponse("missing existingResidentCredentialsCount".into())
            })? as u32;
        let remaining = resp
            .map_get_int(cred_mgmt_result_key::MAX_REMAINING_COUNT)
            .and_then(|v| v.as_int())
            .ok_or_else(|| {
                Ctap2Error::InvalidResponse(
                    "missing maxPossibleRemainingResidentCredentialsCount".into(),
                )
            })? as u32;
        Ok((existing, remaining))
    }

    /// Enumerate all relying parties with stored credentials.
    pub fn enumerate_rps(&mut self) -> Result<Vec<RpInfo>, Ctap2Error<C::Error>> {
        let first = self.call(cred_mgmt_cmd::ENUMERATE_RPS_BEGIN, None, true)?;
        let total = first
            .map_get_int(cred_mgmt_result_key::TOTAL_RPS)
            .and_then(|v| v.as_int())
            .unwrap_or(0) as usize;

        if total == 0 {
            return Ok(Vec::new());
        }

        let mut values = Vec::with_capacity(total);
        values.push(first);
        for _ in 1..total {
            values.push(self.call(cred_mgmt_cmd::ENUMERATE_RPS_NEXT, None, false)?);
        }
        Ok(values.iter().filter_map(RpInfo::from_cbor).collect())
    }

    /// Enumerate all credentials for a given RP ID hash.
    pub fn enumerate_creds(
        &mut self,
        rp_id_hash: &[u8],
    ) -> Result<Vec<CredentialInfo>, Ctap2Error<C::Error>> {
        let params = Value::Map(vec![(Value::Int(0x01), Value::Bytes(rp_id_hash.to_vec()))]);
        let first = self.call(cred_mgmt_cmd::ENUMERATE_CREDS_BEGIN, Some(&params), true)?;
        let total = first
            .map_get_int(cred_mgmt_result_key::TOTAL_CREDENTIALS)
            .and_then(|v| v.as_int())
            .unwrap_or(0) as usize;

        if total == 0 {
            return Ok(Vec::new());
        }

        let mut values = Vec::with_capacity(total);
        values.push(first);
        for _ in 1..total {
            values.push(self.call(cred_mgmt_cmd::ENUMERATE_CREDS_NEXT, None, false)?);
        }
        Ok(values
            .iter()
            .filter_map(CredentialInfo::from_cbor)
            .collect())
    }

    /// Delete a credential by its credential ID.
    pub fn delete_cred(
        &mut self,
        credential_id: &PublicKeyCredentialDescriptor,
    ) -> Result<(), Ctap2Error<C::Error>> {
        let params = Value::Map(vec![(Value::Int(0x02), credential_id.to_cbor())]);
        self.call(cred_mgmt_cmd::DELETE_CREDENTIAL, Some(&params), true)?;
        Ok(())
    }

    /// Update user information for a credential.
    ///
    /// Only supported with the standard (non-preview) command variant.
    pub fn update_user_info(
        &mut self,
        credential_id: &PublicKeyCredentialDescriptor,
        user: &PublicKeyCredentialUserEntity,
    ) -> Result<(), Ctap2Error<C::Error>> {
        if self.use_legacy {
            return Err(Ctap2Error::InvalidResponse(
                "updateUserInfo not supported in preview mode".into(),
            ));
        }
        let params = Value::Map(vec![
            (Value::Int(0x02), credential_id.to_cbor()),
            (Value::Int(0x03), user.to_cbor()),
        ]);
        self.call(cred_mgmt_cmd::UPDATE_USER_INFO, Some(&params), true)?;
        Ok(())
    }
}
