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

//! CTAP2 Authenticator Config — toggle features and set configuration.

use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::core::Connection;

use super::pin_protocol::PinProtocol;
use super::session::Ctap2Session;
use super::{Ctap2Error, build_args_map, ctap2_cmd};

/// Config sub-command identifiers (§6.11).
mod config_cmd {
    /// Enable enterprise attestation mode.
    pub(super) const ENABLE_ENTERPRISE_ATT: u8 = 0x01;
    /// Toggle the alwaysUv (always require user verification) option.
    pub(super) const TOGGLE_ALWAYS_UV: u8 = 0x02;
    /// Set minimum PIN length and related policies.
    pub(super) const SET_MIN_PIN_LENGTH: u8 = 0x03;
}

/// CTAP2 Authenticator Config operations (§6.11).
///
/// Provides authenticator configuration management: enterprise attestation,
/// always-UV toggle, and minimum PIN length enforcement.
/// Owns a [`Ctap2Session`] and a [`PinProtocol`] for authenticated commands.
pub struct Config<C: Connection> {
    session: Ctap2Session<C>,
    protocol: Option<PinProtocol>,
    pin_token: Option<Zeroizing<Vec<u8>>>,
}

impl<C: Connection + 'static> Config<C> {
    /// Whether the authenticator supports authenticator config.
    pub fn is_supported(info: &super::Info) -> bool {
        info.options.get("authnrCfg") == Some(&true)
    }

    /// Create a new `Config` from a `Ctap2Session` and a PIN token.
    ///
    /// The PIN token must have the `AUTHENTICATOR_CFG` permission.
    /// On failure, returns the session alongside the error.
    #[allow(clippy::result_large_err)]
    pub fn new(
        session: Ctap2Session<C>,
        protocol: PinProtocol,
        pin_token: Vec<u8>,
    ) -> Result<Self, (Ctap2Error<C::Error>, Ctap2Session<C>)> {
        if !Self::is_supported(&session.cached_info) {
            return Err((
                Ctap2Error::InvalidResponse(
                    "Authenticator does not support authenticatorConfig".into(),
                ),
                session,
            ));
        }
        Ok(Self {
            session,
            protocol: Some(protocol),
            pin_token: Some(Zeroizing::new(pin_token)),
        })
    }

    /// Create a new `Config` without PIN authentication.
    ///
    /// Used when no PIN is set on the authenticator but config commands are needed.
    /// On failure, returns the session alongside the error.
    #[allow(clippy::result_large_err)]
    pub fn new_unauthenticated(
        session: Ctap2Session<C>,
    ) -> Result<Self, (Ctap2Error<C::Error>, Ctap2Session<C>)> {
        if !Self::is_supported(&session.cached_info) {
            return Err((
                Ctap2Error::InvalidResponse(
                    "Authenticator does not support authenticatorConfig".into(),
                ),
                session,
            ));
        }
        Ok(Self {
            session,
            protocol: None,
            pin_token: None,
        })
    }

    /// Consume this `Config`, returning the underlying `Ctap2Session`.
    pub fn into_session(self) -> Ctap2Session<C> {
        self.session
    }

    fn call(
        &mut self,
        sub_cmd: u8,
        sub_cmd_params: Option<&Value>,
    ) -> Result<(), Ctap2Error<C::Error>> {
        let (protocol_ver, pin_uv_param) =
            if let (Some(protocol), Some(pin_token)) = (&self.protocol, &self.pin_token) {
                // Auth message: 0xff*32 || 0x0d || subCmd || serialize(subCmdParams)
                let mut msg = vec![0xff; 32];
                msg.push(ctap2_cmd::CONFIG);
                msg.push(sub_cmd);
                if let Some(p) = sub_cmd_params {
                    msg.extend_from_slice(&cbor::encode(p));
                }
                let param = protocol.authenticate(pin_token, &msg);
                (
                    Some(Value::Int(protocol.version() as i64)),
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
            .send_cbor(ctap2_cmd::CONFIG, Some(&data), None, None)?;
        Ok(())
    }

    /// Enable enterprise attestation.
    pub fn enable_enterprise_attestation(&mut self) -> Result<(), Ctap2Error<C::Error>> {
        self.call(config_cmd::ENABLE_ENTERPRISE_ATT, None)
    }

    /// Toggle the alwaysUv option.
    pub fn toggle_always_uv(&mut self) -> Result<(), Ctap2Error<C::Error>> {
        self.call(config_cmd::TOGGLE_ALWAYS_UV, None)
    }

    /// Set minimum PIN length and related policies.
    pub fn set_min_pin_length(
        &mut self,
        min_pin_length: Option<u32>,
        rp_ids: Option<&[String]>,
        force_change_pin: bool,
    ) -> Result<(), Ctap2Error<C::Error>> {
        let mut sub_params: Vec<(Value, Value)> = Vec::new();
        if let Some(len) = min_pin_length {
            sub_params.push((Value::Int(0x01), Value::Int(len as i64)));
        }
        if let Some(ids) = rp_ids {
            let arr: Vec<Value> = ids.iter().map(|s| Value::Text(s.clone())).collect();
            sub_params.push((Value::Int(0x02), Value::Array(arr)));
        }
        if force_change_pin {
            sub_params.push((Value::Int(0x03), Value::Bool(true)));
        }
        let params = if sub_params.is_empty() {
            None
        } else {
            Some(Value::Map(sub_params))
        };
        self.call(config_cmd::SET_MIN_PIN_LENGTH, params.as_ref())
    }
}
