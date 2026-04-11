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
use crate::ctap::CtapSession;

use super::{Ctap2Error, CtapStatus, Info, cmd};

/// CTAP2 protocol session.
///
/// Wraps a [`CtapSession`] and provides CTAP2-specific command framing:
/// each command is sent as `[cmd_byte] ++ cbor_data` via CBOR transport,
/// and responses are parsed as `[status_byte] ++ cbor_data`.
pub struct Ctap2Session<C: Connection> {
    session: CtapSession<C>,
    pub(crate) cached_info: Info,
}

impl<C: Connection + 'static> Ctap2Session<C> {
    /// Create a new `Ctap2Session` wrapping the given [`CtapSession`].
    ///
    /// Calls `get_info()` to cache the authenticator's capabilities.
    pub fn new(session: CtapSession<C>) -> Result<Self, Ctap2Error<C::Error>> {
        let mut s = Self {
            session,
            cached_info: Info::default(),
        };
        s.cached_info = s.get_info()?;
        Ok(s)
    }

    /// Get a reference to the cached authenticator info.
    pub fn info(&self) -> &Info {
        &self.cached_info
    }

    /// The protocol version reported by the authenticator.
    pub fn version(&self) -> crate::core::Version {
        self.session.version()
    }

    /// Consume the `Ctap2Session`, returning the underlying [`CtapSession`].
    pub fn into_session(self) -> CtapSession<C> {
        self.session
    }

    /// Send a CTAP2 CBOR command and parse the status + response.
    ///
    /// Frames the request as `[cmd_byte] ++ data` and sends it via the
    /// underlying transport. Parses the response status byte and returns
    /// the remaining response data on success.
    pub fn send_cbor(
        &mut self,
        cmd_byte: u8,
        data: Option<&[u8]>,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, Ctap2Error<C::Error>> {
        let mut request = vec![cmd_byte];
        if let Some(payload) = data {
            request.extend_from_slice(payload);
        }

        let response = self.session.call_cbor(&request, on_keepalive, cancel)?;

        if response.is_empty() {
            return Err(Ctap2Error::InvalidResponse("Empty response".into()));
        }

        let status = CtapStatus::from_byte(response[0]);
        if status != CtapStatus::Success {
            return Err(Ctap2Error::StatusError(status));
        }

        Ok(response[1..].to_vec())
    }

    /// authenticatorReset command.
    ///
    /// Resets the authenticator to factory defaults: deletes all credentials,
    /// resets PIN/UV state. Requires user presence (touch).
    pub fn reset(
        &mut self,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<(), Ctap2Error<C::Error>> {
        self.send_cbor(cmd::RESET, None, on_keepalive, cancel)?;
        Ok(())
    }

    /// authenticatorSelection command (CTAP 2.1+).
    ///
    /// Asks the user to confirm presence on the authenticator. Returns
    /// successfully once the user touches the device, or fails with
    /// [`CtapStatus::KeepaliveCancel`] if cancelled.
    pub fn selection(
        &mut self,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<(), Ctap2Error<C::Error>> {
        self.send_cbor(cmd::SELECTION, None, on_keepalive, cancel)?;
        Ok(())
    }

    /// authenticatorGetInfo command.
    ///
    /// Returns information about the authenticator's capabilities,
    /// supported protocol versions, extensions, and configuration.
    pub fn get_info(&mut self) -> Result<Info, Ctap2Error<C::Error>> {
        let response = self.send_cbor(cmd::GET_INFO, None, None, None)?;
        let value = cbor::decode(&response)
            .map_err(|e| Ctap2Error::InvalidResponse(format!("CBOR decode error: {e}")))?;
        let map = value
            .as_map()
            .ok_or_else(|| Ctap2Error::InvalidResponse("Expected CBOR map".into()))?;
        Ok(Info::from_cbor_map(map))
    }

    /// Send a raw authenticatorClientPIN command and return the parsed CBOR response map.
    ///
    /// This is the low-level interface used by [`ClientPin`] for all PIN/UV operations.
    pub fn client_pin(
        &mut self,
        pin_uv_protocol: u32,
        sub_cmd: u8,
        key_agreement: Option<&Value>,
        pin_uv_param: Option<&[u8]>,
        new_pin_enc: Option<&[u8]>,
        pin_hash_enc: Option<&[u8]>,
        permissions: Option<u8>,
        permissions_rpid: Option<&str>,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<BTreeMap<u32, Value>, Ctap2Error<C::Error>> {
        // Build CBOR map with integer keys per CTAP2 spec §6.5.4
        let mut params: Vec<(Value, Value)> = Vec::new();
        params.push((Value::Int(0x01), Value::Int(pin_uv_protocol as i64)));
        params.push((Value::Int(0x02), Value::Int(sub_cmd as i64)));
        if let Some(ka) = key_agreement {
            params.push((Value::Int(0x03), ka.clone()));
        }
        if let Some(param) = pin_uv_param {
            params.push((Value::Int(0x04), Value::Bytes(param.to_vec())));
        }
        if let Some(enc) = new_pin_enc {
            params.push((Value::Int(0x05), Value::Bytes(enc.to_vec())));
        }
        if let Some(enc) = pin_hash_enc {
            params.push((Value::Int(0x06), Value::Bytes(enc.to_vec())));
        }
        if let Some(p) = permissions {
            params.push((Value::Int(0x09), Value::Int(p as i64)));
        }
        if let Some(rpid) = permissions_rpid {
            params.push((Value::Int(0x0A), Value::Text(rpid.to_string())));
        }

        let data = cbor::encode(&Value::Map(params));
        let response = self.send_cbor(cmd::CLIENT_PIN, Some(&data), on_keepalive, cancel)?;

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
}
