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

//! CTAP2 ClientPIN operations — PIN management and user verification.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::Value;
use crate::core::Connection;

use super::pin_protocol::{CoseKey, PinProtocol};
use super::session::Ctap2Session;
use super::{Ctap2Error, Info, build_args_map, ctap2_cmd};

/// ClientPin sub-command identifiers (§6.5.5).
mod client_pin_cmd {
    /// Get the number of PIN retries remaining.
    pub(super) const GET_PIN_RETRIES: u8 = 0x01;
    /// Perform key agreement to establish a shared secret.
    pub(super) const GET_KEY_AGREEMENT: u8 = 0x02;
    /// Set a new PIN on the authenticator.
    pub(super) const SET_PIN: u8 = 0x03;
    /// Change an existing PIN.
    pub(super) const CHANGE_PIN: u8 = 0x04;
    /// Get a PIN token using the PIN (legacy, pre-2.1).
    pub(super) const GET_TOKEN_USING_PIN_LEGACY: u8 = 0x05;
    /// Get a PIN/UV token using built-in user verification.
    pub(super) const GET_TOKEN_USING_UV: u8 = 0x06;
    /// Get the number of built-in UV retries remaining.
    pub(super) const GET_UV_RETRIES: u8 = 0x07;
    /// Get a PIN token using the PIN (with permissions, FIDO 2.1+).
    pub(super) const GET_TOKEN_USING_PIN: u8 = 0x09;
}

/// ClientPin response map keys (§6.5.6).
mod client_pin_result_key {
    /// Platform key agreement key (COSE_Key).
    pub(super) const KEY_AGREEMENT: i64 = 0x01;
    /// Encrypted PIN/UV auth token.
    pub(super) const PIN_UV_TOKEN: i64 = 0x02;
    /// Number of PIN retries remaining.
    pub(super) const PIN_RETRIES: i64 = 0x03;
    /// Whether a power cycle is needed before retrying.
    pub(super) const POWER_CYCLE_STATE: i64 = 0x04;
    /// Number of built-in UV retries remaining.
    pub(super) const UV_RETRIES: i64 = 0x05;
}

/// Permissions that can be associated with a PIN/UV token (§6.5.5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions(u8);

impl Permissions {
    /// Permission to create credentials (`authenticatorMakeCredential`).
    pub const MAKE_CREDENTIAL: Self = Self(0x01);
    /// Permission to generate assertions (`authenticatorGetAssertion`).
    pub const GET_ASSERTION: Self = Self(0x02);
    /// Permission for credential management operations.
    pub const CREDENTIAL_MGMT: Self = Self(0x04);
    /// Permission for bio enrollment operations.
    pub const BIO_ENROLL: Self = Self(0x08);
    /// Permission to write to the large-blob array.
    pub const LARGE_BLOB_WRITE: Self = Self(0x10);
    /// Permission for authenticator configuration operations.
    pub const AUTHENTICATOR_CFG: Self = Self(0x20);
    /// Permission for persistent credential management (read-only enumeration).
    pub const PERSISTENT_CREDENTIAL_MGMT: Self = Self(0x40);

    /// Create a `Permissions` value from raw permission bits.
    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    /// Return the raw permission bits.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl std::ops::BitOr for Permissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for Permissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// CTAP2 Client PIN / UV token management.
///
/// Owns a [`Ctap2Session`](crate::ctap2::Ctap2Session) and a [`PinProtocol`](crate::ctap2::PinProtocol), providing high-level
/// PIN/UV operations: setting/changing PINs, getting PIN/UV tokens, and
/// querying retry counters.
pub struct ClientPin<C: Connection> {
    session: Ctap2Session<C>,
    protocol: PinProtocol,
}

/// Pad a PIN string per CTAP2 spec: UTF-8, left-padded to ≥64 bytes, 16-byte aligned.
fn pad_pin(pin: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let pin_bytes = pin.as_bytes();
    if pin_bytes.len() < 4 {
        return Err("PIN must be at least 4 bytes".into());
    }
    let mut padded = pin_bytes.to_vec();
    // Pad to at least 64 bytes
    if padded.len() < 64 {
        padded.resize(64, 0);
    }
    // Extend to 16-byte alignment
    let remainder = padded.len() % 16;
    if remainder != 0 {
        padded.resize(padded.len() + (16 - remainder), 0);
    }
    if padded.len() > 255 {
        return Err("PIN must be at most 255 bytes".into());
    }
    Ok(Zeroizing::new(padded))
}

impl<C: Connection + 'static> ClientPin<C> {
    /// Create a new `ClientPin` from a `Ctap2Session`, auto-selecting the best
    /// supported PIN protocol (V2 preferred over V1).
    ///
    /// Uses the cached info from the session to determine supported protocols.
    /// On failure, returns the session alongside the error.
    #[allow(clippy::result_large_err)]
    pub fn new(session: Ctap2Session<C>) -> Result<Self, (Ctap2Error<C::Error>, Ctap2Session<C>)> {
        match Self::select_protocol(&session.cached_info) {
            Ok(protocol) => Ok(Self { session, protocol }),
            Err(e) => Err((e, session)),
        }
    }

    /// Create a new `ClientPin` with a specific `PinProtocol`.
    pub fn new_with_protocol(session: Ctap2Session<C>, protocol: PinProtocol) -> Self {
        Self { session, protocol }
    }

    /// The active PIN protocol.
    pub fn protocol(&self) -> PinProtocol {
        self.protocol
    }

    /// Consume this `ClientPin`, returning the underlying `Ctap2Session`.
    pub fn into_session(self) -> Ctap2Session<C> {
        self.session
    }

    /// Send a clientPin command, building the CBOR args map.
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        sub_cmd: u8,
        key_agreement: Option<&CoseKey>,
        pin_uv_param: Option<&[u8]>,
        new_pin_enc: Option<&[u8]>,
        pin_hash_enc: Option<&[u8]>,
        permissions: Option<u8>,
        permissions_rpid: Option<&str>,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, Ctap2Error<C::Error>> {
        let data = build_args_map(&[
            Some(Value::Int(self.protocol.version() as i64)), // 0x01
            Some(Value::Int(sub_cmd as i64)),                 // 0x02
            key_agreement.cloned(),                           // 0x03
            pin_uv_param.map(|b| Value::Bytes(b.to_vec())),   // 0x04
            new_pin_enc.map(|b| Value::Bytes(b.to_vec())),    // 0x05
            pin_hash_enc.map(|b| Value::Bytes(b.to_vec())),   // 0x06
            None,                                             // 0x07 (unused)
            None,                                             // 0x08 (unused)
            permissions.map(|p| Value::Int(p as i64)),        // 0x09
            permissions_rpid.map(|s| Value::Text(s.to_string())), // 0x0A
        ]);
        self.session
            .send_cbor(ctap2_cmd::CLIENT_PIN, Some(&data), on_keepalive, cancel)
    }

    /// Get the number of PIN retries remaining.
    ///
    /// Returns `(retries, power_cycle_state)`.
    pub fn get_pin_retries(&mut self) -> Result<(u32, Option<u32>), Ctap2Error<C::Error>> {
        log::debug!("Getting PIN retries");
        let resp = self.send(
            client_pin_cmd::GET_PIN_RETRIES,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        let retries = resp
            .map_get_int(client_pin_result_key::PIN_RETRIES)
            .and_then(|v| v.as_int())
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing pinRetries".into()))?
            as u32;
        let pcs = resp
            .map_get_int(client_pin_result_key::POWER_CYCLE_STATE)
            .and_then(|v| v.as_int())
            .map(|n| n as u32);
        Ok((retries, pcs))
    }

    /// Get the number of built-in UV retries remaining.
    pub fn get_uv_retries(&mut self) -> Result<u32, Ctap2Error<C::Error>> {
        log::debug!("Getting UV retries");
        let resp = self.send(
            client_pin_cmd::GET_UV_RETRIES,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        let retries = resp
            .map_get_int(client_pin_result_key::UV_RETRIES)
            .and_then(|v| v.as_int())
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing uvRetries".into()))?
            as u32;
        Ok(retries)
    }

    /// Set a PIN on an authenticator that does not have one set.
    pub fn set_pin(&mut self, pin: &str) -> Result<(), Ctap2Error<C::Error>> {
        log::debug!("Setting PIN");
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let pin_padded = pad_pin(pin).map_err(Ctap2Error::InvalidResponse)?;
        let new_pin_enc = self.protocol.encrypt(&shared_secret, &pin_padded);
        let pin_uv_param = self.protocol.authenticate(&shared_secret, &new_pin_enc);

        self.send(
            client_pin_cmd::SET_PIN,
            Some(&key_agreement),
            Some(&pin_uv_param),
            Some(&new_pin_enc),
            None,
            None,
            None,
            None,
            None,
        )?;
        log::info!("PIN has been set");
        Ok(())
    }

    /// Change the PIN on an authenticator that already has one.
    pub fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), Ctap2Error<C::Error>> {
        log::debug!("Changing PIN");
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let mut pin_hash_full = Sha256::digest(old_pin.as_bytes());
        let pin_hash_enc = self.protocol.encrypt(&shared_secret, &pin_hash_full[..16]);
        pin_hash_full.zeroize();
        let new_pin_padded = pad_pin(new_pin).map_err(Ctap2Error::InvalidResponse)?;
        let new_pin_enc = self.protocol.encrypt(&shared_secret, &new_pin_padded);

        // pinUvParam = authenticate(shared_secret, newPinEnc || pinHashEnc)
        let mut auth_msg = new_pin_enc.clone();
        auth_msg.extend_from_slice(&pin_hash_enc);
        let pin_uv_param = self.protocol.authenticate(&shared_secret, &auth_msg);

        self.send(
            client_pin_cmd::CHANGE_PIN,
            Some(&key_agreement),
            Some(&pin_uv_param),
            Some(&new_pin_enc),
            Some(&pin_hash_enc),
            None,
            None,
            None,
            None,
        )?;
        log::info!("PIN has been changed");
        Ok(())
    }

    /// Get a PIN/UV token using the PIN.
    ///
    /// If `permissions` is provided and the authenticator supports pinUvAuthToken,
    /// uses the new `getPinToken` command (0x09); otherwise falls back to the
    /// legacy command (0x05).
    pub fn get_pin_token(
        &mut self,
        pin: &str,
        permissions: Option<Permissions>,
        permissions_rpid: Option<&str>,
    ) -> Result<Vec<u8>, Ctap2Error<C::Error>> {
        log::debug!("Getting PIN token");
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let mut pin_hash_full = Sha256::digest(pin.as_bytes());
        let pin_hash_enc = self.protocol.encrypt(&shared_secret, &pin_hash_full[..16]);
        pin_hash_full.zeroize();

        let (sub_cmd, perms, rpid) =
            if Self::is_token_supported(&self.session.cached_info) && permissions.is_some() {
                (
                    client_pin_cmd::GET_TOKEN_USING_PIN,
                    permissions.map(|p| p.bits()),
                    permissions_rpid,
                )
            } else {
                (client_pin_cmd::GET_TOKEN_USING_PIN_LEGACY, None, None)
            };

        let resp = self.send(
            sub_cmd,
            Some(&key_agreement),
            None,
            None,
            Some(&pin_hash_enc),
            perms,
            rpid,
            None,
            None,
        )?;

        let token_enc = resp
            .map_get_int(client_pin_result_key::PIN_UV_TOKEN)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing pinUvToken".into()))?;

        let token = self
            .protocol
            .decrypt(&shared_secret, token_enc)
            .map_err(Ctap2Error::InvalidResponse)?;
        self.protocol
            .validate_token(&token)
            .map_err(Ctap2Error::InvalidResponse)?;

        Ok(token)
    }

    /// Get a PIN/UV token using built-in user verification (biometrics, etc.).
    pub fn get_uv_token(
        &mut self,
        permissions: Option<Permissions>,
        permissions_rpid: Option<&str>,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, Ctap2Error<C::Error>> {
        log::debug!("Getting UV token");
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let resp = self.send(
            client_pin_cmd::GET_TOKEN_USING_UV,
            Some(&key_agreement),
            None,
            None,
            None,
            permissions.map(|p| p.bits()),
            permissions_rpid,
            on_keepalive,
            cancel,
        )?;

        let token_enc = resp
            .map_get_int(client_pin_result_key::PIN_UV_TOKEN)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing pinUvToken".into()))?;

        let token = self
            .protocol
            .decrypt(&shared_secret, token_enc)
            .map_err(Ctap2Error::InvalidResponse)?;
        self.protocol
            .validate_token(&token)
            .map_err(Ctap2Error::InvalidResponse)?;

        Ok(token)
    }

    /// Whether the authenticator supports `clientPin`.
    pub fn is_supported(info: &Info) -> bool {
        info.options.contains_key("clientPin")
    }

    /// Whether the authenticator supports `pinUvAuthToken`.
    pub fn is_token_supported(info: &Info) -> bool {
        info.options.get("pinUvAuthToken") == Some(&true)
    }

    fn select_protocol(info: &Info) -> Result<PinProtocol, Ctap2Error<C::Error>> {
        // Prefer V2 over V1
        for &version in &[2u32, 1] {
            if info.pin_uv_protocols.contains(&version) {
                return Ok(match version {
                    2 => PinProtocol::V2,
                    _ => PinProtocol::V1,
                });
            }
        }
        Err(Ctap2Error::InvalidResponse(
            "No compatible PIN/UV protocol supported".into(),
        ))
    }

    pub(crate) fn get_shared_secret(&mut self) -> Result<(CoseKey, Vec<u8>), Ctap2Error<C::Error>> {
        let resp = self.send(
            client_pin_cmd::GET_KEY_AGREEMENT,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        let peer_key = resp
            .map_get_int(client_pin_result_key::KEY_AGREEMENT)
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing keyAgreement".into()))?;

        self.protocol
            .encapsulate(peer_key)
            .map_err(|e| Ctap2Error::InvalidResponse(format!("key agreement failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_pin() {
        // Normal pin
        let padded = pad_pin("1234").unwrap();
        assert_eq!(padded.len(), 64);
        assert_eq!(&padded[..4], b"1234");
        assert!(padded[4..].iter().all(|&b| b == 0));

        // Too short
        assert!(pad_pin("123").is_err());

        // Long pin (64 bytes) → 64 already aligned
        let long = "a".repeat(64);
        let padded = pad_pin(&long).unwrap();
        assert_eq!(padded.len(), 64);
    }
}
