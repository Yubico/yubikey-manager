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

//! CTAP2 protocol session and PIN/UV management.
//!
//! Provides [`Ctap2Session`], which wraps a [`CtapSession`] and implements
//! CTAP2-specific command framing and response parsing.
//!
//! Also provides [`ClientPin`] for PIN/UV token operations, and
//! [`PinProtocol`] (V1/V2) for the underlying cryptographic operations.

use std::collections::BTreeMap;

use aes::Aes256;
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use elliptic_curve::sec1::FromEncodedPoint;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::core::Connection;
use crate::ctap::{CtapError, CtapSession};

// ---------------------------------------------------------------------------
// CTAP2 command bytes
// ---------------------------------------------------------------------------

/// CTAP2 authenticator command identifiers.
#[allow(dead_code)]
mod cmd {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const BIO_ENROLLMENT: u8 = 0x09;
    pub const CREDENTIAL_MGMT: u8 = 0x0A;
    pub const SELECTION: u8 = 0x0B;
    pub const LARGE_BLOBS: u8 = 0x0C;
    pub const CONFIG: u8 = 0x0D;
    pub const BIO_ENROLLMENT_PRE: u8 = 0x40;
    pub const CREDENTIAL_MGMT_PRE: u8 = 0x41;
}

// ---------------------------------------------------------------------------
// CTAP2 status codes
// ---------------------------------------------------------------------------

/// CTAP2 error status codes returned by the authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapStatus {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    FpDatabaseFull = 0x17,
    LargeBlobStorageFull = 0x18,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    UnsupportedOption = 0x2B,
    InvalidOption = 0x2C,
    KeepaliveCancel = 0x2D,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x36,
    PukRequired = 0x39,
    PinPolicyViolation = 0x37,
    UvBlocked = 0x3C,
    IntegrityFailure = 0x3D,
    InvalidSubcommand = 0x3E,
    UvInvalid = 0x3F,
    UnauthorizedPermission = 0x40,
    Other = 0x7F,
}

impl CtapStatus {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Success,
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidParameter,
            0x03 => Self::InvalidLength,
            0x04 => Self::InvalidSeq,
            0x05 => Self::Timeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x11 => Self::CborUnexpectedType,
            0x12 => Self::InvalidCbor,
            0x14 => Self::MissingParameter,
            0x15 => Self::LimitExceeded,
            0x17 => Self::FpDatabaseFull,
            0x18 => Self::LargeBlobStorageFull,
            0x19 => Self::CredentialExcluded,
            0x21 => Self::Processing,
            0x22 => Self::InvalidCredential,
            0x23 => Self::UserActionPending,
            0x24 => Self::OperationPending,
            0x25 => Self::NoOperations,
            0x26 => Self::UnsupportedAlgorithm,
            0x27 => Self::OperationDenied,
            0x28 => Self::KeyStoreFull,
            0x2B => Self::UnsupportedOption,
            0x2C => Self::InvalidOption,
            0x2D => Self::KeepaliveCancel,
            0x2E => Self::NoCredentials,
            0x2F => Self::UserActionTimeout,
            0x30 => Self::NotAllowed,
            0x31 => Self::PinInvalid,
            0x32 => Self::PinBlocked,
            0x33 => Self::PinAuthInvalid,
            0x34 => Self::PinAuthBlocked,
            0x36 => Self::PinNotSet,
            0x39 => Self::PukRequired,
            0x37 => Self::PinPolicyViolation,
            0x3C => Self::UvBlocked,
            0x3D => Self::IntegrityFailure,
            0x3E => Self::InvalidSubcommand,
            0x3F => Self::UvInvalid,
            0x40 => Self::UnauthorizedPermission,
            _ => Self::Other,
        }
    }
}

impl std::fmt::Display for CtapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?} (0x{:02X})", *self as u8)
    }
}

// ---------------------------------------------------------------------------
// Ctap2Error
// ---------------------------------------------------------------------------

/// Error type for [`Ctap2Session`] CTAP2 protocol operations.
#[derive(Debug)]
pub enum Ctap2Error<E: std::error::Error + Send + Sync + 'static> {
    /// The authenticator returned a non-success status code.
    StatusError(CtapStatus),
    /// The underlying transport or session returned an error.
    Transport(CtapError<E>),
    /// The response from the authenticator was malformed.
    InvalidResponse(String),
}

impl<E: std::error::Error + Send + Sync + 'static> std::fmt::Display for Ctap2Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusError(status) => write!(f, "CTAP2 error: {status}"),
            Self::Transport(e) => write!(f, "{e}"),
            Self::InvalidResponse(msg) => write!(f, "Invalid CTAP2 response: {msg}"),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error for Ctap2Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<CtapError<E>> for Ctap2Error<E> {
    fn from(e: CtapError<E>) -> Self {
        Self::Transport(e)
    }
}

// ---------------------------------------------------------------------------
// Aaguid
// ---------------------------------------------------------------------------

/// 16-byte Authenticator Attestation GUID.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Aaguid([u8; 16]);

impl Aaguid {
    pub const NONE: Aaguid = Aaguid([0u8; 16]);

    pub fn new(data: [u8; 16]) -> Self {
        Self(data)
    }

    pub fn from_slice(data: &[u8]) -> Option<Self> {
        data.try_into().ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn is_none(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

impl std::fmt::Debug for Aaguid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }
}

impl std::fmt::Display for Aaguid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// Info (authenticatorGetInfo response)
// ---------------------------------------------------------------------------

/// Parsed response from the authenticatorGetInfo command (§6.4).
///
/// All fields correspond to the integer-keyed CBOR map returned by the
/// authenticator. Optional/defaulted fields follow the CTAP 2.3 spec defaults.
#[derive(Debug, Clone, Default)]
pub struct Info {
    /// 0x01: List of supported protocol versions (e.g. "FIDO_2_0", "FIDO_2_1").
    pub versions: Vec<String>,
    /// 0x02: List of supported extensions.
    pub extensions: Vec<String>,
    /// 0x03: The AAGUID of the authenticator.
    pub aaguid: Aaguid,
    /// 0x04: Map of supported options and their values.
    pub options: BTreeMap<String, bool>,
    /// 0x05: Maximum message size supported by the authenticator (default 1024).
    pub max_msg_size: usize,
    /// 0x06: List of supported PIN/UV auth protocol versions.
    pub pin_uv_protocols: Vec<u32>,
    /// 0x07: Maximum number of credentials in a credential ID list.
    pub max_creds_in_list: Option<usize>,
    /// 0x08: Maximum credential ID length in bytes.
    pub max_cred_id_length: Option<usize>,
    /// 0x09: List of supported transports.
    pub transports: Vec<String>,
    /// 0x0A: List of supported algorithms for credential generation.
    pub algorithms: Vec<PublicKeyCredentialParameters>,
    /// 0x0B: Maximum size of the serialized large-blob array.
    pub max_large_blob: Option<usize>,
    /// 0x0C: Whether the authenticator requires a PIN change.
    pub force_pin_change: bool,
    /// 0x0D: Current minimum PIN length in Unicode code points (default 4).
    pub min_pin_length: usize,
    /// 0x0E: Firmware version of the authenticator.
    pub firmware_version: Option<u64>,
    /// 0x0F: Maximum credBlob length in bytes.
    pub max_cred_blob_length: Option<usize>,
    /// 0x10: Maximum number of RP IDs for setMinPINLength.
    pub max_rpids_for_min_pin: Option<usize>,
    /// 0x11: Preferred number of platform UV attempts before falling back.
    pub preferred_platform_uv_attempts: Option<usize>,
    /// 0x12: Bit field of supported UV modalities.
    pub uv_modality: Option<u32>,
    /// 0x13: Map of certification type to certification level.
    pub certifications: BTreeMap<String, Value>,
    /// 0x14: Estimated number of additional discoverable credentials that can be stored.
    pub remaining_disc_creds: Option<u32>,
    /// 0x15: List of vendor prototype config command identifiers.
    pub vendor_prototype_config_commands: Vec<u32>,
    /// 0x16: List of supported attestation formats (default ["packed"]).
    pub attestation_formats: Vec<String>,
    /// 0x17: Number of UV attempts since last PIN entry.
    pub uv_count_since_pin: Option<u32>,
    /// 0x18: Whether reset requires a long (10 second) touch.
    pub long_touch_for_reset: bool,
    /// 0x19: Encrypted device identifier (opaque, regenerated each getInfo call).
    pub enc_identifier: Option<Vec<u8>>,
    /// 0x1A: List of transports that must be used for reset.
    pub transports_for_reset: Vec<String>,
    /// 0x1B: Whether the authenticator enforces a PIN complexity policy beyond minPINLength.
    pub pin_complexity_policy: Option<bool>,
    /// 0x1C: URL with more information about the enforced PIN complexity policy.
    pub pin_complexity_policy_url: Option<String>,
    /// 0x1D: Maximum PIN length in Unicode code points (default 63 if absent).
    pub max_pin_length: Option<usize>,
    /// 0x1E: Encrypted credential store state (opaque, regenerated each getInfo call).
    pub enc_cred_store_state: Option<Vec<u8>>,
    /// 0x1F: List of supported authenticatorConfig subcommand values.
    pub config_commands: Vec<u32>,
}

/// A supported algorithm for credential generation (COSE algorithm parameters).
#[derive(Debug, Clone)]
pub struct PublicKeyCredentialParameters {
    /// Credential type, typically "public-key".
    pub credential_type: String,
    /// COSE algorithm identifier.
    pub alg: i64,
}

impl Info {
    /// Parse an `Info` from a CBOR map with integer keys.
    pub fn from_cbor_map(map: &[(Value, Value)]) -> Self {
        let get = |key: i64| -> Option<&Value> {
            map.iter()
                .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
                .map(|(_, v)| v)
        };

        let get_strings = |key: i64| -> Vec<String> {
            get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_text().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };

        let get_uint =
            |key: i64| -> Option<u64> { get(key).and_then(|v| v.as_int()).map(|n| n as u64) };

        let get_bool = |key: i64| -> Option<bool> { get(key).and_then(|v| v.as_bool()) };

        let get_uint_vec = |key: i64| -> Vec<u32> {
            get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_int().map(|n| n as u32))
                        .collect()
                })
                .unwrap_or_default()
        };

        let get_string_map = |key: i64| -> BTreeMap<String, Value> {
            get(key)
                .and_then(|v| v.as_map())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|(k, v)| k.as_text().map(|s| (s.to_string(), v.clone())))
                        .collect()
                })
                .unwrap_or_default()
        };

        let aaguid = get(0x03)
            .and_then(|v| v.as_bytes())
            .and_then(Aaguid::from_slice)
            .unwrap_or(Aaguid::NONE);

        let options = get(0x04)
            .and_then(|v| v.as_map())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(k, v)| {
                        k.as_text()
                            .and_then(|key| v.as_bool().map(|val| (key.to_string(), val)))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let algorithms = get(0x0A)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let map = v.as_map()?;
                        let credential_type = map
                            .iter()
                            .find(|(k, _)| k.as_text() == Some("type"))
                            .and_then(|(_, v)| v.as_text())
                            .unwrap_or("public-key")
                            .to_string();
                        let alg = map
                            .iter()
                            .find(|(k, _)| k.as_text() == Some("alg"))
                            .and_then(|(_, v)| v.as_int())?;
                        Some(PublicKeyCredentialParameters {
                            credential_type,
                            alg,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let attestation_formats = {
            let fmts = get_strings(0x16);
            if fmts.is_empty() {
                vec!["packed".to_string()]
            } else {
                fmts
            }
        };

        Info {
            versions: get_strings(0x01),
            extensions: get_strings(0x02),
            aaguid,
            options,
            max_msg_size: get_uint(0x05).unwrap_or(1024) as usize,
            pin_uv_protocols: get_uint_vec(0x06),
            max_creds_in_list: get_uint(0x07).map(|n| n as usize),
            max_cred_id_length: get_uint(0x08).map(|n| n as usize),
            transports: get_strings(0x09),
            algorithms,
            max_large_blob: get_uint(0x0B).map(|n| n as usize),
            force_pin_change: get_bool(0x0C).unwrap_or(false),
            min_pin_length: get_uint(0x0D).unwrap_or(4) as usize,
            firmware_version: get_uint(0x0E),
            max_cred_blob_length: get_uint(0x0F).map(|n| n as usize),
            max_rpids_for_min_pin: get_uint(0x10).map(|n| n as usize),
            preferred_platform_uv_attempts: get_uint(0x11).map(|n| n as usize),
            uv_modality: get_uint(0x12).map(|n| n as u32),
            certifications: get_string_map(0x13),
            remaining_disc_creds: get_uint(0x14).map(|n| n as u32),
            vendor_prototype_config_commands: get_uint_vec(0x15),
            attestation_formats,
            uv_count_since_pin: get_uint(0x17).map(|n| n as u32),
            long_touch_for_reset: get_bool(0x18).unwrap_or(false),
            enc_identifier: get(0x19).and_then(|v| v.as_bytes()).map(|b| b.to_vec()),
            transports_for_reset: get_strings(0x1A),
            pin_complexity_policy: get_bool(0x1B),
            pin_complexity_policy_url: get(0x1C)
                .and_then(|v| v.as_bytes())
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| s.to_string()),
            max_pin_length: get_uint(0x1D).map(|n| n as usize),
            enc_cred_store_state: get(0x1E).and_then(|v| v.as_bytes()).map(|b| b.to_vec()),
            config_commands: get_uint_vec(0x1F),
        }
    }
}
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// PinProtocol (V1/V2 enum dispatch)
// ---------------------------------------------------------------------------

/// COSE key agreement map for the CTAP2 PIN protocol ECDH exchange.
///
/// Represents the platform's ephemeral EC P-256 public key as a COSE_Key
/// structure (integer-keyed CBOR map).
pub type CoseKey = Value;

/// PIN/UV authentication protocol.
///
/// Implements the cryptographic operations for CTAP2 PIN/UV protocols.
/// Uses enum dispatch to support both protocol version 1 and 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    V1,
    V2,
}

impl PinProtocol {
    /// The integer version number as sent to the authenticator.
    pub fn version(&self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    /// Perform ECDH key agreement with the authenticator's public key.
    ///
    /// Returns `(platform_cose_key, shared_secret)`. The platform COSE key
    /// is sent to the authenticator; the shared secret is used locally for
    /// encrypt/decrypt/authenticate.
    pub fn encapsulate(&self, peer_cose_key: &CoseKey) -> Result<(CoseKey, Vec<u8>), String> {
        let peer_map = peer_cose_key.as_map().ok_or("peer key is not a CBOR map")?;

        let x = map_get_bytes(peer_map, -2).ok_or("missing x coordinate (-2)")?;
        let y = map_get_bytes(peer_map, -3).ok_or("missing y coordinate (-3)")?;

        if x.len() != 32 || y.len() != 32 {
            return Err("invalid coordinate length".into());
        }

        // Build uncompressed SEC1 point: 0x04 || x || y
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(x);
        uncompressed.extend_from_slice(y);
        let peer_point = EncodedPoint::from_bytes(&uncompressed)
            .map_err(|e| format!("invalid SEC1 point: {e}"))?;
        let peer_pk = PublicKey::from_encoded_point(&peer_point)
            .into_option()
            .ok_or("invalid P-256 key")?;

        // Generate ephemeral key pair
        let sk = SecretKey::random(&mut OsRng);
        let pk = sk.public_key();
        let pk_point = pk.to_encoded_point(false);

        // ECDH: raw x-coordinate of shared point
        let shared_point = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
        let z = shared_point.raw_secret_bytes();

        // KDF
        let shared_secret = self.kdf(z.as_slice());

        // Build platform COSE key
        let platform_key = Value::Map(vec![
            (Value::Int(1), Value::Int(2)),   // kty: EC2
            (Value::Int(3), Value::Int(-25)), // alg: ECDH-ES+HKDF-256 (placeholder per spec)
            (Value::Int(-1), Value::Int(1)),  // crv: P-256
            (
                Value::Int(-2),
                Value::Bytes(pk_point.x().expect("x").to_vec()),
            ),
            (
                Value::Int(-3),
                Value::Bytes(pk_point.y().expect("y").to_vec()),
            ),
        ]);

        Ok((platform_key, shared_secret))
    }

    /// Encrypt plaintext using the shared secret.
    pub fn encrypt(&self, shared_secret: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::V1 => {
                let iv = [0u8; 16];
                let enc = CbcEncryptor::<Aes256>::new(shared_secret.into(), &iv.into());
                enc.encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(plaintext)
            }
            Self::V2 => {
                let aes_key = &shared_secret[32..];
                let mut iv = [0u8; 16];
                getrandom::fill(&mut iv).expect("getrandom failed");
                let enc = CbcEncryptor::<Aes256>::new(aes_key.into(), &iv.into());
                let ct = enc.encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(plaintext);
                let mut result = iv.to_vec();
                result.extend_from_slice(&ct);
                result
            }
        }
    }

    /// Decrypt ciphertext using the shared secret.
    pub fn decrypt(&self, shared_secret: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::V1 => {
                let iv = [0u8; 16];
                let dec = CbcDecryptor::<Aes256>::new(shared_secret.into(), &iv.into());
                dec.decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(ciphertext)
                    .map_err(|e| format!("decryption failed: {e}"))
            }
            Self::V2 => {
                if ciphertext.len() < 16 {
                    return Err("ciphertext too short for IV".into());
                }
                let (iv, ct) = ciphertext.split_at(16);
                let aes_key = &shared_secret[32..];
                let dec = CbcDecryptor::<Aes256>::new(aes_key.into(), iv.into());
                dec.decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(ct)
                    .map_err(|e| format!("decryption failed: {e}"))
            }
        }
    }

    /// Compute a MAC (pinUvAuthParam) over the given message.
    pub fn authenticate(&self, shared_secret: &[u8], message: &[u8]) -> Vec<u8> {
        match self {
            Self::V1 => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(shared_secret).expect("HMAC key length");
                mac.update(message);
                mac.finalize().into_bytes()[..16].to_vec()
            }
            Self::V2 => {
                let hmac_key = &shared_secret[..32];
                let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).expect("HMAC key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Validate that a returned PIN/UV token has the correct length.
    pub fn validate_token(&self, token: &[u8]) -> Result<(), String> {
        match self {
            Self::V1 => {
                if token.len() != 16 && token.len() != 32 {
                    return Err(format!(
                        "PIN/UV token must be 16 or 32 bytes, got {}",
                        token.len()
                    ));
                }
            }
            Self::V2 => {
                if token.len() != 32 {
                    return Err(format!(
                        "PIN/UV token must be 32 bytes, got {}",
                        token.len()
                    ));
                }
            }
        }
        Ok(())
    }

    fn kdf(&self, z: &[u8]) -> Vec<u8> {
        match self {
            Self::V1 => {
                let mut hasher = Sha256::new();
                hasher.update(z);
                hasher.finalize().to_vec()
            }
            Self::V2 => {
                let salt = [0u8; 32];
                let hk = Hkdf::<Sha256>::new(Some(&salt), z);
                let mut hmac_key = [0u8; 32];
                hk.expand(b"CTAP2 HMAC key", &mut hmac_key)
                    .expect("HKDF expand");
                let hk = Hkdf::<Sha256>::new(Some(&salt), z);
                let mut aes_key = [0u8; 32];
                hk.expand(b"CTAP2 AES key", &mut aes_key)
                    .expect("HKDF expand");
                let mut result = hmac_key.to_vec();
                result.extend_from_slice(&aes_key);
                result
            }
        }
    }
}

fn map_get_bytes(map: &[(Value, Value)], key: i64) -> Option<&[u8]> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
        .and_then(|(_, v)| v.as_bytes())
}

// ---------------------------------------------------------------------------
// ClientPin sub-commands and result keys
// ---------------------------------------------------------------------------

/// ClientPin sub-command identifiers (§6.5.5).
mod client_pin_cmd {
    pub const GET_PIN_RETRIES: u8 = 0x01;
    pub const GET_KEY_AGREEMENT: u8 = 0x02;
    pub const SET_PIN: u8 = 0x03;
    pub const CHANGE_PIN: u8 = 0x04;
    pub const GET_TOKEN_USING_PIN_LEGACY: u8 = 0x05;
    pub const GET_TOKEN_USING_UV: u8 = 0x06;
    pub const GET_UV_RETRIES: u8 = 0x07;
    pub const GET_TOKEN_USING_PIN: u8 = 0x09;
}

/// ClientPin response map keys (§6.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ClientPinResult {
    KeyAgreement = 0x01,
    PinUvToken = 0x02,
    PinRetries = 0x03,
    PowerCycleState = 0x04,
    UvRetries = 0x05,
}

/// Permissions that can be associated with a PIN/UV token (§6.5.5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions(u8);

impl Permissions {
    pub const MAKE_CREDENTIAL: Self = Self(0x01);
    pub const GET_ASSERTION: Self = Self(0x02);
    pub const CREDENTIAL_MGMT: Self = Self(0x04);
    pub const BIO_ENROLL: Self = Self(0x08);
    pub const LARGE_BLOB_WRITE: Self = Self(0x10);
    pub const AUTHENTICATOR_CFG: Self = Self(0x20);

    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

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

// ---------------------------------------------------------------------------
// ClientPin
// ---------------------------------------------------------------------------

/// CTAP2 Client PIN / UV token management.
///
/// Owns a [`Ctap2Session`] and a [`PinProtocol`], providing high-level
/// PIN/UV operations: setting/changing PINs, getting PIN/UV tokens, and
/// querying retry counters.
pub struct ClientPin<C: Connection> {
    session: Ctap2Session<C>,
    protocol: PinProtocol,
}

/// Pad a PIN string per CTAP2 spec: UTF-8, left-padded to ≥64 bytes, 16-byte aligned.
fn pad_pin(pin: &str) -> Result<Vec<u8>, String> {
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
    Ok(padded)
}

impl<C: Connection + 'static> ClientPin<C> {
    /// Create a new `ClientPin` from a `Ctap2Session`, auto-selecting the best
    /// supported PIN protocol (V2 preferred over V1).
    ///
    /// Uses the cached info from the session to determine supported protocols.
    pub fn new(session: Ctap2Session<C>) -> Result<Self, Ctap2Error<C::Error>> {
        let protocol = Self::select_protocol(&session.cached_info)?;
        Ok(Self { session, protocol })
    }

    /// Create a new `ClientPin` with a specific `PinProtocol`.
    pub fn new_with_protocol(
        session: Ctap2Session<C>,
        protocol: PinProtocol,
    ) -> Result<Self, Ctap2Error<C::Error>> {
        Ok(Self { session, protocol })
    }

    /// The active PIN protocol.
    pub fn protocol(&self) -> PinProtocol {
        self.protocol
    }

    /// Consume this `ClientPin`, returning the underlying `Ctap2Session`.
    pub fn into_session(self) -> Ctap2Session<C> {
        self.session
    }

    /// Get the number of PIN retries remaining.
    ///
    /// Returns `(retries, power_cycle_state)`.
    pub fn get_pin_retries(&mut self) -> Result<(u32, Option<u32>), Ctap2Error<C::Error>> {
        let resp = self.session.client_pin(
            self.protocol.version(),
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
            .get(&(ClientPinResult::PinRetries as u32))
            .and_then(|v| v.as_int())
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing pinRetries".into()))?
            as u32;
        let pcs = resp
            .get(&(ClientPinResult::PowerCycleState as u32))
            .and_then(|v| v.as_int())
            .map(|n| n as u32);
        Ok((retries, pcs))
    }

    /// Get the number of built-in UV retries remaining.
    pub fn get_uv_retries(&mut self) -> Result<u32, Ctap2Error<C::Error>> {
        let resp = self.session.client_pin(
            self.protocol.version(),
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
            .get(&(ClientPinResult::UvRetries as u32))
            .and_then(|v| v.as_int())
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing uvRetries".into()))?
            as u32;
        Ok(retries)
    }

    /// Set a PIN on an authenticator that does not have one set.
    pub fn set_pin(&mut self, pin: &str) -> Result<(), Ctap2Error<C::Error>> {
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let pin_padded = pad_pin(pin).map_err(Ctap2Error::InvalidResponse)?;
        let new_pin_enc = self.protocol.encrypt(&shared_secret, &pin_padded);
        let pin_uv_param = self.protocol.authenticate(&shared_secret, &new_pin_enc);

        self.session.client_pin(
            self.protocol.version(),
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
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let pin_hash = &Sha256::digest(old_pin.as_bytes())[..16];
        let pin_hash_enc = self.protocol.encrypt(&shared_secret, pin_hash);
        let new_pin_padded = pad_pin(new_pin).map_err(Ctap2Error::InvalidResponse)?;
        let new_pin_enc = self.protocol.encrypt(&shared_secret, &new_pin_padded);

        // pinUvParam = authenticate(shared_secret, newPinEnc || pinHashEnc)
        let mut auth_msg = new_pin_enc.clone();
        auth_msg.extend_from_slice(&pin_hash_enc);
        let pin_uv_param = self.protocol.authenticate(&shared_secret, &auth_msg);

        self.session.client_pin(
            self.protocol.version(),
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
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let pin_hash = &Sha256::digest(pin.as_bytes())[..16];
        let pin_hash_enc = self.protocol.encrypt(&shared_secret, pin_hash);

        let (sub_cmd, perms, rpid) = if self.is_token_supported() && permissions.is_some() {
            (
                client_pin_cmd::GET_TOKEN_USING_PIN,
                permissions.map(|p| p.bits()),
                permissions_rpid,
            )
        } else {
            (client_pin_cmd::GET_TOKEN_USING_PIN_LEGACY, None, None)
        };

        let resp = self.session.client_pin(
            self.protocol.version(),
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
            .get(&(ClientPinResult::PinUvToken as u32))
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
        let (key_agreement, shared_secret) = self.get_shared_secret()?;

        let resp = self.session.client_pin(
            self.protocol.version(),
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
            .get(&(ClientPinResult::PinUvToken as u32))
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

    /// Whether the cached info indicates `clientPin` support.
    pub fn is_supported(&self) -> bool {
        self.session.cached_info.options.contains_key("clientPin")
    }

    /// Whether the cached info indicates `pinUvAuthToken` support.
    pub fn is_token_supported(&self) -> bool {
        self.session.cached_info.options.get("pinUvAuthToken") == Some(&true)
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

    fn get_shared_secret(&mut self) -> Result<(CoseKey, Vec<u8>), Ctap2Error<C::Error>> {
        let resp = self.session.client_pin(
            self.protocol.version(),
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
            .get(&(ClientPinResult::KeyAgreement as u32))
            .ok_or_else(|| Ctap2Error::InvalidResponse("missing keyAgreement".into()))?;

        self.protocol
            .encapsulate(peer_key)
            .map_err(|e| Ctap2Error::InvalidResponse(format!("key agreement failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// CredentialManagement
// ---------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;

    /// Build a minimal GetInfo CBOR map for testing.
    fn minimal_info_map() -> Value {
        Value::Map(vec![
            (
                Value::Int(0x01),
                Value::Array(vec![
                    Value::Text("FIDO_2_0".into()),
                    Value::Text("FIDO_2_1".into()),
                ]),
            ),
            (
                Value::Int(0x02),
                Value::Array(vec![Value::Text("hmac-secret".into())]),
            ),
            (Value::Int(0x03), Value::Bytes(vec![0xAA; 16])),
            (
                Value::Int(0x04),
                Value::Map(vec![
                    (Value::Text("rk".into()), Value::Bool(true)),
                    (Value::Text("up".into()), Value::Bool(true)),
                    (Value::Text("plat".into()), Value::Bool(false)),
                ]),
            ),
            (Value::Int(0x05), Value::Int(2048)),
            (
                Value::Int(0x06),
                Value::Array(vec![Value::Int(2), Value::Int(1)]),
            ),
            (Value::Int(0x07), Value::Int(8)),
            (Value::Int(0x08), Value::Int(128)),
            (
                Value::Int(0x0A),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("alg".into()), Value::Int(-7)),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ])]),
            ),
            (Value::Int(0x0D), Value::Int(6)),
            (Value::Int(0x0E), Value::Int(328965)),
            (Value::Int(0x14), Value::Int(25)),
        ])
    }

    #[test]
    fn test_info_from_cbor_map() {
        let map = minimal_info_map();
        let entries = map.as_map().unwrap();
        let info = Info::from_cbor_map(entries);

        assert_eq!(info.versions, vec!["FIDO_2_0", "FIDO_2_1"]);
        assert_eq!(info.extensions, vec!["hmac-secret"]);
        assert_eq!(info.aaguid, Aaguid::new([0xAA; 16]));
        assert_eq!(info.options.get("rk"), Some(&true));
        assert_eq!(info.options.get("plat"), Some(&false));
        assert_eq!(info.max_msg_size, 2048);
        assert_eq!(info.pin_uv_protocols, vec![2, 1]);
        assert_eq!(info.max_creds_in_list, Some(8));
        assert_eq!(info.max_cred_id_length, Some(128));
        assert_eq!(info.algorithms.len(), 1);
        assert_eq!(info.algorithms[0].alg, -7);
        assert_eq!(info.algorithms[0].credential_type, "public-key");
        assert_eq!(info.min_pin_length, 6);
        assert_eq!(info.firmware_version, Some(328965));
        assert_eq!(info.remaining_disc_creds, Some(25));
        // Defaults
        assert!(!info.force_pin_change);
        assert!(!info.long_touch_for_reset);
        assert_eq!(info.attestation_formats, vec!["packed"]);
    }

    #[test]
    fn test_info_defaults() {
        let info = Info::from_cbor_map(&[
            (
                Value::Int(0x01),
                Value::Array(vec![Value::Text("U2F_V2".into())]),
            ),
            (Value::Int(0x03), Value::Bytes(vec![0; 16])),
        ]);

        assert_eq!(info.versions, vec!["U2F_V2"]);
        assert_eq!(info.aaguid, Aaguid::NONE);
        assert_eq!(info.max_msg_size, 1024);
        assert_eq!(info.min_pin_length, 4);
        assert!(info.extensions.is_empty());
        assert!(info.options.is_empty());
        assert!(info.pin_uv_protocols.is_empty());
        assert_eq!(info.max_creds_in_list, None);
        assert_eq!(info.firmware_version, None);
    }

    #[test]
    fn test_aaguid_display() {
        let aaguid = Aaguid::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        assert_eq!(format!("{aaguid}"), "01234567-89ab-cdef-fedc-ba9876543210");
    }

    #[test]
    fn test_pin_protocol_v1_encrypt_decrypt() {
        let secret = Sha256::digest(b"test shared secret").to_vec();
        let plaintext = vec![0x42u8; 32];
        let ct = PinProtocol::V1.encrypt(&secret, &plaintext);
        let pt = PinProtocol::V1.decrypt(&secret, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_pin_protocol_v2_encrypt_decrypt() {
        // V2 shared secret is 64 bytes: 32 HMAC key + 32 AES key
        let mut secret = vec![0u8; 64];
        getrandom::fill(&mut secret).unwrap();
        let plaintext = vec![0x42u8; 64];
        let ct = PinProtocol::V2.encrypt(&secret, &plaintext);
        // V2 ciphertext has 16-byte IV prefix
        assert_eq!(ct.len(), 16 + plaintext.len());
        let pt = PinProtocol::V2.decrypt(&secret, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_pin_protocol_v1_authenticate() {
        let key = vec![0xAA; 32];
        let msg = b"hello";
        let mac = PinProtocol::V1.authenticate(&key, msg);
        assert_eq!(mac.len(), 16); // V1 truncates to 16
    }

    #[test]
    fn test_pin_protocol_v2_authenticate() {
        let key = vec![0u8; 64]; // 32 HMAC + 32 AES
        let msg = b"hello";
        let mac = PinProtocol::V2.authenticate(&key, msg);
        assert_eq!(mac.len(), 32); // V2 returns full 32 bytes
    }

    #[test]
    fn test_pin_protocol_v1_validate_token() {
        assert!(PinProtocol::V1.validate_token(&[0; 16]).is_ok());
        assert!(PinProtocol::V1.validate_token(&[0; 32]).is_ok());
        assert!(PinProtocol::V1.validate_token(&[0; 8]).is_err());
    }

    #[test]
    fn test_pin_protocol_v2_validate_token() {
        assert!(PinProtocol::V2.validate_token(&[0; 32]).is_ok());
        assert!(PinProtocol::V2.validate_token(&[0; 16]).is_err());
    }

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

    #[test]
    fn test_pin_protocol_version() {
        assert_eq!(PinProtocol::V1.version(), 1);
        assert_eq!(PinProtocol::V2.version(), 2);
    }
}
