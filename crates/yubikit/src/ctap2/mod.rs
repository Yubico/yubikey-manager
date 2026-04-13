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

mod bio_enrollment;
mod client_pin;
mod config;
mod credential_management;
mod large_blobs;
mod pin_protocol;
mod session;
pub mod types;

use std::collections::BTreeMap;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::cbor::{self, Value};
use crate::ctap::CtapError;

pub use bio_enrollment::BioEnrollment;
pub use client_pin::{ClientPin, Permissions};
pub use config::Config;
pub use credential_management::CredentialManagement;
pub use large_blobs::LargeBlobs;
pub use pin_protocol::{CoseKey, PinProtocol};
pub use session::Ctap2Session;
pub use types::{
    AssertionResponse, AttestationResponse, AuthenticatorOptions, CredentialInfo,
    EnrollSampleResult, FingerprintSensorInfo, FingerprintTemplate, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    RpInfo,
};

// ---------------------------------------------------------------------------
// CTAP2 command bytes
// ---------------------------------------------------------------------------

/// CTAP2 authenticator command identifiers.
#[allow(dead_code)]
pub(crate) mod ctap2_cmd {
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

/// Build a CBOR map with sequential integer keys (1, 2, 3, ...) from positional args.
///
/// `None` entries are skipped (their key position is still consumed).
pub(crate) fn build_args_map(args: &[Option<Value>]) -> Vec<u8> {
    let mut params: Vec<(Value, Value)> = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if let Some(val) = arg {
            params.push((Value::Int((i + 1) as i64), val.clone()));
        }
    }
    cbor::encode(&Value::Map(params))
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
                    .filter_map(PublicKeyCredentialParameters::from_cbor)
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

    /// Decrypt the encrypted device identifier using a persistent PIN/UV auth token.
    ///
    /// The identifier is encrypted by the authenticator and changes with each
    /// `getInfo` call, but decrypts to a stable value using the same persistent
    /// token. Returns `None` if the authenticator did not provide an encrypted
    /// identifier.
    pub fn get_identifier(&self, pin_token: &[u8]) -> Option<Vec<u8>> {
        self.decrypt_field(self.enc_identifier.as_deref(), b"encIdentifier", pin_token)
    }

    /// Decrypt the encrypted credential store state using a persistent PIN/UV auth token.
    ///
    /// The state value changes when credentials are added or removed, allowing
    /// the client to detect changes without re-enumerating. Returns `None` if
    /// the authenticator did not provide an encrypted credential store state.
    pub fn get_cred_store_state(&self, pin_token: &[u8]) -> Option<Vec<u8>> {
        self.decrypt_field(
            self.enc_cred_store_state.as_deref(),
            b"encCredStoreState",
            pin_token,
        )
    }

    /// Decrypt an encrypted Info field using HKDF-SHA256 + AES-256-CBC.
    fn decrypt_field(
        &self,
        encrypted: Option<&[u8]>,
        info_label: &[u8],
        pin_token: &[u8],
    ) -> Option<Vec<u8>> {
        let encrypted = encrypted?;
        if encrypted.len() < 16 {
            return None;
        }

        let salt = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&salt), pin_token);
        let mut key = [0u8; 16];
        hk.expand(info_label, &mut key).ok()?;

        let (iv, ct) = encrypted.split_at(16);
        use aes::Aes128;
        use cbc::Decryptor as CbcDecryptor;
        use cipher::{BlockDecryptMut, KeyIvInit};
        let dec = CbcDecryptor::<Aes128>::new((&key).into(), iv.into());
        dec.decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(ct)
            .ok()
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
        assert_eq!(info.algorithms[0].type_, "public-key");
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
}
