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

//! OpenPGP smart card application for YubiKeys.
//!
//! This module implements the OpenPGP card specification (ISO/IEC 7816) for
//! managing keys, PINs, certificates, and performing cryptographic operations
//! (signing, decryption, authentication) via the YubiKey's OpenPGP applet.
//!
//! The main entry point is [`OpenPgpSession`](crate::openpgp::OpenPgpSession), which wraps a smart card
//! connection and exposes high-level operations such as key generation,
//! key import, PIN management, and KDF configuration.

use std::collections::HashMap;
use std::fmt;

use sha2::Digest;
use thiserror::Error;

use crate::core::Version;
use crate::core::{bytes2int, patch_version};
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol, Sw};
use crate::tlv::{
    TlvError, int2bytes, oid_from_string, oid_to_string, parse_tlv_dict, parse_tlv_list,
    tlv_encode, tlv_unpack,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default user PIN for a factory-reset OpenPGP applet (`"123456"`).
pub const DEFAULT_USER_PIN: &str = "123456";
/// Default admin PIN for a factory-reset OpenPGP applet (`"12345678"`).
pub const DEFAULT_ADMIN_PIN: &str = "12345678";

const INVALID_PIN: &[u8] = &[0; 8];

// INS bytes
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_PIN: u8 = 0x24;
const INS_RESET_RETRY_COUNTER: u8 = 0x2C;
const INS_PSO: u8 = 0x2A;
const INS_ACTIVATE: u8 = 0x44;
const INS_GENERATE_ASYM: u8 = 0x47;
const INS_GET_CHALLENGE: u8 = 0x84;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_SELECT_DATA: u8 = 0xA5;
const INS_GET_DATA: u8 = 0xCA;
const INS_PUT_DATA: u8 = 0xDA;
const INS_PUT_DATA_ODD: u8 = 0xDB;
const INS_TERMINATE: u8 = 0xE6;
const INS_GET_VERSION: u8 = 0xF1;
const INS_SET_PIN_RETRIES: u8 = 0xF2;
const INS_GET_ATTESTATION: u8 = 0xFB;

// TLV tags used in parsing
const TAG_DISCRETIONARY: u32 = 0x73;
const TAG_EXTENDED_CAPABILITIES: u32 = 0xC0;
const TAG_FINGERPRINTS: u32 = 0xC5;
const TAG_CA_FINGERPRINTS: u32 = 0xC6;
const TAG_GENERATION_TIMES: u32 = 0xCD;
const TAG_SIGNATURE_COUNTER: u32 = 0x93;
const TAG_KEY_INFORMATION: u32 = 0xDE;
const TAG_PUBLIC_KEY: u32 = 0x7F49;

const BUTTON_FLAG: u8 = 0x20;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by OpenPGP session operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OpenPgpError {
    /// The requested feature is not supported by this YubiKey firmware version.
    #[error("Not supported: {0}")]
    NotSupported(String),
    /// The data provided or received was malformed or out of range.
    #[error("Invalid data: {0}")]
    InvalidData(String),
    /// PIN verification failed; the inner value is the number of remaining attempts.
    #[error("Invalid PIN, {0} attempts remaining")]
    InvalidPin(u32),
    /// The PIN has been blocked after too many failed attempts.
    #[error("PIN blocked")]
    PinBlocked,
    /// An underlying smart card transport error occurred.
    #[error("Connection error: {0}")]
    Connection(SmartCardError),
}

impl From<SmartCardError> for OpenPgpError {
    fn from(e: SmartCardError) -> Self {
        match e {
            SmartCardError::ApplicationNotAvailable => {
                OpenPgpError::NotSupported("Application not available".into())
            }
            SmartCardError::NotSupported(msg) => OpenPgpError::NotSupported(msg),
            SmartCardError::InvalidData(msg) => OpenPgpError::InvalidData(msg),
            other => OpenPgpError::Connection(other),
        }
    }
}

impl From<TlvError> for OpenPgpError {
    fn from(e: TlvError) -> Self {
        OpenPgpError::InvalidData(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// User Interaction Flag (UIF) setting for a key slot.
///
/// Controls whether the YubiKey requires a physical touch for operations
/// using the associated key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Uif {
    /// Touch is not required.
    Off = 0x00,
    /// Touch is required for each operation.
    On = 0x01,
    /// Touch is permanently required and cannot be changed.
    Fixed = 0x02,
    /// Touch is required but cached for a short period after use.
    Cached = 0x03,
    /// Touch is permanently required with caching; cannot be changed.
    CachedFixed = 0x04,
}

impl Uif {
    /// Convert a raw byte value to a [`Uif`] variant, if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Off),
            0x01 => Some(Self::On),
            0x02 => Some(Self::Fixed),
            0x03 => Some(Self::Cached),
            0x04 => Some(Self::CachedFixed),
            _ => None,
        }
    }

    /// Parse a UIF value from its encoded byte representation.
    pub fn parse(encoded: &[u8]) -> Option<Self> {
        encoded.first().and_then(|&v| Self::from_u8(v))
    }

    /// Returns `true` if this UIF setting is permanent and cannot be changed.
    pub fn is_fixed(self) -> bool {
        matches!(self, Uif::Fixed | Uif::CachedFixed)
    }

    /// Returns `true` if touch confirmation is cached for a short period.
    pub fn is_cached(self) -> bool {
        matches!(self, Uif::Cached | Uif::CachedFixed)
    }

    /// Encode this UIF value as a two-byte array (value byte + button flag).
    pub fn to_bytes(self) -> [u8; 2] {
        [self as u8, BUTTON_FLAG]
    }
}

/// PIN verification policy for the user (signature) PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PinPolicy {
    /// PIN must be verified before every signature operation.
    Always = 0x00,
    /// PIN verification is valid for the entire session after first use.
    Once = 0x01,
}

impl PinPolicy {
    /// Convert a byte value to a [`PinPolicy`], defaulting to [`PinPolicy::Always`].
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Once,
            _ => Self::Always,
        }
    }
}

/// Password reference identifying which PIN to operate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Pw {
    /// User PIN (PW1), used for signing and decryption.
    User = 0x81,
    /// Reset code, used to unblock the user PIN.
    Reset = 0x82,
    /// Admin PIN (PW3), used for card administration.
    Admin = 0x83,
}

/// OpenPGP Data Object (DO) tags used for reading and writing card data.
///
/// Each variant's discriminant encodes the P1/P2 bytes of the GET DATA /
/// PUT DATA APDU commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Do {
    /// Private use data object 1 (read/write with user PIN).
    PrivateUse1 = 0x0101,
    /// Private use data object 2 (read/write with user PIN).
    PrivateUse2 = 0x0102,
    /// Private use data object 3 (read/write with admin PIN).
    PrivateUse3 = 0x0103,
    /// Private use data object 4 (read/write with admin PIN).
    PrivateUse4 = 0x0104,
    /// Application identifier (AID).
    Aid = 0x4F,
    /// Cardholder name.
    Name = 0x5B,
    /// Login data (e.g. a username).
    LoginData = 0x5E,
    /// Preferred language(s) of the cardholder.
    Language = 0xEF2D,
    /// Sex of the cardholder.
    Sex = 0x5F35,
    /// URL (e.g. for public key retrieval).
    Url = 0x5F50,
    /// Historical bytes from the ATR.
    HistoricalBytes = 0x5F52,
    /// Extended length information.
    ExtendedLengthInfo = 0x7F66,
    /// General feature management DO.
    GeneralFeatureManagement = 0x7F74,
    /// Cardholder related data (composite DO).
    CardholderRelatedData = 0x65,
    /// Application related data (composite DO).
    ApplicationRelatedData = 0x6E,
    /// Algorithm attributes for the signature key slot.
    AlgorithmAttributesSig = 0xC1,
    /// Algorithm attributes for the decryption key slot.
    AlgorithmAttributesDec = 0xC2,
    /// Algorithm attributes for the authentication key slot.
    AlgorithmAttributesAut = 0xC3,
    /// Algorithm attributes for the attestation key slot.
    AlgorithmAttributesAtt = 0xDA,
    /// PW status bytes (PIN lengths, retry counters, policy).
    PwStatusBytes = 0xC4,
    /// Fingerprint of the signature key.
    FingerprintSig = 0xC7,
    /// Fingerprint of the decryption key.
    FingerprintDec = 0xC8,
    /// Fingerprint of the authentication key.
    FingerprintAut = 0xC9,
    /// Fingerprint of the attestation key.
    FingerprintAtt = 0xDB,
    /// CA fingerprint 1 (associated with signature key).
    CaFingerprint1 = 0xCA,
    /// CA fingerprint 2 (associated with decryption key).
    CaFingerprint2 = 0xCB,
    /// CA fingerprint 3 (associated with authentication key).
    CaFingerprint3 = 0xCC,
    /// CA fingerprint 4 (associated with attestation key).
    CaFingerprint4 = 0xDC,
    /// Generation timestamp for the signature key.
    GenerationTimeSig = 0xCE,
    /// Generation timestamp for the decryption key.
    GenerationTimeDec = 0xCF,
    /// Generation timestamp for the authentication key.
    GenerationTimeAut = 0xD0,
    /// Generation timestamp for the attestation key.
    GenerationTimeAtt = 0xDD,
    /// Resetting code for unblocking the user PIN.
    ResettingCode = 0xD3,
    /// User Interaction Flag for the signature key.
    UifSig = 0xD6,
    /// User Interaction Flag for the decryption key.
    UifDec = 0xD7,
    /// User Interaction Flag for the authentication key.
    UifAut = 0xD8,
    /// User Interaction Flag for the attestation key.
    UifAtt = 0xD9,
    /// Security support template (contains the signature counter).
    SecuritySupportTemplate = 0x7A,
    /// Cardholder certificate.
    CardholderCertificate = 0x7F21,
    /// Key Derivation Function (KDF) data object.
    Kdf = 0xF9,
    /// Algorithm information (list of supported algorithms per slot).
    AlgorithmInformation = 0xFA,
    /// Attestation certificate.
    AttCertificate = 0xFC,
    /// Key information (generation status of each key slot).
    KeyInformation = 0xDE,
}

impl Do {
    /// Returns the P1 byte (high byte of the DO tag) for APDU commands.
    pub fn p1(self) -> u8 {
        ((self as u16) >> 8) as u8
    }

    /// Returns the P2 byte (low byte of the DO tag) for APDU commands.
    pub fn p2(self) -> u8 {
        (self as u16) as u8
    }
}

/// Reference to one of the four OpenPGP key slots on the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyRef {
    /// Signature key slot.
    Sig = 0x01,
    /// Decryption key slot.
    Dec = 0x02,
    /// Authentication key slot.
    Aut = 0x03,
    /// Attestation key slot (YubiKey 5.2+).
    Att = 0x81,
}

impl KeyRef {
    /// Convert a raw byte value to a [`KeyRef`], if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Sig),
            0x02 => Some(Self::Dec),
            0x03 => Some(Self::Aut),
            0x81 => Some(Self::Att),
            _ => None,
        }
    }

    /// All four key slot references.
    pub const ALL: &[KeyRef] = &[KeyRef::Sig, KeyRef::Dec, KeyRef::Aut, KeyRef::Att];

    /// Returns the algorithm attributes [`Do`] tag for this key slot.
    pub fn algorithm_attributes_do(self) -> Do {
        match self {
            Self::Sig => Do::AlgorithmAttributesSig,
            Self::Dec => Do::AlgorithmAttributesDec,
            Self::Aut => Do::AlgorithmAttributesAut,
            Self::Att => Do::AlgorithmAttributesAtt,
        }
    }

    /// Returns the UIF (touch policy) [`Do`] tag for this key slot.
    pub fn uif_do(self) -> Do {
        match self {
            Self::Sig => Do::UifSig,
            Self::Dec => Do::UifDec,
            Self::Aut => Do::UifAut,
            Self::Att => Do::UifAtt,
        }
    }

    /// Returns the generation time [`Do`] tag for this key slot.
    pub fn generation_time_do(self) -> Do {
        match self {
            Self::Sig => Do::GenerationTimeSig,
            Self::Dec => Do::GenerationTimeDec,
            Self::Aut => Do::GenerationTimeAut,
            Self::Att => Do::GenerationTimeAtt,
        }
    }

    /// Returns the fingerprint [`Do`] tag for this key slot.
    pub fn fingerprint_do(self) -> Do {
        match self {
            Self::Sig => Do::FingerprintSig,
            Self::Dec => Do::FingerprintDec,
            Self::Aut => Do::FingerprintAut,
            Self::Att => Do::FingerprintAtt,
        }
    }

    /// Control Reference Template bytes for this key slot.
    pub fn crt(self) -> Vec<u8> {
        match self {
            Self::Sig => tlv_encode(0xB6, &[]),
            Self::Dec => tlv_encode(0xB8, &[]),
            Self::Aut => tlv_encode(0xA4, &[]),
            Self::Att => {
                let inner = tlv_encode(0x84, &[0x81]);
                tlv_encode(0xB6, &inner)
            }
        }
    }
}

/// Status of a key slot (whether a key has been generated, imported, or is absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyStatus {
    /// No key is present in this slot.
    None = 0,
    /// A key was generated on-card.
    Generated = 1,
    /// A key was imported from an external source.
    Imported = 2,
}

impl KeyStatus {
    /// Convert a raw byte value to a [`KeyStatus`], if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Generated),
            2 => Some(Self::Imported),
            _ => Option::None,
        }
    }
}

/// Supported RSA key sizes for key generation and import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RsaSize {
    /// 2048-bit RSA key.
    Rsa2048 = 2048,
    /// 3072-bit RSA key.
    Rsa3072 = 3072,
    /// 4096-bit RSA key.
    Rsa4096 = 4096,
}

/// RSA private key import format as indicated in the algorithm attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RsaImportFormat {
    /// Standard format: (e, p, q).
    Standard = 0,
    /// Standard format with modulus: (e, p, q, n).
    StandardWMod = 1,
    /// CRT (Chinese Remainder Theorem) format: (e, p, q, iqmp, dmp1, dmq1).
    Crt = 2,
    /// CRT format with modulus: (e, p, q, iqmp, dmp1, dmq1, n).
    CrtWMod = 3,
}

impl RsaImportFormat {
    /// Convert a raw byte value to an [`RsaImportFormat`], if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Standard),
            1 => Some(Self::StandardWMod),
            2 => Some(Self::Crt),
            3 => Some(Self::CrtWMod),
            _ => None,
        }
    }
}

/// Elliptic curve private key import format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EcImportFormat {
    /// Standard format: private scalar only.
    Standard = 0,
    /// Standard format with public key included.
    StandardWPubkey = 0xFF,
}

impl EcImportFormat {
    /// Convert a raw byte value to an [`EcImportFormat`], if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Standard),
            0xFF => Some(Self::StandardWPubkey),
            _ => None,
        }
    }
}

/// Hash algorithm identifier used in KDF (Key Derivation Function) configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// SHA-256 (OpenPGP hash algorithm ID `0x08`).
    Sha256 = 0x08,
    /// SHA-512 (OpenPGP hash algorithm ID `0x0A`).
    Sha512 = 0x0A,
}

impl HashAlgorithm {
    /// Convert a raw byte value to a [`HashAlgorithm`], if valid.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x08 => Some(Self::Sha256),
            0x0A => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Extended capability flags (bitfield).
pub mod extended_capability_flags {
    /// Device supports Key Derivation Function (KDF) for PIN hashing.
    pub const KDF: u8 = 1 << 0;
    /// Device supports PSO:DEC/ENC with AES.
    pub const PSO_DEC_ENC_AES: u8 = 1 << 1;
    /// Algorithm attributes of key slots can be changed.
    pub const ALGORITHM_ATTRIBUTES_CHANGEABLE: u8 = 1 << 2;
    /// Private use data objects are supported.
    pub const PRIVATE_USE: u8 = 1 << 3;
    /// PW status bytes (PIN policy) can be changed.
    pub const PW_STATUS_CHANGEABLE: u8 = 1 << 4;
    /// Private key import is supported.
    pub const KEY_IMPORT: u8 = 1 << 5;
    /// GET CHALLENGE command is supported.
    pub const GET_CHALLENGE: u8 = 1 << 6;
    /// Secure messaging is supported.
    pub const SECURE_MESSAGING: u8 = 1 << 7;
}

/// Well-known elliptic curve OIDs as dotted-decimal strings.
pub mod curve_oid {
    /// NIST P-256 (secp256r1 / prime256v1).
    pub const SECP256R1: &str = "1.2.840.10045.3.1.7";
    /// secp256k1 (used in Bitcoin / Ethereum).
    pub const SECP256K1: &str = "1.3.132.0.10";
    /// NIST P-384 (secp384r1).
    pub const SECP384R1: &str = "1.3.132.0.34";
    /// NIST P-521 (secp521r1).
    pub const SECP521R1: &str = "1.3.132.0.35";
    /// Brainpool P-256r1.
    pub const BRAINPOOL_P256R1: &str = "1.3.36.3.3.2.8.1.1.7";
    /// Brainpool P-384r1.
    pub const BRAINPOOL_P384R1: &str = "1.3.36.3.3.2.8.1.1.11";
    /// Brainpool P-512r1.
    pub const BRAINPOOL_P512R1: &str = "1.3.36.3.3.2.8.1.1.13";
    /// Curve25519 for ECDH (X25519).
    pub const X25519: &str = "1.3.6.1.4.1.3029.1.5.1";
    /// Curve25519 for EdDSA signatures (Ed25519).
    pub const ED25519: &str = "1.3.6.1.4.1.11591.15.1";
}

// EC algorithm IDs
const EC_ALG_ECDH: u8 = 0x12;
const EC_ALG_ECDSA: u8 = 0x13;
const EC_ALG_EDDSA: u8 = 0x16;

// RSA algorithm ID
const RSA_ALG_ID: u8 = 0x01;

// PKCS#1 v1.5 DigestInfo headers
const PKCS1_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
];
const PKCS1_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const PKCS1_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const PKCS1_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Algorithm attributes for an OpenPGP key slot (RSA or elliptic curve).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmAttributes {
    /// RSA algorithm attributes.
    Rsa(RsaAttributes),
    /// Elliptic curve algorithm attributes.
    Ec(EcAttributes),
}

impl AlgorithmAttributes {
    /// Parse algorithm attributes from their TLV-encoded representation.
    pub fn parse(encoded: &[u8]) -> Result<Self, OpenPgpError> {
        if encoded.is_empty() {
            return Err(OpenPgpError::InvalidData(
                "Empty algorithm attributes".into(),
            ));
        }
        let algorithm_id = encoded[0];
        match algorithm_id {
            RSA_ALG_ID => Ok(Self::Rsa(RsaAttributes::parse_data(&encoded[1..])?)),
            EC_ALG_ECDH | EC_ALG_ECDSA | EC_ALG_EDDSA => Ok(Self::Ec(EcAttributes::parse_data(
                algorithm_id,
                &encoded[1..],
            )?)),
            _ => Err(OpenPgpError::InvalidData(format!(
                "Unsupported algorithm ID: 0x{algorithm_id:02X}"
            ))),
        }
    }

    /// Serialize these algorithm attributes to bytes for storage on the card.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Rsa(a) => a.to_bytes(),
            Self::Ec(a) => a.to_bytes(),
        }
    }

    /// Returns the algorithm identifier byte (RSA = 0x01, EC varies).
    /// Returns the OpenPGP algorithm identifier byte.
    pub fn algorithm_id(&self) -> u8 {
        match self {
            Self::Rsa(_) => RSA_ALG_ID,
            Self::Ec(a) => a.algorithm_id,
        }
    }
}

/// RSA algorithm attributes stored on the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaAttributes {
    /// Length of the RSA modulus (n) in bits.
    pub n_len: u16,
    /// Length of the public exponent (e) in bits.
    pub e_len: u16,
    /// Private key import format.
    pub import_format: RsaImportFormat,
}

impl RsaAttributes {
    /// Create RSA attributes with the given key size and import format.
    /// Creates RSA attributes with the given key size and import format.
    pub fn create(n_len: RsaSize, import_format: RsaImportFormat) -> Self {
        Self {
            n_len: n_len as u16,
            e_len: 17,
            import_format,
        }
    }

    fn parse_data(data: &[u8]) -> Result<Self, OpenPgpError> {
        if data.len() < 5 {
            return Err(OpenPgpError::InvalidData("RSA attributes too short".into()));
        }
        let n_len = u16::from_be_bytes([data[0], data[1]]);
        let e_len = u16::from_be_bytes([data[2], data[3]]);
        let import_format = RsaImportFormat::from_u8(data[4]).ok_or_else(|| {
            OpenPgpError::InvalidData(format!("Unknown RSA import format: {}", data[4]))
        })?;
        Ok(Self {
            n_len,
            e_len,
            import_format,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![RSA_ALG_ID];
        buf.extend_from_slice(&self.n_len.to_be_bytes());
        buf.extend_from_slice(&self.e_len.to_be_bytes());
        buf.push(self.import_format as u8);
        buf
    }
}

/// Elliptic curve algorithm attributes stored on the OpenPGP card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcAttributes {
    /// EC algorithm identifier (ECDH, ECDSA, or EdDSA).
    pub algorithm_id: u8,
    /// DER-encoded curve OID bytes.
    pub oid: Vec<u8>,
    /// Private key import format.
    pub import_format: EcImportFormat,
}

impl EcAttributes {
    /// Create EC attributes for the given key slot and curve OID string.
    ///
    /// The algorithm ID is inferred automatically: EdDSA for Ed25519,
    /// ECDH for the decryption slot, and ECDSA otherwise.
    pub fn create(key_ref: KeyRef, oid_str: &str) -> Result<Self, OpenPgpError> {
        let oid_bytes = oid_from_string(oid_str)
            .map_err(|e| OpenPgpError::InvalidData(format!("Invalid OID: {e}")))?;
        let algorithm_id = if oid_str == curve_oid::ED25519 {
            EC_ALG_EDDSA
        } else if key_ref == KeyRef::Dec {
            EC_ALG_ECDH
        } else {
            EC_ALG_ECDSA
        };
        Ok(Self {
            algorithm_id,
            oid: oid_bytes,
            import_format: EcImportFormat::Standard,
        })
    }

    fn parse_data(algorithm_id: u8, data: &[u8]) -> Result<Self, OpenPgpError> {
        if data.is_empty() {
            return Err(OpenPgpError::InvalidData("EC attributes too short".into()));
        }
        let (oid, import_format) = if *data.last().unwrap() == 0xFF {
            (&data[..data.len() - 1], EcImportFormat::StandardWPubkey)
        } else {
            (data, EcImportFormat::Standard)
        };
        Ok(Self {
            algorithm_id,
            oid: oid.to_vec(),
            import_format,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.algorithm_id];
        buf.extend_from_slice(&self.oid);
        if self.import_format == EcImportFormat::StandardWPubkey {
            buf.push(0xFF);
        }
        buf
    }

    /// Returns the curve OID as a dotted-decimal string (e.g. `"1.2.840.10045.3.1.7"`).
    pub fn oid_string(&self) -> Result<String, TlvError> {
        oid_to_string(&self.oid)
    }
}

// ---------------------------------------------------------------------------
// Parsed data objects
// ---------------------------------------------------------------------------

fn bcd(value: u8) -> u8 {
    10 * (value >> 4) + (value & 0x0F)
}

/// Parsed OpenPGP Application Identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpAid {
    /// Raw AID bytes as returned by the card.
    pub raw: Vec<u8>,
}

impl OpenPgpAid {
    /// Parse an AID from raw bytes.
    pub fn parse(data: &[u8]) -> Self {
        Self { raw: data.to_vec() }
    }

    /// Returns the OpenPGP specification version as `(major, minor)`.
    pub fn version(&self) -> (u8, u8) {
        (
            bcd(*self.raw.get(6).unwrap_or(&0)),
            bcd(*self.raw.get(7).unwrap_or(&0)),
        )
    }

    /// Returns the manufacturer ID from the AID.
    pub fn manufacturer(&self) -> u16 {
        if self.raw.len() >= 10 {
            u16::from_be_bytes([self.raw[8], self.raw[9]])
        } else {
            0
        }
    }

    /// Returns the card serial number decoded from BCD.
    pub fn serial(&self) -> i64 {
        if self.raw.len() >= 14 {
            let bytes = &self.raw[10..14];
            // Try BCD decode
            let hex_str = format!(
                "{:02X}{:02X}{:02X}{:02X}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            );
            if let Ok(val) = hex_str.parse::<i64>() {
                val
            } else {
                // Not valid BCD: return unsigned int negated
                -(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
            }
        } else {
            0
        }
    }
}

/// PIN/password status bytes describing lengths, retry counters, and policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PwStatus {
    /// User PIN verification policy (once per session vs. every operation).
    pub pin_policy_user: PinPolicy,
    /// Maximum allowed length for the user PIN.
    pub max_len_user: u8,
    /// Maximum allowed length for the reset code.
    pub max_len_reset: u8,
    /// Maximum allowed length for the admin PIN.
    pub max_len_admin: u8,
    /// Remaining verification attempts for the user PIN.
    pub attempts_user: u8,
    /// Remaining verification attempts for the reset code.
    pub attempts_reset: u8,
    /// Remaining verification attempts for the admin PIN.
    pub attempts_admin: u8,
}

impl PwStatus {
    /// Parse PW status bytes from the card's encoded response (at least 7 bytes).
    pub fn parse(encoded: &[u8]) -> Result<Self, OpenPgpError> {
        if encoded.len() < 7 {
            return Err(OpenPgpError::InvalidData("PwStatus too short".into()));
        }
        Ok(Self {
            pin_policy_user: PinPolicy::from_u8(encoded[0]),
            max_len_user: encoded[1],
            max_len_reset: encoded[2],
            max_len_admin: encoded[3],
            attempts_user: encoded[4],
            attempts_reset: encoded[5],
            attempts_admin: encoded[6],
        })
    }

    /// Returns the maximum PIN length for the given password reference.
    pub fn get_max_len(&self, pw: Pw) -> u8 {
        match pw {
            Pw::User => self.max_len_user,
            Pw::Reset => self.max_len_reset,
            Pw::Admin => self.max_len_admin,
        }
    }

    /// Returns the remaining verification attempts for the given password reference.
    pub fn get_attempts(&self, pw: Pw) -> u8 {
        match pw {
            Pw::User => self.attempts_user,
            Pw::Reset => self.attempts_reset,
            Pw::Admin => self.attempts_admin,
        }
    }
}

/// Extended capabilities of the OpenPGP card, describing supported features and limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedCapabilities {
    /// Bitfield of capability flags (see [`extended_capability_flags`]).
    pub flags: u8,
    /// Secure messaging algorithm identifier.
    pub sm_algorithm: u8,
    /// Maximum number of bytes that GET CHALLENGE can return.
    pub challenge_max_length: u16,
    /// Maximum certificate storage size in bytes.
    pub certificate_max_length: u16,
    /// Maximum size of special data objects in bytes.
    pub special_do_max_length: u16,
    /// Whether PIN block 2 format is supported.
    pub pin_block_2_format: bool,
    /// Whether the MSE (Manage Security Environment) command is supported.
    pub mse_command: bool,
}

impl ExtendedCapabilities {
    /// Parse extended capabilities from the card's encoded response (at least 10 bytes).
    pub fn parse(encoded: &[u8]) -> Result<Self, OpenPgpError> {
        if encoded.len() < 10 {
            return Err(OpenPgpError::InvalidData(
                "ExtendedCapabilities too short".into(),
            ));
        }
        Ok(Self {
            flags: encoded[0],
            sm_algorithm: encoded[1],
            challenge_max_length: u16::from_be_bytes([encoded[2], encoded[3]]),
            certificate_max_length: u16::from_be_bytes([encoded[4], encoded[5]]),
            special_do_max_length: u16::from_be_bytes([encoded[6], encoded[7]]),
            pin_block_2_format: encoded[8] == 1,
            mse_command: encoded[9] == 1,
        })
    }

    /// Check whether a specific capability flag is set.
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Map of key slot references to their 20-byte SHA-1 fingerprints.
pub type Fingerprints = HashMap<KeyRef, Vec<u8>>;
/// Map of key slot references to their generation timestamps (Unix epoch seconds).
pub type GenerationTimes = HashMap<KeyRef, u32>;
/// Map of key slot references to their key status (none, generated, or imported).
pub type KeyInformation = HashMap<KeyRef, KeyStatus>;

fn parse_fingerprints(encoded: &[u8]) -> Fingerprints {
    let mut map = HashMap::new();
    for (i, key) in KeyRef::ALL.iter().enumerate() {
        let start = i * 20;
        if start + 20 <= encoded.len() {
            map.insert(*key, encoded[start..start + 20].to_vec());
        }
    }
    map
}

fn parse_timestamps(encoded: &[u8]) -> GenerationTimes {
    let mut map = HashMap::new();
    for (i, key) in KeyRef::ALL.iter().enumerate() {
        let start = i * 4;
        if start + 4 <= encoded.len() {
            let ts = u32::from_be_bytes([
                encoded[start],
                encoded[start + 1],
                encoded[start + 2],
                encoded[start + 3],
            ]);
            map.insert(*key, ts);
        }
    }
    map
}

fn parse_key_information(encoded: &[u8]) -> KeyInformation {
    let mut map = HashMap::new();
    let mut i = 0;
    while i + 1 < encoded.len() {
        if let (Some(key), Some(status)) = (
            KeyRef::from_u8(encoded[i]),
            KeyStatus::from_u8(encoded[i + 1]),
        ) {
            map.insert(key, status);
        }
        i += 2;
    }
    map
}

// ---------------------------------------------------------------------------
// Discretionary and ApplicationRelatedData
// ---------------------------------------------------------------------------

/// Parsed discretionary data objects from the application related data DO.
///
/// Contains the algorithm attributes, PIN status, key fingerprints,
/// generation timestamps, key status, and UIF settings for all key slots.
#[derive(Debug, Clone)]
pub struct DiscretionaryDataObjects {
    /// Extended capabilities of the card.
    pub extended_capabilities: ExtendedCapabilities,
    /// Algorithm attributes for the signature key slot.
    pub attributes_sig: AlgorithmAttributes,
    /// Algorithm attributes for the decryption key slot.
    pub attributes_dec: AlgorithmAttributes,
    /// Algorithm attributes for the authentication key slot.
    pub attributes_aut: AlgorithmAttributes,
    /// Algorithm attributes for the attestation key slot (if supported).
    pub attributes_att: Option<AlgorithmAttributes>,
    /// Current PIN/password status bytes.
    pub pw_status: PwStatus,
    /// SHA-1 fingerprints for each key slot.
    pub fingerprints: Fingerprints,
    /// CA fingerprints for each key slot.
    pub ca_fingerprints: Fingerprints,
    /// Key generation timestamps for each key slot.
    pub generation_times: GenerationTimes,
    /// Key status (none/generated/imported) for each key slot.
    pub key_information: KeyInformation,
    /// User Interaction Flag for the signature key.
    pub uif_sig: Option<Uif>,
    /// User Interaction Flag for the decryption key.
    pub uif_dec: Option<Uif>,
    /// User Interaction Flag for the authentication key.
    pub uif_aut: Option<Uif>,
    /// User Interaction Flag for the attestation key.
    pub uif_att: Option<Uif>,
}

impl DiscretionaryDataObjects {
    /// Parse discretionary data objects from TLV-encoded bytes.
    pub fn parse(encoded: &[u8]) -> Result<Self, OpenPgpError> {
        let data = parse_tlv_dict(encoded)?;
        Ok(Self {
            extended_capabilities: ExtendedCapabilities::parse(
                data.get(&TAG_EXTENDED_CAPABILITIES).ok_or_else(|| {
                    OpenPgpError::InvalidData("Missing extended capabilities".into())
                })?,
            )?,
            attributes_sig: AlgorithmAttributes::parse(
                data.get(&(Do::AlgorithmAttributesSig as u32))
                    .ok_or_else(|| {
                        OpenPgpError::InvalidData("Missing SIG algorithm attributes".into())
                    })?,
            )?,
            attributes_dec: AlgorithmAttributes::parse(
                data.get(&(Do::AlgorithmAttributesDec as u32))
                    .ok_or_else(|| {
                        OpenPgpError::InvalidData("Missing DEC algorithm attributes".into())
                    })?,
            )?,
            attributes_aut: AlgorithmAttributes::parse(
                data.get(&(Do::AlgorithmAttributesAut as u32))
                    .ok_or_else(|| {
                        OpenPgpError::InvalidData("Missing AUT algorithm attributes".into())
                    })?,
            )?,
            attributes_att: data
                .get(&(Do::AlgorithmAttributesAtt as u32))
                .map(|v| AlgorithmAttributes::parse(v))
                .transpose()?,
            pw_status: PwStatus::parse(
                data.get(&(Do::PwStatusBytes as u32))
                    .ok_or_else(|| OpenPgpError::InvalidData("Missing PW status bytes".into()))?,
            )?,
            fingerprints: parse_fingerprints(
                data.get(&TAG_FINGERPRINTS)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
            ),
            ca_fingerprints: parse_fingerprints(
                data.get(&TAG_CA_FINGERPRINTS)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
            ),
            generation_times: parse_timestamps(
                data.get(&TAG_GENERATION_TIMES)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
            ),
            key_information: parse_key_information(
                data.get(&TAG_KEY_INFORMATION)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
            ),
            uif_sig: data.get(&(Do::UifSig as u32)).and_then(|v| Uif::parse(v)),
            uif_dec: data.get(&(Do::UifDec as u32)).and_then(|v| Uif::parse(v)),
            uif_aut: data.get(&(Do::UifAut as u32)).and_then(|v| Uif::parse(v)),
            uif_att: data.get(&(Do::UifAtt as u32)).and_then(|v| Uif::parse(v)),
        })
    }

    /// Returns the algorithm attributes for the given key slot, if present.
    pub fn get_algorithm_attributes(&self, key_ref: KeyRef) -> Option<&AlgorithmAttributes> {
        match key_ref {
            KeyRef::Sig => Some(&self.attributes_sig),
            KeyRef::Dec => Some(&self.attributes_dec),
            KeyRef::Aut => Some(&self.attributes_aut),
            KeyRef::Att => self.attributes_att.as_ref(),
        }
    }

    /// Returns the UIF (touch policy) for the given key slot, if set.
    pub fn get_uif(&self, key_ref: KeyRef) -> Option<Uif> {
        match key_ref {
            KeyRef::Sig => self.uif_sig,
            KeyRef::Dec => self.uif_dec,
            KeyRef::Aut => self.uif_aut,
            KeyRef::Att => self.uif_att,
        }
    }
}

/// Parsed application related data (DO `0x6E`), the top-level composite
/// data object returned by the OpenPGP applet.
#[derive(Debug, Clone)]
pub struct ApplicationRelatedData {
    /// The application identifier.
    pub aid: OpenPgpAid,
    /// Historical bytes from the ATR.
    pub historical: Vec<u8>,
    /// Discretionary data objects (algorithm attributes, PIN status, etc.).
    pub discretionary: DiscretionaryDataObjects,
}

impl ApplicationRelatedData {
    /// Parse the application related data from TLV-encoded bytes.
    pub fn parse(encoded: &[u8]) -> Result<Self, OpenPgpError> {
        let outer = tlv_unpack(Do::ApplicationRelatedData as u32, encoded)?;
        let data = parse_tlv_dict(&outer)?;
        let aid_bytes = data
            .get(&(Do::Aid as u32))
            .ok_or_else(|| OpenPgpError::InvalidData("Missing AID".into()))?;
        let historical = data
            .get(&(Do::HistoricalBytes as u32))
            .cloned()
            .unwrap_or_default();

        // Discretionary data: try tag 0x73, fall back to outer dict
        // NEO (OpenPGP v2.0) has tag 0x73 with empty content, so check for that
        let disc_data = data
            .get(&TAG_DISCRETIONARY)
            .filter(|v| !v.is_empty())
            .map(|v| v.as_slice())
            .unwrap_or(&outer);
        let discretionary = DiscretionaryDataObjects::parse(disc_data)?;

        Ok(Self {
            aid: OpenPgpAid::parse(aid_bytes),
            historical,
            discretionary,
        })
    }
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

/// Key Derivation Function (KDF) configuration for PIN hashing.
///
/// When KDF is enabled, PINs are hashed on the host before being sent to the
/// card, improving resistance to passive eavesdropping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    /// KDF is disabled; PINs are sent in plaintext.
    None,
    /// Iterated-salted S2K (string-to-key) as defined in OpenPGP.
    IterSaltedS2k {
        /// Hash algorithm used for key derivation.
        hash_algorithm: HashAlgorithm,
        /// Total number of bytes to hash (controls iteration count).
        iteration_count: u32,
        /// Salt for deriving the user PIN.
        salt_user: Vec<u8>,
        /// Salt for deriving the reset code.
        salt_reset: Option<Vec<u8>>,
        /// Salt for deriving the admin PIN.
        salt_admin: Option<Vec<u8>>,
        /// Pre-computed hash of the default user PIN (for initial setup).
        initial_hash_user: Option<Vec<u8>>,
        /// Pre-computed hash of the default admin PIN (for initial setup).
        initial_hash_admin: Option<Vec<u8>>,
    },
}

impl Kdf {
    /// Parse KDF configuration from TLV-encoded bytes.
    pub fn parse(encoded: &[u8]) -> Result<Self, OpenPgpError> {
        let data = parse_tlv_dict(encoded)?;
        let algorithm = data.get(&0x81).map(|v| bytes2int(v) as u8).unwrap_or(0);

        if algorithm == 3 {
            let hash_algorithm =
                HashAlgorithm::from_u8(data.get(&0x82).map(|v| bytes2int(v) as u8).unwrap_or(0x08))
                    .unwrap_or(HashAlgorithm::Sha256);

            let iteration_count = data.get(&0x83).map(|v| bytes2int(v) as u32).unwrap_or(0);

            Ok(Kdf::IterSaltedS2k {
                hash_algorithm,
                iteration_count,
                salt_user: data.get(&0x84).cloned().unwrap_or_default(),
                salt_reset: data.get(&0x85).cloned(),
                salt_admin: data.get(&0x86).cloned(),
                initial_hash_user: data.get(&0x87).cloned(),
                initial_hash_admin: data.get(&0x88).cloned(),
            })
        } else {
            Ok(Kdf::None)
        }
    }

    /// Serialize this KDF configuration to bytes for storage on the card.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Kdf::None => tlv_encode(0x81, &[0x00]),
            Kdf::IterSaltedS2k {
                hash_algorithm,
                iteration_count,
                salt_user,
                salt_reset,
                salt_admin,
                initial_hash_user,
                initial_hash_admin,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&tlv_encode(0x81, &[0x03]));
                buf.extend_from_slice(&tlv_encode(0x82, &[*hash_algorithm as u8]));
                buf.extend_from_slice(&tlv_encode(0x83, &iteration_count.to_be_bytes()));
                buf.extend_from_slice(&tlv_encode(0x84, salt_user));
                if let Some(sr) = salt_reset {
                    buf.extend_from_slice(&tlv_encode(0x85, sr));
                }
                if let Some(sa) = salt_admin {
                    buf.extend_from_slice(&tlv_encode(0x86, sa));
                }
                if let Some(ih) = initial_hash_user {
                    buf.extend_from_slice(&tlv_encode(0x87, ih));
                }
                if let Some(ia) = initial_hash_admin {
                    buf.extend_from_slice(&tlv_encode(0x88, ia));
                }
                buf
            }
        }
    }

    /// Create a new KdfIterSaltedS2k with random salts and default PIN hashes.
    pub fn create_iter_salted_s2k(
        hash_algorithm: HashAlgorithm,
        iteration_count: u32,
    ) -> Result<Self, OpenPgpError> {
        let mut salt_user = [0u8; 8];
        let mut salt_reset = [0u8; 8];
        let mut salt_admin = [0u8; 8];
        getrandom::fill(&mut salt_user)
            .map_err(|e| OpenPgpError::InvalidData(format!("RNG error: {e}")))?;
        getrandom::fill(&mut salt_reset)
            .map_err(|e| OpenPgpError::InvalidData(format!("RNG error: {e}")))?;
        getrandom::fill(&mut salt_admin)
            .map_err(|e| OpenPgpError::InvalidData(format!("RNG error: {e}")))?;

        let initial_hash_user = kdf_s2k_hash(
            hash_algorithm,
            iteration_count,
            &salt_user,
            DEFAULT_USER_PIN,
        );
        let initial_hash_admin = kdf_s2k_hash(
            hash_algorithm,
            iteration_count,
            &salt_admin,
            DEFAULT_ADMIN_PIN,
        );

        Ok(Kdf::IterSaltedS2k {
            hash_algorithm,
            iteration_count,
            salt_user: salt_user.to_vec(),
            salt_reset: Some(salt_reset.to_vec()),
            salt_admin: Some(salt_admin.to_vec()),
            initial_hash_user: Some(initial_hash_user),
            initial_hash_admin: Some(initial_hash_admin),
        })
    }

    /// Apply KDF processing to a PIN for the given password reference.
    ///
    /// When KDF is [`Kdf::None`], the raw PIN bytes are returned.
    /// Otherwise the PIN is hashed with the appropriate salt.
    pub fn process(&self, pw: Pw, pin: &str) -> Vec<u8> {
        match self {
            Kdf::None => pin.as_bytes().to_vec(),
            Kdf::IterSaltedS2k {
                hash_algorithm,
                iteration_count,
                salt_user,
                salt_reset,
                salt_admin,
                ..
            } => {
                let salt = match pw {
                    Pw::User => salt_user.as_slice(),
                    Pw::Reset => salt_reset.as_deref().unwrap_or(salt_user.as_slice()),
                    Pw::Admin => salt_admin.as_deref().unwrap_or(salt_user.as_slice()),
                };
                kdf_s2k_hash(*hash_algorithm, *iteration_count, salt, pin)
            }
        }
    }
}

/// Iterated-salted S2K hash: hash `iteration_count` bytes of (salt || pin) repeated.
fn kdf_s2k_hash(
    hash_algorithm: HashAlgorithm,
    iteration_count: u32,
    salt: &[u8],
    pin: &str,
) -> Vec<u8> {
    let data: Vec<u8> = [salt, pin.as_bytes()].concat();
    let count = iteration_count as usize;
    let (full_rounds, trailing) = if data.is_empty() {
        (0, 0)
    } else {
        (count / data.len(), count % data.len())
    };

    match hash_algorithm {
        HashAlgorithm::Sha256 => {
            let mut digest = sha2::Sha256::new();
            for _ in 0..full_rounds {
                digest.update(&data);
            }
            if trailing > 0 {
                digest.update(&data[..trailing]);
            }
            digest.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut digest = sha2::Sha512::new();
            for _ in 0..full_rounds {
                digest.update(&data);
            }
            if trailing > 0 {
                digest.update(&data[..trailing]);
            }
            digest.finalize().to_vec()
        }
    }
}

// ---------------------------------------------------------------------------
// Private Key Template (for import)
// ---------------------------------------------------------------------------

/// A private key to be imported into an OpenPGP key slot.
#[derive(Clone)]
pub enum OpenPgpPrivateKey {
    /// RSA private key in standard format (e, p, q).
    Rsa {
        /// Public exponent.
        e: Vec<u8>,
        /// First prime factor.
        p: Vec<u8>,
        /// Second prime factor.
        q: Vec<u8>,
    },
    /// RSA private key in CRT (Chinese Remainder Theorem) format.
    RsaCrt {
        /// Public exponent.
        e: Vec<u8>,
        /// First prime factor.
        p: Vec<u8>,
        /// Second prime factor.
        q: Vec<u8>,
        /// CRT coefficient: q^{-1} mod p.
        iqmp: Vec<u8>,
        /// CRT exponent: d mod (p-1).
        dmp1: Vec<u8>,
        /// CRT exponent: d mod (q-1).
        dmq1: Vec<u8>,
        /// Public modulus n = p * q.
        n: Vec<u8>,
    },
    /// Elliptic curve private key.
    Ec {
        /// Private scalar value.
        scalar: Vec<u8>,
        /// Optional uncompressed public key point.
        public_key: Option<Vec<u8>>,
    },
}

impl fmt::Debug for OpenPgpPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenPgpPrivateKey::Rsa { .. } => write!(f, "OpenPgpPrivateKey::Rsa(..)"),
            OpenPgpPrivateKey::RsaCrt { .. } => write!(f, "OpenPgpPrivateKey::RsaCrt(..)"),
            OpenPgpPrivateKey::Ec { .. } => write!(f, "OpenPgpPrivateKey::Ec(..)"),
        }
    }
}

/// Build the private key template for PUT_DATA_ODD (tag 0x4D).
fn build_private_key_template(key_ref: KeyRef, private_key: &OpenPgpPrivateKey) -> Vec<u8> {
    let component_tlvs: Vec<(u32, &[u8])> = match private_key {
        OpenPgpPrivateKey::Rsa { e, p, q } => {
            vec![
                (0x91, e.as_slice()),
                (0x92, p.as_slice()),
                (0x93, q.as_slice()),
            ]
        }
        OpenPgpPrivateKey::RsaCrt {
            e,
            p,
            q,
            iqmp,
            dmp1,
            dmq1,
            n,
        } => vec![
            (0x91, e.as_slice()),
            (0x92, p.as_slice()),
            (0x93, q.as_slice()),
            (0x94, iqmp.as_slice()),
            (0x95, dmp1.as_slice()),
            (0x96, dmq1.as_slice()),
            (0x97, n.as_slice()),
        ],
        OpenPgpPrivateKey::Ec { scalar, public_key } => {
            let mut v = vec![(0x92, scalar.as_slice())];
            if let Some(pk) = public_key {
                v.push((0x99, pk.as_slice()));
            }
            v
        }
    };

    // 0x7F48: concatenated tag+length headers (no values)
    let mut headers = Vec::new();
    // 0x5F48: concatenated values
    let mut values = Vec::new();
    for (tag, value) in &component_tlvs {
        let encoded = tlv_encode(*tag, value);
        // Header = everything before the value = tag + length bytes
        let header_len = encoded.len() - value.len();
        headers.extend_from_slice(&encoded[..header_len]);
        values.extend_from_slice(value);
    }

    let mut inner = key_ref.crt();
    inner.extend_from_slice(&tlv_encode(0x7F48, &headers));
    inner.extend_from_slice(&tlv_encode(0x5F48, &values));

    tlv_encode(0x4D, &inner)
}

// ---------------------------------------------------------------------------
// Padding helpers for sign/authenticate
// ---------------------------------------------------------------------------

/// Hash algorithm enum for sign/authenticate operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignHashAlgorithm {
    /// SHA-1 hash (legacy; 160-bit digest).
    Sha1,
    /// SHA-256 hash (256-bit digest).
    Sha256,
    /// SHA-384 hash (384-bit digest).
    Sha384,
    /// SHA-512 hash (512-bit digest).
    Sha512,
    /// Data is already hashed; the wrapped algorithm selects the DigestInfo header for RSA.
    Prehashed(PrehashAlgorithm),
    /// EdDSA: no hashing, pass message directly.
    None,
}

/// The hash algorithm used to produce a prehashed digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrehashAlgorithm {
    /// SHA-1 was used to produce the digest.
    Sha1,
    /// SHA-256 was used to produce the digest.
    Sha256,
    /// SHA-384 was used to produce the digest.
    Sha384,
    /// SHA-512 was used to produce the digest.
    Sha512,
}

fn pad_message(
    attributes: &AlgorithmAttributes,
    message: &[u8],
    hash_algorithm: SignHashAlgorithm,
) -> Result<Vec<u8>, OpenPgpError> {
    // EdDSA: never hash
    if attributes.algorithm_id() == EC_ALG_EDDSA {
        return Ok(message.to_vec());
    }

    let hashed = match hash_algorithm {
        SignHashAlgorithm::Prehashed(_) => message.to_vec(),
        SignHashAlgorithm::None => message.to_vec(),
        SignHashAlgorithm::Sha1 => {
            let mut h = sha1::Sha1::new();
            h.update(message);
            h.finalize().to_vec()
        }
        SignHashAlgorithm::Sha256 => {
            let mut h = sha2::Sha256::new();
            h.update(message);
            h.finalize().to_vec()
        }
        SignHashAlgorithm::Sha384 => {
            let mut h = sha2::Sha384::new();
            h.update(message);
            h.finalize().to_vec()
        }
        SignHashAlgorithm::Sha512 => {
            let mut h = sha2::Sha512::new();
            h.update(message);
            h.finalize().to_vec()
        }
    };

    match attributes {
        AlgorithmAttributes::Ec(_) => Ok(hashed),
        AlgorithmAttributes::Rsa(_) => {
            let header = match hash_algorithm {
                SignHashAlgorithm::Sha1 => PKCS1_SHA1,
                SignHashAlgorithm::Sha256 => PKCS1_SHA256,
                SignHashAlgorithm::Sha384 => PKCS1_SHA384,
                SignHashAlgorithm::Sha512 => PKCS1_SHA512,
                SignHashAlgorithm::Prehashed(algo) => match algo {
                    PrehashAlgorithm::Sha1 => PKCS1_SHA1,
                    PrehashAlgorithm::Sha256 => PKCS1_SHA256,
                    PrehashAlgorithm::Sha384 => PKCS1_SHA384,
                    PrehashAlgorithm::Sha512 => PKCS1_SHA512,
                },
                SignHashAlgorithm::None => {
                    return Err(OpenPgpError::InvalidData(
                        "Hash algorithm required for RSA".into(),
                    ));
                }
            };
            let mut padded = header.to_vec();
            padded.extend_from_slice(&hashed);
            Ok(padded)
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// An active session with the OpenPGP applet on a YubiKey.
///
/// Provides methods for PIN management, key generation and import,
/// cryptographic operations (sign, decrypt, authenticate), certificate
/// management, and card configuration.
pub struct OpenPgpSession<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
    app_data: ApplicationRelatedData,
}

impl<C: SmartCardConnection> OpenPgpSession<C> {
    /// Open an OpenPGP session on the given connection.
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new(connection: C) -> Result<Self, (OpenPgpError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);

        // SELECT OpenPGP application; auto-activate if needed
        match protocol.select(Aid::OPENPGP) {
            Ok(_) => {}
            Err(SmartCardError::Apdu { sw, .. }) if sw == 0x6285 || sw == 0x6985 => {
                if let Err(e) = protocol.send_apdu(0, INS_ACTIVATE, 0, 0, &[]) {
                    return Err((e.into(), protocol.into_connection()));
                }
                if let Err(e) = protocol.select(Aid::OPENPGP) {
                    return Err((e.into(), protocol.into_connection()));
                }
            }
            Err(e) => return Err((e.into(), protocol.into_connection())),
        }

        Self::init(protocol)
    }

    /// Open an OpenPGP session with SCP (Secure Channel Protocol).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, (OpenPgpError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);

        // SELECT OpenPGP application; auto-activate if needed
        match protocol.select(Aid::OPENPGP) {
            Ok(_) => {}
            Err(SmartCardError::Apdu { sw, .. }) if sw == 0x6285 || sw == 0x6985 => {
                if let Err(e) = protocol.send_apdu(0, INS_ACTIVATE, 0, 0, &[]) {
                    return Err((e.into(), protocol.into_connection()));
                }
                if let Err(e) = protocol.select(Aid::OPENPGP) {
                    return Err((e.into(), protocol.into_connection()));
                }
            }
            Err(e) => return Err((e.into(), protocol.into_connection())),
        }

        if let Err(e) = protocol.init_scp(scp_key_params) {
            return Err((e.into(), protocol.into_connection()));
        }
        Self::init(protocol)
    }

    fn init(mut protocol: SmartCardProtocol<C>) -> Result<Self, (OpenPgpError, C)> {
        log::debug!("Opening OpenPgpSession");
        // Read version (BCD encoded)
        let version = match protocol.send_apdu(0, INS_GET_VERSION, 0, 0, &[]) {
            Ok(bcd_bytes) => Version(
                bcd(*bcd_bytes.first().unwrap_or(&0)),
                bcd(*bcd_bytes.get(1).unwrap_or(&0)),
                bcd(*bcd_bytes.get(2).unwrap_or(&0)),
            ),
            Err(SmartCardError::Apdu { sw: 0x6985, .. }) => Version(1, 0, 0),
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        let version = patch_version(version);

        protocol.configure(version);

        // Cache application related data
        let app_data_raw = match protocol.send_apdu(
            0,
            INS_GET_DATA,
            Do::ApplicationRelatedData.p1(),
            Do::ApplicationRelatedData.p2(),
            &[],
        ) {
            Ok(v) => v,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        let app_data = match ApplicationRelatedData::parse(&app_data_raw) {
            Ok(v) => v,
            Err(e) => return Err((e, protocol.into_connection())),
        };

        Ok(Self {
            protocol,
            version,
            app_data,
        })
    }

    // -- Accessors --

    /// Returns the application identifier for this OpenPGP session.
    pub fn aid(&self) -> &OpenPgpAid {
        &self.app_data.aid
    }

    /// Returns the YubiKey firmware version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the card's extended capabilities.
    pub fn extended_capabilities(&self) -> &ExtendedCapabilities {
        &self.app_data.discretionary.extended_capabilities
    }

    /// Returns a reference to the underlying smart card protocol.
    pub fn protocol(&self) -> &SmartCardProtocol<C> {
        &self.protocol
    }

    /// Returns a mutable reference to the underlying smart card protocol.
    pub fn protocol_mut(&mut self) -> &mut SmartCardProtocol<C> {
        &mut self.protocol
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        self.protocol.into_connection()
    }

    // -- Data Object I/O --

    /// Read a data object from the card by its [`Do`] tag.
    pub fn get_data(&mut self, data_object: Do) -> Result<Vec<u8>, OpenPgpError> {
        Ok(self
            .protocol
            .send_apdu(0, INS_GET_DATA, data_object.p1(), data_object.p2(), &[])?)
    }

    /// Write a data object to the card by its [`Do`] tag.
    pub fn put_data(&mut self, data_object: Do, data: &[u8]) -> Result<(), OpenPgpError> {
        self.protocol
            .send_apdu(0, INS_PUT_DATA, data_object.p1(), data_object.p2(), data)?;
        Ok(())
    }

    // -- Status / Metadata --

    /// Read the current PIN status (retry counters, max lengths, and policy).
    pub fn get_pin_status(&mut self) -> Result<PwStatus, OpenPgpError> {
        let data = self.get_data(Do::PwStatusBytes)?;
        PwStatus::parse(&data)
    }

    /// Read the global signature counter from the security support template.
    pub fn get_signature_counter(&mut self) -> Result<u32, OpenPgpError> {
        let data = self.get_data(Do::SecuritySupportTemplate)?;
        let inner = tlv_unpack(Do::SecuritySupportTemplate as u32, &data)?;
        let dict = parse_tlv_dict(&inner)?;
        let counter_bytes = dict
            .get(&TAG_SIGNATURE_COUNTER)
            .ok_or_else(|| OpenPgpError::InvalidData("Missing signature counter".into()))?;
        Ok(bytes2int(counter_bytes) as u32)
    }

    /// Read and parse the full application related data from the card.
    pub fn get_application_related_data(&mut self) -> Result<ApplicationRelatedData, OpenPgpError> {
        let data = self.get_data(Do::ApplicationRelatedData)?;
        let mut app_data = ApplicationRelatedData::parse(&data)?;
        // Pre 3.0: UIF readable separately but missing from discretionary
        if app_data.aid.version() < (3, 0) {
            app_data.discretionary.uif_sig = self.get_uif(KeyRef::Sig).ok();
            app_data.discretionary.uif_dec = self.get_uif(KeyRef::Dec).ok();
            app_data.discretionary.uif_aut = self.get_uif(KeyRef::Aut).ok();
        }
        Ok(app_data)
    }

    /// Read the key information (status of each key slot) from the card.
    pub fn get_key_information(&mut self) -> Result<KeyInformation, OpenPgpError> {
        Ok(self
            .get_application_related_data()?
            .discretionary
            .key_information)
    }

    /// Read the key generation timestamps for all key slots.
    pub fn get_generation_times(&mut self) -> Result<GenerationTimes, OpenPgpError> {
        Ok(self
            .get_application_related_data()?
            .discretionary
            .generation_times)
    }

    /// Read the key fingerprints for all key slots.
    pub fn get_fingerprints(&mut self) -> Result<Fingerprints, OpenPgpError> {
        Ok(self
            .get_application_related_data()?
            .discretionary
            .fingerprints)
    }

    // -- PIN Management --

    fn process_pin(&self, kdf: &Kdf, pw: Pw, pin: &str) -> Result<Vec<u8>, OpenPgpError> {
        if matches!(kdf, Kdf::None) {
            let pin_len = pin.len();
            let min_len: usize = if matches!(pw, Pw::User) { 6 } else { 8 };
            let max_len = self.app_data.discretionary.pw_status.get_max_len(pw) as usize;
            if pin_len < min_len || pin_len > max_len {
                return Err(OpenPgpError::InvalidData(format!(
                    "PIN length must be in the range {min_len}-{max_len}"
                )));
            }
        }
        Ok(kdf.process(pw, pin))
    }

    fn verify_inner(&mut self, pw: Pw, pin: &str, mode: u8) -> Result<(), OpenPgpError> {
        let kdf = self.get_kdf()?;
        let pin_enc = self.process_pin(&kdf, pw, pin)?;
        match self
            .protocol
            .send_apdu(0, INS_VERIFY, 0, pw as u8 + mode, &pin_enc)
        {
            Ok(_) => Ok(()),
            Err(SmartCardError::Apdu { sw, .. })
                if sw == 0x6982 || (sw >> 8 == 0x63 && self.version < Version(4, 0, 0)) =>
            {
                let attempts = self.get_pin_status()?.get_attempts(pw) as u32;
                Err(OpenPgpError::InvalidPin(attempts))
            }
            Err(SmartCardError::Apdu { sw: 0x6983, .. }) => Err(OpenPgpError::PinBlocked),
            Err(e) => Err(e.into()),
        }
    }

    /// Verify the user PIN. If `extended` is true, uses extended mode (PW1 for signing).
    pub fn verify_pin(&mut self, pin: &str, extended: bool) -> Result<(), OpenPgpError> {
        let mode = if extended { 1 } else { 0 };
        self.verify_inner(Pw::User, pin, mode)
    }

    /// Verify the admin PIN.
    pub fn verify_admin(&mut self, admin_pin: &str) -> Result<(), OpenPgpError> {
        self.verify_inner(Pw::Admin, admin_pin, 0)
    }

    /// Clear the verification state of the given PIN (requires YubiKey 5.6.0+).
    pub fn unverify_pin(&mut self, pw: Pw) -> Result<(), OpenPgpError> {
        require_version(self.version, Version(5, 6, 0), "unverify_pin")?;
        self.protocol
            .send_apdu(0, INS_VERIFY, 0xFF, pw as u8, &[])?;
        Ok(())
    }

    fn change_inner(&mut self, pw: Pw, pin: &str, new_pin: &str) -> Result<(), OpenPgpError> {
        let kdf = self.get_kdf()?;
        let mut data = self.process_pin(&kdf, pw, pin)?;
        data.extend_from_slice(&self.process_pin(&kdf, pw, new_pin)?);
        match self
            .protocol
            .send_apdu(0, INS_CHANGE_PIN, 0, pw as u8, &data)
        {
            Ok(_) => Ok(()),
            Err(SmartCardError::Apdu { sw, .. })
                if sw == 0x6982 || (sw == 0x6985 && self.version < Version(4, 0, 0)) =>
            {
                let attempts = self.get_pin_status()?.get_attempts(pw) as u32;
                Err(OpenPgpError::InvalidPin(attempts))
            }
            Err(SmartCardError::Apdu { sw: 0x6983, .. }) => Err(OpenPgpError::PinBlocked),
            Err(e) => Err(e.into()),
        }
    }

    /// Change the user PIN from `pin` to `new_pin`.
    pub fn change_pin(&mut self, pin: &str, new_pin: &str) -> Result<(), OpenPgpError> {
        self.change_inner(Pw::User, pin, new_pin)
    }

    /// Change the admin PIN from `admin_pin` to `new_admin_pin`.
    pub fn change_admin(
        &mut self,
        admin_pin: &str,
        new_admin_pin: &str,
    ) -> Result<(), OpenPgpError> {
        self.change_inner(Pw::Admin, admin_pin, new_admin_pin)
    }

    /// Set the resetting code used to unblock the user PIN.
    pub fn set_reset_code(&mut self, reset_code: &str) -> Result<(), OpenPgpError> {
        let kdf = self.get_kdf()?;
        let data = self.process_pin(&kdf, Pw::Reset, reset_code)?;
        self.put_data(Do::ResettingCode, &data)
    }

    /// Reset the user PIN to `new_pin`, optionally using a reset code.
    ///
    /// If `reset_code` is `None`, the admin PIN must have been verified first.
    pub fn reset_pin(
        &mut self,
        new_pin: &str,
        reset_code: Option<&str>,
    ) -> Result<(), OpenPgpError> {
        let kdf = self.get_kdf()?;
        let new_pin_data = self.process_pin(&kdf, Pw::User, new_pin)?;
        let (p1, data) = if let Some(code) = reset_code {
            let mut d = self.process_pin(&kdf, Pw::Reset, code)?;
            d.extend_from_slice(&new_pin_data);
            (0u8, d)
        } else {
            (2u8, new_pin_data)
        };

        match self
            .protocol
            .send_apdu(0, INS_RESET_RETRY_COUNTER, p1, Pw::User as u8, &data)
        {
            Ok(_) => Ok(()),
            Err(SmartCardError::Apdu { sw, .. }) if sw == 0x6982 && reset_code.is_some() => {
                let attempts = self.get_pin_status()?.attempts_reset as u32;
                Err(OpenPgpError::InvalidPin(attempts))
            }
            Err(SmartCardError::Apdu { sw, .. })
                if (sw == 0x6983 || sw == 0x6A80) && reset_code.is_some() =>
            {
                Err(OpenPgpError::PinBlocked)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Set the signature PIN policy (verify once per session or every operation).
    pub fn set_signature_pin_policy(&mut self, pin_policy: PinPolicy) -> Result<(), OpenPgpError> {
        self.put_data(Do::PwStatusBytes, &[pin_policy as u8])
    }

    /// Set the maximum retry attempts for user PIN, reset code, and admin PIN.
    pub fn set_pin_attempts(
        &mut self,
        user_attempts: u8,
        reset_attempts: u8,
        admin_attempts: u8,
    ) -> Result<(), OpenPgpError> {
        if self.version.0 == 1 {
            require_version(self.version, Version(1, 0, 7), "set_pin_attempts")?;
        } else {
            require_version(self.version, Version(4, 3, 1), "set_pin_attempts")?;
        }
        self.protocol.send_apdu(
            0,
            INS_SET_PIN_RETRIES,
            0,
            0,
            &[user_attempts, reset_attempts, admin_attempts],
        )?;
        Ok(())
    }

    // -- KDF --

    /// Read the current KDF configuration from the card.
    pub fn get_kdf(&mut self) -> Result<Kdf, OpenPgpError> {
        if !self
            .app_data
            .discretionary
            .extended_capabilities
            .has_flag(extended_capability_flags::KDF)
        {
            return Ok(Kdf::None);
        }
        let data = self.get_data(Do::Kdf)?;
        Kdf::parse(&data)
    }

    /// Write a new KDF configuration to the card.
    pub fn set_kdf(&mut self, kdf: &Kdf) -> Result<(), OpenPgpError> {
        if !self
            .app_data
            .discretionary
            .extended_capabilities
            .has_flag(extended_capability_flags::KDF)
        {
            return Err(OpenPgpError::NotSupported("KDF is not supported".into()));
        }
        self.put_data(Do::Kdf, &kdf.to_bytes())
    }

    // -- Factory Reset --

    /// Perform a factory reset of the OpenPGP applet, erasing all keys and settings.
    pub fn reset(&mut self) -> Result<(), OpenPgpError> {
        require_version(self.version, Version(1, 0, 6), "reset")?;

        // Block PINs by sending invalid PINs
        let status = self.get_pin_status()?;
        for pw in [Pw::User, Pw::Admin] {
            let attempts = status.get_attempts(pw);
            for _ in 0..attempts {
                let _ = self
                    .protocol
                    .send_apdu(0, INS_VERIFY, 0, pw as u8, INVALID_PIN);
            }
        }

        // TERMINATE + ACTIVATE
        self.protocol.send_apdu(0, INS_TERMINATE, 0, 0, &[])?;
        self.protocol.send_apdu(0, INS_ACTIVATE, 0, 0, &[])?;
        Ok(())
    }

    // -- Algorithm Attributes --

    /// Read the current algorithm attributes for a key slot.
    pub fn get_algorithm_attributes(
        &mut self,
        key_ref: KeyRef,
    ) -> Result<AlgorithmAttributes, OpenPgpError> {
        let data = self.get_application_related_data()?;
        data.discretionary
            .get_algorithm_attributes(key_ref)
            .cloned()
            .ok_or_else(|| {
                OpenPgpError::InvalidData(format!("No algorithm attributes for key {:?}", key_ref))
            })
    }

    /// Read the list of supported algorithms for each key slot.
    pub fn get_algorithm_information(
        &mut self,
    ) -> Result<HashMap<KeyRef, Vec<AlgorithmAttributes>>, OpenPgpError> {
        if !self
            .app_data
            .discretionary
            .extended_capabilities
            .has_flag(extended_capability_flags::ALGORITHM_ATTRIBUTES_CHANGEABLE)
        {
            return Err(OpenPgpError::NotSupported(
                "Writing Algorithm Attributes is not supported".into(),
            ));
        }

        if self.version < Version(5, 2, 0) && self.version.0 > 0 {
            // Pre-5.2 hardcoded support
            let fmt = if 0 < self.version.0 && self.version.0 < 4 {
                RsaImportFormat::CrtWMod
            } else {
                RsaImportFormat::Standard
            };
            let mut sizes = vec![RsaSize::Rsa2048];
            if self.version.0 >= 4 && (self.version.0, self.version.1) != (4, 4) {
                sizes.push(RsaSize::Rsa3072);
                sizes.push(RsaSize::Rsa4096);
            }
            let attrs: Vec<AlgorithmAttributes> = sizes
                .iter()
                .map(|&s| AlgorithmAttributes::Rsa(RsaAttributes::create(s, fmt)))
                .collect();
            let mut map = HashMap::new();
            map.insert(KeyRef::Sig, attrs.clone());
            map.insert(KeyRef::Dec, attrs.clone());
            map.insert(KeyRef::Aut, attrs);
            return Ok(map);
        }

        let buf = self.get_data(Do::AlgorithmInformation)?;
        // Try to unpack outer TLV; handle trailing-zero quirk
        let inner = match tlv_unpack(Do::AlgorithmInformation as u32, &buf) {
            Ok(v) => v,
            Err(_) => {
                let mut padded = buf.clone();
                padded.extend_from_slice(&[0, 0]);
                let v = tlv_unpack(Do::AlgorithmInformation as u32, &padded)?;
                if v.len() >= 2 {
                    v[..v.len() - 2].to_vec()
                } else {
                    v
                }
            }
        };

        let entries = parse_tlv_list(&inner)?;
        let slot_map: HashMap<u32, KeyRef> = [
            (Do::AlgorithmAttributesSig as u32, KeyRef::Sig),
            (Do::AlgorithmAttributesDec as u32, KeyRef::Dec),
            (Do::AlgorithmAttributesAut as u32, KeyRef::Aut),
            (Do::AlgorithmAttributesAtt as u32, KeyRef::Att),
        ]
        .into();

        let mut result: HashMap<KeyRef, Vec<AlgorithmAttributes>> = HashMap::new();
        for (tag, value) in &entries {
            if let Some(&key) = slot_map.get(tag)
                && let Ok(attrs) = AlgorithmAttributes::parse(value)
            {
                result.entry(key).or_default().push(attrs);
            }
        }

        Ok(result)
    }

    /// Set the algorithm attributes for a key slot.
    pub fn set_algorithm_attributes(
        &mut self,
        key_ref: KeyRef,
        attributes: &AlgorithmAttributes,
    ) -> Result<(), OpenPgpError> {
        self.put_data(key_ref.algorithm_attributes_do(), &attributes.to_bytes())
    }

    // -- UIF (Touch) --

    /// Read the User Interaction Flag (touch policy) for a key slot.
    pub fn get_uif(&mut self, key_ref: KeyRef) -> Result<Uif, OpenPgpError> {
        if self.version >= Version(4, 2, 0) {
            let data = self.get_data(key_ref.uif_do())?;
            Uif::parse(&data).ok_or_else(|| OpenPgpError::InvalidData("Invalid UIF value".into()))
        } else {
            Ok(Uif::Off)
        }
    }

    /// Set the User Interaction Flag (touch policy) for a key slot.
    pub fn set_uif(&mut self, key_ref: KeyRef, uif: Uif) -> Result<(), OpenPgpError> {
        require_version(self.version, Version(4, 2, 0), "set_uif")?;
        if key_ref == KeyRef::Att {
            require_version(self.version, Version(5, 2, 1), "set_uif for ATT key")?;
        }
        if uif.is_cached() {
            require_version(self.version, Version(5, 2, 1), "cached UIF")?;
        }

        let current = self.get_uif(key_ref)?;
        if current.is_fixed() {
            return Err(OpenPgpError::InvalidData(
                "Cannot change UIF when set to FIXED".into(),
            ));
        }

        self.put_data(key_ref.uif_do(), &uif.to_bytes())
    }

    // -- Key Metadata --

    /// Set the key generation timestamp for a key slot (Unix epoch seconds).
    pub fn set_generation_time(
        &mut self,
        key_ref: KeyRef,
        timestamp: u32,
    ) -> Result<(), OpenPgpError> {
        self.put_data(key_ref.generation_time_do(), &timestamp.to_be_bytes())
    }

    /// Set the key fingerprint for a key slot.
    pub fn set_fingerprint(
        &mut self,
        key_ref: KeyRef,
        fingerprint: &[u8],
    ) -> Result<(), OpenPgpError> {
        self.put_data(key_ref.fingerprint_do(), fingerprint)
    }

    // -- Key Generation --

    /// Generate an RSA key pair on-card and return the raw public key data.
    pub fn generate_rsa_key(
        &mut self,
        key_ref: KeyRef,
        key_size: RsaSize,
    ) -> Result<Vec<u8>, OpenPgpError> {
        if self.version >= Version(4, 2, 0) && self.version < Version(4, 3, 5) {
            return Err(OpenPgpError::NotSupported(
                "RSA key generation not supported on this YubiKey".into(),
            ));
        }

        if self
            .app_data
            .discretionary
            .extended_capabilities
            .has_flag(extended_capability_flags::ALGORITHM_ATTRIBUTES_CHANGEABLE)
        {
            let import_format = if 0 < self.version.0 && self.version.0 < 4 {
                RsaImportFormat::CrtWMod
            } else {
                RsaImportFormat::Standard
            };
            let attributes =
                AlgorithmAttributes::Rsa(RsaAttributes::create(key_size, import_format));
            self.set_algorithm_attributes(key_ref, &attributes)?;
        } else if key_size as u16 != RsaSize::Rsa2048 as u16 {
            return Err(OpenPgpError::NotSupported(
                "Algorithm attributes not supported".into(),
            ));
        }

        let crt = key_ref.crt();
        let resp = self
            .protocol
            .send_apdu(0, INS_GENERATE_ASYM, 0x80, 0x00, &crt)?;
        let pk_data = tlv_unpack(TAG_PUBLIC_KEY, &resp)?;
        Ok(pk_data)
    }

    /// Generate an EC key pair on-card for the given curve and return the raw public key data.
    pub fn generate_ec_key(
        &mut self,
        key_ref: KeyRef,
        curve_oid: &str,
    ) -> Result<Vec<u8>, OpenPgpError> {
        require_version(self.version, Version(5, 2, 0), "generate_ec_key")?;

        let attributes = AlgorithmAttributes::Ec(EcAttributes::create(key_ref, curve_oid)?);
        self.set_algorithm_attributes(key_ref, &attributes)?;

        let crt = key_ref.crt();
        let resp = self
            .protocol
            .send_apdu(0, INS_GENERATE_ASYM, 0x80, 0x00, &crt)?;
        let pk_data = tlv_unpack(TAG_PUBLIC_KEY, &resp)?;
        Ok(pk_data)
    }

    /// Read the public key from a key slot without generating a new one.
    pub fn get_public_key(&mut self, key_ref: KeyRef) -> Result<Vec<u8>, OpenPgpError> {
        let crt = key_ref.crt();
        let resp = self
            .protocol
            .send_apdu(0, INS_GENERATE_ASYM, 0x81, 0x00, &crt)?;
        let pk_data = tlv_unpack(TAG_PUBLIC_KEY, &resp)?;
        Ok(pk_data)
    }

    // -- Key Import / Delete --

    /// Import a private key into a key slot.
    pub fn put_key(
        &mut self,
        key_ref: KeyRef,
        private_key: &OpenPgpPrivateKey,
    ) -> Result<(), OpenPgpError> {
        let template = build_private_key_template(key_ref, private_key);
        self.protocol
            .send_apdu(0, INS_PUT_DATA_ODD, 0x3F, 0xFF, &template)?;
        Ok(())
    }

    /// Delete the key in a slot by resetting its algorithm attributes.
    pub fn delete_key(&mut self, key_ref: KeyRef) -> Result<(), OpenPgpError> {
        if 0 < self.version.0 && self.version.0 < 4 {
            // NEO: overwrite with a dummy RSA key import is not easily supported
            // without generating a real key; use put_data to change attributes instead
            return Err(OpenPgpError::NotSupported(
                "delete_key on NEO requires full key import".into(),
            ));
        }
        // Delete by changing key attributes twice
        self.put_data(
            key_ref.algorithm_attributes_do(),
            &AlgorithmAttributes::Rsa(RsaAttributes::create(
                RsaSize::Rsa4096,
                RsaImportFormat::Standard,
            ))
            .to_bytes(),
        )?;
        self.set_algorithm_attributes(
            key_ref,
            &AlgorithmAttributes::Rsa(RsaAttributes::create(
                RsaSize::Rsa2048,
                RsaImportFormat::Standard,
            )),
        )?;
        Ok(())
    }

    // -- Crypto Operations --

    /// Perform a signing operation using the SIG key slot (PSO: COMPUTE DIGITAL SIGNATURE).
    pub fn sign(
        &mut self,
        message: &[u8],
        hash_algorithm: SignHashAlgorithm,
    ) -> Result<Vec<u8>, OpenPgpError> {
        let attributes = self.get_algorithm_attributes(KeyRef::Sig)?;
        let padded = pad_message(&attributes, message, hash_algorithm)?;
        let response = self.protocol.send_apdu(0, INS_PSO, 0x9E, 0x9A, &padded)?;
        Ok(response)
    }

    /// Perform a decryption operation using the DEC key slot (PSO: DECIPHER).
    pub fn decrypt(&mut self, value: &[u8]) -> Result<Vec<u8>, OpenPgpError> {
        let attributes = self.get_algorithm_attributes(KeyRef::Dec)?;
        let data = match &attributes {
            AlgorithmAttributes::Rsa(_) => {
                let mut d = vec![0x00];
                d.extend_from_slice(value);
                d
            }
            AlgorithmAttributes::Ec(_) => {
                let inner = tlv_encode(0x86, value);
                let mid = tlv_encode(0x7F49, &inner);
                tlv_encode(0xA6, &mid)
            }
        };
        let response = self.protocol.send_apdu(0, INS_PSO, 0x80, 0x86, &data)?;
        Ok(response)
    }

    /// Perform an authentication operation using the AUT key slot (INTERNAL AUTHENTICATE).
    pub fn authenticate(
        &mut self,
        message: &[u8],
        hash_algorithm: SignHashAlgorithm,
    ) -> Result<Vec<u8>, OpenPgpError> {
        let attributes = self.get_algorithm_attributes(KeyRef::Aut)?;
        let padded = pad_message(&attributes, message, hash_algorithm)?;
        let response =
            self.protocol
                .send_apdu(0, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, &padded)?;
        Ok(response)
    }

    // -- Certificate Management --

    fn select_certificate(&mut self, key_ref: KeyRef) -> Result<(), OpenPgpError> {
        if self.version >= Version(5, 2, 0) {
            let do_bytes = int2bytes(Do::CardholderCertificate as u64);
            let inner = tlv_encode(0x5C, &do_bytes);
            let mut outer = tlv_encode(0x60, &inner);
            if self.version <= Version(5, 4, 3) {
                // Non-standard leading byte
                let mut patched = vec![0x06];
                patched.extend_from_slice(&outer);
                outer = patched;
            }
            // Index: 3 - key_ref for SIG(1)→2, DEC(2)→1, AUT(3)→0
            let index = 3u8.saturating_sub(key_ref as u8);
            self.protocol
                .send_apdu(0, INS_SELECT_DATA, index, 0x04, &outer)?;
        } else if key_ref != KeyRef::Aut {
            return Err(OpenPgpError::NotSupported(
                "Certificate slot selection requires v5.2.0+".into(),
            ));
        }
        Ok(())
    }

    /// Read the certificate stored for a key slot (DER-encoded X.509).
    pub fn get_certificate(&mut self, key_ref: KeyRef) -> Result<Vec<u8>, OpenPgpError> {
        if key_ref == KeyRef::Att {
            require_version(self.version, Version(5, 2, 0), "ATT certificate")?;
            let data = self.get_data(Do::AttCertificate)?;
            if data.is_empty() {
                return Err(OpenPgpError::InvalidData("No certificate found".into()));
            }
            return Ok(data);
        }
        self.select_certificate(key_ref)?;
        let data = self.get_data(Do::CardholderCertificate)?;
        if data.is_empty() {
            return Err(OpenPgpError::InvalidData("No certificate found".into()));
        }
        Ok(data)
    }

    /// Write a DER-encoded X.509 certificate to a key slot.
    pub fn put_certificate(
        &mut self,
        key_ref: KeyRef,
        cert_der: &[u8],
    ) -> Result<(), OpenPgpError> {
        if key_ref == KeyRef::Att {
            require_version(self.version, Version(5, 2, 0), "ATT certificate")?;
            return self.put_data(Do::AttCertificate, cert_der);
        }
        self.select_certificate(key_ref)?;
        self.put_data(Do::CardholderCertificate, cert_der)
    }

    /// Delete the certificate stored for a key slot.
    pub fn delete_certificate(&mut self, key_ref: KeyRef) -> Result<(), OpenPgpError> {
        if key_ref == KeyRef::Att {
            require_version(self.version, Version(5, 2, 0), "ATT certificate")?;
            return self.put_data(Do::AttCertificate, &[]);
        }
        self.select_certificate(key_ref)?;
        self.put_data(Do::CardholderCertificate, &[])
    }

    /// Generate an attestation certificate for a key slot (YubiKey 5.2+).
    pub fn attest_key(&mut self, key_ref: KeyRef) -> Result<Vec<u8>, OpenPgpError> {
        require_version(self.version, Version(5, 2, 0), "attest_key")?;
        self.protocol
            .send_apdu(0x80, INS_GET_ATTESTATION, key_ref as u8, 0, &[])?;
        self.get_certificate(key_ref)
    }

    // -- Challenge --

    /// Request random bytes from the card's RNG (GET CHALLENGE).
    pub fn get_challenge(&mut self, length: u16) -> Result<Vec<u8>, OpenPgpError> {
        let ec = &self.app_data.discretionary.extended_capabilities;
        if !ec.has_flag(extended_capability_flags::GET_CHALLENGE) {
            return Err(OpenPgpError::NotSupported(
                "GET_CHALLENGE is not supported".into(),
            ));
        }
        if length == 0 || length > ec.challenge_max_length {
            return Err(OpenPgpError::InvalidData(
                "Unsupported challenge length".into(),
            ));
        }
        // Send GET CHALLENGE with Le = length
        // The protocol's send_apdu uses data=[], so Le is handled by providing empty data
        // and the card returns `length` random bytes.
        // We pass length in P1/P2=0 and rely on card behavior.
        let resp = self
            .protocol
            .send_apdu_with_le(0, INS_GET_CHALLENGE, 0, 0, &[], length)?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Safe Reset
// ---------------------------------------------------------------------------

/// Performs an OpenPGP factory reset without requiring a working session.
///
/// Unlike [`OpenPgpSession::reset`], this operates directly on a connection
/// and avoids reading application data that may be corrupted. It blocks all
/// PINs by repeatedly verifying with invalid values, then issues TERMINATE
/// and ACTIVATE to restore the application to its factory state.
pub fn safe_reset<C: SmartCardConnection>(connection: C) -> Result<(), SmartCardError> {
    let mut protocol = SmartCardProtocol::new(connection);
    protocol.select(Aid::OPENPGP)?;

    for pw in [Pw::User, Pw::Admin] {
        loop {
            match protocol.send_apdu(0, INS_VERIFY, 0, pw as u8, INVALID_PIN) {
                Err(SmartCardError::Apdu { sw, .. })
                    if sw == Sw::SecurityConditionNotSatisfied as u16 =>
                {
                    // PIN not yet blocked, try again
                    continue;
                }
                _ => break,
            }
        }
    }

    protocol.send_apdu(0, INS_TERMINATE, 0, 0, &[])?;
    protocol.send_apdu(0, INS_ACTIVATE, 0, 0, &[])?;
    Ok(())
}

fn require_version(current: Version, required: Version, feature: &str) -> Result<(), OpenPgpError> {
    crate::core::require_version(current, required, feature).map_err(OpenPgpError::NotSupported)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::tlv_parse;

    #[test]
    fn test_uif_properties() {
        assert!(!Uif::Off.is_fixed());
        assert!(!Uif::Off.is_cached());
        assert!(!Uif::On.is_fixed());
        assert!(Uif::Fixed.is_fixed());
        assert!(Uif::Cached.is_cached());
        assert!(Uif::CachedFixed.is_fixed());
        assert!(Uif::CachedFixed.is_cached());
    }

    #[test]
    fn test_uif_to_bytes() {
        assert_eq!(Uif::Off.to_bytes(), [0x00, 0x20]);
        assert_eq!(Uif::On.to_bytes(), [0x01, 0x20]);
        assert_eq!(Uif::Fixed.to_bytes(), [0x02, 0x20]);
    }

    #[test]
    fn test_uif_parse() {
        assert_eq!(Uif::parse(&[0x00, 0x20]), Some(Uif::Off));
        assert_eq!(Uif::parse(&[0x03, 0x20]), Some(Uif::Cached));
        assert_eq!(Uif::parse(&[]), None);
    }

    #[test]
    fn test_do_p1_p2() {
        assert_eq!(Do::ApplicationRelatedData.p1(), 0x00);
        assert_eq!(Do::ApplicationRelatedData.p2(), 0x6E);
        assert_eq!(Do::PrivateUse1.p1(), 0x01);
        assert_eq!(Do::PrivateUse1.p2(), 0x01);
        assert_eq!(Do::Language.p1(), 0xEF);
        assert_eq!(Do::Language.p2(), 0x2D);
    }

    #[test]
    fn test_key_ref_crt() {
        let sig_crt = KeyRef::Sig.crt();
        // Should be TLV(0xB6, empty)
        assert_eq!(sig_crt, vec![0xB6, 0x00]);

        let att_crt = KeyRef::Att.crt();
        // TLV(0xB6, TLV(0x84, [0x81]))
        assert_eq!(att_crt, vec![0xB6, 0x03, 0x84, 0x01, 0x81]);
    }

    #[test]
    fn test_rsa_attributes_roundtrip() {
        let attrs = RsaAttributes::create(RsaSize::Rsa2048, RsaImportFormat::Standard);
        let bytes = attrs.to_bytes();
        assert_eq!(bytes, vec![0x01, 0x08, 0x00, 0x00, 0x11, 0x00]);
        let parsed = AlgorithmAttributes::parse(&bytes).unwrap();
        match parsed {
            AlgorithmAttributes::Rsa(r) => {
                assert_eq!(r.n_len, 2048);
                assert_eq!(r.e_len, 17);
                assert_eq!(r.import_format, RsaImportFormat::Standard);
            }
            _ => panic!("Expected RSA"),
        }
    }

    #[test]
    fn test_ec_attributes_roundtrip() {
        let attrs = EcAttributes::create(KeyRef::Sig, curve_oid::ED25519).unwrap();
        assert_eq!(attrs.algorithm_id, EC_ALG_EDDSA);
        let bytes = attrs.to_bytes();
        let parsed = AlgorithmAttributes::parse(&bytes).unwrap();
        match parsed {
            AlgorithmAttributes::Ec(e) => {
                assert_eq!(e.algorithm_id, EC_ALG_EDDSA);
                assert_eq!(e.import_format, EcImportFormat::Standard);
                assert_eq!(e.oid_string().unwrap(), curve_oid::ED25519);
            }
            _ => panic!("Expected EC"),
        }
    }

    #[test]
    fn test_ec_attributes_ecdh_for_dec() {
        let attrs = EcAttributes::create(KeyRef::Dec, curve_oid::SECP256R1).unwrap();
        assert_eq!(attrs.algorithm_id, EC_ALG_ECDH);
    }

    #[test]
    fn test_ec_attributes_ecdsa_for_sig() {
        let attrs = EcAttributes::create(KeyRef::Sig, curve_oid::SECP256R1).unwrap();
        assert_eq!(attrs.algorithm_id, EC_ALG_ECDSA);
    }

    #[test]
    fn test_pw_status_parse() {
        let data = [0x01, 127, 127, 127, 3, 0, 3];
        let status = PwStatus::parse(&data).unwrap();
        assert_eq!(status.pin_policy_user, PinPolicy::Once);
        assert_eq!(status.max_len_user, 127);
        assert_eq!(status.attempts_user, 3);
        assert_eq!(status.attempts_admin, 3);
    }

    #[test]
    fn test_extended_capabilities_parse() {
        let data = [0xFF, 0x01, 0x00, 0x80, 0x04, 0x00, 0x04, 0x00, 0x01, 0x01];
        let ec = ExtendedCapabilities::parse(&data).unwrap();
        assert!(ec.has_flag(extended_capability_flags::KDF));
        assert!(ec.has_flag(extended_capability_flags::SECURE_MESSAGING));
        assert_eq!(ec.challenge_max_length, 128);
        assert_eq!(ec.certificate_max_length, 1024);
        assert!(ec.pin_block_2_format);
        assert!(ec.mse_command);
    }

    #[test]
    fn test_openpgp_aid_parse() {
        // Minimal 16-byte AID
        let mut raw = vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
        raw.push(0x03); // version major BCD 03 → 3
        raw.push(0x04); // version minor BCD 04 → 4
        raw.push(0x00); // manufacturer high
        raw.push(0x06); // manufacturer low = 6 (Yubico)
        raw.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // serial BCD
        raw.extend_from_slice(&[0x00, 0x00]); // padding

        let aid = OpenPgpAid::parse(&raw);
        assert_eq!(aid.version(), (3, 4));
        assert_eq!(aid.manufacturer(), 6);
        assert_eq!(aid.serial(), 12345678);
    }

    #[test]
    fn test_kdf_none_roundtrip() {
        let kdf = Kdf::None;
        let bytes = kdf.to_bytes();
        assert_eq!(bytes, vec![0x81, 0x01, 0x00]);
        let parsed = Kdf::parse(&bytes).unwrap();
        assert_eq!(parsed, Kdf::None);
    }

    #[test]
    fn test_kdf_none_process() {
        let kdf = Kdf::None;
        assert_eq!(kdf.process(Pw::User, "123456"), b"123456");
    }

    #[test]
    fn test_kdf_s2k_hash_basic() {
        let result = kdf_s2k_hash(HashAlgorithm::Sha256, 14, b"saltslt", "123456");
        // salt(7 bytes) + pin(6 bytes) = 13 bytes
        // iteration_count=14 → 1 full round + 1 trailing byte
        assert_eq!(result.len(), 32); // SHA256 output
    }

    #[test]
    fn test_kdf_iter_salted_s2k_roundtrip() {
        let kdf = Kdf::IterSaltedS2k {
            hash_algorithm: HashAlgorithm::Sha256,
            iteration_count: 0x780000,
            salt_user: vec![1, 2, 3, 4, 5, 6, 7, 8],
            salt_reset: Some(vec![9, 10, 11, 12, 13, 14, 15, 16]),
            salt_admin: Some(vec![17, 18, 19, 20, 21, 22, 23, 24]),
            initial_hash_user: None,
            initial_hash_admin: None,
        };
        let bytes = kdf.to_bytes();
        let parsed = Kdf::parse(&bytes).unwrap();
        assert_eq!(parsed, kdf);
    }

    #[test]
    fn test_parse_fingerprints() {
        let mut data = vec![0u8; 80]; // 4 * 20 bytes
        data[0] = 0xAA; // SIG fingerprint first byte
        data[20] = 0xBB; // DEC fingerprint first byte
        let fps = parse_fingerprints(&data);
        assert_eq!(fps[&KeyRef::Sig][0], 0xAA);
        assert_eq!(fps[&KeyRef::Dec][0], 0xBB);
        assert_eq!(fps.len(), 4);
    }

    #[test]
    fn test_parse_timestamps() {
        let data = [
            0x00, 0x00, 0x00, 0x01, // SIG = 1
            0x00, 0x00, 0x00, 0x02, // DEC = 2
            0x00, 0x00, 0x00, 0x03, // AUT = 3
            0x00, 0x00, 0x00, 0x04, // ATT = 4
        ];
        let ts = parse_timestamps(&data);
        assert_eq!(ts[&KeyRef::Sig], 1);
        assert_eq!(ts[&KeyRef::Dec], 2);
        assert_eq!(ts[&KeyRef::Aut], 3);
        assert_eq!(ts[&KeyRef::Att], 4);
    }

    #[test]
    fn test_parse_key_information() {
        let data = [0x01, 0x01, 0x02, 0x02, 0x03, 0x00];
        let ki = parse_key_information(&data);
        assert_eq!(ki[&KeyRef::Sig], KeyStatus::Generated);
        assert_eq!(ki[&KeyRef::Dec], KeyStatus::Imported);
        assert_eq!(ki[&KeyRef::Aut], KeyStatus::None);
    }

    #[test]
    fn test_build_private_key_template_ec() {
        let key = OpenPgpPrivateKey::Ec {
            scalar: vec![0x01, 0x02, 0x03],
            public_key: None,
        };
        let template = build_private_key_template(KeyRef::Sig, &key);
        // Should start with 0x4D tag
        assert_eq!(template[0], 0x4D);
    }

    #[test]
    fn test_build_private_key_template_rsa() {
        let key = OpenPgpPrivateKey::Rsa {
            e: vec![0x01, 0x00, 0x01],
            p: vec![0xAA; 128],
            q: vec![0xBB; 128],
        };
        let template = build_private_key_template(KeyRef::Sig, &key);
        assert_eq!(template[0], 0x4D);
    }

    #[test]
    fn test_build_private_key_template_rsa_crt() {
        let key = OpenPgpPrivateKey::RsaCrt {
            e: vec![0x01, 0x00, 0x01],
            p: vec![0xAA; 128],
            q: vec![0xBB; 128],
            iqmp: vec![0xCC; 128],
            dmp1: vec![0xDD; 128],
            dmq1: vec![0xEE; 128],
            n: vec![0xFF; 256],
        };
        let template = build_private_key_template(KeyRef::Sig, &key);
        assert_eq!(template[0], 0x4D);
        // Parse outer TLV to verify structure
        let (tag, val_off, val_len, _) = tlv_parse(&template, 0).unwrap();
        assert_eq!(tag, 0x4D);
        let inner = &template[val_off..val_off + val_len];
        // Inner starts with CRT (B6 00)
        assert!(inner.starts_with(&[0xB6, 0x00]));
    }

    #[test]
    fn test_pad_message_eddsa_no_hash() {
        let attrs = AlgorithmAttributes::Ec(EcAttributes {
            algorithm_id: EC_ALG_EDDSA,
            oid: oid_from_string(curve_oid::ED25519).unwrap(),
            import_format: EcImportFormat::Standard,
        });
        let msg = b"hello world";
        let padded = pad_message(&attrs, msg, SignHashAlgorithm::None).unwrap();
        assert_eq!(padded, msg);
    }

    #[test]
    fn test_pad_message_rsa_sha256() {
        let attrs = AlgorithmAttributes::Rsa(RsaAttributes::create(
            RsaSize::Rsa2048,
            RsaImportFormat::Standard,
        ));
        let msg = b"test message";
        let padded = pad_message(&attrs, msg, SignHashAlgorithm::Sha256).unwrap();
        // PKCS1_SHA256 header (19 bytes) + SHA256 hash (32 bytes) = 51 bytes
        assert_eq!(padded.len(), 19 + 32);
        assert!(padded.starts_with(PKCS1_SHA256));
    }

    #[test]
    fn test_pad_message_ec_sha256() {
        let attrs = AlgorithmAttributes::Ec(EcAttributes {
            algorithm_id: EC_ALG_ECDSA,
            oid: oid_from_string(curve_oid::SECP256R1).unwrap(),
            import_format: EcImportFormat::Standard,
        });
        let msg = b"test message";
        let padded = pad_message(&attrs, msg, SignHashAlgorithm::Sha256).unwrap();
        // EC just returns the hash, SHA256 = 32 bytes
        assert_eq!(padded.len(), 32);
    }

    #[test]
    fn test_require_version_ok() {
        assert!(require_version(Version(5, 3, 0), Version(5, 2, 0), "test").is_ok());
    }

    #[test]
    fn test_require_version_fail() {
        let err = require_version(Version(4, 1, 0), Version(5, 2, 0), "test").unwrap_err();
        match err {
            OpenPgpError::NotSupported(msg) => assert!(msg.contains("test")),
            _ => panic!("Expected NotSupported"),
        }
    }

    #[test]
    fn test_bytes2int() {
        assert_eq!(bytes2int(&[]), 0);
        assert_eq!(bytes2int(&[0x01]), 1);
        assert_eq!(bytes2int(&[0x01, 0x00]), 256);
        assert_eq!(bytes2int(&[0xFF, 0xFF]), 65535);
    }

    #[test]
    fn test_key_ref_all() {
        assert_eq!(KeyRef::ALL.len(), 4);
        assert_eq!(KeyRef::ALL[0], KeyRef::Sig);
        assert_eq!(KeyRef::ALL[3], KeyRef::Att);
    }

    #[test]
    fn test_pin_policy_from_u8() {
        assert_eq!(PinPolicy::from_u8(0x00), PinPolicy::Always);
        assert_eq!(PinPolicy::from_u8(0x01), PinPolicy::Once);
        assert_eq!(PinPolicy::from_u8(0xFF), PinPolicy::Always); // fallback
    }

    #[test]
    fn test_key_ref_associated_dos() {
        assert_eq!(
            KeyRef::Sig.algorithm_attributes_do() as u16,
            Do::AlgorithmAttributesSig as u16
        );
        assert_eq!(KeyRef::Dec.uif_do() as u16, Do::UifDec as u16);
        assert_eq!(
            KeyRef::Aut.generation_time_do() as u16,
            Do::GenerationTimeAut as u16
        );
        assert_eq!(
            KeyRef::Att.fingerprint_do() as u16,
            Do::FingerprintAtt as u16
        );
    }
}
