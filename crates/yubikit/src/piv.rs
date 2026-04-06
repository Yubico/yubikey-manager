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

use std::cell::RefCell;
use std::fmt;
use std::io::{Read, Write};

use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::TdesEde3;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use sha2::Digest;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x509_cert::der;
use x509_cert::der::asn1::BitString;
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::{
    self, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    ObjectIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

use crate::core::Version;
use crate::core::patch_version;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol, Sw};
use crate::tlv::{int2bytes, parse_tlv_dict, tlv_encode, tlv_parse, tlv_unpack};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PivError {
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Invalid PIN, {0} attempts remaining")]
    InvalidPin(u32),
    #[error("Connection error: {0}")]
    Connection(SmartCardError),
}

impl From<SmartCardError> for PivError {
    fn from(e: SmartCardError) -> Self {
        match e {
            SmartCardError::ApplicationNotAvailable => {
                PivError::NotSupported("Application not available".into())
            }
            SmartCardError::NotSupported(msg) => PivError::NotSupported(msg),
            SmartCardError::InvalidData(msg) => PivError::InvalidData(msg),
            other => PivError::Connection(other),
        }
    }
}

impl From<crate::tlv::TlvError> for PivError {
    fn from(e: crate::tlv::TlvError) -> Self {
        PivError::InvalidData(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Algorithm enum (str-like)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Ec,
    Rsa,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Ec => write!(f, "ec"),
            Algorithm::Rsa => write!(f, "rsa"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyType {
    Rsa1024 = 0x06,
    Rsa2048 = 0x07,
    Rsa3072 = 0x05,
    Rsa4096 = 0x16,
    EccP256 = 0x11,
    EccP384 = 0x14,
    Ed25519 = 0xE0,
    X25519 = 0xE1,
}

impl KeyType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x06 => Some(Self::Rsa1024),
            0x07 => Some(Self::Rsa2048),
            0x05 => Some(Self::Rsa3072),
            0x16 => Some(Self::Rsa4096),
            0x11 => Some(Self::EccP256),
            0x14 => Some(Self::EccP384),
            0xE0 => Some(Self::Ed25519),
            0xE1 => Some(Self::X25519),
            _ => None,
        }
    }

    pub fn algorithm(self) -> Algorithm {
        match self {
            Self::Rsa1024 | Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => Algorithm::Rsa,
            _ => Algorithm::Ec,
        }
    }

    pub fn bit_len(self) -> u32 {
        match self {
            Self::Rsa1024 => 1024,
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::EccP256 => 256,
            Self::EccP384 => 384,
            Self::Ed25519 | Self::X25519 => 256,
        }
    }

    /// Detect key type from a SubjectPublicKeyInfo DER encoding.
    pub fn from_public_key_der(der: &[u8]) -> Result<Self, PivError> {
        Self::detect_algorithm_from_der(der, false)
    }

    /// Detect key type from a PKCS#8 PrivateKeyInfo DER encoding.
    pub fn from_private_key_der(der: &[u8]) -> Result<Self, PivError> {
        Self::detect_algorithm_from_der(der, true)
    }

    fn detect_algorithm_from_der(der: &[u8], is_private: bool) -> Result<Self, PivError> {
        // Parse outer SEQUENCE
        let (_, seq_off, seq_len, _) =
            tlv_parse(der, 0).map_err(|_| PivError::InvalidData("Invalid DER".into()))?;
        let seq_data = &der[seq_off..seq_off + seq_len];

        // For PKCS#8 PrivateKeyInfo, skip the version INTEGER
        let algo_start = if is_private {
            let (_, _, _, ver_end) = tlv_parse(seq_data, 0)
                .map_err(|_| PivError::InvalidData("Invalid version INTEGER".into()))?;
            ver_end
        } else {
            0
        };

        // Parse AlgorithmIdentifier SEQUENCE
        let (_, algo_off, algo_len, algo_end) = tlv_parse(seq_data, algo_start)
            .map_err(|_| PivError::InvalidData("Invalid AlgorithmIdentifier".into()))?;
        let algo_data = &seq_data[algo_off..algo_off + algo_len];

        // Parse OID
        let (_, oid_off, oid_len, _) =
            tlv_parse(algo_data, 0).map_err(|_| PivError::InvalidData("Invalid OID".into()))?;
        let oid = &algo_data[oid_off..oid_off + oid_len];

        // RSA OID: 1.2.840.113549.1.1.1
        const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        // EC OID: 1.2.840.10045.2.1
        const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        // Ed25519 OID: 1.3.101.112
        const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
        // X25519 OID: 1.3.101.110
        const X25519_OID: &[u8] = &[0x2b, 0x65, 0x6e];

        if oid == RSA_OID {
            // For public keys: BIT STRING containing SEQUENCE { modulus, exponent }
            // For private keys: OCTET STRING containing SEQUENCE { version, modulus, ... }
            let (tag, data_off, data_len, _) = tlv_parse(seq_data, algo_end)
                .map_err(|_| PivError::InvalidData("Invalid key data".into()))?;
            let key_data = if tag == 0x03 {
                // BIT STRING: skip unused-bits prefix byte
                &seq_data[data_off + 1..data_off + data_len]
            } else if tag == 0x04 {
                // OCTET STRING: content is RSAPrivateKey directly
                &seq_data[data_off..data_off + data_len]
            } else {
                return Err(PivError::InvalidData(
                    "Expected BIT STRING or OCTET STRING".into(),
                ));
            };
            // Parse inner SEQUENCE
            let (_, inner_off, inner_len, _) = tlv_parse(key_data, 0)
                .map_err(|_| PivError::InvalidData("Invalid RSA inner SEQUENCE".into()))?;
            let inner = &key_data[inner_off..inner_off + inner_len];
            // For private keys, skip version INTEGER first
            let mod_start = if is_private {
                let (_, _, _, ver_end) = tlv_parse(inner, 0)
                    .map_err(|_| PivError::InvalidData("Invalid RSA version".into()))?;
                ver_end
            } else {
                0
            };
            // Parse modulus INTEGER
            let (_, mod_off, mod_len, _) = tlv_parse(inner, mod_start)
                .map_err(|_| PivError::InvalidData("Invalid RSA modulus".into()))?;
            let modulus = &inner[mod_off..mod_off + mod_len];
            // Strip leading zero if present
            let mod_bytes = if !modulus.is_empty() && modulus[0] == 0 {
                modulus.len() - 1
            } else {
                modulus.len()
            };
            let bit_len = mod_bytes * 8;
            match bit_len {
                1024 => Ok(Self::Rsa1024),
                2048 => Ok(Self::Rsa2048),
                3072 => Ok(Self::Rsa3072),
                4096 => Ok(Self::Rsa4096),
                _ => Err(PivError::InvalidData(format!(
                    "Unsupported RSA key size: {bit_len}"
                ))),
            }
        } else if oid == EC_OID {
            // Parse curve OID parameter
            let (_, curve_off, curve_len, _) = tlv_parse(algo_data, oid_off + oid_len)
                .map_err(|_| PivError::InvalidData("Invalid EC curve OID".into()))?;
            let curve_oid = &algo_data[curve_off..curve_off + curve_len];
            // P-256: 1.2.840.10045.3.1.7
            const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
            // P-384: 1.3.132.0.34
            const P384_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
            if curve_oid == P256_OID {
                Ok(Self::EccP256)
            } else if curve_oid == P384_OID {
                Ok(Self::EccP384)
            } else {
                Err(PivError::InvalidData("Unsupported EC curve".into()))
            }
        } else if oid == ED25519_OID {
            Ok(Self::Ed25519)
        } else if oid == X25519_OID {
            Ok(Self::X25519)
        } else {
            Err(PivError::InvalidData("Unknown key algorithm OID".into()))
        }
    }

    /// Extract the inner private key data from a PKCS#8 PrivateKeyInfo DER.
    ///
    /// For RSA, returns the PKCS#1 RSAPrivateKey.
    /// For EC, returns the raw secret key scalar bytes.
    /// For Ed25519/X25519, returns the 32-byte key.
    pub fn extract_private_key_from_pkcs8(pkcs8_der: &[u8]) -> Result<Vec<u8>, PivError> {
        // Parse outer SEQUENCE
        let (_, seq_off, seq_len, _) =
            tlv_parse(pkcs8_der, 0).map_err(|_| PivError::InvalidData("Invalid DER".into()))?;
        let seq_data = &pkcs8_der[seq_off..seq_off + seq_len];

        // Skip version INTEGER
        let (_, _, _, ver_end) =
            tlv_parse(seq_data, 0).map_err(|_| PivError::InvalidData("Invalid version".into()))?;

        // Parse AlgorithmIdentifier SEQUENCE
        let (_, algo_off, algo_len, algo_end) = tlv_parse(seq_data, ver_end)
            .map_err(|_| PivError::InvalidData("Invalid AlgorithmIdentifier".into()))?;
        let algo_data = &seq_data[algo_off..algo_off + algo_len];

        // Parse OID
        let (_, oid_off, oid_len, _) =
            tlv_parse(algo_data, 0).map_err(|_| PivError::InvalidData("Invalid OID".into()))?;
        let oid = &algo_data[oid_off..oid_off + oid_len];

        const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

        // Parse OCTET STRING containing the private key
        let (_, oct_off, oct_len, _) = tlv_parse(seq_data, algo_end)
            .map_err(|_| PivError::InvalidData("Invalid OCTET STRING".into()))?;
        let private_key_data = &seq_data[oct_off..oct_off + oct_len];

        if oid == RSA_OID {
            // RSA: OCTET STRING contains PKCS#1 RSAPrivateKey SEQUENCE
            Ok(private_key_data.to_vec())
        } else if oid == EC_OID {
            // EC: OCTET STRING contains ECPrivateKey SEQUENCE { version, privateKey, ... }
            // Parse SEQUENCE
            let (_, inner_off, inner_len, _) = tlv_parse(private_key_data, 0)
                .map_err(|_| PivError::InvalidData("Invalid ECPrivateKey".into()))?;
            let inner = &private_key_data[inner_off..inner_off + inner_len];
            // Skip version INTEGER
            let (_, _, _, ver_end) = tlv_parse(inner, 0)
                .map_err(|_| PivError::InvalidData("Invalid EC version".into()))?;
            // Parse privateKey OCTET STRING
            let (_, key_off, key_len, _) = tlv_parse(inner, ver_end)
                .map_err(|_| PivError::InvalidData("Invalid EC private key".into()))?;
            Ok(inner[key_off..key_off + key_len].to_vec())
        } else {
            // Ed25519/X25519: OCTET STRING contains another OCTET STRING wrapping the 32-byte key
            let (_, key_off, key_len, _) = tlv_parse(private_key_data, 0)
                .map_err(|_| PivError::InvalidData("Invalid key OCTET STRING".into()))?;
            Ok(private_key_data[key_off..key_off + key_len].to_vec())
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa1024 => write!(f, "RSA1024"),
            Self::Rsa2048 => write!(f, "RSA2048"),
            Self::Rsa3072 => write!(f, "RSA3072"),
            Self::Rsa4096 => write!(f, "RSA4096"),
            Self::EccP256 => write!(f, "ECCP256"),
            Self::EccP384 => write!(f, "ECCP384"),
            Self::Ed25519 => write!(f, "ED25519"),
            Self::X25519 => write!(f, "X25519"),
        }
    }
}

// ---------------------------------------------------------------------------
// ManagementKeyType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ManagementKeyType {
    Tdes = 0x03,
    Aes128 = 0x08,
    Aes192 = 0x0A,
    Aes256 = 0x0C,
}

impl ManagementKeyType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x03 => Some(Self::Tdes),
            0x08 => Some(Self::Aes128),
            0x0A => Some(Self::Aes192),
            0x0C => Some(Self::Aes256),
            _ => None,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Tdes => 24,
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    pub fn challenge_len(self) -> usize {
        match self {
            Self::Tdes => 8,
            _ => 16,
        }
    }
}

impl fmt::Display for ManagementKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tdes => write!(f, "TDES"),
            Self::Aes128 => write!(f, "AES128"),
            Self::Aes192 => write!(f, "AES192"),
            Self::Aes256 => write!(f, "AES256"),
        }
    }
}

// ---------------------------------------------------------------------------
// Slot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Slot {
    Authentication = 0x9A,
    Signature = 0x9C,
    KeyManagement = 0x9D,
    CardAuth = 0x9E,
    Retired1 = 0x82,
    Retired2 = 0x83,
    Retired3 = 0x84,
    Retired4 = 0x85,
    Retired5 = 0x86,
    Retired6 = 0x87,
    Retired7 = 0x88,
    Retired8 = 0x89,
    Retired9 = 0x8A,
    Retired10 = 0x8B,
    Retired11 = 0x8C,
    Retired12 = 0x8D,
    Retired13 = 0x8E,
    Retired14 = 0x8F,
    Retired15 = 0x90,
    Retired16 = 0x91,
    Retired17 = 0x92,
    Retired18 = 0x93,
    Retired19 = 0x94,
    Retired20 = 0x95,
    Attestation = 0xF9,
}

impl Slot {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x9A => Some(Self::Authentication),
            0x9C => Some(Self::Signature),
            0x9D => Some(Self::KeyManagement),
            0x9E => Some(Self::CardAuth),
            0x82 => Some(Self::Retired1),
            0x83 => Some(Self::Retired2),
            0x84 => Some(Self::Retired3),
            0x85 => Some(Self::Retired4),
            0x86 => Some(Self::Retired5),
            0x87 => Some(Self::Retired6),
            0x88 => Some(Self::Retired7),
            0x89 => Some(Self::Retired8),
            0x8A => Some(Self::Retired9),
            0x8B => Some(Self::Retired10),
            0x8C => Some(Self::Retired11),
            0x8D => Some(Self::Retired12),
            0x8E => Some(Self::Retired13),
            0x8F => Some(Self::Retired14),
            0x90 => Some(Self::Retired15),
            0x91 => Some(Self::Retired16),
            0x92 => Some(Self::Retired17),
            0x93 => Some(Self::Retired18),
            0x94 => Some(Self::Retired19),
            0x95 => Some(Self::Retired20),
            0xF9 => Some(Self::Attestation),
            _ => None,
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X} ({:?})", *self as u8, self)
    }
}

// ---------------------------------------------------------------------------
// ObjectId
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ObjectId {
    Capability = 0x5FC107,
    Chuid = 0x5FC102,
    Authentication = 0x5FC105,
    Fingerprints = 0x5FC103,
    Security = 0x5FC106,
    Facial = 0x5FC108,
    Printed = 0x5FC109,
    Signature = 0x5FC10A,
    KeyManagement = 0x5FC10B,
    CardAuth = 0x5FC101,
    Discovery = 0x7E,
    KeyHistory = 0x5FC10C,
    Iris = 0x5FC121,
    Retired1 = 0x5FC10D,
    Retired2 = 0x5FC10E,
    Retired3 = 0x5FC10F,
    Retired4 = 0x5FC110,
    Retired5 = 0x5FC111,
    Retired6 = 0x5FC112,
    Retired7 = 0x5FC113,
    Retired8 = 0x5FC114,
    Retired9 = 0x5FC115,
    Retired10 = 0x5FC116,
    Retired11 = 0x5FC117,
    Retired12 = 0x5FC118,
    Retired13 = 0x5FC119,
    Retired14 = 0x5FC11A,
    Retired15 = 0x5FC11B,
    Retired16 = 0x5FC11C,
    Retired17 = 0x5FC11D,
    Retired18 = 0x5FC11E,
    Retired19 = 0x5FC11F,
    Retired20 = 0x5FC120,
    Attestation = 0x5FFF01,
}

impl ObjectId {
    pub fn from_slot(slot: Slot) -> Self {
        match slot {
            Slot::Authentication => Self::Authentication,
            Slot::Signature => Self::Signature,
            Slot::KeyManagement => Self::KeyManagement,
            Slot::CardAuth => Self::CardAuth,
            Slot::Retired1 => Self::Retired1,
            Slot::Retired2 => Self::Retired2,
            Slot::Retired3 => Self::Retired3,
            Slot::Retired4 => Self::Retired4,
            Slot::Retired5 => Self::Retired5,
            Slot::Retired6 => Self::Retired6,
            Slot::Retired7 => Self::Retired7,
            Slot::Retired8 => Self::Retired8,
            Slot::Retired9 => Self::Retired9,
            Slot::Retired10 => Self::Retired10,
            Slot::Retired11 => Self::Retired11,
            Slot::Retired12 => Self::Retired12,
            Slot::Retired13 => Self::Retired13,
            Slot::Retired14 => Self::Retired14,
            Slot::Retired15 => Self::Retired15,
            Slot::Retired16 => Self::Retired16,
            Slot::Retired17 => Self::Retired17,
            Slot::Retired18 => Self::Retired18,
            Slot::Retired19 => Self::Retired19,
            Slot::Retired20 => Self::Retired20,
            Slot::Attestation => Self::Attestation,
        }
    }
}

// ---------------------------------------------------------------------------
// PinPolicy / TouchPolicy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PinPolicy {
    Default = 0x00,
    Never = 0x01,
    Once = 0x02,
    Always = 0x03,
    MatchOnce = 0x04,
    MatchAlways = 0x05,
}

impl PinPolicy {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::Never),
            0x02 => Some(Self::Once),
            0x03 => Some(Self::Always),
            0x04 => Some(Self::MatchOnce),
            0x05 => Some(Self::MatchAlways),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TouchPolicy {
    Default = 0x00,
    Never = 0x01,
    Always = 0x02,
    Cached = 0x03,
}

impl TouchPolicy {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::Never),
            0x02 => Some(Self::Always),
            0x03 => Some(Self::Cached),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PinMetadata {
    pub default_value: bool,
    pub total_attempts: u32,
    pub attempts_remaining: u32,
}

#[derive(Debug, Clone)]
pub struct ManagementKeyMetadata {
    pub key_type: ManagementKeyType,
    pub default_value: bool,
    pub touch_policy: TouchPolicy,
}

#[derive(Debug, Clone)]
pub struct SlotMetadata {
    pub key_type: KeyType,
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    pub generated: bool,
    pub public_key_der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BioMetadata {
    pub configured: bool,
    pub attempts_remaining: u32,
    pub temporary_pin: bool,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DEFAULT_MANAGEMENT_KEY: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

const PIN_LEN: usize = 8;
const TEMPORARY_PIN_LEN: usize = 16;

// Special slots not in the Slot enum
const SLOT_CARD_MANAGEMENT: u8 = 0x9B;
const SLOT_OCC_AUTH: u8 = 0x96;

// Instruction set
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;
const INS_MOVE_KEY: u8 = 0xF6;
const INS_GET_METADATA: u8 = 0xF7;
const INS_GET_SERIAL: u8 = 0xF8;
const INS_ATTEST: u8 = 0xF9;
const INS_SET_PIN_RETRIES: u8 = 0xFA;
const INS_RESET: u8 = 0xFB;
const INS_GET_VERSION: u8 = 0xFD;
const INS_IMPORT_KEY: u8 = 0xFE;
const INS_SET_MGMKEY: u8 = 0xFF;

// Tags
pub const TAG_AUTH_WITNESS: u32 = 0x80;
pub const TAG_AUTH_CHALLENGE: u32 = 0x81;
pub const TAG_AUTH_RESPONSE: u32 = 0x82;
pub const TAG_AUTH_EXPONENTIATION: u32 = 0x85;
pub const TAG_GEN_ALGORITHM: u32 = 0x80;
pub const TAG_OBJ_DATA: u32 = 0x53;
pub const TAG_OBJ_ID: u32 = 0x5C;
pub const TAG_CERTIFICATE: u32 = 0x70;
pub const TAG_CERT_INFO: u32 = 0x71;
pub const TAG_DYN_AUTH: u32 = 0x7C;
pub const TAG_LRC: u32 = 0xFE;
pub const TAG_PIN_POLICY: u32 = 0xAA;
pub const TAG_TOUCH_POLICY: u32 = 0xAB;

// Metadata tags
const TAG_METADATA_ALGO: u32 = 0x01;
const TAG_METADATA_POLICY: u32 = 0x02;
const TAG_METADATA_ORIGIN: u32 = 0x03;
const TAG_METADATA_PUBLIC_KEY: u32 = 0x04;
const TAG_METADATA_IS_DEFAULT: u32 = 0x05;
const TAG_METADATA_RETRIES: u32 = 0x06;
const TAG_METADATA_BIO_CONFIGURED: u32 = 0x07;
const TAG_METADATA_TEMPORARY_PIN: u32 = 0x08;

const ORIGIN_GENERATED: u8 = 1;

const INDEX_PIN_POLICY: usize = 0;
const INDEX_TOUCH_POLICY: usize = 1;
const INDEX_RETRIES_TOTAL: usize = 0;
const INDEX_RETRIES_REMAINING: usize = 1;

pub const PIN_P2: u8 = 0x80;
pub const PUK_P2: u8 = 0x81;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pin_bytes(pin: &str) -> Result<Vec<u8>, PivError> {
    let bytes = pin.as_bytes();
    if bytes.len() > PIN_LEN {
        return Err(PivError::InvalidData(
            "PIN/PUK must be no longer than 8 bytes".into(),
        ));
    }
    let mut padded = vec![0xff; PIN_LEN];
    padded[..bytes.len()].copy_from_slice(bytes);
    Ok(padded)
}

fn retries_from_sw(sw: u16) -> Option<u32> {
    if sw == Sw::AuthMethodBlocked as u16 {
        return Some(0);
    }
    if sw & 0xFFF0 == 0x63C0 {
        return Some((sw & 0x0F) as u32);
    }
    if sw & 0xFF00 == 0x6300 {
        return Some((sw & 0xFF) as u32);
    }
    None
}

/// Encode an integer value as big-endian bytes with a specific length (zero-padded).
fn int_to_bytes(value: &[u8], len: usize) -> Vec<u8> {
    if value.len() >= len {
        return value[value.len() - len..].to_vec();
    }
    let mut buf = vec![0u8; len];
    buf[len - value.len()..].copy_from_slice(value);
    buf
}

/// Encode an arbitrary-precision integer (big-endian) into `len` bytes.
fn bigint_to_bytes(value: &[u8], len: usize) -> Vec<u8> {
    // Strip leading zeros
    let stripped = strip_leading_zeros(value);
    int_to_bytes(stripped, len)
}

fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[start..]
}

fn bytes_to_u32(data: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &b in data {
        result = (result << 8) | b as u32;
    }
    result
}

/// Encode u32 as minimal big-endian bytes.
fn u32_to_bytes(value: u32) -> Vec<u8> {
    int2bytes(value as u64)
}

fn require_version(version: Version, required: Version, feature: &str) -> Result<(), PivError> {
    crate::core::require_version(version, required, feature).map_err(PivError::NotSupported)
}

/// Encrypt a single block using management key (ECB mode).
fn mgmt_key_encrypt(
    key_type: ManagementKeyType,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, PivError> {
    match key_type {
        ManagementKeyType::Tdes => {
            let cipher = TdesEde3::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid TDES key".into()))?;
            let mut block = cipher::Block::<TdesEde3>::clone_from_slice(data);
            cipher.encrypt_block(&mut block);
            Ok(block.to_vec())
        }
        ManagementKeyType::Aes128 => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid AES-128 key".into()))?;
            let mut block = aes::Block::clone_from_slice(data);
            cipher.encrypt_block(&mut block);
            Ok(block.to_vec())
        }
        ManagementKeyType::Aes192 => {
            let cipher = Aes192::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid AES-192 key".into()))?;
            let mut block = aes::Block::clone_from_slice(data);
            cipher.encrypt_block(&mut block);
            Ok(block.to_vec())
        }
        ManagementKeyType::Aes256 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid AES-256 key".into()))?;
            let mut block = aes::Block::clone_from_slice(data);
            cipher.encrypt_block(&mut block);
            Ok(block.to_vec())
        }
    }
}

/// Decrypt a single block using management key (ECB mode).
fn mgmt_key_decrypt(
    key_type: ManagementKeyType,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, PivError> {
    match key_type {
        ManagementKeyType::Tdes => {
            let cipher = TdesEde3::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid TDES key".into()))?;
            let mut block = cipher::Block::<TdesEde3>::clone_from_slice(data);
            cipher.decrypt_block(&mut block);
            Ok(block.to_vec())
        }
        ManagementKeyType::Aes128 => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid AES-128 key".into()))?;
            let mut block = aes::Block::clone_from_slice(data);
            cipher.decrypt_block(&mut block);
            Ok(block.to_vec())
        }
        ManagementKeyType::Aes192 => {
            let cipher = Aes192::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid AES-192 key".into()))?;
            let mut block = aes::Block::clone_from_slice(data);
            cipher.decrypt_block(&mut block);
            Ok(block.to_vec())
        }
        ManagementKeyType::Aes256 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| PivError::InvalidData("Invalid AES-256 key".into()))?;
            let mut block = aes::Block::clone_from_slice(data);
            cipher.decrypt_block(&mut block);
            Ok(block.to_vec())
        }
    }
}

/// Decompress a compressed certificate using various methods.
fn decompress_certificate(cert_data: &[u8]) -> Result<Vec<u8>, PivError> {
    if cert_data.len() >= 2 {
        match (cert_data[0], cert_data[1]) {
            (0x1F, 0x8B) => {
                // Gzip
                let mut decoder = GzDecoder::new(cert_data);
                let mut decompressed = Vec::new();
                decoder
                    .read_to_end(&mut decompressed)
                    .map_err(|_| PivError::InvalidData("Failed to decompress gzip".into()))?;
                return Ok(decompressed);
            }
            (0x01, 0x00) => {
                // Net iD zlib format
                if cert_data.len() >= 4 {
                    let expected_len = u16::from_le_bytes([cert_data[2], cert_data[3]]) as usize;
                    let mut decoder = flate2::read::ZlibDecoder::new(&cert_data[4..]);
                    let mut decompressed = Vec::new();
                    decoder
                        .read_to_end(&mut decompressed)
                        .map_err(|_| PivError::InvalidData("Failed to decompress zlib".into()))?;
                    if decompressed.len() != expected_len {
                        return Err(PivError::InvalidData(
                            "Decompressed length does not match expected length".into(),
                        ));
                    }
                    return Ok(decompressed);
                }
            }
            _ => {}
        }
    }
    Err(PivError::InvalidData(
        "Failed to decompress certificate".into(),
    ))
}

/// Check if a key type is supported by a specific YubiKey firmware version.
pub fn check_key_support(
    version: Version,
    key_type: KeyType,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    generate: bool,
    fips_restrictions: bool,
) -> Result<(), PivError> {
    if key_type == KeyType::EccP384 {
        require_version(version, Version(4, 0, 0), "ECC P-384")?;
    }
    if touch_policy != TouchPolicy::Default || pin_policy != PinPolicy::Default {
        require_version(version, Version(4, 0, 0), "PIN/touch policy")?;
    }
    if touch_policy == TouchPolicy::Cached {
        require_version(version, Version(4, 3, 0), "cached touch policy")?;
    }

    // ROCA
    if version >= Version(4, 2, 0)
        && version < Version(4, 3, 5)
        && generate
        && key_type.algorithm() == Algorithm::Rsa
    {
        return Err(PivError::NotSupported(
            "RSA key generation not supported on this YubiKey".into(),
        ));
    }

    // FIPS
    if fips_restrictions || (version >= Version(4, 4, 0) && version < Version(4, 5, 0)) {
        if key_type == KeyType::Rsa1024 || key_type == KeyType::X25519 {
            return Err(PivError::NotSupported(
                "RSA 1024 not supported on YubiKey FIPS".into(),
            ));
        }
        if pin_policy == PinPolicy::Never {
            return Err(PivError::NotSupported(
                "PIN_POLICY.NEVER not allowed on YubiKey FIPS".into(),
            ));
        }
    }

    // New key types
    if matches!(
        key_type,
        KeyType::Rsa3072 | KeyType::Rsa4096 | KeyType::Ed25519 | KeyType::X25519
    ) {
        require_version(version, Version(5, 7, 0), &format!("{key_type:?}"))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PivSession
// ---------------------------------------------------------------------------

pub struct PivSession<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
    mgmt_key_type: ManagementKeyType,
    current_pin_retries: u32,
    max_pin_retries: u32,
}

impl<C: SmartCardConnection> PivSession<C> {
    /// Open a PIV session on the given connection.
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new(connection: C) -> Result<Self, (PivError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        if let Err(e) = protocol.select(Aid::PIV) {
            return Err((e.into(), protocol.into_connection()));
        }
        Self::init(protocol)
    }

    /// Open a PIV session with SCP (Secure Channel Protocol).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, (PivError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        if let Err(e) = protocol.select(Aid::PIV) {
            return Err((e.into(), protocol.into_connection()));
        }
        if let Err(e) = protocol.init_scp(scp_key_params) {
            return Err((e.into(), protocol.into_connection()));
        }
        Self::init(protocol)
    }

    fn init(mut protocol: SmartCardProtocol<C>) -> Result<Self, (PivError, C)> {
        log::debug!("Opening PivSession");
        let version_data = match protocol.send_apdu(0, INS_GET_VERSION, 0, 0, &[]) {
            Ok(v) => v,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        let version = patch_version(Version::from_bytes(&version_data));
        protocol.configure(version);

        let mut session = Self {
            protocol,
            version,
            mgmt_key_type: ManagementKeyType::Tdes,
            current_pin_retries: 3,
            max_pin_retries: 3,
        };

        session.mgmt_key_type = match session.get_management_key_metadata() {
            Ok(meta) => meta.key_type,
            Err(PivError::NotSupported(_)) => ManagementKeyType::Tdes,
            Err(e) => return Err((e, session.protocol.into_connection())),
        };

        Ok(session)
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn management_key_type(&self) -> ManagementKeyType {
        self.mgmt_key_type
    }

    /// Consume the session and return the underlying protocol.
    pub fn into_protocol(self) -> SmartCardProtocol<C> {
        self.protocol
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        self.protocol.into_connection()
    }

    /// Get a mutable reference to the underlying protocol.
    pub fn protocol_mut(&mut self) -> &mut SmartCardProtocol<C> {
        &mut self.protocol
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    pub fn reset(&mut self) -> Result<(), PivError> {
        // Check biometrics
        match self.get_bio_metadata() {
            Ok(bio) if bio.configured => {
                return Err(PivError::InvalidData(
                    "Cannot perform PIV reset when biometrics are configured".into(),
                ));
            }
            _ => {}
        }

        // Block PIN
        let mut counter = self.get_pin_attempts()?;
        while counter > 0 {
            match self.verify_pin("") {
                Ok(()) => break,
                Err(PivError::InvalidPin(r)) => counter = r,
                Err(e) => return Err(e),
            }
        }

        // Block PUK
        counter = match self.get_puk_metadata() {
            Ok(meta) => meta.attempts_remaining,
            Err(_) => 1,
        };
        while counter > 0 {
            match self.change_reference(INS_RESET_RETRY, PIN_P2, "", "") {
                Ok(()) => break,
                Err(PivError::InvalidPin(r)) => counter = r,
                Err(e) => return Err(e),
            }
        }

        // Reset
        self.protocol.send_apdu(0, INS_RESET, 0, 0, &[])?;
        self.current_pin_retries = 3;
        self.max_pin_retries = 3;

        // Update management key type
        self.mgmt_key_type = match self.get_management_key_metadata() {
            Ok(meta) => meta.key_type,
            Err(_) => ManagementKeyType::Tdes,
        };

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Serial
    // -----------------------------------------------------------------------

    pub fn get_serial(&mut self) -> Result<u32, PivError> {
        require_version(self.version, Version(5, 0, 3), "get_serial")?;
        let response = self.protocol.send_apdu(0, INS_GET_SERIAL, 0, 0, &[])?;
        Ok(bytes_to_u32(&response))
    }

    // -----------------------------------------------------------------------
    // Management key authentication
    // -----------------------------------------------------------------------

    pub fn authenticate(&mut self, management_key: &[u8]) -> Result<(), PivError> {
        let key_type = self.mgmt_key_type;

        // Step 1: Request witness from card
        let witness_request = tlv_encode(TAG_DYN_AUTH, &tlv_encode(TAG_AUTH_WITNESS, &[]));
        let response = self.protocol.send_apdu(
            0,
            INS_AUTHENTICATE,
            key_type as u8,
            SLOT_CARD_MANAGEMENT,
            &witness_request,
        )?;

        let dyn_auth = tlv_unpack(TAG_DYN_AUTH, &response)?;
        let witness = tlv_unpack(TAG_AUTH_WITNESS, &dyn_auth)?;

        // Step 2: Decrypt witness, send back with our challenge
        let decrypted = mgmt_key_decrypt(key_type, management_key, &witness)?;

        let challenge_len = key_type.challenge_len();
        let mut challenge = vec![0u8; challenge_len];
        getrandom::fill(&mut challenge)
            .map_err(|_| PivError::InvalidData("Failed to generate random bytes".into()))?;

        let mut auth_data = tlv_encode(TAG_AUTH_WITNESS, &decrypted);
        auth_data.extend_from_slice(&tlv_encode(TAG_AUTH_CHALLENGE, &challenge));
        let request = tlv_encode(TAG_DYN_AUTH, &auth_data);

        let response = self.protocol.send_apdu(
            0,
            INS_AUTHENTICATE,
            key_type as u8,
            SLOT_CARD_MANAGEMENT,
            &request,
        )?;

        // Step 3: Verify card's response
        let dyn_auth = tlv_unpack(TAG_DYN_AUTH, &response)?;
        let encrypted = tlv_unpack(TAG_AUTH_RESPONSE, &dyn_auth)?;

        let expected = mgmt_key_encrypt(key_type, management_key, &challenge)?;
        if expected.ct_eq(&encrypted).into() {
            Ok(())
        } else {
            Err(PivError::InvalidData("Device response is incorrect".into()))
        }
    }

    // -----------------------------------------------------------------------
    // Management key
    // -----------------------------------------------------------------------

    pub fn set_management_key(
        &mut self,
        key_type: ManagementKeyType,
        management_key: &[u8],
        require_touch: bool,
    ) -> Result<(), PivError> {
        if key_type != ManagementKeyType::Tdes {
            require_version(self.version, Version(5, 4, 0), "AES management key")?;
        }
        if management_key.len() != key_type.key_len() {
            return Err(PivError::InvalidData(format!(
                "Management key must be {} bytes",
                key_type.key_len()
            )));
        }

        let mut data = vec![key_type as u8];
        data.extend_from_slice(&tlv_encode(SLOT_CARD_MANAGEMENT as u32, management_key));

        let p2 = if require_touch { 0xFE } else { 0xFF };
        self.protocol
            .send_apdu(0, INS_SET_MGMKEY, 0xFF, p2, &data)?;
        self.mgmt_key_type = key_type;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // PIN / PUK
    // -----------------------------------------------------------------------

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), PivError> {
        let data = pin_bytes(pin)?;
        match self.protocol.send_apdu(0, INS_VERIFY, 0, PIN_P2, &data) {
            Ok(_) => {
                self.current_pin_retries = self.max_pin_retries;
                Ok(())
            }
            Err(e) => {
                if let SmartCardError::Apdu { sw, .. } = &e
                    && let Some(retries) = retries_from_sw(*sw)
                {
                    self.current_pin_retries = retries;
                    return Err(PivError::InvalidPin(retries));
                }
                Err(PivError::Connection(e))
            }
        }
    }

    pub fn verify_uv(
        &mut self,
        temporary_pin: bool,
        check_only: bool,
    ) -> Result<Option<Vec<u8>>, PivError> {
        if temporary_pin && check_only {
            return Err(PivError::InvalidData(
                "Cannot request temporary PIN when doing check-only verification".into(),
            ));
        }

        let data = if check_only {
            vec![]
        } else if temporary_pin {
            tlv_encode(0x02, &[])
        } else {
            tlv_encode(0x03, &[])
        };

        match self
            .protocol
            .send_apdu(0, INS_VERIFY, 0, SLOT_OCC_AUTH, &data)
        {
            Ok(response) => {
                if temporary_pin {
                    Ok(Some(response))
                } else {
                    Ok(None)
                }
            }
            Err(SmartCardError::Apdu { sw, .. })
                if Sw::from_u16(sw) == Some(Sw::ReferenceDataNotFound) =>
            {
                Err(PivError::NotSupported(
                    "Biometric verification not supported by this YubiKey".into(),
                ))
            }
            Err(e) => {
                if let SmartCardError::Apdu { sw, .. } = &e
                    && let Some(retries) = retries_from_sw(*sw)
                {
                    return Err(PivError::InvalidPin(retries));
                }
                Err(PivError::Connection(e))
            }
        }
    }

    pub fn verify_temporary_pin(&mut self, pin: &[u8]) -> Result<(), PivError> {
        if pin.len() != TEMPORARY_PIN_LEN {
            return Err(PivError::InvalidData(format!(
                "Temporary PIN must be exactly {TEMPORARY_PIN_LEN} bytes"
            )));
        }
        let data = tlv_encode(0x01, pin);
        match self
            .protocol
            .send_apdu(0, INS_VERIFY, 0, SLOT_OCC_AUTH, &data)
        {
            Ok(_) => Ok(()),
            Err(SmartCardError::Apdu { sw, .. })
                if Sw::from_u16(sw) == Some(Sw::ReferenceDataNotFound) =>
            {
                Err(PivError::NotSupported(
                    "Biometric verification not supported by this YubiKey".into(),
                ))
            }
            Err(e) => {
                if let SmartCardError::Apdu { sw, .. } = &e
                    && let Some(retries) = retries_from_sw(*sw)
                {
                    return Err(PivError::InvalidPin(retries));
                }
                Err(PivError::Connection(e))
            }
        }
    }

    pub fn get_pin_attempts(&mut self) -> Result<u32, PivError> {
        match self.get_pin_metadata() {
            Ok(meta) => return Ok(meta.attempts_remaining),
            Err(PivError::NotSupported(_)) => {}
            Err(e) => return Err(e),
        }

        // Fallback: send empty verify
        match self.protocol.send_apdu(0, INS_VERIFY, 0, PIN_P2, &[]) {
            Ok(_) => {
                // Already verified, use cached value
                Ok(self.current_pin_retries)
            }
            Err(SmartCardError::Apdu { sw, .. }) => {
                if let Some(retries) = retries_from_sw(sw) {
                    self.current_pin_retries = retries;
                    Ok(retries)
                } else {
                    Err(PivError::Connection(SmartCardError::Apdu {
                        data: vec![],
                        sw,
                    }))
                }
            }
            Err(e) => Err(PivError::Connection(e)),
        }
    }

    pub fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), PivError> {
        self.change_reference(INS_CHANGE_REFERENCE, PIN_P2, old_pin, new_pin)
    }

    pub fn change_puk(&mut self, old_puk: &str, new_puk: &str) -> Result<(), PivError> {
        match self.change_reference(INS_CHANGE_REFERENCE, PUK_P2, old_puk, new_puk) {
            Err(PivError::Connection(SmartCardError::Apdu { sw, .. }))
                if Sw::from_u16(sw) == Some(Sw::InvalidInstruction) =>
            {
                Err(PivError::NotSupported(
                    "Setting PUK is not supported on this YubiKey".into(),
                ))
            }
            other => other,
        }
    }

    pub fn unblock_pin(&mut self, puk: &str, new_pin: &str) -> Result<(), PivError> {
        match self.change_reference(INS_RESET_RETRY, PIN_P2, puk, new_pin) {
            Err(PivError::Connection(SmartCardError::Apdu { sw, .. }))
                if Sw::from_u16(sw) == Some(Sw::InvalidInstruction) =>
            {
                Err(PivError::NotSupported(
                    "Unblocking PIN is not supported on this YubiKey".into(),
                ))
            }
            other => other,
        }
    }

    pub fn set_pin_attempts(&mut self, pin_attempts: u8, puk_attempts: u8) -> Result<(), PivError> {
        match self
            .protocol
            .send_apdu(0, INS_SET_PIN_RETRIES, pin_attempts, puk_attempts, &[])
        {
            Ok(_) => {
                self.max_pin_retries = pin_attempts as u32;
                self.current_pin_retries = pin_attempts as u32;
                Ok(())
            }
            Err(SmartCardError::Apdu { sw, .. })
                if Sw::from_u16(sw) == Some(Sw::InvalidInstruction) =>
            {
                Err(PivError::NotSupported(
                    "Setting PIN attempts not supported on this YubiKey".into(),
                ))
            }
            Err(e) => Err(PivError::Connection(e)),
        }
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    pub fn get_pin_metadata(&mut self) -> Result<PinMetadata, PivError> {
        self.get_pin_puk_metadata(PIN_P2)
    }

    pub fn get_puk_metadata(&mut self) -> Result<PinMetadata, PivError> {
        self.get_pin_puk_metadata(PUK_P2)
    }

    pub fn get_management_key_metadata(&mut self) -> Result<ManagementKeyMetadata, PivError> {
        require_version(
            self.version,
            Version(5, 3, 0),
            "get_management_key_metadata",
        )?;
        let response =
            self.protocol
                .send_apdu(0, INS_GET_METADATA, 0, SLOT_CARD_MANAGEMENT, &[])?;
        let data = parse_tlv_dict(&response)?;

        let algo_byte = data
            .get(&TAG_METADATA_ALGO)
            .and_then(|v| v.first().copied())
            .unwrap_or(0x03);
        let key_type = ManagementKeyType::from_u8(algo_byte).ok_or_else(|| {
            PivError::InvalidData(format!("Unknown management key type: 0x{algo_byte:02X}"))
        })?;

        let default_value = data
            .get(&TAG_METADATA_IS_DEFAULT)
            .map(|v| v != &[0])
            .unwrap_or(false);

        let policy = data
            .get(&TAG_METADATA_POLICY)
            .ok_or_else(|| PivError::InvalidData("Missing policy in metadata".into()))?;
        let touch_policy = TouchPolicy::from_u8(
            *policy
                .get(INDEX_TOUCH_POLICY)
                .ok_or_else(|| PivError::InvalidData("Missing touch policy".into()))?,
        )
        .ok_or_else(|| PivError::InvalidData("Invalid touch policy".into()))?;

        Ok(ManagementKeyMetadata {
            key_type,
            default_value,
            touch_policy,
        })
    }

    pub fn get_slot_metadata(&mut self, slot: Slot) -> Result<SlotMetadata, PivError> {
        require_version(self.version, Version(5, 3, 0), "get_slot_metadata")?;
        let response = self
            .protocol
            .send_apdu(0, INS_GET_METADATA, 0, slot as u8, &[])?;
        let data = parse_tlv_dict(&response)?;

        let algo_byte = data
            .get(&TAG_METADATA_ALGO)
            .and_then(|v| v.first().copied())
            .ok_or_else(|| PivError::InvalidData("Missing algorithm in metadata".into()))?;
        let key_type = KeyType::from_u8(algo_byte)
            .ok_or_else(|| PivError::InvalidData(format!("Unknown key type: 0x{algo_byte:02X}")))?;

        let policy = data
            .get(&TAG_METADATA_POLICY)
            .ok_or_else(|| PivError::InvalidData("Missing policy in metadata".into()))?;
        let pin_policy = PinPolicy::from_u8(policy[INDEX_PIN_POLICY])
            .ok_or_else(|| PivError::InvalidData("Invalid pin policy".into()))?;
        let touch_policy = TouchPolicy::from_u8(policy[INDEX_TOUCH_POLICY])
            .ok_or_else(|| PivError::InvalidData("Invalid touch policy".into()))?;

        let origin = data
            .get(&TAG_METADATA_ORIGIN)
            .and_then(|v| v.first().copied())
            .ok_or_else(|| PivError::InvalidData("Missing origin in metadata".into()))?;

        let public_key_der = data
            .get(&TAG_METADATA_PUBLIC_KEY)
            .cloned()
            .ok_or_else(|| PivError::InvalidData("Missing public key in metadata".into()))?;

        Ok(SlotMetadata {
            key_type,
            pin_policy,
            touch_policy,
            generated: origin == ORIGIN_GENERATED,
            public_key_der,
        })
    }

    pub fn get_bio_metadata(&mut self) -> Result<BioMetadata, PivError> {
        let response = match self
            .protocol
            .send_apdu(0, INS_GET_METADATA, 0, SLOT_OCC_AUTH, &[])
        {
            Ok(r) => r,
            Err(SmartCardError::Apdu { sw, .. })
                if matches!(
                    Sw::from_u16(sw),
                    Some(Sw::ReferenceDataNotFound | Sw::InvalidInstruction)
                ) =>
            {
                return Err(PivError::NotSupported(
                    "Biometric verification not supported by this YubiKey".into(),
                ));
            }
            Err(e) => return Err(PivError::Connection(e)),
        };

        let data = parse_tlv_dict(&response)?;

        let configured = data
            .get(&TAG_METADATA_BIO_CONFIGURED)
            .and_then(|v| v.first().copied())
            .unwrap_or(0)
            == 1;

        let attempts_remaining = data
            .get(&TAG_METADATA_RETRIES)
            .and_then(|v| v.first().copied())
            .ok_or_else(|| PivError::InvalidData("Missing retries in bio metadata".into()))?
            as u32;

        let temporary_pin = data
            .get(&TAG_METADATA_TEMPORARY_PIN)
            .and_then(|v| v.first().copied())
            .unwrap_or(0)
            == 1;

        Ok(BioMetadata {
            configured,
            attempts_remaining,
            temporary_pin,
        })
    }

    // -----------------------------------------------------------------------
    // Signing / Decryption / Key Agreement
    // -----------------------------------------------------------------------

    /// Sign data with a private key in a slot.
    /// The `message` should be the pre-padded/pre-hashed data appropriate for the key type.
    pub fn sign(
        &mut self,
        slot: Slot,
        key_type: KeyType,
        message: &[u8],
    ) -> Result<Vec<u8>, PivError> {
        self.use_private_key(slot, key_type, message, false)
    }

    /// Decrypt ciphertext with an RSA private key in a slot.
    pub fn decrypt(&mut self, slot: Slot, cipher_text: &[u8]) -> Result<Vec<u8>, PivError> {
        let key_type = match cipher_text.len() * 8 {
            1024 => KeyType::Rsa1024,
            2048 => KeyType::Rsa2048,
            3072 => KeyType::Rsa3072,
            4096 => KeyType::Rsa4096,
            _ => {
                return Err(PivError::InvalidData("Invalid length of ciphertext".into()));
            }
        };
        self.use_private_key(slot, key_type, cipher_text, false)
    }

    /// Calculate shared secret using ECDH.
    /// `peer_public_key` should be the uncompressed EC point (X9.62) or raw X25519 bytes.
    pub fn calculate_secret(
        &mut self,
        slot: Slot,
        key_type: KeyType,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, PivError> {
        if key_type.algorithm() != Algorithm::Ec {
            return Err(PivError::InvalidData("Unsupported key type".into()));
        }
        self.use_private_key(slot, key_type, peer_public_key, true)
    }

    // -----------------------------------------------------------------------
    // Objects
    // -----------------------------------------------------------------------

    pub fn get_object(&mut self, object_id: ObjectId) -> Result<Vec<u8>, PivError> {
        self.get_object_raw(object_id as u32)
    }

    pub fn put_object(&mut self, object_id: ObjectId, data: Option<&[u8]>) -> Result<(), PivError> {
        self.put_object_raw(object_id as u32, data)
    }

    pub fn get_object_raw(&mut self, object_id: u32) -> Result<Vec<u8>, PivError> {
        let expected = if object_id == ObjectId::Discovery as u32 {
            ObjectId::Discovery as u32
        } else {
            TAG_OBJ_DATA
        };

        let id_bytes = u32_to_bytes(object_id);
        let request = tlv_encode(TAG_OBJ_ID, &id_bytes);
        let response = self
            .protocol
            .send_apdu(0, INS_GET_DATA, 0x3F, 0xFF, &request)?;

        tlv_unpack(expected, &response)
            .map_err(|_| PivError::InvalidData("Malformed object data".into()))
    }

    pub fn put_object_raw(&mut self, object_id: u32, data: Option<&[u8]>) -> Result<(), PivError> {
        let id_bytes = u32_to_bytes(object_id);
        let obj_data = data.unwrap_or(&[]);
        let mut request = tlv_encode(TAG_OBJ_ID, &id_bytes);
        request.extend_from_slice(&tlv_encode(TAG_OBJ_DATA, obj_data));
        self.protocol
            .send_apdu(0, INS_PUT_DATA, 0x3F, 0xFF, &request)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Certificates
    // -----------------------------------------------------------------------

    /// Get certificate from slot as DER bytes.
    pub fn get_certificate(&mut self, slot: Slot) -> Result<Vec<u8>, PivError> {
        let obj_data = self.get_object(ObjectId::from_slot(slot))?;
        let entries = parse_tlv_dict(&obj_data)
            .map_err(|_| PivError::InvalidData("Malformed certificate data object".into()))?;

        let cert_data = entries
            .get(&TAG_CERTIFICATE)
            .ok_or_else(|| PivError::InvalidData("Malformed certificate data object".into()))?;

        let cert_info = entries
            .get(&TAG_CERT_INFO)
            .and_then(|v| v.first().copied())
            .unwrap_or(0);

        if cert_info == 1 {
            decompress_certificate(cert_data)
        } else if cert_info == 0 {
            Ok(cert_data.clone())
        } else {
            Err(PivError::NotSupported(
                "Unsupported value in CertInfo".into(),
            ))
        }
    }

    /// Import a certificate (DER bytes) to a slot.
    pub fn put_certificate(
        &mut self,
        slot: Slot,
        cert_der: &[u8],
        compress: bool,
    ) -> Result<(), PivError> {
        let (cert_info, cert_data) = if compress {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(cert_der)
                .map_err(|_| PivError::InvalidData("Failed to compress certificate".into()))?;
            let compressed = encoder
                .finish()
                .map_err(|_| PivError::InvalidData("Failed to finish compression".into()))?;
            (1u8, compressed)
        } else {
            (0u8, cert_der.to_vec())
        };

        let mut data = tlv_encode(TAG_CERTIFICATE, &cert_data);
        data.extend_from_slice(&tlv_encode(TAG_CERT_INFO, &[cert_info]));
        data.extend_from_slice(&tlv_encode(TAG_LRC, &[]));

        self.put_object(ObjectId::from_slot(slot), Some(&data))
    }

    pub fn delete_certificate(&mut self, slot: Slot) -> Result<(), PivError> {
        self.put_object(ObjectId::from_slot(slot), None)
    }

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /// Import a private key (DER encoded) into a slot.
    ///
    /// For RSA keys, the DER should be PKCS#1 RSAPrivateKey.
    /// For EC keys, the DER should be SEC1 ECPrivateKey or raw private key bytes.
    /// For Ed25519/X25519, provide raw 32-byte secret key.
    ///
    /// `key_der` contains the raw key material as TLV-encoded components:
    /// - RSA: p, q, dp, dq, qinv as big-endian integers
    /// - EC: private scalar bytes
    /// - Ed25519/X25519: raw 32-byte secret
    pub fn put_key(
        &mut self,
        slot: Slot,
        key_type: KeyType,
        key_der: &[u8],
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<(), PivError> {
        check_key_support(
            self.version,
            key_type,
            pin_policy,
            touch_policy,
            false,
            false,
        )?;

        let mut data = build_put_key_data(key_type, key_der)?;

        if pin_policy != PinPolicy::Default {
            data.extend_from_slice(&tlv_encode(
                TAG_PIN_POLICY,
                &u32_to_bytes(pin_policy as u32),
            ));
        }
        if touch_policy != TouchPolicy::Default {
            data.extend_from_slice(&tlv_encode(
                TAG_TOUCH_POLICY,
                &u32_to_bytes(touch_policy as u32),
            ));
        }

        self.protocol
            .send_apdu(0, INS_IMPORT_KEY, key_type as u8, slot as u8, &data)?;
        Ok(())
    }

    /// Generate a key pair in a slot. Returns the public key as device-encoded bytes.
    pub fn generate_key(
        &mut self,
        slot: Slot,
        key_type: KeyType,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<Vec<u8>, PivError> {
        check_key_support(
            self.version,
            key_type,
            pin_policy,
            touch_policy,
            true,
            false,
        )?;

        let mut inner = tlv_encode(TAG_GEN_ALGORITHM, &u32_to_bytes(key_type as u32));
        if pin_policy != PinPolicy::Default {
            inner.extend_from_slice(&tlv_encode(
                TAG_PIN_POLICY,
                &u32_to_bytes(pin_policy as u32),
            ));
        }
        if touch_policy != TouchPolicy::Default {
            inner.extend_from_slice(&tlv_encode(
                TAG_TOUCH_POLICY,
                &u32_to_bytes(touch_policy as u32),
            ));
        }

        let request = tlv_encode(0xAC, &inner);
        let response =
            self.protocol
                .send_apdu(0, INS_GENERATE_ASYMMETRIC, 0, slot as u8, &request)?;

        // Return the 0x7F49 container contents (device public key encoding)
        Ok(tlv_unpack(0x7F49, &response)?)
    }

    /// Attest key in slot. Returns DER-encoded X.509 certificate.
    pub fn attest_key(&mut self, slot: Slot) -> Result<Vec<u8>, PivError> {
        require_version(self.version, Version(4, 3, 0), "attest_key")?;
        let response = self.protocol.send_apdu(0, INS_ATTEST, slot as u8, 0, &[])?;
        Ok(response)
    }

    /// Move key from one slot to another. Requires firmware >= 5.7.0.
    pub fn move_key(&mut self, from_slot: Slot, to_slot: Slot) -> Result<(), PivError> {
        require_version(self.version, Version(5, 7, 0), "move_key")?;
        self.protocol
            .send_apdu(0, INS_MOVE_KEY, to_slot as u8, from_slot as u8, &[])?;
        Ok(())
    }

    /// Delete a key in a slot. Requires firmware >= 5.7.0.
    pub fn delete_key(&mut self, slot: Slot) -> Result<(), PivError> {
        require_version(self.version, Version(5, 7, 0), "delete_key")?;
        self.protocol
            .send_apdu(0, INS_MOVE_KEY, 0xFF, slot as u8, &[])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Check key support (instance method)
    // -----------------------------------------------------------------------

    pub fn check_key_support(
        &mut self,
        key_type: KeyType,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
        generate: bool,
        fips_restrictions: bool,
    ) -> Result<(), PivError> {
        check_key_support(
            self.version,
            key_type,
            pin_policy,
            touch_policy,
            generate,
            fips_restrictions,
        )?;

        if pin_policy == PinPolicy::MatchOnce || pin_policy == PinPolicy::MatchAlways {
            self.get_bio_metadata()?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn change_reference(
        &mut self,
        ins: u8,
        p2: u8,
        value1: &str,
        value2: &str,
    ) -> Result<(), PivError> {
        let mut data = pin_bytes(value1)?;
        data.extend_from_slice(&pin_bytes(value2)?);
        match self.protocol.send_apdu(0, ins, 0, p2, &data) {
            Ok(_) => Ok(()),
            Err(e) => {
                if let SmartCardError::Apdu { sw, .. } = &e
                    && let Some(retries) = retries_from_sw(*sw)
                {
                    if p2 == PIN_P2 {
                        self.current_pin_retries = retries;
                    }
                    return Err(PivError::InvalidPin(retries));
                }
                Err(PivError::Connection(e))
            }
        }
    }

    fn get_pin_puk_metadata(&mut self, p2: u8) -> Result<PinMetadata, PivError> {
        require_version(self.version, Version(5, 3, 0), "get_pin_puk_metadata")?;
        let response = self.protocol.send_apdu(0, INS_GET_METADATA, 0, p2, &[])?;
        let data = parse_tlv_dict(&response)?;

        let default_value = data
            .get(&TAG_METADATA_IS_DEFAULT)
            .map(|v| v != &[0])
            .unwrap_or(false);

        let attempts = data
            .get(&TAG_METADATA_RETRIES)
            .ok_or_else(|| PivError::InvalidData("Missing retries in metadata".into()))?;

        Ok(PinMetadata {
            default_value,
            total_attempts: attempts[INDEX_RETRIES_TOTAL] as u32,
            attempts_remaining: attempts[INDEX_RETRIES_REMAINING] as u32,
        })
    }

    fn use_private_key(
        &mut self,
        slot: Slot,
        key_type: KeyType,
        message: &[u8],
        exponentiation: bool,
    ) -> Result<Vec<u8>, PivError> {
        let tag = if exponentiation {
            TAG_AUTH_EXPONENTIATION
        } else {
            TAG_AUTH_CHALLENGE
        };

        let mut inner = tlv_encode(TAG_AUTH_RESPONSE, &[]);
        inner.extend_from_slice(&tlv_encode(tag, message));
        let request = tlv_encode(TAG_DYN_AUTH, &inner);

        match self
            .protocol
            .send_apdu(0, INS_AUTHENTICATE, key_type as u8, slot as u8, &request)
        {
            Ok(response) => {
                let dyn_auth = tlv_unpack(TAG_DYN_AUTH, &response)?;
                tlv_unpack(TAG_AUTH_RESPONSE, &dyn_auth).map_err(PivError::from)
            }
            Err(SmartCardError::Apdu { sw, .. })
                if Sw::from_u16(sw) == Some(Sw::IncorrectParameters) =>
            {
                Err(PivError::Connection(SmartCardError::Apdu {
                    data: vec![],
                    sw,
                }))
            }
            Err(e) => Err(PivError::Connection(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Key import helper
// ---------------------------------------------------------------------------

/// Build the TLV data payload for INS_IMPORT_KEY from raw key material.
///
/// For RSA: `key_der` should be a PKCS#1 DER-encoded RSAPrivateKey.
/// For EC (P-256/P-384): `key_der` should be a SEC1 DER-encoded ECPrivateKey, or just the raw
/// private scalar bytes (32 or 48 bytes).
/// For Ed25519: raw 32-byte secret.
/// For X25519: raw 32-byte secret.
fn build_put_key_data(key_type: KeyType, key_der: &[u8]) -> Result<Vec<u8>, PivError> {
    match key_type {
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            build_rsa_key_data(key_type, key_der)
        }
        KeyType::EccP256 | KeyType::EccP384 => build_ec_key_data(key_type, key_der),
        KeyType::Ed25519 => {
            if key_der.len() != 32 {
                return Err(PivError::InvalidData(
                    "Ed25519 secret key must be 32 bytes".into(),
                ));
            }
            Ok(tlv_encode(0x07, key_der))
        }
        KeyType::X25519 => {
            if key_der.len() != 32 {
                return Err(PivError::InvalidData(
                    "X25519 secret key must be 32 bytes".into(),
                ));
            }
            Ok(tlv_encode(0x08, key_der))
        }
    }
}

/// Parse PKCS#1 RSAPrivateKey DER and build TLV import data.
fn build_rsa_key_data(key_type: KeyType, key_der: &[u8]) -> Result<Vec<u8>, PivError> {
    let ln = (key_type.bit_len() / 16) as usize; // half-prime length in bytes

    // Parse PKCS#1 RSAPrivateKey SEQUENCE
    let (_, seq_off, seq_len, _) =
        tlv_parse(key_der, 0).map_err(|_| PivError::InvalidData("Invalid RSA DER".into()))?;
    let seq_data = &key_der[seq_off..seq_off + seq_len];

    // Parse fields: version, n, e, d, p, q, dp, dq, qinv
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < seq_data.len() {
        let (_, val_off, val_len, end) = tlv_parse(seq_data, offset)
            .map_err(|_| PivError::InvalidData("Invalid RSA key field".into()))?;
        fields.push(&seq_data[val_off..val_off + val_len]);
        offset = end;
    }

    if fields.len() < 9 {
        return Err(PivError::InvalidData(
            "RSA key missing required fields".into(),
        ));
    }

    // fields: [version, n, e, d, p, q, dp, dq, qinv]
    let e = fields[2];
    // Verify exponent is 65537
    let e_val = bytes_to_u32(strip_leading_zeros(e));
    if e_val != 65537 {
        return Err(PivError::NotSupported("RSA exponent must be 65537".into()));
    }

    let p = bigint_to_bytes(fields[4], ln);
    let q = bigint_to_bytes(fields[5], ln);
    let dp = bigint_to_bytes(fields[6], ln);
    let dq = bigint_to_bytes(fields[7], ln);
    let qinv = bigint_to_bytes(fields[8], ln);

    let mut data = tlv_encode(0x01, &p);
    data.extend_from_slice(&tlv_encode(0x02, &q));
    data.extend_from_slice(&tlv_encode(0x03, &dp));
    data.extend_from_slice(&tlv_encode(0x04, &dq));
    data.extend_from_slice(&tlv_encode(0x05, &qinv));

    Ok(data)
}

/// Parse SEC1 ECPrivateKey DER or raw scalar and build TLV import data.
fn build_ec_key_data(key_type: KeyType, key_der: &[u8]) -> Result<Vec<u8>, PivError> {
    let scalar_len = (key_type.bit_len() / 8) as usize;

    // If the data is exactly the scalar length, treat it as raw
    if key_der.len() == scalar_len {
        return Ok(tlv_encode(0x06, key_der));
    }

    // Otherwise, parse SEC1 ECPrivateKey DER
    let (_, seq_off, seq_len, _) =
        tlv_parse(key_der, 0).map_err(|_| PivError::InvalidData("Invalid EC DER".into()))?;
    let seq_data = &key_der[seq_off..seq_off + seq_len];

    // Parse fields: version, privateKey, [parameters], [publicKey]
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < seq_data.len() {
        let (_, val_off, val_len, end) = tlv_parse(seq_data, offset)
            .map_err(|_| PivError::InvalidData("Invalid EC key field".into()))?;
        fields.push(&seq_data[val_off..val_off + val_len]);
        offset = end;
    }

    if fields.len() < 2 {
        return Err(PivError::InvalidData(
            "EC key missing required fields".into(),
        ));
    }

    // fields[1] is the privateKey OCTET STRING value
    let scalar = bigint_to_bytes(fields[1], scalar_len);
    Ok(tlv_encode(0x06, &scalar))
}

// ---------------------------------------------------------------------------
// Hash algorithm
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

// ---------------------------------------------------------------------------
// Hashing & PKCS#1 v1.5 padding
// ---------------------------------------------------------------------------

const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

pub fn hash_data(hash_alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match hash_alg {
        HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

pub fn pkcs1v15_pad(hash_alg: HashAlgorithm, hash: &[u8], key_byte_len: usize) -> Vec<u8> {
    let digest_info_prefix = match hash_alg {
        HashAlgorithm::Sha256 => DIGEST_INFO_SHA256,
        HashAlgorithm::Sha384 => DIGEST_INFO_SHA384,
        HashAlgorithm::Sha512 => DIGEST_INFO_SHA512,
    };
    let t_len = digest_info_prefix.len() + hash.len();
    let pad_len = key_byte_len - 3 - t_len;
    let mut padded = Vec::with_capacity(key_byte_len);
    padded.push(0x00);
    padded.push(0x01);
    padded.extend(std::iter::repeat_n(0xFF, pad_len));
    padded.push(0x00);
    padded.extend_from_slice(digest_info_prefix);
    padded.extend_from_slice(hash);
    padded
}

// ---------------------------------------------------------------------------
// Device public key → SPKI conversion
// ---------------------------------------------------------------------------

// Well-known OIDs
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ED25519_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_X25519_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// Parse a single TLV from PIV device-encoded public key data.
fn parse_device_tlv(data: &[u8], offset: usize) -> Result<(u8, Vec<u8>, usize), PivError> {
    if offset >= data.len() {
        return Err(PivError::InvalidData(
            "Unexpected end of device public key data".into(),
        ));
    }
    let tag = data[offset];
    let mut pos = offset + 1;
    if pos >= data.len() {
        return Err(PivError::InvalidData("Truncated TLV length".into()));
    }
    let len = if data[pos] < 0x80 {
        let l = data[pos] as usize;
        pos += 1;
        l
    } else if data[pos] == 0x81 {
        pos += 1;
        let l = data[pos] as usize;
        pos += 1;
        l
    } else if data[pos] == 0x82 {
        pos += 1;
        let l = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;
        l
    } else {
        return Err(PivError::InvalidData(
            "Unsupported TLV length encoding".into(),
        ));
    };
    if pos + len > data.len() {
        return Err(PivError::InvalidData("TLV value extends past data".into()));
    }
    Ok((tag, data[pos..pos + len].to_vec(), pos + len))
}

/// Convert PIV device-encoded public key bytes to SubjectPublicKeyInfo DER.
///
/// PIV device encoding (from `generate_key`/`get_slot_metadata`):
/// - EC keys: `86 <len> <uncompressed_point>`
/// - RSA keys: `81 <len> <modulus> 82 <len> <exponent>`
/// - Ed25519/X25519: `86 <len> <32_bytes>`
pub fn device_pubkey_to_spki(key_type: KeyType, device_bytes: &[u8]) -> Result<Vec<u8>, PivError> {
    let spki = match key_type {
        KeyType::EccP256 | KeyType::EccP384 => {
            let (tag, ec_point, _) = parse_device_tlv(device_bytes, 0)?;
            if tag != 0x86 {
                return Err(PivError::InvalidData(format!(
                    "Expected tag 0x86 for EC point, got 0x{tag:02X}"
                )));
            }
            let curve_oid = if key_type == KeyType::EccP256 {
                OID_CURVE_P256
            } else {
                OID_CURVE_P384
            };
            let algo = AlgorithmIdentifierOwned {
                oid: OID_EC_PUBLIC_KEY,
                parameters: Some(der::Any::from(&curve_oid)),
            };
            SubjectPublicKeyInfoOwned {
                algorithm: algo,
                subject_public_key: BitString::from_bytes(&ec_point).map_err(|e| {
                    PivError::InvalidData(format!("Failed to encode EC point: {e}"))
                })?,
            }
        }
        KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let (tag1, modulus, end1) = parse_device_tlv(device_bytes, 0)?;
            if tag1 != 0x81 {
                return Err(PivError::InvalidData(format!(
                    "Expected tag 0x81 for RSA modulus, got 0x{tag1:02X}"
                )));
            }
            let (tag2, exponent, _) = parse_device_tlv(device_bytes, end1)?;
            if tag2 != 0x82 {
                return Err(PivError::InvalidData(format!(
                    "Expected tag 0x82 for RSA exponent, got 0x{tag2:02X}"
                )));
            }
            // Build RSAPublicKey DER: SEQUENCE { INTEGER modulus, INTEGER exponent }
            let mod_int = der::asn1::UintRef::new(&modulus)
                .map_err(|e| PivError::InvalidData(format!("Invalid RSA modulus: {e}")))?;
            let exp_int = der::asn1::UintRef::new(&exponent)
                .map_err(|e| PivError::InvalidData(format!("Invalid RSA exponent: {e}")))?;
            let mut rsa_body = Vec::new();
            mod_int
                .encode_to_vec(&mut rsa_body)
                .map_err(|e| PivError::InvalidData(format!("Failed to encode modulus: {e}")))?;
            exp_int
                .encode_to_vec(&mut rsa_body)
                .map_err(|e| PivError::InvalidData(format!("Failed to encode exponent: {e}")))?;
            // Wrap in SEQUENCE
            let mut rsa_pub_key = Vec::new();
            // Tag 0x30 = SEQUENCE
            rsa_pub_key.push(0x30);
            let len_bytes = der::Length::new(rsa_body.len() as u16);
            len_bytes
                .encode_to_vec(&mut rsa_pub_key)
                .map_err(|e| PivError::InvalidData(format!("Failed to encode length: {e}")))?;
            rsa_pub_key.extend_from_slice(&rsa_body);

            let algo = AlgorithmIdentifierOwned {
                oid: OID_RSA_ENCRYPTION,
                parameters: Some(der::Any::from(der::asn1::Null)),
            };
            SubjectPublicKeyInfoOwned {
                algorithm: algo,
                subject_public_key: BitString::from_bytes(&rsa_pub_key)
                    .map_err(|e| PivError::InvalidData(format!("Failed to encode RSA key: {e}")))?,
            }
        }
        KeyType::Ed25519 => {
            let (tag, raw_key, _) = parse_device_tlv(device_bytes, 0)?;
            if tag != 0x86 {
                return Err(PivError::InvalidData(format!(
                    "Expected tag 0x86 for Ed25519 key, got 0x{tag:02X}"
                )));
            }
            let algo = AlgorithmIdentifierOwned {
                oid: OID_ED25519_KEY,
                parameters: None,
            };
            SubjectPublicKeyInfoOwned {
                algorithm: algo,
                subject_public_key: BitString::from_bytes(&raw_key).map_err(|e| {
                    PivError::InvalidData(format!("Failed to encode Ed25519 key: {e}"))
                })?,
            }
        }
        KeyType::X25519 => {
            let (tag, raw_key, _) = parse_device_tlv(device_bytes, 0)?;
            if tag != 0x86 {
                return Err(PivError::InvalidData(format!(
                    "Expected tag 0x86 for X25519 key, got 0x{tag:02X}"
                )));
            }
            let algo = AlgorithmIdentifierOwned {
                oid: OID_X25519_KEY,
                parameters: None,
            };
            SubjectPublicKeyInfoOwned {
                algorithm: algo,
                subject_public_key: BitString::from_bytes(&raw_key).map_err(|e| {
                    PivError::InvalidData(format!("Failed to encode X25519 key: {e}"))
                })?,
            }
        }
    };

    spki.to_der()
        .map_err(|e| PivError::InvalidData(format!("Failed to encode SPKI: {e}")))
}

// ---------------------------------------------------------------------------
// PivSignature
// ---------------------------------------------------------------------------

/// Signature output from the PIV device, suitable for use with `x509-cert` builders.
#[derive(Clone, Debug)]
pub struct PivSignature(Vec<u8>);

impl AsRef<[u8]> for PivSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PivSignature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(PivSignature(bytes.to_vec()))
    }
}

impl TryInto<Box<[u8]>> for PivSignature {
    type Error = signature::Error;

    fn try_into(self) -> Result<Box<[u8]>, Self::Error> {
        Ok(self.0.into_boxed_slice())
    }
}

impl signature::SignatureEncoding for PivSignature {
    type Repr = Box<[u8]>;
}

impl SignatureBitStringEncoding for PivSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

// ---------------------------------------------------------------------------
// PivVerifyingKey — wraps SPKI DER bytes for EncodePublicKey
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PivVerifyingKey(Vec<u8>);

impl EncodePublicKey for PivVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        der::Document::from_der(&self.0).map_err(|_| spki::Error::KeyMalformed)
    }
}

// ---------------------------------------------------------------------------
// PivSigner
// ---------------------------------------------------------------------------

// Signature algorithm OIDs
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ED25519_SIG: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// A signer that delegates to a PIV session's on-device signing.
///
/// Uses `RefCell` for interior mutability since `Signer::try_sign` takes `&self`
/// but `PivSession::sign` needs `&mut self`.
pub struct PivSigner<'a, C: SmartCardConnection> {
    session: RefCell<&'a mut PivSession<C>>,
    slot: Slot,
    key_type: KeyType,
    hash_alg: HashAlgorithm,
    spki_der: Vec<u8>,
}

impl<'a, C: SmartCardConnection> PivSigner<'a, C> {
    pub fn new(
        session: &'a mut PivSession<C>,
        slot: Slot,
        key_type: KeyType,
        hash_alg: HashAlgorithm,
        spki_der: &[u8],
    ) -> Self {
        Self {
            session: RefCell::new(session),
            slot,
            key_type,
            hash_alg,
            spki_der: spki_der.to_vec(),
        }
    }
}

impl<C: SmartCardConnection> signature::Keypair for PivSigner<'_, C> {
    type VerifyingKey = PivVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        PivVerifyingKey(self.spki_der.clone())
    }
}

impl<C: SmartCardConnection> DynSignatureAlgorithmIdentifier for PivSigner<'_, C> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        let (oid, params) = match self.key_type {
            KeyType::EccP256 | KeyType::EccP384 => {
                let oid = match self.hash_alg {
                    HashAlgorithm::Sha256 => OID_ECDSA_SHA256,
                    HashAlgorithm::Sha384 => OID_ECDSA_SHA384,
                    HashAlgorithm::Sha512 => OID_ECDSA_SHA512,
                };
                (oid, None)
            }
            KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                let oid = match self.hash_alg {
                    HashAlgorithm::Sha256 => OID_RSA_SHA256,
                    HashAlgorithm::Sha384 => OID_RSA_SHA384,
                    HashAlgorithm::Sha512 => OID_RSA_SHA512,
                };
                (oid, Some(der::Any::from(der::asn1::Null)))
            }
            KeyType::Ed25519 => (OID_ED25519_SIG, None),
            KeyType::X25519 => return Err(spki::Error::KeyMalformed),
        };
        Ok(AlgorithmIdentifierOwned {
            oid,
            parameters: params,
        })
    }
}

impl<C: SmartCardConnection> signature::Signer<PivSignature> for PivSigner<'_, C> {
    fn try_sign(&self, msg: &[u8]) -> Result<PivSignature, signature::Error> {
        let message = match self.key_type {
            KeyType::EccP256 | KeyType::EccP384 => hash_data(self.hash_alg, msg),
            KeyType::Rsa1024 | KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
                let hash = hash_data(self.hash_alg, msg);
                let key_byte_len = (self.key_type.bit_len() / 8) as usize;
                pkcs1v15_pad(self.hash_alg, &hash, key_byte_len)
            }
            KeyType::Ed25519 => msg.to_vec(),
            KeyType::X25519 => return Err(signature::Error::new()),
        };

        let mut session = self.session.borrow_mut();
        let raw_sig = session
            .sign(self.slot, self.key_type, &message)
            .map_err(|_| signature::Error::new())?;

        // EC signatures from the device are DER-encoded (SEQUENCE { INTEGER r, INTEGER s }).
        // Pass them through directly.
        let sig_bytes = raw_sig;

        Ok(PivSignature(sig_bytes))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_algorithm() {
        assert_eq!(KeyType::Rsa1024.algorithm(), Algorithm::Rsa);
        assert_eq!(KeyType::Rsa2048.algorithm(), Algorithm::Rsa);
        assert_eq!(KeyType::Rsa3072.algorithm(), Algorithm::Rsa);
        assert_eq!(KeyType::Rsa4096.algorithm(), Algorithm::Rsa);
        assert_eq!(KeyType::EccP256.algorithm(), Algorithm::Ec);
        assert_eq!(KeyType::EccP384.algorithm(), Algorithm::Ec);
        assert_eq!(KeyType::Ed25519.algorithm(), Algorithm::Ec);
        assert_eq!(KeyType::X25519.algorithm(), Algorithm::Ec);
    }

    #[test]
    fn test_key_type_bit_len() {
        assert_eq!(KeyType::Rsa1024.bit_len(), 1024);
        assert_eq!(KeyType::Rsa2048.bit_len(), 2048);
        assert_eq!(KeyType::Rsa3072.bit_len(), 3072);
        assert_eq!(KeyType::Rsa4096.bit_len(), 4096);
        assert_eq!(KeyType::EccP256.bit_len(), 256);
        assert_eq!(KeyType::EccP384.bit_len(), 384);
        assert_eq!(KeyType::Ed25519.bit_len(), 256);
        assert_eq!(KeyType::X25519.bit_len(), 256);
    }

    #[test]
    fn test_key_type_from_u8() {
        assert_eq!(KeyType::from_u8(0x06), Some(KeyType::Rsa1024));
        assert_eq!(KeyType::from_u8(0x07), Some(KeyType::Rsa2048));
        assert_eq!(KeyType::from_u8(0x05), Some(KeyType::Rsa3072));
        assert_eq!(KeyType::from_u8(0x16), Some(KeyType::Rsa4096));
        assert_eq!(KeyType::from_u8(0x11), Some(KeyType::EccP256));
        assert_eq!(KeyType::from_u8(0x14), Some(KeyType::EccP384));
        assert_eq!(KeyType::from_u8(0xE0), Some(KeyType::Ed25519));
        assert_eq!(KeyType::from_u8(0xE1), Some(KeyType::X25519));
        assert_eq!(KeyType::from_u8(0xFF), None);
    }

    #[test]
    fn test_management_key_type_properties() {
        assert_eq!(ManagementKeyType::Tdes.key_len(), 24);
        assert_eq!(ManagementKeyType::Aes128.key_len(), 16);
        assert_eq!(ManagementKeyType::Aes192.key_len(), 24);
        assert_eq!(ManagementKeyType::Aes256.key_len(), 32);

        assert_eq!(ManagementKeyType::Tdes.challenge_len(), 8);
        assert_eq!(ManagementKeyType::Aes128.challenge_len(), 16);
        assert_eq!(ManagementKeyType::Aes192.challenge_len(), 16);
        assert_eq!(ManagementKeyType::Aes256.challenge_len(), 16);
    }

    #[test]
    fn test_management_key_type_from_u8() {
        assert_eq!(
            ManagementKeyType::from_u8(0x03),
            Some(ManagementKeyType::Tdes)
        );
        assert_eq!(
            ManagementKeyType::from_u8(0x08),
            Some(ManagementKeyType::Aes128)
        );
        assert_eq!(
            ManagementKeyType::from_u8(0x0A),
            Some(ManagementKeyType::Aes192)
        );
        assert_eq!(
            ManagementKeyType::from_u8(0x0C),
            Some(ManagementKeyType::Aes256)
        );
        assert_eq!(ManagementKeyType::from_u8(0xFF), None);
    }

    #[test]
    fn test_slot_to_object_id() {
        assert_eq!(
            ObjectId::from_slot(Slot::Authentication),
            ObjectId::Authentication
        );
        assert_eq!(ObjectId::from_slot(Slot::Signature), ObjectId::Signature);
        assert_eq!(
            ObjectId::from_slot(Slot::KeyManagement),
            ObjectId::KeyManagement
        );
        assert_eq!(ObjectId::from_slot(Slot::CardAuth), ObjectId::CardAuth);
        assert_eq!(ObjectId::from_slot(Slot::Retired1), ObjectId::Retired1);
        assert_eq!(ObjectId::from_slot(Slot::Retired10), ObjectId::Retired10);
        assert_eq!(ObjectId::from_slot(Slot::Retired20), ObjectId::Retired20);
        assert_eq!(
            ObjectId::from_slot(Slot::Attestation),
            ObjectId::Attestation
        );
    }

    #[test]
    fn test_pin_policy_values() {
        assert_eq!(PinPolicy::Default as u8, 0x00);
        assert_eq!(PinPolicy::Never as u8, 0x01);
        assert_eq!(PinPolicy::Once as u8, 0x02);
        assert_eq!(PinPolicy::Always as u8, 0x03);
        assert_eq!(PinPolicy::MatchOnce as u8, 0x04);
        assert_eq!(PinPolicy::MatchAlways as u8, 0x05);
    }

    #[test]
    fn test_touch_policy_values() {
        assert_eq!(TouchPolicy::Default as u8, 0x00);
        assert_eq!(TouchPolicy::Never as u8, 0x01);
        assert_eq!(TouchPolicy::Always as u8, 0x02);
        assert_eq!(TouchPolicy::Cached as u8, 0x03);
    }

    #[test]
    fn test_pin_padding() {
        let padded = pin_bytes("123456").unwrap();
        assert_eq!(padded, [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]);

        let padded = pin_bytes("12345678").unwrap();
        assert_eq!(padded, [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        let padded = pin_bytes("").unwrap();
        assert_eq!(padded, [0xFF; 8]);

        assert!(pin_bytes("123456789").is_err());
    }

    #[test]
    fn test_retries_from_sw() {
        assert_eq!(retries_from_sw(0x6983), Some(0)); // AUTH_METHOD_BLOCKED
        assert_eq!(retries_from_sw(0x63C3), Some(3));
        assert_eq!(retries_from_sw(0x63CF), Some(15));
        assert_eq!(retries_from_sw(0x63C0), Some(0));
        assert_eq!(retries_from_sw(0x9000), None);
        assert_eq!(retries_from_sw(0x6A80), None);
    }

    #[test]
    fn test_slot_display() {
        assert_eq!(format!("{}", Slot::Authentication), "9A (Authentication)");
        assert_eq!(format!("{}", Slot::Attestation), "F9 (Attestation)");
    }

    #[test]
    fn test_default_management_key() {
        assert_eq!(DEFAULT_MANAGEMENT_KEY.len(), 24);
    }

    #[test]
    fn test_object_id_values() {
        assert_eq!(ObjectId::Chuid as u32, 0x5FC102);
        assert_eq!(ObjectId::Capability as u32, 0x5FC107);
        assert_eq!(ObjectId::Discovery as u32, 0x7E);
        assert_eq!(ObjectId::Attestation as u32, 0x5FFF01);
    }

    #[test]
    fn test_mgmt_key_encrypt_decrypt_tdes() {
        let key = DEFAULT_MANAGEMENT_KEY;
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let encrypted = mgmt_key_encrypt(ManagementKeyType::Tdes, key, &data).unwrap();
        let decrypted = mgmt_key_decrypt(ManagementKeyType::Tdes, key, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_mgmt_key_encrypt_decrypt_aes128() {
        let key = [0u8; 16];
        let data = [0u8; 16];
        let encrypted = mgmt_key_encrypt(ManagementKeyType::Aes128, &key, &data).unwrap();
        let decrypted = mgmt_key_decrypt(ManagementKeyType::Aes128, &key, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_check_key_support_basic() {
        let v5_7 = Version(5, 7, 0);
        assert!(
            check_key_support(
                v5_7,
                KeyType::EccP256,
                PinPolicy::Default,
                TouchPolicy::Default,
                false,
                false
            )
            .is_ok()
        );

        // Ed25519 needs 5.7.0
        assert!(
            check_key_support(
                Version(5, 6, 0),
                KeyType::Ed25519,
                PinPolicy::Default,
                TouchPolicy::Default,
                false,
                false
            )
            .is_err()
        );

        assert!(
            check_key_support(
                v5_7,
                KeyType::Ed25519,
                PinPolicy::Default,
                TouchPolicy::Default,
                false,
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn test_check_key_support_roca() {
        // ROCA-affected range: 4.2.0 <= v < 4.3.5
        assert!(
            check_key_support(
                Version(4, 2, 0),
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Default,
                true, // generate
                false
            )
            .is_err()
        );

        // Import should still work
        assert!(
            check_key_support(
                Version(4, 2, 0),
                KeyType::Rsa2048,
                PinPolicy::Default,
                TouchPolicy::Default,
                false,
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn test_check_key_support_fips() {
        assert!(
            check_key_support(
                Version(4, 4, 0),
                KeyType::Rsa1024,
                PinPolicy::Default,
                TouchPolicy::Default,
                false,
                false
            )
            .is_err()
        );

        assert!(
            check_key_support(
                Version(4, 4, 0),
                KeyType::Rsa2048,
                PinPolicy::Never,
                TouchPolicy::Default,
                false,
                false
            )
            .is_err()
        );
    }
}
