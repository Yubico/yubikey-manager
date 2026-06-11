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

//! Cryptographic key types and parsing utilities.
//!
//! This module provides:
//! - [`crate::keys::KeyAlgorithm`] — algorithm identifier for asymmetric keys
//! - [`crate::keys::PrivateKey`] — private key material parsed from PKCS#8 or constructed directly
//! - [`crate::keys::PublicKey`] — public key material with SPKI serialization
//! - OID encoding/decoding utilities
//! - Well-known curve OID constants

use std::fmt;

use x509_cert::der;
use x509_cert::der::asn1::BitString;
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use zeroize::Zeroizing;

use crate::secret::SecretValue;
use crate::tlv::tlv_parse;

// ---------------------------------------------------------------------------
// Well-known curve OIDs (dotted-decimal strings)
// ---------------------------------------------------------------------------

/// NIST P-256 (secp256r1 / prime256v1).
pub(crate) const OID_SECP256R1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp256k1 (used in Bitcoin / Ethereum).
pub(crate) const OID_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
/// NIST P-384 (secp384r1).
pub(crate) const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// NIST P-521 (secp521r1).
pub(crate) const OID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
/// Brainpool P-256r1.
pub(crate) const OID_BRAINPOOL_P256R1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");
/// Brainpool P-384r1.
pub(crate) const OID_BRAINPOOL_P384R1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.11");
/// Brainpool P-512r1.
pub(crate) const OID_BRAINPOOL_P512R1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.13");

// ---------------------------------------------------------------------------
// KeyAlgorithm
// ---------------------------------------------------------------------------

/// RSA modulus bit length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum RsaKeySize {
    /// 1024-bit RSA key.
    Rsa1024 = 1024,
    /// 2048-bit RSA key.
    Rsa2048 = 2048,
    /// 3072-bit RSA key.
    Rsa3072 = 3072,
    /// 4096-bit RSA key.
    Rsa4096 = 4096,
}

impl RsaKeySize {
    /// Returns the bit length of this RSA key size.
    pub fn bit_len(self) -> usize {
        self as usize
    }

    /// Create from a bit length, if it matches a known size.
    pub fn from_bit_len(bits: usize) -> Option<Self> {
        match bits {
            1024 => Some(Self::Rsa1024),
            2048 => Some(Self::Rsa2048),
            3072 => Some(Self::Rsa3072),
            4096 => Some(Self::Rsa4096),
            _ => None,
        }
    }
}

/// Cryptographic algorithm for an asymmetric key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// RSA with the given key size.
    Rsa(RsaKeySize),
    /// Elliptic curve (NIST/Brainpool/secp256k1).
    Ec(EcCurve),
    /// Ed25519 signing key.
    Ed25519,
    /// X25519 key agreement.
    X25519,
    /// ML-DSA (FIPS 204) signing.
    MlDsa(MlDsaParameterSet),
    /// ML-KEM (FIPS 203) key encapsulation.
    MlKem(MlKemParameterSet),
}

/// Elliptic curve identifiers for use with ECDSA and/or ECDH.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EcCurve {
    /// NIST P-256 (secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
    /// NIST P-521 (secp521r1).
    P521,
    /// secp256k1.
    Secp256k1,
    /// Brainpool P-256r1.
    BrainpoolP256r1,
    /// Brainpool P-384r1.
    BrainpoolP384r1,
    /// Brainpool P-512r1.
    BrainpoolP512r1,
}

impl EcCurve {
    /// The expected scalar length in bytes.
    pub fn scalar_len(&self) -> usize {
        match self {
            Self::P256 | Self::Secp256k1 | Self::BrainpoolP256r1 => 32,
            Self::P384 | Self::BrainpoolP384r1 => 48,
            Self::P521 => 66,
            Self::BrainpoolP512r1 => 64,
        }
    }

    fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::P256 => OID_SECP256R1,
            Self::P384 => OID_SECP384R1,
            Self::P521 => OID_SECP521R1,
            Self::Secp256k1 => OID_SECP256K1,
            Self::BrainpoolP256r1 => OID_BRAINPOOL_P256R1,
            Self::BrainpoolP384r1 => OID_BRAINPOOL_P384R1,
            Self::BrainpoolP512r1 => OID_BRAINPOOL_P512R1,
        }
    }

    pub(crate) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            OID_SECP256R1 => Some(Self::P256),
            OID_SECP384R1 => Some(Self::P384),
            OID_SECP521R1 => Some(Self::P521),
            OID_SECP256K1 => Some(Self::Secp256k1),
            OID_BRAINPOOL_P256R1 => Some(Self::BrainpoolP256r1),
            OID_BRAINPOOL_P384R1 => Some(Self::BrainpoolP384r1),
            OID_BRAINPOOL_P512R1 => Some(Self::BrainpoolP512r1),
            _ => None,
        }
    }

    /// Parse a dotted-decimal OID string to an `EcCurve`.
    pub fn from_oid_str(s: &str) -> Option<Self> {
        let oid = ObjectIdentifier::new(s).ok()?;
        Self::from_oid(&oid)
    }
}

/// ML-DSA parameter sets (FIPS 204).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (security category 2).
    MlDsa44,
    /// ML-DSA-65 (security category 3).
    MlDsa65,
    /// ML-DSA-87 (security category 5).
    MlDsa87,
}

/// ML-KEM parameter sets (FIPS 203).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlKemParameterSet {
    /// ML-KEM-512 (security category 1).
    MlKem512,
    /// ML-KEM-768 (security category 3).
    MlKem768,
    /// ML-KEM-1024 (security category 5).
    MlKem1024,
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

/// An asymmetric private key.
///
/// Key material is automatically zeroized when dropped.
/// Construct via [`PrivateKey::from_pkcs8`] or directly from components.
#[non_exhaustive]
pub enum PrivateKey {
    /// RSA private key in CRT form.
    Rsa(RsaPrivateKey),
    /// Elliptic curve private key (NIST/Brainpool/secp256k1).
    Ec(EcPrivateKey),
    /// Ed25519 signing key.
    Ed25519(Ed25519PrivateKey),
    /// X25519 key agreement key.
    X25519(X25519PrivateKey),
    /// ML-DSA private key.
    MlDsa(MlDsaPrivateKey),
    /// ML-KEM private key.
    MlKem(MlKemPrivateKey),
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Each inner struct has its own Drop implementation.
        match self {
            Self::Rsa(_)
            | Self::Ec(_)
            | Self::Ed25519(_)
            | Self::X25519(_)
            | Self::MlDsa(_)
            | Self::MlKem(_) => {}
        }
    }
}

/// RSA private key components in CRT form.
pub struct RsaPrivateKey {
    /// Key size.
    pub(crate) key_size: RsaKeySize,
    /// Public modulus n = p*q.
    pub(crate) n: Vec<u8>,
    /// Public exponent (typically 65537).
    pub(crate) e: Vec<u8>,
    /// First prime factor.
    pub(crate) p: SecretValue<Vec<u8>>,
    /// Second prime factor.
    pub(crate) q: SecretValue<Vec<u8>>,
    /// d mod (p-1).
    pub(crate) dp: SecretValue<Vec<u8>>,
    /// d mod (q-1).
    pub(crate) dq: SecretValue<Vec<u8>>,
    /// q^{-1} mod p.
    pub(crate) qinv: SecretValue<Vec<u8>>,
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsaPrivateKey({:?})", self.key_size)
    }
}

impl RsaPrivateKey {
    /// Construct an RSA private key from integer components.
    ///
    /// Components are big-endian unsigned integers. `n`, `dp`, `dq`, and `qinv`
    /// may be empty for OpenPGP import formats that omit them.
    pub fn new(
        key_size: RsaKeySize,
        n: Vec<u8>,
        e: Vec<u8>,
        p: Vec<u8>,
        q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        qinv: Vec<u8>,
    ) -> Result<Self, KeyError> {
        let key_len = key_size.bit_len() / 8;
        let prime_len = key_len / 2;

        validate_non_empty("RSA public exponent", &e)?;
        validate_non_empty("RSA prime p", &p)?;
        validate_non_empty("RSA prime q", &q)?;
        validate_max_int_len("RSA prime p", &p, prime_len)?;
        validate_max_int_len("RSA prime q", &q, prime_len)?;
        validate_optional_int_len("RSA private exponent dp", &dp, prime_len)?;
        validate_optional_int_len("RSA private exponent dq", &dq, prime_len)?;
        validate_optional_int_len("RSA CRT coefficient qinv", &qinv, prime_len)?;
        if !n.is_empty() {
            validate_exact_int_len("RSA modulus", &n, key_len)?;
        }

        Ok(Self {
            key_size,
            n,
            e,
            p: SecretValue::new(p),
            q: SecretValue::new(q),
            dp: SecretValue::new(dp),
            dq: SecretValue::new(dq),
            qinv: SecretValue::new(qinv),
        })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa(self.key_size)
    }

    /// Parse a PKCS#1 RSAPrivateKey DER encoding into an `RsaPrivateKey`.
    pub fn from_pkcs1(pkcs1_der: &[u8]) -> Result<Self, KeyError> {
        let (_, seq_off, seq_len, _) =
            tlv_parse(pkcs1_der, 0).map_err(|_| KeyError("Invalid RSA DER"))?;
        let seq_data = &pkcs1_der[seq_off..seq_off + seq_len];

        let mut offset = 0;
        let mut fields: Vec<&[u8]> = Vec::new();
        while offset < seq_data.len() {
            let (_, val_off, val_len, end) =
                tlv_parse(seq_data, offset).map_err(|_| KeyError("Invalid RSA field"))?;
            fields.push(&seq_data[val_off..val_off + val_len]);
            offset = end;
        }

        if fields.len() < 9 {
            return Err(KeyError("RSA key missing required fields"));
        }

        let n = strip_leading_zero(fields[1]).to_vec();
        let key_size =
            RsaKeySize::from_bit_len(n.len() * 8).ok_or(KeyError("Unsupported RSA key size"))?;

        Self::new(
            key_size,
            n,
            strip_leading_zero(fields[2]).to_vec(),
            strip_leading_zero(fields[4]).to_vec(),
            strip_leading_zero(fields[5]).to_vec(),
            strip_leading_zero(fields[6]).to_vec(),
            strip_leading_zero(fields[7]).to_vec(),
            strip_leading_zero(fields[8]).to_vec(),
        )
    }
}

/// Elliptic curve private key.
pub struct EcPrivateKey {
    /// The curve.
    pub(crate) curve: EcCurve,
    /// The scalar value (big-endian, zero-padded to curve scalar length).
    pub(crate) scalar: SecretValue<Vec<u8>>,
    /// Optional uncompressed public key point.
    pub(crate) public_key: Option<Vec<u8>>,
}

impl fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcPrivateKey({:?})", self.curve)
    }
}

impl EcPrivateKey {
    /// Construct an EC private key.
    ///
    /// `scalar` is a big-endian unsigned integer and may be shorter than the
    /// curve scalar length; import code will left-pad it for applet wire formats.
    pub fn new(
        curve: EcCurve,
        scalar: Vec<u8>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Self, KeyError> {
        validate_non_empty("EC scalar", &scalar)?;
        validate_max_int_len("EC scalar", &scalar, curve.scalar_len())?;
        if strip_leading_zero(&scalar).is_empty() {
            return Err(KeyError("EC scalar must not be zero"));
        }
        if let Some(point) = &public_key {
            validate_ec_public_point(&curve, point)?;
        }
        Ok(Self {
            curve,
            scalar: SecretValue::new(scalar),
            public_key,
        })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Ec(self.curve.clone())
    }
}

/// Ed25519 signing private key (32-byte secret).
pub struct Ed25519PrivateKey {
    /// The 32-byte secret.
    pub(crate) secret: SecretValue<Vec<u8>>,
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PrivateKey")
    }
}

impl Ed25519PrivateKey {
    /// Construct an Ed25519 private key from a 32-byte secret.
    pub fn new(secret: Vec<u8>) -> Result<Self, KeyError> {
        validate_exact_len("Ed25519 secret key", &secret, 32)?;
        Ok(Self {
            secret: SecretValue::new(secret),
        })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Ed25519
    }
}

/// X25519 key agreement private key (32-byte secret).
pub struct X25519PrivateKey {
    /// The 32-byte secret.
    pub(crate) secret: SecretValue<Vec<u8>>,
}

impl fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519PrivateKey")
    }
}

impl X25519PrivateKey {
    /// Construct an X25519 private key from a 32-byte secret.
    pub fn new(secret: Vec<u8>) -> Result<Self, KeyError> {
        validate_exact_len("X25519 secret key", &secret, 32)?;
        Ok(Self {
            secret: SecretValue::new(secret),
        })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::X25519
    }
}

/// ML-DSA (FIPS 204) private key.
pub struct MlDsaPrivateKey {
    /// The ML-DSA parameter set.
    pub(crate) parameter_set: MlDsaParameterSet,
    /// The raw private key bytes.
    pub(crate) private_key: SecretValue<Vec<u8>>,
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlDsaPrivateKey({:?})", self.parameter_set)
    }
}

impl MlDsaPrivateKey {
    /// Construct an ML-DSA private key from raw private key bytes.
    pub fn new(parameter_set: MlDsaParameterSet, private_key: Vec<u8>) -> Result<Self, KeyError> {
        validate_non_empty("ML-DSA private key", &private_key)?;
        Ok(Self {
            parameter_set,
            private_key: SecretValue::new(private_key),
        })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::MlDsa(self.parameter_set)
    }
}

/// ML-KEM (FIPS 203) private key.
pub struct MlKemPrivateKey {
    /// The ML-KEM parameter set.
    pub(crate) parameter_set: MlKemParameterSet,
    /// The raw private key bytes.
    pub(crate) private_key: SecretValue<Vec<u8>>,
}

impl fmt::Debug for MlKemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlKemPrivateKey({:?})", self.parameter_set)
    }
}

impl MlKemPrivateKey {
    /// Construct an ML-KEM private key from raw private key bytes.
    pub fn new(parameter_set: MlKemParameterSet, private_key: Vec<u8>) -> Result<Self, KeyError> {
        validate_non_empty("ML-KEM private key", &private_key)?;
        Ok(Self {
            parameter_set,
            private_key: SecretValue::new(private_key),
        })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::MlKem(self.parameter_set)
    }
}

impl PrivateKey {
    /// Parse a PKCS#8 PrivateKeyInfo DER encoding.
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<Self, KeyError> {
        let (algorithm, key_data) = parse_pkcs8(pkcs8_der)?;

        match algorithm {
            KeyAlgorithm::Rsa(_) => Ok(Self::Rsa(RsaPrivateKey::from_pkcs1(&key_data)?)),
            KeyAlgorithm::Ec(curve) => {
                Ok(Self::Ec(EcPrivateKey::new(curve, key_data.to_vec(), None)?))
            }
            KeyAlgorithm::Ed25519 => Ok(Self::Ed25519(Ed25519PrivateKey::new(key_data.to_vec())?)),
            KeyAlgorithm::X25519 => Ok(Self::X25519(X25519PrivateKey::new(key_data.to_vec())?)),
            KeyAlgorithm::MlDsa(parameter_set) => Ok(Self::MlDsa(MlDsaPrivateKey::new(
                parameter_set,
                key_data.to_vec(),
            )?)),
            KeyAlgorithm::MlKem(parameter_set) => Ok(Self::MlKem(MlKemPrivateKey::new(
                parameter_set,
                key_data.to_vec(),
            )?)),
        }
    }

    /// Returns the algorithm of this private key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Rsa(k) => k.algorithm(),
            Self::Ec(k) => k.algorithm(),
            Self::Ed25519(k) => k.algorithm(),
            Self::X25519(k) => k.algorithm(),
            Self::MlDsa(k) => k.algorithm(),
            Self::MlKem(k) => k.algorithm(),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(k) => write!(f, "PrivateKey::Rsa({k:?})"),
            Self::Ec(k) => write!(f, "PrivateKey::Ec({k:?})"),
            Self::Ed25519(k) => write!(f, "PrivateKey::{k:?}"),
            Self::X25519(k) => write!(f, "PrivateKey::{k:?}"),
            Self::MlDsa(k) => write!(f, "PrivateKey::{k:?}"),
            Self::MlKem(k) => write!(f, "PrivateKey::{k:?}"),
        }
    }
}

impl From<RsaPrivateKey> for PrivateKey {
    fn from(k: RsaPrivateKey) -> Self {
        Self::Rsa(k)
    }
}

impl From<EcPrivateKey> for PrivateKey {
    fn from(k: EcPrivateKey) -> Self {
        Self::Ec(k)
    }
}

impl From<Ed25519PrivateKey> for PrivateKey {
    fn from(k: Ed25519PrivateKey) -> Self {
        Self::Ed25519(k)
    }
}

impl From<X25519PrivateKey> for PrivateKey {
    fn from(k: X25519PrivateKey) -> Self {
        Self::X25519(k)
    }
}

impl From<MlDsaPrivateKey> for PrivateKey {
    fn from(k: MlDsaPrivateKey) -> Self {
        Self::MlDsa(k)
    }
}

impl From<MlKemPrivateKey> for PrivateKey {
    fn from(k: MlKemPrivateKey) -> Self {
        Self::MlKem(k)
    }
}

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

/// An asymmetric public key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKey {
    /// RSA public key.
    Rsa(RsaPublicKey),
    /// Elliptic curve public key.
    Ec(EcPublicKey),
    /// Ed25519 public key (32 bytes).
    Ed25519(Ed25519PublicKey),
    /// X25519 public key (32 bytes).
    X25519(X25519PublicKey),
    /// ML-DSA public key.
    MlDsa(MlDsaPublicKey),
    /// ML-KEM public key.
    MlKem(MlKemPublicKey),
}

impl From<RsaPublicKey> for PublicKey {
    fn from(k: RsaPublicKey) -> Self {
        Self::Rsa(k)
    }
}

impl From<EcPublicKey> for PublicKey {
    fn from(k: EcPublicKey) -> Self {
        Self::Ec(k)
    }
}

impl From<Ed25519PublicKey> for PublicKey {
    fn from(k: Ed25519PublicKey) -> Self {
        Self::Ed25519(k)
    }
}

impl From<X25519PublicKey> for PublicKey {
    fn from(k: X25519PublicKey) -> Self {
        Self::X25519(k)
    }
}

impl From<MlDsaPublicKey> for PublicKey {
    fn from(k: MlDsaPublicKey) -> Self {
        Self::MlDsa(k)
    }
}

impl From<MlKemPublicKey> for PublicKey {
    fn from(k: MlKemPublicKey) -> Self {
        Self::MlKem(k)
    }
}

/// RSA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// Key size.
    pub key_size: RsaKeySize,
    /// Modulus (big-endian, unsigned).
    pub n: Vec<u8>,
    /// Public exponent (big-endian, unsigned).
    pub e: Vec<u8>,
}

impl RsaPublicKey {
    /// Construct an RSA public key.
    pub fn new(n: Vec<u8>, e: Vec<u8>) -> Result<Self, KeyError> {
        validate_non_empty("RSA modulus", &n)?;
        validate_non_empty("RSA public exponent", &e)?;
        let n = strip_leading_zero(&n).to_vec();
        let key_size =
            RsaKeySize::from_bit_len(n.len() * 8).ok_or(KeyError("Unsupported RSA key size"))?;
        Ok(Self { key_size, n, e })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa(self.key_size)
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        let mod_int =
            der::asn1::UintRef::new(&self.n).map_err(|_| KeyError("Invalid RSA modulus"))?;
        let exp_int =
            der::asn1::UintRef::new(&self.e).map_err(|_| KeyError("Invalid RSA exponent"))?;
        let mut rsa_body = Vec::new();
        mod_int
            .encode_to_vec(&mut rsa_body)
            .map_err(|_| KeyError("Failed to encode RSA modulus"))?;
        exp_int
            .encode_to_vec(&mut rsa_body)
            .map_err(|_| KeyError("Failed to encode RSA exponent"))?;
        let mut rsa_pub_key = Vec::new();
        rsa_pub_key.push(0x30);
        der::Length::new(rsa_body.len() as u16)
            .encode_to_vec(&mut rsa_pub_key)
            .map_err(|_| KeyError("Failed to encode RSA length"))?;
        rsa_pub_key.extend_from_slice(&rsa_body);

        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: SPKI_OID_RSA,
                parameters: Some(der::Any::from(der::asn1::Null)),
            },
            subject_public_key: BitString::from_bytes(&rsa_pub_key)
                .map_err(|_| KeyError("Failed to encode RSA BIT STRING"))?,
        };
        spki.to_der()
            .map_err(|_| KeyError("Failed to encode SPKI DER"))
    }
}

/// Elliptic curve public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcPublicKey {
    /// The curve.
    pub curve: EcCurve,
    /// Uncompressed point (0x04 || x || y).
    pub point: Vec<u8>,
}

impl EcPublicKey {
    /// Construct an EC public key from an uncompressed SEC 1 point.
    pub fn new(curve: EcCurve, point: Vec<u8>) -> Result<Self, KeyError> {
        validate_ec_public_point(&curve, &point)?;
        Ok(Self { curve, point })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Ec(self.curve.clone())
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: SPKI_OID_EC,
                parameters: Some(der::Any::from(&self.curve.oid())),
            },
            subject_public_key: BitString::from_bytes(&self.point)
                .map_err(|_| KeyError("Failed to encode EC BIT STRING"))?,
        };
        spki.to_der()
            .map_err(|_| KeyError("Failed to encode SPKI DER"))
    }
}

/// Ed25519 public key (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    /// The 32-byte public key.
    pub key: Vec<u8>,
}

impl Ed25519PublicKey {
    /// Construct an Ed25519 public key from 32 raw bytes.
    pub fn new(key: Vec<u8>) -> Result<Self, KeyError> {
        validate_exact_len("Ed25519 public key", &key, 32)?;
        Ok(Self { key })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Ed25519
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: SPKI_OID_ED25519,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&self.key)
                .map_err(|_| KeyError("Failed to encode Ed25519 BIT STRING"))?,
        };
        spki.to_der()
            .map_err(|_| KeyError("Failed to encode SPKI DER"))
    }
}

/// X25519 public key (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey {
    /// The 32-byte public key.
    pub key: Vec<u8>,
}

impl X25519PublicKey {
    /// Construct an X25519 public key from 32 raw bytes.
    pub fn new(key: Vec<u8>) -> Result<Self, KeyError> {
        validate_exact_len("X25519 public key", &key, 32)?;
        Ok(Self { key })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::X25519
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: SPKI_OID_X25519,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&self.key)
                .map_err(|_| KeyError("Failed to encode X25519 BIT STRING"))?,
        };
        spki.to_der()
            .map_err(|_| KeyError("Failed to encode SPKI DER"))
    }
}

/// ML-DSA (FIPS 204) public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlDsaPublicKey {
    /// The ML-DSA parameter set.
    pub parameter_set: MlDsaParameterSet,
    /// The raw public key bytes.
    pub key: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Construct an ML-DSA public key from raw public key bytes.
    pub fn new(parameter_set: MlDsaParameterSet, key: Vec<u8>) -> Result<Self, KeyError> {
        validate_non_empty("ML-DSA public key", &key)?;
        Ok(Self { parameter_set, key })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::MlDsa(self.parameter_set)
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        let oid = match self.parameter_set {
            MlDsaParameterSet::MlDsa44 => SPKI_OID_ML_DSA_44,
            MlDsaParameterSet::MlDsa65 => SPKI_OID_ML_DSA_65,
            MlDsaParameterSet::MlDsa87 => SPKI_OID_ML_DSA_87,
        };
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&self.key)
                .map_err(|_| KeyError("Failed to encode ML-DSA BIT STRING"))?,
        };
        spki.to_der()
            .map_err(|_| KeyError("Failed to encode SPKI DER"))
    }
}

/// ML-KEM (FIPS 203) public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKemPublicKey {
    /// The ML-KEM parameter set.
    pub parameter_set: MlKemParameterSet,
    /// The raw public key bytes.
    pub key: Vec<u8>,
}

impl MlKemPublicKey {
    /// Construct an ML-KEM public key from raw public key bytes.
    pub fn new(parameter_set: MlKemParameterSet, key: Vec<u8>) -> Result<Self, KeyError> {
        validate_non_empty("ML-KEM public key", &key)?;
        Ok(Self { parameter_set, key })
    }

    /// Returns the algorithm of this key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::MlKem(self.parameter_set)
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        let oid = match self.parameter_set {
            MlKemParameterSet::MlKem512 => SPKI_OID_ML_KEM_512,
            MlKemParameterSet::MlKem768 => SPKI_OID_ML_KEM_768,
            MlKemParameterSet::MlKem1024 => SPKI_OID_ML_KEM_1024,
        };
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&self.key)
                .map_err(|_| KeyError("Failed to encode ML-KEM BIT STRING"))?,
        };
        spki.to_der()
            .map_err(|_| KeyError("Failed to encode SPKI DER"))
    }
}

fn strip_leading_zero(b: &[u8]) -> &[u8] {
    if !b.is_empty() && b[0] == 0 {
        &b[1..]
    } else {
        b
    }
}

fn validate_non_empty(name: &'static str, value: &[u8]) -> Result<(), KeyError> {
    if value.is_empty() {
        Err(KeyError(name))
    } else {
        Ok(())
    }
}

fn validate_exact_len(name: &'static str, value: &[u8], len: usize) -> Result<(), KeyError> {
    if value.len() == len {
        Ok(())
    } else {
        Err(KeyError(name))
    }
}

fn validate_max_int_len(name: &'static str, value: &[u8], max_len: usize) -> Result<(), KeyError> {
    if strip_leading_zero(value).len() <= max_len {
        Ok(())
    } else {
        Err(KeyError(name))
    }
}

fn validate_optional_int_len(
    name: &'static str,
    value: &[u8],
    max_len: usize,
) -> Result<(), KeyError> {
    if value.is_empty() {
        Ok(())
    } else {
        validate_max_int_len(name, value, max_len)
    }
}

fn validate_exact_int_len(name: &'static str, value: &[u8], len: usize) -> Result<(), KeyError> {
    if strip_leading_zero(value).len() == len {
        Ok(())
    } else {
        Err(KeyError(name))
    }
}

fn validate_ec_public_point(curve: &EcCurve, point: &[u8]) -> Result<(), KeyError> {
    let coordinate_len = curve.scalar_len();
    if point.len() == 1 + coordinate_len * 2 && point.first() == Some(&0x04) {
        Ok(())
    } else {
        Err(KeyError("Invalid EC public point"))
    }
}

// SPKI OID constants
const SPKI_OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SPKI_OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SPKI_OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const SPKI_OID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
const SPKI_OID_ML_DSA_44: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const SPKI_OID_ML_DSA_65: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const SPKI_OID_ML_DSA_87: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");
const SPKI_OID_ML_KEM_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");
const SPKI_OID_ML_KEM_768: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");
const SPKI_OID_ML_KEM_1024: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

impl PublicKey {
    /// Parse a public key from SubjectPublicKeyInfo (SPKI) DER encoding.
    pub fn from_spki(der: &[u8]) -> Result<Self, KeyError> {
        let spki = SubjectPublicKeyInfoOwned::from_der(der)
            .map_err(|_| KeyError("Invalid SPKI DER encoding"))?;

        let key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(KeyError("Invalid BIT STRING in SPKI"))?;

        let oid = spki.algorithm.oid;
        if oid == SPKI_OID_RSA {
            // RSA: key_bytes is a DER SEQUENCE { INTEGER modulus, INTEGER exponent }
            let (_, seq_off, seq_len, _) =
                tlv_parse(key_bytes, 0).map_err(|_| KeyError("Invalid RSA public key"))?;
            let inner = &key_bytes[seq_off..seq_off + seq_len];
            let (_, n_off, n_len, n_end) =
                tlv_parse(inner, 0).map_err(|_| KeyError("Invalid RSA modulus"))?;
            let (_, e_off, e_len, _) =
                tlv_parse(inner, n_end).map_err(|_| KeyError("Invalid RSA exponent"))?;
            let n = strip_leading_zero(&inner[n_off..n_off + n_len]);
            let e = strip_leading_zero(&inner[e_off..e_off + e_len]);
            let key_size = RsaKeySize::from_bit_len(n.len() * 8)
                .ok_or(KeyError("Unsupported RSA key size"))?;
            let public_key = RsaPublicKey::new(n.to_vec(), e.to_vec())?;
            if public_key.key_size != key_size {
                return Err(KeyError("RSA public key size mismatch"));
            }
            Ok(Self::Rsa(public_key))
        } else if oid == SPKI_OID_EC {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| ObjectIdentifier::from_der(p.value()).ok())
                .ok_or(KeyError("Missing EC curve parameter"))?;
            let curve =
                EcCurve::from_oid(&curve_oid).ok_or(KeyError("Unsupported EC curve in SPKI"))?;
            Ok(Self::Ec(EcPublicKey::new(curve, key_bytes.to_vec())?))
        } else if oid == SPKI_OID_ED25519 {
            Ok(Self::Ed25519(Ed25519PublicKey::new(key_bytes.to_vec())?))
        } else if oid == SPKI_OID_X25519 {
            Ok(Self::X25519(X25519PublicKey::new(key_bytes.to_vec())?))
        } else if oid == SPKI_OID_ML_DSA_44 {
            Ok(Self::MlDsa(MlDsaPublicKey::new(
                MlDsaParameterSet::MlDsa44,
                key_bytes.to_vec(),
            )?))
        } else if oid == SPKI_OID_ML_DSA_65 {
            Ok(Self::MlDsa(MlDsaPublicKey::new(
                MlDsaParameterSet::MlDsa65,
                key_bytes.to_vec(),
            )?))
        } else if oid == SPKI_OID_ML_DSA_87 {
            Ok(Self::MlDsa(MlDsaPublicKey::new(
                MlDsaParameterSet::MlDsa87,
                key_bytes.to_vec(),
            )?))
        } else if oid == SPKI_OID_ML_KEM_512 {
            Ok(Self::MlKem(MlKemPublicKey::new(
                MlKemParameterSet::MlKem512,
                key_bytes.to_vec(),
            )?))
        } else if oid == SPKI_OID_ML_KEM_768 {
            Ok(Self::MlKem(MlKemPublicKey::new(
                MlKemParameterSet::MlKem768,
                key_bytes.to_vec(),
            )?))
        } else if oid == SPKI_OID_ML_KEM_1024 {
            Ok(Self::MlKem(MlKemPublicKey::new(
                MlKemParameterSet::MlKem1024,
                key_bytes.to_vec(),
            )?))
        } else {
            Err(KeyError("Unsupported algorithm in SPKI"))
        }
    }

    /// Returns the algorithm of this public key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Rsa(k) => k.algorithm(),
            Self::Ec(k) => k.algorithm(),
            Self::Ed25519(k) => k.algorithm(),
            Self::X25519(k) => k.algorithm(),
            Self::MlDsa(k) => k.algorithm(),
            Self::MlKem(k) => k.algorithm(),
        }
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::Rsa(k) => k.to_spki(),
            Self::Ec(k) => k.to_spki(),
            Self::Ed25519(k) => k.to_spki(),
            Self::X25519(k) => k.to_spki(),
            Self::MlDsa(k) => k.to_spki(),
            Self::MlKem(k) => k.to_spki(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error type for key parsing/encoding operations.
#[derive(Debug, Clone)]
pub struct KeyError(pub &'static str);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for KeyError {}

// ---------------------------------------------------------------------------
// Internal parsing helpers
// ---------------------------------------------------------------------------

/// Parse a PKCS#8 PrivateKeyInfo DER encoding, returning the algorithm and raw key data.
fn parse_pkcs8(pkcs8_der: &[u8]) -> Result<(KeyAlgorithm, Zeroizing<Vec<u8>>), KeyError> {
    let (_, seq_off, seq_len, _) = tlv_parse(pkcs8_der, 0).map_err(|_| KeyError("Invalid DER"))?;
    let seq_data = &pkcs8_der[seq_off..seq_off + seq_len];

    let (_, _, _, ver_end) = tlv_parse(seq_data, 0).map_err(|_| KeyError("Invalid version"))?;

    let (_, algo_off, algo_len, algo_end) =
        tlv_parse(seq_data, ver_end).map_err(|_| KeyError("Invalid AlgorithmIdentifier"))?;
    let algo_data = &seq_data[algo_off..algo_off + algo_len];

    let (_, oid_off, oid_len, oid_end) =
        tlv_parse(algo_data, 0).map_err(|_| KeyError("Invalid OID"))?;
    let oid = &algo_data[oid_off..oid_off + oid_len];

    let (_, oct_off, oct_len, _) =
        tlv_parse(seq_data, algo_end).map_err(|_| KeyError("Invalid OCTET STRING"))?;
    let private_key_data = &seq_data[oct_off..oct_off + oct_len];

    if oid == SPKI_OID_RSA.as_bytes() {
        // For RSA, determine key size from the modulus in the inner PKCS#1 structure
        let (_, inner_off, inner_len, _) =
            tlv_parse(private_key_data, 0).map_err(|_| KeyError("Invalid RSA inner SEQUENCE"))?;
        let inner = &private_key_data[inner_off..inner_off + inner_len];
        let (_, _, _, mod_start) =
            tlv_parse(inner, 0).map_err(|_| KeyError("Invalid RSA version"))?;
        let (_, mod_off, mod_len, _) =
            tlv_parse(inner, mod_start).map_err(|_| KeyError("Invalid RSA modulus"))?;
        let modulus = &inner[mod_off..mod_off + mod_len];
        let mod_bytes = if !modulus.is_empty() && modulus[0] == 0 {
            modulus.len() - 1
        } else {
            modulus.len()
        };
        let mod_bits = mod_bytes * 8;
        let key_size =
            RsaKeySize::from_bit_len(mod_bits).ok_or(KeyError("Unsupported RSA key size"))?;
        Ok((
            KeyAlgorithm::Rsa(key_size),
            Zeroizing::new(private_key_data.to_vec()),
        ))
    } else if oid == SPKI_OID_EC.as_bytes() {
        let (_, curve_off, curve_len, _) =
            tlv_parse(algo_data, oid_end).map_err(|_| KeyError("Invalid EC curve OID"))?;
        let curve_oid = &algo_data[curve_off..curve_off + curve_len];
        let curve = ObjectIdentifier::from_bytes(curve_oid)
            .ok()
            .and_then(|o| EcCurve::from_oid(&o))
            .ok_or(KeyError("Unsupported EC curve"))?;
        // Extract the raw scalar from ECPrivateKey SEQUENCE
        let (_, inner_off, inner_len, _) =
            tlv_parse(private_key_data, 0).map_err(|_| KeyError("Invalid ECPrivateKey"))?;
        let inner = &private_key_data[inner_off..inner_off + inner_len];
        let (_, _, _, ec_ver_end) =
            tlv_parse(inner, 0).map_err(|_| KeyError("Invalid EC version"))?;
        let (_, key_off, key_len, _) =
            tlv_parse(inner, ec_ver_end).map_err(|_| KeyError("Invalid EC private key"))?;
        Ok((
            KeyAlgorithm::Ec(curve),
            Zeroizing::new(inner[key_off..key_off + key_len].to_vec()),
        ))
    } else {
        let algo_oid =
            ObjectIdentifier::from_bytes(oid).map_err(|_| KeyError("Invalid algorithm OID"))?;
        let algorithm = match algo_oid {
            SPKI_OID_ED25519 => KeyAlgorithm::Ed25519,
            SPKI_OID_X25519 => KeyAlgorithm::X25519,
            SPKI_OID_ML_DSA_44 => KeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            SPKI_OID_ML_DSA_65 => KeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
            SPKI_OID_ML_DSA_87 => KeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87),
            SPKI_OID_ML_KEM_512 => KeyAlgorithm::MlKem(MlKemParameterSet::MlKem512),
            SPKI_OID_ML_KEM_768 => KeyAlgorithm::MlKem(MlKemParameterSet::MlKem768),
            SPKI_OID_ML_KEM_1024 => KeyAlgorithm::MlKem(MlKemParameterSet::MlKem1024),
            _ => return Err(KeyError("Unsupported key algorithm")),
        };
        // Raw key is wrapped in an OCTET STRING inside the outer OCTET STRING
        let (_, key_off, key_len, _) =
            tlv_parse(private_key_data, 0).map_err(|_| KeyError("Invalid key OCTET STRING"))?;
        Ok((
            algorithm,
            Zeroizing::new(private_key_data[key_off..key_off + key_len].to_vec()),
        ))
    }
}
