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
//! - [`KeyAlgorithm`] — algorithm identifier for asymmetric keys
//! - [`PrivateKey`] — private key material parsed from PKCS#8 or constructed directly
//! - [`PublicKey`] — public key material with SPKI serialization
//! - OID encoding/decoding utilities
//! - Well-known curve OID constants

use std::fmt;

use x509_cert::der;
use x509_cert::der::asn1::BitString;
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use zeroize::{Zeroize, Zeroizing};

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

/// Cryptographic algorithm for an asymmetric key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// RSA with the given modulus bit length.
    Rsa(usize),
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

/// Elliptic curve identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
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
pub enum PrivateKey {
    /// RSA private key in CRT form.
    Rsa(RsaPrivateKey),
    /// Elliptic curve private key (NIST/Brainpool/secp256k1).
    Ec(EcPrivateKey),
    /// Ed25519 signing key (32-byte secret).
    Ed25519 {
        /// The 32-byte secret.
        secret: Vec<u8>,
    },
    /// X25519 key agreement (32-byte secret).
    X25519 {
        /// The 32-byte secret.
        secret: Vec<u8>,
    },
    /// ML-DSA private key.
    MlDsa {
        /// The ML-DSA parameter set.
        parameter_set: MlDsaParameterSet,
        /// The raw private key bytes.
        private_key: Vec<u8>,
    },
    /// ML-KEM private key.
    MlKem {
        /// The ML-KEM parameter set.
        parameter_set: MlKemParameterSet,
        /// The raw private key bytes.
        private_key: Vec<u8>,
    },
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        match self {
            Self::Rsa(_) => {} // RsaPrivateKey has its own Drop
            Self::Ec(_) => {}  // EcPrivateKey has its own Drop
            Self::Ed25519 { secret } => secret.zeroize(),
            Self::X25519 { secret } => secret.zeroize(),
            Self::MlDsa { private_key, .. } => private_key.zeroize(),
            Self::MlKem { private_key, .. } => private_key.zeroize(),
        }
    }
}

/// RSA private key components in CRT form.
pub struct RsaPrivateKey {
    /// Public modulus n = p*q.
    pub n: Vec<u8>,
    /// Public exponent (typically 65537).
    pub e: Vec<u8>,
    /// First prime factor.
    pub p: Vec<u8>,
    /// Second prime factor.
    pub q: Vec<u8>,
    /// d mod (p-1).
    pub dp: Vec<u8>,
    /// d mod (q-1).
    pub dq: Vec<u8>,
    /// q^{-1} mod p.
    pub qinv: Vec<u8>,
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.n.zeroize();
        self.e.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsaPrivateKey({}bit)", self.n.len() * 8)
    }
}

impl RsaPrivateKey {
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

        Ok(Self {
            n: strip_leading_zero(fields[1]).to_vec(),
            e: strip_leading_zero(fields[2]).to_vec(),
            p: strip_leading_zero(fields[4]).to_vec(),
            q: strip_leading_zero(fields[5]).to_vec(),
            dp: strip_leading_zero(fields[6]).to_vec(),
            dq: strip_leading_zero(fields[7]).to_vec(),
            qinv: strip_leading_zero(fields[8]).to_vec(),
        })
    }
}

/// Elliptic curve private key.
pub struct EcPrivateKey {
    /// The curve.
    pub curve: EcCurve,
    /// The scalar value (big-endian, zero-padded to curve scalar length).
    pub scalar: Vec<u8>,
    /// Optional uncompressed public key point.
    pub public_key: Option<Vec<u8>>,
}

impl Drop for EcPrivateKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcPrivateKey({:?})", self.curve)
    }
}

impl PrivateKey {
    /// Parse a PKCS#8 PrivateKeyInfo DER encoding.
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<Self, KeyError> {
        let (algorithm, key_data) = parse_pkcs8(pkcs8_der)?;

        match algorithm {
            KeyAlgorithm::Rsa(_) => Ok(Self::Rsa(RsaPrivateKey::from_pkcs1(&key_data)?)),
            KeyAlgorithm::Ec(curve) => Ok(Self::Ec(EcPrivateKey {
                curve,
                scalar: key_data.to_vec(),
                public_key: None,
            })),
            KeyAlgorithm::Ed25519 => Ok(Self::Ed25519 {
                secret: key_data.to_vec(),
            }),
            KeyAlgorithm::X25519 => Ok(Self::X25519 {
                secret: key_data.to_vec(),
            }),
            KeyAlgorithm::MlDsa(parameter_set) => Ok(Self::MlDsa {
                parameter_set,
                private_key: key_data.to_vec(),
            }),
            KeyAlgorithm::MlKem(parameter_set) => Ok(Self::MlKem {
                parameter_set,
                private_key: key_data.to_vec(),
            }),
        }
    }

    /// Returns the algorithm of this private key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Rsa(rsa) => KeyAlgorithm::Rsa(rsa.n.len() * 8),
            Self::Ec(ec) => KeyAlgorithm::Ec(ec.curve.clone()),
            Self::Ed25519 { .. } => KeyAlgorithm::Ed25519,
            Self::X25519 { .. } => KeyAlgorithm::X25519,
            Self::MlDsa { parameter_set, .. } => KeyAlgorithm::MlDsa(*parameter_set),
            Self::MlKem { parameter_set, .. } => KeyAlgorithm::MlKem(*parameter_set),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(rsa) => write!(f, "PrivateKey::Rsa({rsa:?})"),
            Self::Ec(ec) => write!(f, "PrivateKey::Ec({ec:?})"),
            Self::Ed25519 { .. } => write!(f, "PrivateKey::Ed25519"),
            Self::X25519 { .. } => write!(f, "PrivateKey::X25519"),
            Self::MlDsa { parameter_set, .. } => write!(f, "PrivateKey::MlDsa({parameter_set:?})"),
            Self::MlKem { parameter_set, .. } => write!(f, "PrivateKey::MlKem({parameter_set:?})"),
        }
    }
}

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

/// An asymmetric public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA public key.
    Rsa {
        /// Modulus (big-endian, unsigned).
        n: Vec<u8>,
        /// Public exponent (big-endian, unsigned).
        e: Vec<u8>,
    },
    /// Elliptic curve public key.
    Ec {
        /// The curve.
        curve: EcCurve,
        /// Uncompressed point (0x04 || x || y).
        point: Vec<u8>,
    },
    /// Ed25519 public key (32 bytes).
    Ed25519 {
        /// The 32-byte public key.
        key: Vec<u8>,
    },
    /// X25519 public key (32 bytes).
    X25519 {
        /// The 32-byte public key.
        key: Vec<u8>,
    },
    /// ML-DSA public key.
    MlDsa {
        /// The ML-DSA parameter set.
        parameter_set: MlDsaParameterSet,
        /// The raw public key bytes.
        key: Vec<u8>,
    },
    /// ML-KEM public key.
    MlKem {
        /// The ML-KEM parameter set.
        parameter_set: MlKemParameterSet,
        /// The raw public key bytes.
        key: Vec<u8>,
    },
}

fn strip_leading_zero(b: &[u8]) -> &[u8] {
    if !b.is_empty() && b[0] == 0 {
        &b[1..]
    } else {
        b
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
            Ok(Self::Rsa {
                n: n.to_vec(),
                e: e.to_vec(),
            })
        } else if oid == SPKI_OID_EC {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| ObjectIdentifier::from_der(p.value()).ok())
                .ok_or(KeyError("Missing EC curve parameter"))?;
            let curve =
                EcCurve::from_oid(&curve_oid).ok_or(KeyError("Unsupported EC curve in SPKI"))?;
            Ok(Self::Ec {
                curve,
                point: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_ED25519 {
            Ok(Self::Ed25519 {
                key: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_X25519 {
            Ok(Self::X25519 {
                key: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_ML_DSA_44 {
            Ok(Self::MlDsa {
                parameter_set: MlDsaParameterSet::MlDsa44,
                key: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_ML_DSA_65 {
            Ok(Self::MlDsa {
                parameter_set: MlDsaParameterSet::MlDsa65,
                key: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_ML_DSA_87 {
            Ok(Self::MlDsa {
                parameter_set: MlDsaParameterSet::MlDsa87,
                key: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_ML_KEM_512 {
            Ok(Self::MlKem {
                parameter_set: MlKemParameterSet::MlKem512,
                key: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_ML_KEM_768 {
            Ok(Self::MlKem {
                parameter_set: MlKemParameterSet::MlKem768,
                key: key_bytes.to_vec(),
            })
        } else if oid == SPKI_OID_ML_KEM_1024 {
            Ok(Self::MlKem {
                parameter_set: MlKemParameterSet::MlKem1024,
                key: key_bytes.to_vec(),
            })
        } else {
            Err(KeyError("Unsupported algorithm in SPKI"))
        }
    }

    /// Returns the algorithm of this public key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Rsa { n, .. } => KeyAlgorithm::Rsa(n.len() * 8),
            Self::Ec { curve, .. } => KeyAlgorithm::Ec(curve.clone()),
            Self::Ed25519 { .. } => KeyAlgorithm::Ed25519,
            Self::X25519 { .. } => KeyAlgorithm::X25519,
            Self::MlDsa { parameter_set, .. } => KeyAlgorithm::MlDsa(*parameter_set),
            Self::MlKem { parameter_set, .. } => KeyAlgorithm::MlKem(*parameter_set),
        }
    }

    /// Encode this public key as SubjectPublicKeyInfo (SPKI) DER.
    pub fn to_spki(&self) -> Result<Vec<u8>, KeyError> {
        let spki = match self {
            Self::Rsa { n, e } => {
                let mod_int =
                    der::asn1::UintRef::new(n).map_err(|_| KeyError("Invalid RSA modulus"))?;
                let exp_int =
                    der::asn1::UintRef::new(e).map_err(|_| KeyError("Invalid RSA exponent"))?;
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

                SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid: SPKI_OID_RSA,
                        parameters: Some(der::Any::from(der::asn1::Null)),
                    },
                    subject_public_key: BitString::from_bytes(&rsa_pub_key)
                        .map_err(|_| KeyError("Failed to encode RSA BIT STRING"))?,
                }
            }
            Self::Ec { curve, point } => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: SPKI_OID_EC,
                    parameters: Some(der::Any::from(&curve.oid())),
                },
                subject_public_key: BitString::from_bytes(point)
                    .map_err(|_| KeyError("Failed to encode EC BIT STRING"))?,
            },
            Self::Ed25519 { key } => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: SPKI_OID_ED25519,
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(key)
                    .map_err(|_| KeyError("Failed to encode Ed25519 BIT STRING"))?,
            },
            Self::X25519 { key } => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: SPKI_OID_X25519,
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(key)
                    .map_err(|_| KeyError("Failed to encode X25519 BIT STRING"))?,
            },
            Self::MlDsa { parameter_set, key } => {
                let oid = match parameter_set {
                    MlDsaParameterSet::MlDsa44 => SPKI_OID_ML_DSA_44,
                    MlDsaParameterSet::MlDsa65 => SPKI_OID_ML_DSA_65,
                    MlDsaParameterSet::MlDsa87 => SPKI_OID_ML_DSA_87,
                };
                SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid,
                        parameters: None,
                    },
                    subject_public_key: BitString::from_bytes(key)
                        .map_err(|_| KeyError("Failed to encode ML-DSA BIT STRING"))?,
                }
            }
            Self::MlKem { parameter_set, key } => {
                let oid = match parameter_set {
                    MlKemParameterSet::MlKem512 => SPKI_OID_ML_KEM_512,
                    MlKemParameterSet::MlKem768 => SPKI_OID_ML_KEM_768,
                    MlKemParameterSet::MlKem1024 => SPKI_OID_ML_KEM_1024,
                };
                SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid,
                        parameters: None,
                    },
                    subject_public_key: BitString::from_bytes(key)
                        .map_err(|_| KeyError("Failed to encode ML-KEM BIT STRING"))?,
                }
            }
        };

        spki.to_der()
            .map_err(|_| KeyError("Failed to encode SPKI DER"))
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
        Ok((
            KeyAlgorithm::Rsa(mod_bytes * 8),
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
