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

//! Private key parsing utilities.
//!
//! This module provides PKCS#8 (PrivateKeyInfo) and PKCS#1 (RSAPrivateKey)
//! parsing for extracting raw key material from standard DER-encoded
//! private key structures.

use zeroize::Zeroizing;

use crate::tlv::tlv_parse;

/// The algorithm family detected from a PKCS#8 AlgorithmIdentifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pkcs8Algorithm {
    /// RSA (any key size). Inner data is a PKCS#1 RSAPrivateKey DER.
    Rsa,
    /// NIST EC (P-256, P-384, etc.). Inner data is the raw scalar bytes.
    Ec,
    /// Ed25519, X25519, ML-DSA, ML-KEM, or other non-EC/RSA algorithm.
    /// Inner data is the raw private key bytes.
    Other,
}

/// Result of parsing a PKCS#8 PrivateKeyInfo structure.
#[derive(Debug)]
pub(crate) struct Pkcs8Parsed {
    /// The algorithm family.
    pub(crate) algorithm: Pkcs8Algorithm,
    /// The inner private key material (zeroized on drop).
    pub(crate) key_data: Zeroizing<Vec<u8>>,
}

/// Parse a PKCS#8 PrivateKeyInfo DER and extract the inner private key data.
///
/// Returns the detected algorithm family and the raw key bytes:
/// - RSA: PKCS#1 RSAPrivateKey DER
/// - EC (NIST curves): raw scalar bytes extracted from SEC1 ECPrivateKey
/// - Other (Ed25519/X25519/ML-DSA/ML-KEM): raw private key bytes
pub(crate) fn parse_pkcs8(pkcs8_der: &[u8]) -> Result<Pkcs8Parsed, Pkcs8Error> {
    // Parse outer SEQUENCE
    let (_, seq_off, seq_len, _) =
        tlv_parse(pkcs8_der, 0).map_err(|_| Pkcs8Error("Invalid DER"))?;
    let seq_data = &pkcs8_der[seq_off..seq_off + seq_len];

    // Skip version INTEGER
    let (_, _, _, ver_end) = tlv_parse(seq_data, 0).map_err(|_| Pkcs8Error("Invalid version"))?;

    // Parse AlgorithmIdentifier SEQUENCE
    let (_, algo_off, algo_len, algo_end) =
        tlv_parse(seq_data, ver_end).map_err(|_| Pkcs8Error("Invalid AlgorithmIdentifier"))?;
    let algo_data = &seq_data[algo_off..algo_off + algo_len];

    // Parse OID
    let (_, oid_off, oid_len, _) =
        tlv_parse(algo_data, 0).map_err(|_| Pkcs8Error("Invalid OID"))?;
    let oid = &algo_data[oid_off..oid_off + oid_len];

    const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    // Parse OCTET STRING containing the private key
    let (_, oct_off, oct_len, _) =
        tlv_parse(seq_data, algo_end).map_err(|_| Pkcs8Error("Invalid OCTET STRING"))?;
    let private_key_data = &seq_data[oct_off..oct_off + oct_len];

    if oid == RSA_OID {
        Ok(Pkcs8Parsed {
            algorithm: Pkcs8Algorithm::Rsa,
            key_data: Zeroizing::new(private_key_data.to_vec()),
        })
    } else if oid == EC_OID {
        // EC: OCTET STRING contains ECPrivateKey SEQUENCE { version, privateKey, ... }
        let (_, inner_off, inner_len, _) =
            tlv_parse(private_key_data, 0).map_err(|_| Pkcs8Error("Invalid ECPrivateKey"))?;
        let inner = &private_key_data[inner_off..inner_off + inner_len];
        // Skip version INTEGER
        let (_, _, _, ver_end) =
            tlv_parse(inner, 0).map_err(|_| Pkcs8Error("Invalid EC version"))?;
        // Parse privateKey OCTET STRING
        let (_, key_off, key_len, _) =
            tlv_parse(inner, ver_end).map_err(|_| Pkcs8Error("Invalid EC private key"))?;
        Ok(Pkcs8Parsed {
            algorithm: Pkcs8Algorithm::Ec,
            key_data: Zeroizing::new(inner[key_off..key_off + key_len].to_vec()),
        })
    } else {
        // Ed25519/X25519/ML-DSA/ML-KEM: OCTET STRING contains another OCTET STRING
        let (_, key_off, key_len, _) =
            tlv_parse(private_key_data, 0).map_err(|_| Pkcs8Error("Invalid key OCTET STRING"))?;
        Ok(Pkcs8Parsed {
            algorithm: Pkcs8Algorithm::Other,
            key_data: Zeroizing::new(private_key_data[key_off..key_off + key_len].to_vec()),
        })
    }
}

/// Detected key algorithm from a DER-encoded key structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyAlgorithmInfo {
    /// RSA with the given modulus bit length.
    Rsa { bit_len: usize },
    /// Elliptic curve with the given curve OID (DER-encoded bytes).
    Ec { curve_oid: Vec<u8> },
    /// Algorithm identified only by its OID (Ed25519, X25519, ML-DSA, ML-KEM, etc).
    Oid { oid: Vec<u8> },
}

/// Detect the key algorithm from a PKCS#8 PrivateKeyInfo or SubjectPublicKeyInfo DER.
///
/// Set `is_private` to `true` for PKCS#8, `false` for SPKI.
pub(crate) fn detect_key_algorithm(
    der: &[u8],
    is_private: bool,
) -> Result<KeyAlgorithmInfo, Pkcs8Error> {
    // Parse outer SEQUENCE
    let (_, seq_off, seq_len, _) = tlv_parse(der, 0).map_err(|_| Pkcs8Error("Invalid DER"))?;
    let seq_data = &der[seq_off..seq_off + seq_len];

    // For PKCS#8, skip the version INTEGER
    let algo_start = if is_private {
        let (_, _, _, ver_end) =
            tlv_parse(seq_data, 0).map_err(|_| Pkcs8Error("Invalid version INTEGER"))?;
        ver_end
    } else {
        0
    };

    // Parse AlgorithmIdentifier SEQUENCE
    let (_, algo_off, algo_len, algo_end) =
        tlv_parse(seq_data, algo_start).map_err(|_| Pkcs8Error("Invalid AlgorithmIdentifier"))?;
    let algo_data = &seq_data[algo_off..algo_off + algo_len];

    // Parse OID
    let (_, oid_off, oid_len, oid_end) =
        tlv_parse(algo_data, 0).map_err(|_| Pkcs8Error("Invalid OID"))?;
    let oid = &algo_data[oid_off..oid_off + oid_len];

    const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    if oid == RSA_OID {
        // Determine RSA modulus bit length from the key data
        let (tag, data_off, data_len, _) =
            tlv_parse(seq_data, algo_end).map_err(|_| Pkcs8Error("Invalid key data"))?;
        let key_data = if tag == 0x03 {
            // BIT STRING (SPKI): skip unused-bits prefix byte
            &seq_data[data_off + 1..data_off + data_len]
        } else if tag == 0x04 {
            // OCTET STRING (PKCS#8): RSAPrivateKey directly
            &seq_data[data_off..data_off + data_len]
        } else {
            return Err(Pkcs8Error("Expected BIT STRING or OCTET STRING"));
        };
        // Parse inner SEQUENCE
        let (_, inner_off, inner_len, _) =
            tlv_parse(key_data, 0).map_err(|_| Pkcs8Error("Invalid RSA inner SEQUENCE"))?;
        let inner = &key_data[inner_off..inner_off + inner_len];
        // For private keys, skip version INTEGER first
        let mod_start = if is_private {
            let (_, _, _, ver_end) =
                tlv_parse(inner, 0).map_err(|_| Pkcs8Error("Invalid RSA version"))?;
            ver_end
        } else {
            0
        };
        // Parse modulus INTEGER
        let (_, mod_off, mod_len, _) =
            tlv_parse(inner, mod_start).map_err(|_| Pkcs8Error("Invalid RSA modulus"))?;
        let modulus = &inner[mod_off..mod_off + mod_len];
        // Strip leading zero
        let mod_bytes = if !modulus.is_empty() && modulus[0] == 0 {
            modulus.len() - 1
        } else {
            modulus.len()
        };
        Ok(KeyAlgorithmInfo::Rsa {
            bit_len: mod_bytes * 8,
        })
    } else if oid == EC_OID {
        // Parse curve OID parameter from AlgorithmIdentifier
        let (_, curve_off, curve_len, _) =
            tlv_parse(algo_data, oid_end).map_err(|_| Pkcs8Error("Invalid EC curve OID"))?;
        Ok(KeyAlgorithmInfo::Ec {
            curve_oid: algo_data[curve_off..curve_off + curve_len].to_vec(),
        })
    } else {
        Ok(KeyAlgorithmInfo::Oid { oid: oid.to_vec() })
    }
}

/// Parse a PKCS#1 RSAPrivateKey DER into its component fields.
///
/// Returns the fields: (n, e, d, p, q, dp, dq, qinv) with leading zeros stripped.
pub(crate) fn parse_pkcs1_rsa(pkcs1_der: &[u8]) -> Result<Pkcs1RsaComponents, Pkcs8Error> {
    // Parse SEQUENCE
    let (_, seq_off, seq_len, _) =
        tlv_parse(pkcs1_der, 0).map_err(|_| Pkcs8Error("Invalid RSA DER"))?;
    let seq_data = &pkcs1_der[seq_off..seq_off + seq_len];

    // Parse all INTEGER fields: version, n, e, d, p, q, dp, dq, qinv
    let mut offset = 0;
    let mut fields: Vec<&[u8]> = Vec::new();
    while offset < seq_data.len() {
        let (_, val_off, val_len, end) =
            tlv_parse(seq_data, offset).map_err(|_| Pkcs8Error("Invalid RSA field"))?;
        fields.push(&seq_data[val_off..val_off + val_len]);
        offset = end;
    }

    if fields.len() < 9 {
        return Err(Pkcs8Error("RSA key missing required fields"));
    }

    fn strip_leading_zero(b: &[u8]) -> Vec<u8> {
        let s = if !b.is_empty() && b[0] == 0 {
            &b[1..]
        } else {
            b
        };
        s.to_vec()
    }

    // fields: [version, n, e, d, p, q, dp, dq, qinv]
    Ok(Pkcs1RsaComponents {
        n: strip_leading_zero(fields[1]),
        e: strip_leading_zero(fields[2]),
        d: strip_leading_zero(fields[3]),
        p: strip_leading_zero(fields[4]),
        q: strip_leading_zero(fields[5]),
        dp: strip_leading_zero(fields[6]),
        dq: strip_leading_zero(fields[7]),
        qinv: strip_leading_zero(fields[8]),
    })
}

/// Parsed RSA private key components from PKCS#1 format.
///
/// Fields have leading zero bytes stripped. Callers are responsible for
/// zeroizing sensitive fields after use.
#[allow(dead_code)]
pub(crate) struct Pkcs1RsaComponents {
    /// Public modulus.
    pub(crate) n: Vec<u8>,
    /// Public exponent.
    pub(crate) e: Vec<u8>,
    /// Private exponent.
    pub(crate) d: Vec<u8>,
    /// First prime factor.
    pub(crate) p: Vec<u8>,
    /// Second prime factor.
    pub(crate) q: Vec<u8>,
    /// CRT exponent: d mod (p-1).
    pub(crate) dp: Vec<u8>,
    /// CRT exponent: d mod (q-1).
    pub(crate) dq: Vec<u8>,
    /// CRT coefficient: q^{-1} mod p.
    pub(crate) qinv: Vec<u8>,
}

/// Error type for PKCS#8/PKCS#1 parsing failures.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pkcs8Error(pub(crate) &'static str);

impl std::fmt::Display for Pkcs8Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PKCS#8 parse error: {}", self.0)
    }
}

impl std::error::Error for Pkcs8Error {}
