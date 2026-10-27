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

//! CTAP2 PIN/UV protocol implementations (protocol 1 and 2).

use aes::Aes256;
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use elliptic_curve::{Generate, sec1::FromSec1Point};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, Sec1Point, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::Value;

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
    /// PIN/UV auth protocol version 1 (CTAP 2.0).
    V1,
    /// PIN/UV auth protocol version 2 (CTAP 2.1+).
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
    /// encrypt/decrypt/authenticate. The peer must declare integer COSE labels
    /// `kty=2`, `alg=-25`, and `crv=1` for the CTAP P-256 key agreement profile.
    pub(crate) fn encapsulate(
        &self,
        peer_cose_key: &CoseKey,
    ) -> Result<(CoseKey, Zeroizing<Vec<u8>>), String> {
        let peer_map = peer_cose_key.as_map().ok_or("peer key is not a CBOR map")?;

        for (label, expected, name) in [(1, 2, "kty"), (3, -25, "alg"), (-1, 1, "crv")] {
            if peer_cose_key.map_get_int(label).and_then(Value::as_int) != Some(expected) {
                return Err(format!(
                    "invalid peer key {name}: expected integer {expected}"
                ));
            }
        }

        let x = map_get_bytes(peer_map, -2).ok_or("missing x coordinate (-2)")?;
        let y = map_get_bytes(peer_map, -3).ok_or("missing y coordinate (-3)")?;

        if x.len() != 32 || y.len() != 32 {
            return Err("invalid coordinate length".into());
        }

        // Build uncompressed SEC1 point: 0x04 || x || y
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(x);
        uncompressed.extend_from_slice(y);
        let peer_point =
            Sec1Point::from_bytes(&uncompressed).map_err(|e| format!("invalid SEC1 point: {e}"))?;
        let peer_pk = PublicKey::from_sec1_point(&peer_point)
            .into_option()
            .ok_or("invalid P-256 key")?;

        // Generate ephemeral key pair
        let sk = SecretKey::try_generate()
            .map_err(|e| format!("failed to generate key agreement secret: {e}"))?;
        let pk = sk.public_key();
        let pk_point = pk.to_sec1_point(false);

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

    fn kdf(&self, z: &[u8]) -> Zeroizing<Vec<u8>> {
        match self {
            Self::V1 => {
                let mut hasher = Sha256::new();
                hasher.update(z);
                Zeroizing::new(hasher.finalize().to_vec())
            }
            Self::V2 => {
                let salt = [0u8; 32];
                let hk = Hkdf::<Sha256>::new(Some(&salt), z);
                let mut hmac_key = Zeroizing::new([0u8; 32]);
                hk.expand(b"CTAP2 HMAC key", &mut *hmac_key)
                    .expect("HKDF expand");
                let hk = Hkdf::<Sha256>::new(Some(&salt), z);
                let mut aes_key = Zeroizing::new([0u8; 32]);
                hk.expand(b"CTAP2 AES key", &mut *aes_key)
                    .expect("HKDF expand");
                let mut result = Zeroizing::new(hmac_key.to_vec());
                result.extend_from_slice(&*aes_key);
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn peer_key() -> (SecretKey, CoseKey) {
        let secret = SecretKey::generate();
        let point = secret.public_key().to_sec1_point(false);
        let key = Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(3), Value::Int(-25)),
            (Value::Int(-1), Value::Int(1)),
            (Value::Int(-2), Value::Bytes(point.x().unwrap().to_vec())),
            (Value::Int(-3), Value::Bytes(point.y().unwrap().to_vec())),
        ]);
        (secret, key)
    }

    #[test]
    fn test_encapsulate_requires_integer_peer_profile_labels() {
        let (_, key) = peer_key();
        for protocol in [PinProtocol::V1, PinProtocol::V2] {
            for label in [1, 3, -1] {
                for replacement in [
                    None,
                    Some(Value::Int(0)),
                    Some(Value::Bool(true)),
                    Some(Value::Text("1".into())),
                    Some(Value::Bytes(vec![1])),
                ] {
                    let mut entries = key.as_map().unwrap().to_vec();
                    entries.retain(|(k, _)| k != &Value::Int(label));
                    if let Some(value) = replacement {
                        entries.push((Value::Int(label), value));
                    }
                    assert!(
                        protocol.encapsulate(&Value::Map(entries)).is_err(),
                        "{protocol:?} accepted invalid label {label}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_encapsulate_accepts_profile_and_validates_coordinates() {
        let (peer_secret, key) = peer_key();
        for protocol in [PinProtocol::V1, PinProtocol::V2] {
            let (platform, secret) = protocol.encapsulate(&key).unwrap();
            assert_eq!(platform.map_get_int(1).and_then(Value::as_int), Some(2));
            assert_eq!(platform.map_get_int(3).and_then(Value::as_int), Some(-25));
            assert_eq!(platform.map_get_int(-1).and_then(Value::as_int), Some(1));
            assert_eq!(
                secret.len(),
                if protocol == PinProtocol::V1 { 32 } else { 64 }
            );
            let mut platform_sec1 = vec![0x04];
            for coordinate in [-2, -3] {
                platform_sec1.extend_from_slice(
                    platform
                        .map_get_int(coordinate)
                        .unwrap()
                        .as_bytes()
                        .unwrap(),
                );
            }
            let platform_pk = PublicKey::from_sec1_bytes(&platform_sec1).unwrap();
            let expected_shared = peer_secret.diffie_hellman(&platform_pk);
            assert_eq!(secret, protocol.kdf(expected_shared.raw_secret_bytes()));

            for coordinate in [-2, -3] {
                for value in [Value::Bytes(vec![0; 31]), Value::Bytes(vec![0; 32])] {
                    let mut entries = key.as_map().unwrap().to_vec();
                    entries.retain(|(k, _)| k != &Value::Int(coordinate));
                    entries.push((Value::Int(coordinate), value));
                    assert!(protocol.encapsulate(&Value::Map(entries)).is_err());
                }
            }
        }
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
        assert_eq!(
            mac,
            [
                0xb6, 0xe8, 0x13, 0x6a, 0x04, 0x0e, 0x71, 0x26, 0x6e, 0x36, 0x0e, 0x23, 0xc7, 0xd4,
                0x8e, 0xac,
            ]
        );
    }

    #[test]
    fn test_pin_protocol_v2_authenticate() {
        let key = vec![0u8; 64]; // 32 HMAC + 32 AES
        let msg = b"hello";
        let mac = PinProtocol::V2.authenticate(&key, msg);
        assert_eq!(
            mac,
            [
                0x43, 0x52, 0xb2, 0x6e, 0x33, 0xfe, 0x0d, 0x76, 0x9a, 0x89, 0x22, 0xa6, 0xba, 0x29,
                0x00, 0x41, 0x09, 0xf0, 0x16, 0x88, 0xe2, 0x6a, 0xcc, 0x9e, 0x6c, 0xb3, 0x47, 0xe5,
                0xa5, 0xaf, 0xc4, 0xda,
            ]
        );
    }

    #[test]
    fn test_pin_protocol_kdf_vectors() {
        for (protocol, expected) in [
            (
                PinProtocol::V1,
                "425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c",
            ),
            (
                PinProtocol::V2,
                concat!(
                    "d5863ba7709d4f73fd1e262e8bf166dc879f322261adeee5bc9f312427662fbeb",
                    "78d4fb41bf531372da915f6626fc41fbd255114d7c6ecd7663ff2aed8cb1dc0",
                ),
            ),
        ] {
            let actual: String = protocol
                .kdf(&[0x42; 32])
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(actual, expected, "{protocol:?}");
        }
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
    fn test_pin_protocol_version() {
        assert_eq!(PinProtocol::V1.version(), 1);
        assert_eq!(PinProtocol::V2.version(), 2);
    }
}
