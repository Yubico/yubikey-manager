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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

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
    fn test_pin_protocol_version() {
        assert_eq!(PinProtocol::V1.version(), 1);
        assert_eq!(PinProtocol::V2.version(), 2);
    }
}
