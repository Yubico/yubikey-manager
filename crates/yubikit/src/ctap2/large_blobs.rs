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

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use crate::cbor::{self, Value};
use crate::core::Connection;

use super::pin_protocol::PinProtocol;
use super::session::Ctap2Session;
use super::{Ctap2Error, cmd};

/// CTAP2 Large Blobs operations (§6.10).
///
/// Provides reading and writing of the large-blob array stored on the
/// authenticator. Uses chunked transfer with SHA-256 integrity verification.
pub struct LargeBlobs<C: Connection> {
    session: Ctap2Session<C>,
    protocol: PinProtocol,
    pin_token: Vec<u8>,
    max_fragment_length: usize,
}

impl<C: Connection + 'static> LargeBlobs<C> {
    /// Create a new `LargeBlobs` from a `Ctap2Session` and a PIN token.
    ///
    /// The PIN token must have the `LARGE_BLOB_WRITE` permission for write
    /// operations. Read operations do not require authentication.
    pub fn new(
        session: Ctap2Session<C>,
        protocol: PinProtocol,
        pin_token: Vec<u8>,
    ) -> Result<Self, Ctap2Error<C::Error>> {
        let info = &session.cached_info;
        if info.max_large_blob.is_none() {
            return Err(Ctap2Error::InvalidResponse(
                "Authenticator does not support largeBlobs".into(),
            ));
        }
        let max_msg = info.max_msg_size;
        let max_fragment_length = max_msg.saturating_sub(64);
        Ok(Self {
            session,
            protocol,
            pin_token,
            max_fragment_length,
        })
    }

    /// Consume this `LargeBlobs`, returning the underlying `Ctap2Session`.
    pub fn into_session(self) -> Ctap2Session<C> {
        self.session
    }

    /// Read the complete large-blob array from the authenticator.
    ///
    /// Performs chunked reads and verifies SHA-256 integrity. Returns the
    /// raw CBOR-encoded blob array (without the trailing hash).
    pub fn read_blob_array(&mut self) -> Result<Vec<u8>, Ctap2Error<C::Error>> {
        let mut data = Vec::new();
        let mut offset: usize = 0;

        loop {
            let params: Vec<(Value, Value)> = vec![
                (
                    Value::Int(0x01),
                    Value::Int(self.max_fragment_length as i64),
                ),
                (Value::Int(0x03), Value::Int(offset as i64)),
            ];

            let encoded = cbor::encode(&Value::Map(params));
            let response = self
                .session
                .send_cbor(cmd::LARGE_BLOBS, Some(&encoded), None, None)?;

            if response.is_empty() {
                break;
            }

            let value = cbor::decode(&response)
                .map_err(|e| Ctap2Error::InvalidResponse(format!("CBOR decode error: {e}")))?;
            let map = value
                .as_map()
                .ok_or_else(|| Ctap2Error::InvalidResponse("Expected CBOR map".into()))?;

            let fragment = map
                .iter()
                .find(|(k, _)| k.as_int() == Some(0x01))
                .and_then(|(_, v)| v.as_bytes())
                .ok_or_else(|| {
                    Ctap2Error::InvalidResponse(
                        "Missing config (0x01) in largeBlobs response".into(),
                    )
                })?;

            let frag_len = fragment.len();
            data.extend_from_slice(fragment);
            offset += frag_len;

            if frag_len < self.max_fragment_length {
                break;
            }
        }

        // Verify SHA-256 integrity: last 16 bytes are hash of the rest
        if data.len() < 16 {
            return Err(Ctap2Error::InvalidResponse(
                "Large blob data too short for integrity check".into(),
            ));
        }
        let (blob_data, hash_suffix) = data.split_at(data.len() - 16);
        let digest = Sha256::digest(blob_data);
        if &digest[..16] != hash_suffix {
            return Err(Ctap2Error::InvalidResponse(
                "Large blob integrity check failed".into(),
            ));
        }

        Ok(blob_data.to_vec())
    }

    /// Write a complete large-blob array to the authenticator.
    ///
    /// `blob_data` should be the CBOR-encoded blob array (without hash).
    /// This method appends the SHA-256 hash and writes in fragments.
    pub fn write_blob_array(&mut self, blob_data: &[u8]) -> Result<(), Ctap2Error<C::Error>> {
        // Append SHA-256 hash (first 16 bytes)
        let digest = Sha256::digest(blob_data);
        let mut data = blob_data.to_vec();
        data.extend_from_slice(&digest[..16]);

        let total_length = data.len();
        let mut offset: usize = 0;

        while offset < total_length {
            let end = (offset + self.max_fragment_length).min(total_length);
            let fragment = &data[offset..end];

            let mut params: Vec<(Value, Value)> = Vec::new();
            params.push((Value::Int(0x02), Value::Bytes(fragment.to_vec())));
            params.push((Value::Int(0x03), Value::Int(offset as i64)));

            if offset == 0 {
                params.push((Value::Int(0x04), Value::Int(total_length as i64)));
            }

            // Auth: authenticate(pinToken, 0xff*32 || h'0c00' || uint32le(offset) || sha256(fragment))
            let mut msg = vec![0xff; 32];
            msg.extend_from_slice(&[0x0c, 0x00]);
            msg.extend_from_slice(&(offset as u32).to_le_bytes());
            let frag_hash = Sha256::digest(fragment);
            msg.extend_from_slice(&frag_hash);
            let pin_uv_param = self.protocol.authenticate(&self.pin_token, &msg);

            params.push((Value::Int(0x06), Value::Int(self.protocol.version() as i64)));
            params.push((Value::Int(0x05), Value::Bytes(pin_uv_param)));

            let encoded = cbor::encode(&Value::Map(params));
            self.session
                .send_cbor(cmd::LARGE_BLOBS, Some(&encoded), None, None)?;

            offset = end;
        }

        Ok(())
    }

    /// Get the decrypted blob for a single credential.
    ///
    /// Reads the blob array and tries to decrypt each entry with the given
    /// `large_blob_key`. Returns the first entry that decrypts and decompresses
    /// successfully, or `None` if no matching entry is found.
    pub fn get_blob(
        &mut self,
        large_blob_key: &[u8],
    ) -> Result<Option<Vec<u8>>, Ctap2Error<C::Error>> {
        let array_data = self.read_blob_array()?;
        let array = parse_blob_array(&array_data)?;
        for entry in &array {
            if let Ok(data) = lb_unpack(large_blob_key, entry) {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }

    /// Store a blob for a single credential.
    ///
    /// Reads the blob array, removes any existing entry matching
    /// `large_blob_key`, appends the new encrypted entry, and writes back.
    pub fn put_blob(
        &mut self,
        large_blob_key: &[u8],
        data: &[u8],
    ) -> Result<(), Ctap2Error<C::Error>> {
        let array_data = self.read_blob_array()?;
        let mut entries = parse_blob_array(&array_data)?;
        // Remove existing entries for this key
        entries.retain(|entry| lb_unpack(large_blob_key, entry).is_err());
        entries.push(lb_pack(large_blob_key, data)?);
        let encoded = cbor::encode(&Value::Array(entries));
        self.write_blob_array(&encoded)
    }

    /// Delete any blob(s) stored for a single credential.
    ///
    /// Reads the blob array, removes any entries matching `large_blob_key`,
    /// and writes back if anything was removed.
    pub fn delete_blob(&mut self, large_blob_key: &[u8]) -> Result<(), Ctap2Error<C::Error>> {
        let array_data = self.read_blob_array()?;
        let mut entries = parse_blob_array(&array_data)?;
        let orig_len = entries.len();
        entries.retain(|entry| lb_unpack(large_blob_key, entry).is_err());
        if entries.len() != orig_len {
            let encoded = cbor::encode(&Value::Array(entries));
            self.write_blob_array(&encoded)?;
        }
        Ok(())
    }
}

/// Parse the raw blob array data (CBOR bytes) into a Vec of CBOR Values.
fn parse_blob_array<E: std::error::Error + Send + Sync + 'static>(
    data: &[u8],
) -> Result<Vec<Value>, Ctap2Error<E>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let value =
        cbor::decode(data).map_err(|e| Ctap2Error::InvalidResponse(format!("CBOR error: {e}")))?;
    match value {
        Value::Array(arr) => Ok(arr),
        _ => Err(Ctap2Error::InvalidResponse(
            "Large blob array is not a CBOR array".into(),
        )),
    }
}

/// Associated data for AES-256-GCM: `"blob" || uint64le(orig_size)`.
fn lb_associated_data(orig_size: u64) -> Vec<u8> {
    let mut ad = b"blob".to_vec();
    ad.extend_from_slice(&orig_size.to_le_bytes());
    ad
}

/// Encrypt and compress data into a large blob entry.
fn lb_pack<E: std::error::Error + Send + Sync + 'static>(
    key: &[u8],
    data: &[u8],
) -> Result<Value, Ctap2Error<E>> {
    let orig_size = data.len() as u64;

    // DEFLATE compress (raw, no zlib/gzip headers)
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| Ctap2Error::InvalidResponse(format!("Compression failed: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| Ctap2Error::InvalidResponse(format!("Compression failed: {e}")))?;

    // AES-256-GCM encrypt
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Ctap2Error::InvalidResponse(format!("Invalid key: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| Ctap2Error::InvalidResponse(format!("RNG failed: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ad = lb_associated_data(orig_size);
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &compressed,
                aad: &ad,
            },
        )
        .map_err(|e| Ctap2Error::InvalidResponse(format!("Encryption failed: {e}")))?;

    Ok(Value::Map(vec![
        (Value::Int(0x01), Value::Bytes(ciphertext)),
        (Value::Int(0x02), Value::Bytes(nonce_bytes.to_vec())),
        (Value::Int(0x03), Value::Int(orig_size as i64)),
    ]))
}

/// Decrypt and decompress a large blob entry.
fn lb_unpack(key: &[u8], entry: &Value) -> Result<Vec<u8>, String> {
    let map = entry.as_map().ok_or("not a map")?;

    let ciphertext = map
        .iter()
        .find(|(k, _)| k.as_int() == Some(0x01))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or("missing ciphertext")?;
    let nonce_bytes = map
        .iter()
        .find(|(k, _)| k.as_int() == Some(0x02))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or("missing nonce")?;
    let orig_size = map
        .iter()
        .find(|(k, _)| k.as_int() == Some(0x03))
        .and_then(|(_, v)| v.as_int())
        .ok_or("missing origSize")? as u64;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("invalid key: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let ad = lb_associated_data(orig_size);
    let compressed = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| "wrong key")?;

    // DEFLATE decompress
    let mut decoder = DeflateDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("decompression failed: {e}"))?;
    if decompressed.len() as u64 != orig_size {
        return Err("size mismatch".into());
    }

    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lb_pack_unpack_roundtrip() {
        let key = [0x42u8; 32];
        let data = b"hello, large blobs!";
        let entry: Value = lb_pack::<std::io::Error>(&key, data).expect("pack should succeed");
        let recovered = lb_unpack(&key, &entry).expect("unpack should succeed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_lb_unpack_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let data = b"secret data";
        let entry: Value = lb_pack::<std::io::Error>(&key, data).expect("pack should succeed");
        assert!(lb_unpack(&wrong_key, &entry).is_err());
    }

    #[test]
    fn test_lb_pack_unpack_empty_data() {
        let key = [0xaa; 32];
        let data = b"";
        let entry: Value = lb_pack::<std::io::Error>(&key, data).expect("pack should succeed");
        let recovered = lb_unpack(&key, &entry).expect("unpack should succeed");
        assert_eq!(recovered, data);
    }
}
