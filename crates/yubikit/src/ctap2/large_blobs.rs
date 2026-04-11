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

use sha2::{Digest, Sha256};

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
}
