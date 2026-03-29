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

use aes::Aes128;
use cbc::Decryptor as CbcDecryptor;
use cbc::Encryptor as CbcEncryptor;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use cmac::{Cmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

type Aes128CbcEnc = CbcEncryptor<Aes128>;
type Aes128CbcDec = CbcDecryptor<Aes128>;

#[derive(Debug, Error)]
pub enum ScpError {
    #[error("L must be 0x40 or 0x80")]
    InvalidDerivationLength,
    #[error("CMAC init failed: {0}")]
    CmacInit(String),
    #[error("AES init failed: {0}")]
    AesInit(String),
    #[error("CBC init failed: {0}")]
    CbcInit(String),
    #[error("CBC decrypt failed: {0}")]
    CbcDecrypt(String),
    #[error("Wrong MAC")]
    WrongMac,
    #[error("Wrong padding")]
    WrongPadding,
    #[error("Response too short for MAC")]
    ResponseTooShort,
}

/// Compute AES-CMAC over data.
pub fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; 16], ScpError> {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key)
        .map_err(|e| ScpError::CmacInit(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Compute AES-CMAC over chain + message, return (new_chain, mac[:8]).
fn calculate_mac_inner(
    key: &[u8],
    chain: &[u8],
    message: &[u8],
) -> Result<([u8; 16], [u8; 8]), ScpError> {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key)
        .map_err(|e| ScpError::CmacInit(e.to_string()))?;
    mac.update(chain);
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let chain: [u8; 16] = result.into();
    let truncated: [u8; 8] = chain[..8].try_into().unwrap();
    Ok((chain, truncated))
}

/// SCP03 key derivation using AES-CMAC.
pub fn scp03_derive(key: &[u8], t: u8, context: &[u8], l: u16) -> Result<Vec<u8>, ScpError> {
    if l != 0x80 && l != 0x40 {
        return Err(ScpError::InvalidDerivationLength);
    }
    let mut input = vec![0u8; 11];
    input.push(t);
    input.push(0);
    input.push((l >> 8) as u8);
    input.push(l as u8);
    input.push(1);
    input.extend_from_slice(context);

    let result = aes_cmac(key, &input)?;
    Ok(result[..(l as usize / 8)].to_vec())
}

/// SCP03 MAC calculation: CMAC(key, chain || message).
/// Returns (new_chain, mac) where mac is first 8 bytes.
pub fn scp03_calculate_mac(
    key: &[u8],
    chain: &[u8],
    message: &[u8],
) -> Result<([u8; 16], [u8; 8]), ScpError> {
    calculate_mac_inner(key, chain, message)
}

/// Constant-time byte comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

fn derive_iv(key: &[u8], counter: u32, response: bool) -> Result<[u8; 16], ScpError> {
    let mut cipher = Aes128::new_from_slice(key).map_err(|e| ScpError::AesInit(e.to_string()))?;
    let mut iv_input = [0u8; 16];
    iv_input[0] = if response { 0x80 } else { 0x00 };
    iv_input[12..16].copy_from_slice(&counter.to_be_bytes());
    let mut iv_block = iv_input.into();
    cipher.encrypt_block_mut(&mut iv_block);
    Ok(iv_block.into())
}

fn aes_cbc_encrypt(
    key: &[u8],
    counter: u32,
    response: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, ScpError> {
    let iv = derive_iv(key, counter, response)?;
    let encryptor =
        Aes128CbcEnc::new_from_slices(key, &iv).map_err(|e| ScpError::CbcInit(e.to_string()))?;
    Ok(encryptor.encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(plaintext))
}

fn aes_cbc_decrypt(
    key: &[u8],
    counter: u32,
    response: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ScpError> {
    let iv = derive_iv(key, counter, response)?;
    let decryptor =
        Aes128CbcDec::new_from_slices(key, &iv).map_err(|e| ScpError::CbcInit(e.to_string()))?;
    decryptor
        .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(ciphertext)
        .map_err(|e| ScpError::CbcDecrypt(e.to_string()))
}

/// SCP session state managing encryption, decryption, and MAC operations.
pub struct ScpState {
    key_senc: Vec<u8>,
    key_smac: Vec<u8>,
    key_srmac: Vec<u8>,
    mac_chain: Vec<u8>,
    enc_counter: u32,
    /// Data-encryption key for wrapping imported keys (PUT KEY).
    /// For SCP03: the static DEK from the key set.
    /// For SCP11: derived as the 5th key from the X9.63-KDF output.
    key_dek: Option<Vec<u8>>,
}

impl ScpState {
    pub fn new(
        key_senc: Vec<u8>,
        key_smac: Vec<u8>,
        key_srmac: Vec<u8>,
        mac_chain: Option<Vec<u8>>,
        enc_counter: Option<u32>,
    ) -> Self {
        ScpState {
            key_senc,
            key_smac,
            key_srmac,
            mac_chain: mac_chain.unwrap_or_else(|| vec![0u8; 16]),
            enc_counter: enc_counter.unwrap_or(1),
            key_dek: None,
        }
    }

    pub fn with_dek(mut self, dek: Option<Vec<u8>>) -> Self {
        self.key_dek = dek;
        self
    }

    /// The data-encryption key, if available.
    pub fn dek(&self) -> Option<&[u8]> {
        self.key_dek.as_deref()
    }

    /// Pad and encrypt data using AES-CBC with counter-derived IV.
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, ScpError> {
        let mut padded = data.to_vec();
        padded.push(0x80);
        let pad_len = 16 - (padded.len() % 16);
        if pad_len < 16 {
            padded.extend(std::iter::repeat_n(0u8, pad_len));
        }

        let result = aes_cbc_encrypt(&self.key_senc, self.enc_counter, false, &padded)?;
        self.enc_counter += 1;
        Ok(result)
    }

    /// Compute MAC over data, updating the MAC chain. Returns 8-byte MAC.
    pub fn mac(&mut self, data: &[u8]) -> Result<[u8; 8], ScpError> {
        let (new_chain, mac) = calculate_mac_inner(&self.key_smac, &self.mac_chain, data)?;
        self.mac_chain = new_chain.to_vec();
        Ok(mac)
    }

    /// Verify and strip response MAC. Returns data without MAC on success.
    pub fn unmac(&self, data: &[u8], sw: u16) -> Result<Vec<u8>, ScpError> {
        if data.len() < 8 {
            return Err(ScpError::ResponseTooShort);
        }
        let msg = &data[..data.len() - 8];
        let mac = &data[data.len() - 8..];

        let sw_bytes = sw.to_be_bytes();
        let mut rmac_input = msg.to_vec();
        rmac_input.extend_from_slice(&sw_bytes);

        let (_, expected_mac) = calculate_mac_inner(&self.key_srmac, &self.mac_chain, &rmac_input)?;

        if !bool::from(mac.ct_eq(&expected_mac)) {
            return Err(ScpError::WrongMac);
        }
        Ok(msg.to_vec())
    }

    /// Decrypt response data and remove padding.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, ScpError> {
        let decrypted = aes_cbc_decrypt(&self.key_senc, self.enc_counter - 1, true, encrypted)?;

        let unpadded = decrypted
            .iter()
            .rposition(|&b| b != 0x00)
            .ok_or(ScpError::WrongPadding)?;
        if decrypted[unpadded] != 0x80 {
            return Err(ScpError::WrongPadding);
        }
        Ok(decrypted[..unpadded].to_vec())
    }
}

/// X9.63 KDF using SHA-256.
pub fn x963_kdf(shared_secret: &[u8], shared_info: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut counter: u32 = 1;
    while output.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(counter.to_be_bytes());
        hasher.update(shared_info);
        output.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    output.truncate(length);
    output
}

/// SCP key parameters for establishing a secure channel when opening a session.
#[derive(Clone, Debug)]
pub enum ScpKeyParams {
    /// SCP03 with static keys.
    Scp03 {
        kvn: u8,
        key_enc: Vec<u8>,
        key_mac: Vec<u8>,
        key_dek: Option<Vec<u8>>,
    },
    /// SCP11b — needs card key reference + public key from SD.
    Scp11b {
        kid: u8,
        kvn: u8,
        pk_sd_ecka: Vec<u8>,
    },
    /// SCP11a or SCP11c — needs OCE private key + cert chain.
    Scp11ac {
        kid: u8,
        kvn: u8,
        pk_sd_ecka: Vec<u8>,
        sk_oce_ecka: Vec<u8>,
        certificates: Vec<Vec<u8>>,
        oce_ref: Option<(u8, u8)>,
    },
}
