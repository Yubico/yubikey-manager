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
use cbc::Encryptor as CbcEncryptor;
use cbc::Decryptor as CbcDecryptor;
use cipher::{BlockEncryptMut, BlockDecryptMut, KeyInit, KeyIvInit};
use cmac::{Cmac, Mac};
use pyo3::prelude::*;
use subtle::ConstantTimeEq;

type Aes128CbcEnc = CbcEncryptor<Aes128>;
type Aes128CbcDec = CbcDecryptor<Aes128>;

/// Compute AES-CMAC over data.
fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; 16], String> {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key)
        .map_err(|e| format!("CMAC init failed: {e}"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Compute AES-CMAC over chain + message, return (new_chain, mac[:8]).
fn calculate_mac_inner(key: &[u8], chain: &[u8], message: &[u8]) -> Result<([u8; 16], [u8; 8]), String> {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key)
        .map_err(|e| format!("CMAC init failed: {e}"))?;
    mac.update(chain);
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let chain: [u8; 16] = result.into();
    let truncated: [u8; 8] = chain[..8].try_into().unwrap();
    Ok((chain, truncated))
}

/// SCP03 key derivation using AES-CMAC.
fn derive_inner(key: &[u8], t: u8, context: &[u8], l: u16) -> Result<Vec<u8>, String> {
    if l != 0x80 && l != 0x40 {
        return Err("L must be 0x40 or 0x80".into());
    }
    // Build derivation data: 11 zero bytes + t + 0 + L(big-endian) + 1 + context
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

/// Generate AES-CBC IV from counter using AES-ECB, then return encrypted data.
fn aes_cbc_encrypt(key: &[u8], counter: u32, response: bool, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    // Generate IV: AES-ECB encrypt (0x80 or 0x00) + counter as 15-byte big-endian
    let mut cipher = Aes128::new_from_slice(key)
        .map_err(|e| format!("AES init failed: {e}"))?;
    let mut iv_input = [0u8; 16];
    iv_input[0] = if response { 0x80 } else { 0x00 };
    // counter as big-endian in last 4 bytes of the 15-byte area
    let counter_bytes = counter.to_be_bytes();
    iv_input[12..16].copy_from_slice(&counter_bytes);
    let mut iv_block = iv_input.into();
    cipher.encrypt_block_mut(&mut iv_block);
    let iv: [u8; 16] = iv_block.into();

    // AES-CBC encrypt
    let encryptor = Aes128CbcEnc::new_from_slices(key, &iv)
        .map_err(|e| format!("CBC init failed: {e}"))?;
    Ok(encryptor.encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(plaintext))
}

fn aes_cbc_decrypt(key: &[u8], counter: u32, response: bool, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut cipher = Aes128::new_from_slice(key)
        .map_err(|e| format!("AES init failed: {e}"))?;
    let mut iv_input = [0u8; 16];
    iv_input[0] = if response { 0x80 } else { 0x00 };
    let counter_bytes = counter.to_be_bytes();
    iv_input[12..16].copy_from_slice(&counter_bytes);
    let mut iv_block = iv_input.into();
    cipher.encrypt_block_mut(&mut iv_block);
    let iv: [u8; 16] = iv_block.into();

    let decryptor = Aes128CbcDec::new_from_slices(key, &iv)
        .map_err(|e| format!("CBC init failed: {e}"))?;
    decryptor
        .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(ciphertext)
        .map_err(|e| format!("CBC decrypt failed: {e}"))
}

/// SCP03 key derivation: CMAC-based derive function.
#[pyfunction]
#[pyo3(signature = (key, t, context, l=0x80))]
fn scp_derive(key: &[u8], t: u8, context: &[u8], l: u16) -> PyResult<Vec<u8>> {
    derive_inner(key, t, context, l)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
}

/// SCP03 MAC calculation: CMAC(key, chain || message).
/// Returns (new_chain, mac) where mac is first 8 bytes.
#[pyfunction]
fn scp_calculate_mac(key: &[u8], chain: &[u8], message: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let (new_chain, mac) = calculate_mac_inner(key, chain, message)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok((new_chain.to_vec(), mac.to_vec()))
}

/// Constant-time byte comparison.
#[pyfunction]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// SCP03 session state managing encryption, decryption, and MAC operations.
#[pyclass]
struct ScpState {
    key_senc: Vec<u8>,
    key_smac: Vec<u8>,
    key_srmac: Vec<u8>,
    mac_chain: Vec<u8>,
    enc_counter: u32,
}

#[pymethods]
impl ScpState {
    #[new]
    #[pyo3(signature = (key_senc, key_smac, key_srmac, mac_chain=None, enc_counter=1))]
    fn new(
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
        }
    }

    /// Pad and encrypt data using AES-CBC with counter-derived IV.
    fn encrypt(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        // ISO 9797-1 Method 2 padding
        let mut padded = data.to_vec();
        padded.push(0x80);
        let pad_len = 16 - (padded.len() % 16);
        if pad_len < 16 {
            padded.extend(std::iter::repeat_n(0u8, pad_len));
        }

        let result = aes_cbc_encrypt(&self.key_senc, self.enc_counter, false, &padded)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
        self.enc_counter += 1;
        Ok(result)
    }

    /// Compute MAC over data, updating the MAC chain. Returns 8-byte MAC.
    fn mac(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        let (new_chain, mac) = calculate_mac_inner(&self.key_smac, &self.mac_chain, data)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
        self.mac_chain = new_chain.to_vec();
        Ok(mac.to_vec())
    }

    /// Verify and strip response MAC. Raises on mismatch.
    fn unmac(&self, data: &[u8], sw: u16) -> PyResult<Vec<u8>> {
        if data.len() < 8 {
            return Err(pyo3::exceptions::PyValueError::new_err("Response too short for MAC"));
        }
        let msg = &data[..data.len() - 8];
        let mac = &data[data.len() - 8..];

        let mut sw_bytes = [0u8; 2];
        sw_bytes[0] = (sw >> 8) as u8;
        sw_bytes[1] = sw as u8;

        let mut rmac_input = msg.to_vec();
        rmac_input.extend_from_slice(&sw_bytes);

        let (_, expected_mac) = calculate_mac_inner(&self.key_srmac, &self.mac_chain, &rmac_input)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

        if !bool::from(mac.ct_eq(&expected_mac)) {
            return Err(pyo3::exceptions::PyValueError::new_err("Wrong MAC"));
        }
        Ok(msg.to_vec())
    }

    /// Decrypt response data and remove padding.
    fn decrypt(&self, encrypted: &[u8]) -> PyResult<Vec<u8>> {
        let decrypted = aes_cbc_decrypt(
            &self.key_senc,
            self.enc_counter - 1,
            true,
            encrypted,
        ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

        // Remove ISO 9797-1 Method 2 padding
        let unpadded = decrypted.iter().rposition(|&b| b != 0x00)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Wrong padding"))?;
        if decrypted[unpadded] != 0x80 {
            return Err(pyo3::exceptions::PyValueError::new_err("Wrong padding"));
        }
        Ok(decrypted[..unpadded].to_vec())
    }
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "scp")?;
    m.add_function(wrap_pyfunction!(scp_derive, &m)?)?;
    m.add_function(wrap_pyfunction!(scp_calculate_mac, &m)?)?;
    m.add_function(wrap_pyfunction!(constant_time_eq, &m)?)?;
    m.add_class::<ScpState>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.scp", &m)?;

    Ok(())
}
