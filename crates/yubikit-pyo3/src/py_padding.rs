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

//! Host-side RSA padding, so Python does not need throwaway RSA keys to pad
//! and unpad for raw RSA operations.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use yubikit::__internal::padding::{self, Hash, PaddingError};

fn value_err(e: PaddingError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn hash(name: &str) -> PyResult<Hash> {
    Hash::from_name(name).map_err(value_err)
}

/// EMSA-PKCS1-v1_5 encode a digest for a `bit_len`-bit RSA modulus.
#[pyfunction]
fn pkcs1v15_sign_pad(bit_len: usize, hash_name: &str, digest: &[u8]) -> PyResult<Vec<u8>> {
    padding::pkcs1v15_sign_pad(bit_len, hash(hash_name)?, digest).map_err(value_err)
}

/// EMSA-PSS encode a digest for a `bit_len`-bit RSA modulus. A salt length of
/// `None` selects the maximum length.
#[pyfunction]
#[pyo3(signature = (bit_len, hash_name, digest, salt_len, mgf_hash_name))]
fn pss_sign_pad(
    bit_len: usize,
    hash_name: &str,
    digest: &[u8],
    salt_len: Option<usize>,
    mgf_hash_name: &str,
) -> PyResult<Vec<u8>> {
    padding::pss_sign_pad(
        bit_len,
        hash(hash_name)?,
        digest,
        salt_len,
        hash(mgf_hash_name)?,
    )
    .map_err(value_err)
}

/// Remove RSAES-PKCS1-v1_5 padding from a raw RSA decryption result.
#[pyfunction]
fn pkcs1v15_decrypt_unpad(block: &[u8]) -> PyResult<Vec<u8>> {
    padding::pkcs1v15_decrypt_unpad(block)
        .map(|m| m.to_vec())
        .map_err(value_err)
}

/// Remove RSAES-OAEP padding from a raw RSA decryption result.
#[pyfunction]
fn oaep_decrypt_unpad(
    block: &[u8],
    hash_name: &str,
    mgf_hash_name: &str,
    label: &[u8],
) -> PyResult<Vec<u8>> {
    padding::oaep_decrypt_unpad(block, hash(hash_name)?, hash(mgf_hash_name)?, label)
        .map(|m| m.to_vec())
        .map_err(value_err)
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "padding")?;
    m.add_function(wrap_pyfunction!(pkcs1v15_sign_pad, &m)?)?;
    m.add_function(wrap_pyfunction!(pss_sign_pad, &m)?)?;
    m.add_function(wrap_pyfunction!(pkcs1v15_decrypt_unpad, &m)?)?;
    m.add_function(wrap_pyfunction!(oaep_decrypt_unpad, &m)?)?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.padding", &m)?;

    Ok(())
}
