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

use pyo3::prelude::*;

const MODHEX_ALPHABET: &[u8; 16] = b"cbdefghijklnrtuv";
const CRC_OK_RESIDUAL: u16 = 0xF0B8;

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry == 1 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

#[pyfunction]
fn calculate_crc(data: &[u8]) -> u16 {
    crc16(data)
}

#[pyfunction]
fn check_crc(data: &[u8]) -> bool {
    crc16(data) == CRC_OK_RESIDUAL
}

#[pyfunction]
fn modhex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push(MODHEX_ALPHABET[(byte >> 4) as usize] as char);
        result.push(MODHEX_ALPHABET[(byte & 0x0F) as usize] as char);
    }
    result
}

#[pyfunction]
fn modhex_decode(string: &str) -> PyResult<Vec<u8>> {
    if string.len() % 2 != 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Length must be a multiple of 2",
        ));
    }
    let bytes = string.as_bytes();
    let mut result = Vec::with_capacity(string.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = modhex_char_value(bytes[i])?;
        let lo = modhex_char_value(bytes[i + 1])?;
        result.push((hi << 4) | lo);
    }
    Ok(result)
}

fn modhex_char_value(ch: u8) -> PyResult<u8> {
    MODHEX_ALPHABET
        .iter()
        .position(|&c| c == ch)
        .map(|p| p as u8)
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "'{}' is not a valid modhex character",
                ch as char
            ))
        })
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "core")?;
    m.add_function(wrap_pyfunction!(calculate_crc, &m)?)?;
    m.add_function(wrap_pyfunction!(check_crc, &m)?)?;
    m.add_function(wrap_pyfunction!(modhex_encode, &m)?)?;
    m.add_function(wrap_pyfunction!(modhex_decode, &m)?)?;
    parent.add_submodule(&m)?;

    // Register in sys.modules for "from _ykman_native.core import ..." to work
    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.core", &m)?;

    Ok(())
}
