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

/// Parse BER-TLV tag/length/value boundaries from data.
/// Returns (tag, value_offset, value_length, end_offset).
fn tlv_parse_inner(data: &[u8], mut offset: usize) -> PyResult<(u32, usize, usize, usize)> {
    let get = |i: usize| -> PyResult<u8> {
        data.get(i).copied().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid encoding of tag/length")
        })
    };

    let mut tag = get(offset)? as u32;
    offset += 1;
    if tag & 0x1F == 0x1F {
        tag = (tag << 8) | get(offset)? as u32;
        offset += 1;
        while tag & 0x80 == 0x80 {
            tag = (tag << 8) | get(offset)? as u32;
            offset += 1;
        }
    }

    let ln_byte = get(offset)? as usize;
    offset += 1;

    let (ln, end) = if ln_byte == 0x80 {
        // Indefinite length: scan for 0x0000 terminator
        let mut end = offset;
        while get(end)? != 0 || get(end + 1)? != 0 {
            let (_, _, _, next_end) = tlv_parse_inner(data, end)?;
            end = next_end;
        }
        let ln = end - offset;
        (ln, end + 2)
    } else if ln_byte > 0x80 {
        let n_bytes = ln_byte - 0x80;
        let mut ln: usize = 0;
        for i in 0..n_bytes {
            ln = (ln << 8) | get(offset + i)? as usize;
        }
        offset += n_bytes;
        (ln, offset + ln)
    } else {
        (ln_byte, offset + ln_byte)
    };

    Ok((tag, offset, ln, end))
}

#[pyfunction]
#[pyo3(signature = (data, offset=None))]
fn tlv_parse(data: &[u8], offset: Option<usize>) -> PyResult<(u32, usize, usize, usize)> {
    tlv_parse_inner(data, offset.unwrap_or(0))
}

/// Encode a tag and value into BER-TLV format.
#[pyfunction]
fn tlv_encode(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();

    // Encode tag (big-endian, variable width)
    if tag > 0xFFFF {
        buf.push((tag >> 24) as u8);
        buf.push((tag >> 16) as u8);
        buf.push((tag >> 8) as u8);
        buf.push(tag as u8);
    } else if tag > 0xFF {
        buf.push((tag >> 8) as u8);
        buf.push(tag as u8);
    } else {
        buf.push(tag as u8);
    }

    let length = value.len();
    if length < 0x80 {
        buf.push(length as u8);
    } else {
        let ln_bytes = int2bytes_inner(length as u64);
        buf.push(0x80 | ln_bytes.len() as u8);
        buf.extend_from_slice(&ln_bytes);
    }

    buf.extend_from_slice(value);
    buf
}

fn int2bytes_inner(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let byte_len = ((64 - value.leading_zeros()) as usize + 7) / 8;
    value.to_be_bytes()[8 - byte_len..].to_vec()
}

#[pyfunction]
#[pyo3(signature = (value, min_len=1))]
fn int2bytes<'py>(value: &Bound<'py, PyAny>, min_len: usize) -> PyResult<Bound<'py, PyAny>> {
    let bit_length: usize = value.call_method0("bit_length")?.extract()?;
    let byte_len = std::cmp::max(min_len, (bit_length + 7) / 8);
    value.call_method1("to_bytes", (byte_len, "big"))
}

#[pyfunction]
fn bytes2int<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let int_type = py.get_type::<pyo3::types::PyInt>();
    int_type.call_method1("from_bytes", (data, "big"))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "core")?;
    m.add_function(wrap_pyfunction!(calculate_crc, &m)?)?;
    m.add_function(wrap_pyfunction!(check_crc, &m)?)?;
    m.add_function(wrap_pyfunction!(modhex_encode, &m)?)?;
    m.add_function(wrap_pyfunction!(modhex_decode, &m)?)?;
    m.add_function(wrap_pyfunction!(tlv_parse, &m)?)?;
    m.add_function(wrap_pyfunction!(tlv_encode, &m)?)?;
    m.add_function(wrap_pyfunction!(int2bytes, &m)?)?;
    m.add_function(wrap_pyfunction!(bytes2int, &m)?)?;
    parent.add_submodule(&m)?;

    // Register in sys.modules for "from _ykman_native.core import ..." to work
    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.core", &m)?;

    Ok(())
}
