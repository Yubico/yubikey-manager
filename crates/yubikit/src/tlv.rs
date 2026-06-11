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

//! BER-TLV (Tag-Length-Value) encoding and decoding.
//!
//! Used by SmartCard-based applications (PIV, OpenPGP, OATH, etc.) to
//! parse and construct APDU payloads. Supports multi-byte tags,
//! definite and indefinite length encoding, and OID conversions.

use std::collections::HashMap;
use thiserror::Error;

use crate::core::int2bytes;

/// Error type for TLV parsing operations.
#[derive(Debug, Error)]
pub enum TlvError {
    /// The tag or length bytes are malformed.
    #[error("Invalid encoding of tag/length")]
    InvalidEncoding,
    /// The encoded length does not match the available data.
    #[error("Incorrect TLV length")]
    IncorrectLength,
    /// The parsed tag does not match the expected value.
    #[error("Wrong tag, got 0x{got:02x} expected 0x{expected:02x}")]
    WrongTag {
        /// The tag value that was actually parsed.
        got: u32,
        /// The tag value that was expected.
        expected: u32,
    },
}

/// Parsed TLV boundaries: (tag, value_offset, value_length, end_offset).
pub fn tlv_parse(data: &[u8], offset: usize) -> Result<(u32, usize, usize, usize), TlvError> {
    tlv_parse_inner(data, offset)
}

fn tlv_parse_inner(data: &[u8], mut offset: usize) -> Result<(u32, usize, usize, usize), TlvError> {
    fn checked_add(a: usize, b: usize) -> Result<usize, TlvError> {
        a.checked_add(b).ok_or(TlvError::InvalidEncoding)
    }

    let get = |i: usize| -> Result<u8, TlvError> {
        data.get(i).copied().ok_or(TlvError::InvalidEncoding)
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
        while get(end)? != 0 || get(checked_add(end, 1)?)? != 0 {
            let (_, _, _, next_end) = tlv_parse_inner(data, end)?;
            if next_end <= end {
                return Err(TlvError::InvalidEncoding);
            }
            end = next_end;
        }
        let ln = end.checked_sub(offset).ok_or(TlvError::InvalidEncoding)?;
        (ln, checked_add(end, 2)?)
    } else if ln_byte > 0x80 {
        let n_bytes = ln_byte - 0x80;
        let mut ln: usize = 0;
        for i in 0..n_bytes {
            ln = ln.checked_mul(0x100).ok_or(TlvError::InvalidEncoding)?
                | get(checked_add(offset, i)?)? as usize;
        }
        offset = checked_add(offset, n_bytes)?;
        (ln, checked_add(offset, ln)?)
    } else {
        (ln_byte, checked_add(offset, ln_byte)?)
    };

    if end > data.len() {
        return Err(TlvError::InvalidEncoding);
    }

    Ok((tag, offset, ln, end))
}

/// Parse a byte slice into a list of (tag, value) pairs.
pub fn parse_tlv_list(data: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, TlvError> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (tag, val_offset, val_len, end) = tlv_parse(data, offset)?;
        let val_end = val_offset
            .checked_add(val_len)
            .ok_or(TlvError::InvalidEncoding)?;
        let value = data
            .get(val_offset..val_end)
            .ok_or(TlvError::IncorrectLength)?;
        result.push((tag, value.to_vec()));
        offset = end;
    }
    Ok(result)
}

/// Parse a byte slice into a tag→value map (last value for duplicate tags wins).
pub fn parse_tlv_dict(data: &[u8]) -> Result<HashMap<u32, Vec<u8>>, TlvError> {
    let entries = parse_tlv_list(data)?;
    Ok(entries.into_iter().collect())
}

/// Unpack a single TLV and verify the tag matches the expected value.
pub fn tlv_unpack(expected_tag: u32, data: &[u8]) -> Result<Vec<u8>, TlvError> {
    let (tag, val_offset, val_len, _) = tlv_parse(data, 0)?;
    if tag != expected_tag {
        return Err(TlvError::WrongTag {
            got: tag,
            expected: expected_tag,
        });
    }
    let val_end = val_offset
        .checked_add(val_len)
        .ok_or(TlvError::InvalidEncoding)?;
    data.get(val_offset..val_end)
        .map(|v| v.to_vec())
        .ok_or(TlvError::IncorrectLength)
}

/// Find the first entry with the given tag in a TLV list.
pub(crate) fn tlv_get(tlvs: &[(u32, Vec<u8>)], tag: u32) -> Option<&[u8]> {
    tlvs.iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, v)| v.as_slice())
}

/// Encode a tag and value into BER-TLV format.
pub fn tlv_encode(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    tlv_append(&mut buf, tag, value);
    buf
}

/// Append a TLV-encoded tag and value directly into an existing buffer.
///
/// This avoids creating a temporary `Vec` that would contain a copy of the
/// value — important when the value is secret key material that must not
/// linger in unzeroized memory.
pub fn tlv_append(buf: &mut Vec<u8>, tag: u32, value: &[u8]) {
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
        let ln_bytes = int2bytes(length as u64);
        buf.push(0x80 | ln_bytes.len() as u8);
        buf.extend_from_slice(&ln_bytes);
    }

    buf.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_roundtrip() {
        let encoded = tlv_encode(0x71, b"hello");
        let (tag, offset, ln, end) = tlv_parse(&encoded, 0).unwrap();
        assert_eq!(tag, 0x71);
        assert_eq!(&encoded[offset..offset + ln], b"hello");
        assert_eq!(end, encoded.len());
    }

    #[test]
    fn test_tlv_rejects_oversized_length() {
        let mut encoded = vec![0x71, 0x88];
        encoded.extend_from_slice(&usize::MAX.to_be_bytes());
        assert!(matches!(
            tlv_parse(&encoded, 0),
            Err(TlvError::InvalidEncoding)
        ));
    }

    #[test]
    fn test_parse_tlv_list_rejects_truncated_value() {
        let encoded = [0x71, 0x02, 0xAA];
        assert!(matches!(
            parse_tlv_list(&encoded),
            Err(TlvError::InvalidEncoding | TlvError::IncorrectLength)
        ));
    }

    #[test]
    fn test_int2bytes() {
        assert_eq!(int2bytes(0), vec![0]);
        assert_eq!(int2bytes(255), vec![0xFF]);
        assert_eq!(int2bytes(256), vec![0x01, 0x00]);
    }
}
