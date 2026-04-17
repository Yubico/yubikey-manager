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

//! BER-TLV (Tag-Length-Value) encoding and decoding.
//!
//! Used by SmartCard-based applications (PIV, OpenPGP, OATH, etc.) to
//! parse and construct APDU payloads. Supports multi-byte tags,
//! definite and indefinite length encoding, and OID conversions.

use std::collections::HashMap;
use thiserror::Error;

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
        result.push((tag, data[val_offset..val_offset + val_len].to_vec()));
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
    Ok(data[val_offset..val_offset + val_len].to_vec())
}

/// Find the first entry with the given tag in a TLV list.
pub fn tlv_get(tlvs: &[(u32, Vec<u8>)], tag: u32) -> Option<&[u8]> {
    tlvs.iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, v)| v.as_slice())
}

/// Encode a tag and value into BER-TLV format.
pub fn tlv_encode(tag: u32, value: &[u8]) -> Vec<u8> {
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
        let ln_bytes = int2bytes(length as u64);
        buf.push(0x80 | ln_bytes.len() as u8);
        buf.extend_from_slice(&ln_bytes);
    }

    buf.extend_from_slice(value);
    buf
}

/// Encode an integer as big-endian bytes with no leading zeros.
pub fn int2bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let byte_len = ((64 - value.leading_zeros()) as usize).div_ceil(8);
    value.to_be_bytes()[8 - byte_len..].to_vec()
}

/// Decode OID bytes to dotted string notation.
pub fn oid_to_string(data: &[u8]) -> Result<String, TlvError> {
    if data.is_empty() {
        return Err(TlvError::InvalidEncoding);
    }
    let mut parts = vec![(data[0] / 40) as u32, (data[0] % 40) as u32];
    let mut num: u32 = 0;
    for &x in &data[1..] {
        num = (num << 7) | (x & 0x7F) as u32;
        if x & 0x80 == 0 {
            parts.push(num);
            num = 0;
        }
    }
    Ok(parts
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

/// Encode a dotted string OID into bytes.
pub fn oid_from_string(data: &str) -> Result<Vec<u8>, TlvError> {
    let parts: Vec<u32> = data
        .split('.')
        .map(|s| s.parse::<u32>().map_err(|_| TlvError::InvalidEncoding))
        .collect::<Result<Vec<_>, _>>()?;

    if parts.len() < 2 {
        return Err(TlvError::InvalidEncoding);
    }

    let mut buf = vec![(parts[0] * 40 + parts[1]) as u8];

    for &part in &parts[2..] {
        let mut part = part;
        let mut part_buf = Vec::new();
        while part > 0x7F {
            part_buf.push((part & 0x7F) as u8);
            part >>= 7;
        }
        part_buf.push(part as u8);
        part_buf.reverse();
        let last = part_buf.len() - 1;
        for b in &mut part_buf[..last] {
            *b |= 0x80;
        }
        buf.extend_from_slice(&part_buf);
    }

    Ok(buf)
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
    fn test_oid_roundtrip() {
        let oid_str = "1.2.840.113549.1.1.1";
        let encoded = oid_from_string(oid_str).unwrap();
        let decoded = oid_to_string(&encoded).unwrap();
        assert_eq!(decoded, oid_str);
    }

    #[test]
    fn test_int2bytes() {
        assert_eq!(int2bytes(0), vec![0]);
        assert_eq!(int2bytes(255), vec![0xFF]);
        assert_eq!(int2bytes(256), vec![0x01, 0x00]);
    }
}
