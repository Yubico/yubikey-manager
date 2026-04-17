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

//! Minimal CBOR implementation supporting the subset of types required for
//! FIDO2 CTAP.
//!
//! Supported types: unsigned/negative integers, byte strings, text strings,
//! arrays, maps, and booleans. Maps are encoded using CTAP2 canonical ordering.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

/// CBOR value type supporting the subset used by CTAP2.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// Signed or unsigned integer (CBOR major types 0 and 1).
    Int(i64),
    /// Byte string (CBOR major type 2).
    Bytes(Vec<u8>),
    /// UTF-8 text string (CBOR major type 3).
    Text(String),
    /// Boolean (`true` / `false`, CBOR simple values 20/21).
    Bool(bool),
    /// Ordered array of values (CBOR major type 4).
    Array(Vec<Value>),
    /// Ordered list of key-value pairs (CBOR major type 5).
    Map(Vec<(Value, Value)>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(n) => write!(f, "{n}"),
            Value::Bytes(b) => write!(f, "h'{}'", crate::logging::hex_encode(b)),
            Value::Text(s) => write!(f, "{s:?}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Array(arr) => f.debug_list().entries(arr).finish(),
            Value::Map(entries) => {
                let mut m = f.debug_map();
                for (k, v) in entries {
                    m.entry(k, v);
                }
                m.finish()
            }
        }
    }
}

/// Error type for CBOR encoding and decoding operations.
#[derive(Debug, thiserror::Error)]
pub enum CborError {
    /// Input data ended before a complete CBOR value could be read.
    #[error("Unexpected end of input")]
    UnexpectedEof,
    /// The additional information field contains a reserved value.
    #[error("Invalid additional information: {0}")]
    InvalidAdditionalInfo(u8),
    /// The CBOR major type is not supported by this implementation.
    #[error("Unsupported major type: {0}")]
    UnsupportedMajorType(u8),
    /// A text string contains invalid UTF-8 data.
    #[error("Invalid UTF-8 in text string")]
    InvalidUtf8,
    /// Trailing bytes remain after decoding a complete CBOR value.
    #[error("Extraneous data after CBOR value")]
    ExtraneousData,
    /// An integer value exceeds the representable range.
    #[error("Integer overflow")]
    IntegerOverflow,
    /// The input exceeds the maximum allowed CBOR message size.
    #[error("Input exceeds maximum CBOR message size")]
    InputTooLarge,
    /// Nested arrays/maps exceed the maximum allowed depth.
    #[error("Nesting depth exceeds maximum of {MAX_DEPTH}")]
    MaxDepthExceeded,
}

/// Maximum allowed input size for CBOR decoding (1 MB).
const MAX_CBOR_SIZE: usize = 1_048_576;

/// Maximum nesting depth for arrays and maps.
const MAX_DEPTH: usize = 32;

// --- Encoding ---

fn encode_head(mt: u8, val: u64) -> Vec<u8> {
    let mt = mt << 5;
    if val <= 23 {
        vec![mt | val as u8]
    } else if val <= 0xFF {
        vec![mt | 24, val as u8]
    } else if val <= 0xFFFF {
        let mut buf = vec![mt | 25, 0, 0];
        buf[1..3].copy_from_slice(&(val as u16).to_be_bytes());
        buf
    } else if val <= 0xFFFF_FFFF {
        let mut buf = vec![mt | 26, 0, 0, 0, 0];
        buf[1..5].copy_from_slice(&(val as u32).to_be_bytes());
        buf
    } else {
        let mut buf = vec![mt | 27, 0, 0, 0, 0, 0, 0, 0, 0];
        buf[1..9].copy_from_slice(&val.to_be_bytes());
        buf
    }
}

/// CTAP2 canonical key ordering: sort by (first_byte, length, raw_bytes).
fn canonical_cmp(a: &[u8], b: &[u8]) -> Ordering {
    a[0].cmp(&b[0])
        .then_with(|| a.len().cmp(&b.len()))
        .then_with(|| a.cmp(b))
}

impl Value {
    /// Encode this value to CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf);
        buf
    }

    /// Encode this value, appending to the given buffer.
    pub fn encode_to(&self, buf: &mut Vec<u8>) {
        match self {
            Value::Int(n) => {
                if *n >= 0 {
                    buf.extend_from_slice(&encode_head(0, *n as u64));
                } else {
                    buf.extend_from_slice(&encode_head(1, (-1 - *n) as u64));
                }
            }
            Value::Bytes(data) => {
                buf.extend_from_slice(&encode_head(2, data.len() as u64));
                buf.extend_from_slice(data);
            }
            Value::Text(s) => {
                let data = s.as_bytes();
                buf.extend_from_slice(&encode_head(3, data.len() as u64));
                buf.extend_from_slice(data);
            }
            Value::Bool(b) => {
                buf.push(if *b { 0xF5 } else { 0xF4 });
            }
            Value::Array(arr) => {
                buf.extend_from_slice(&encode_head(4, arr.len() as u64));
                for item in arr {
                    item.encode_to(buf);
                }
            }
            Value::Map(entries) => {
                buf.extend_from_slice(&encode_head(5, entries.len() as u64));
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (k.encode(), v.encode()))
                    .collect();
                encoded.sort_by(|(a, _), (b, _)| canonical_cmp(a, b));
                for (k, v) in &encoded {
                    buf.extend_from_slice(k);
                    buf.extend_from_slice(v);
                }
            }
        }
    }
}

// --- Decoding ---

fn decode_head(data: &[u8]) -> Result<(u8, u64, &[u8]), CborError> {
    if data.is_empty() {
        return Err(CborError::UnexpectedEof);
    }
    let fb = data[0];
    let mt = fb >> 5;
    let ai = fb & 0x1F;
    let rest = &data[1..];

    let (val, rest) = decode_int(ai, rest)?;
    Ok((mt, val, rest))
}

fn decode_int(ai: u8, data: &[u8]) -> Result<(u64, &[u8]), CborError> {
    if ai < 24 {
        Ok((ai as u64, data))
    } else if ai == 24 {
        if data.is_empty() {
            return Err(CborError::UnexpectedEof);
        }
        Ok((data[0] as u64, &data[1..]))
    } else if ai == 25 {
        if data.len() < 2 {
            return Err(CborError::UnexpectedEof);
        }
        Ok((u16::from_be_bytes([data[0], data[1]]) as u64, &data[2..]))
    } else if ai == 26 {
        if data.len() < 4 {
            return Err(CborError::UnexpectedEof);
        }
        Ok((
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
            &data[4..],
        ))
    } else if ai == 27 {
        if data.len() < 8 {
            return Err(CborError::UnexpectedEof);
        }
        Ok((
            u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            &data[8..],
        ))
    } else {
        Err(CborError::InvalidAdditionalInfo(ai))
    }
}

/// Decode a CBOR value from the start of a byte slice, returning the value
/// and any remaining bytes.
pub fn decode_from(data: &[u8]) -> Result<(Value, &[u8]), CborError> {
    if data.len() > MAX_CBOR_SIZE {
        return Err(CborError::InputTooLarge);
    }
    decode_from_depth(data, 0)
}

fn decode_from_depth(data: &[u8], depth: usize) -> Result<(Value, &[u8]), CborError> {
    let (mt, val, rest) = decode_head(data)?;
    match mt {
        0 => {
            // Unsigned integer
            let n: i64 = val.try_into().map_err(|_| CborError::IntegerOverflow)?;
            Ok((Value::Int(n), rest))
        }
        1 => {
            // Negative integer
            let n: i64 = val.try_into().map_err(|_| CborError::IntegerOverflow)?;
            Ok((Value::Int(-1 - n), rest))
        }
        2 => {
            // Byte string
            let len = val as usize;
            if rest.len() < len {
                return Err(CborError::UnexpectedEof);
            }
            Ok((Value::Bytes(rest[..len].to_vec()), &rest[len..]))
        }
        3 => {
            // Text string
            let len = val as usize;
            if rest.len() < len {
                return Err(CborError::UnexpectedEof);
            }
            let s = std::str::from_utf8(&rest[..len]).map_err(|_| CborError::InvalidUtf8)?;
            Ok((Value::Text(s.to_string()), &rest[len..]))
        }
        4 => {
            // Array
            if depth >= MAX_DEPTH {
                return Err(CborError::MaxDepthExceeded);
            }
            let count = val as usize;
            let mut items = Vec::with_capacity(count.min(rest.len()));
            let mut remaining = rest;
            for _ in 0..count {
                let (item, r) = decode_from_depth(remaining, depth + 1)?;
                items.push(item);
                remaining = r;
            }
            Ok((Value::Array(items), remaining))
        }
        5 => {
            // Map
            if depth >= MAX_DEPTH {
                return Err(CborError::MaxDepthExceeded);
            }
            let count = val as usize;
            let mut entries = Vec::with_capacity(count.min(rest.len()));
            let mut remaining = rest;
            for _ in 0..count {
                let (k, r) = decode_from_depth(remaining, depth + 1)?;
                let (v, r) = decode_from_depth(r, depth + 1)?;
                entries.push((k, v));
                remaining = r;
            }
            Ok((Value::Map(entries), remaining))
        }
        7 => {
            // Simple values (bool)
            match val {
                20 => Ok((Value::Bool(false), rest)),
                21 => Ok((Value::Bool(true), rest)),
                _ => Err(CborError::UnsupportedMajorType(7)),
            }
        }
        _ => Err(CborError::UnsupportedMajorType(mt)),
    }
}

/// Decode a single CBOR value from a byte slice.
///
/// Returns an error if there is extra data after the value.
pub fn decode(data: &[u8]) -> Result<Value, CborError> {
    if data.len() > MAX_CBOR_SIZE {
        return Err(CborError::InputTooLarge);
    }
    let (value, rest) = decode_from_depth(data, 0)?;
    if !rest.is_empty() {
        return Err(CborError::ExtraneousData);
    }
    Ok(value)
}

/// Encode a CBOR value to bytes.
pub fn encode(value: &Value) -> Vec<u8> {
    value.encode()
}

// --- Convenience conversions ---

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Int(n)
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::Int(n as i64)
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::Int(n as i64)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}

impl<V: Into<Value>> From<Vec<V>> for Value {
    fn from(arr: Vec<V>) -> Self {
        Value::Array(arr.into_iter().map(Into::into).collect())
    }
}

impl<K: Into<Value>, V: Into<Value>> From<BTreeMap<K, V>> for Value {
    fn from(map: BTreeMap<K, V>) -> Self {
        Value::Map(map.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
    }
}

impl Value {
    /// Get as integer, if this value is an Int.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Get as byte slice, if this value is Bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Get as string slice, if this value is Text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Get as bool, if this value is Bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as array slice, if this value is an Array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Get as map entries, if this value is a Map.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// Look up a value in a Map by key.
    pub fn map_get(&self, key: &Value) -> Option<&Value> {
        self.as_map()
            .and_then(|entries| entries.iter().find(|(k, _)| k == key).map(|(_, v)| v))
    }

    /// Look up a value in a Map by integer key.
    pub fn map_get_int(&self, key: i64) -> Option<&Value> {
        self.map_get(&Value::Int(key))
    }

    /// Look up a value in a Map by text key.
    pub fn map_get_text(&self, key: &str) -> Option<&Value> {
        self.map_get(&Value::Text(key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_int() {
        for n in [0i64, 1, 23, 24, 255, 256, 65535, 65536, 0x1_0000_0000] {
            let encoded = Value::Int(n).encode();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, Value::Int(n));
        }
    }

    #[test]
    fn test_encode_decode_negative_int() {
        for n in [-1i64, -24, -25, -256, -257, -65536, -65537] {
            let encoded = Value::Int(n).encode();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, Value::Int(n));
        }
    }

    #[test]
    fn test_encode_decode_bool() {
        let t = Value::Bool(true).encode();
        let f = Value::Bool(false).encode();
        assert_eq!(t, vec![0xF5]);
        assert_eq!(f, vec![0xF4]);
        assert_eq!(decode(&t).unwrap(), Value::Bool(true));
        assert_eq!(decode(&f).unwrap(), Value::Bool(false));
    }

    #[test]
    fn test_encode_decode_bytes() {
        let data = b"hello";
        let encoded = Value::Bytes(data.to_vec()).encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, Value::Bytes(data.to_vec()));
    }

    #[test]
    fn test_encode_decode_text() {
        let encoded = Value::Text("hello".into()).encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, Value::Text("hello".into()));
    }

    #[test]
    fn test_encode_decode_array() {
        let arr = Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        let encoded = arr.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, arr);
    }

    #[test]
    fn test_encode_decode_map() {
        let map = Value::Map(vec![
            (Value::Int(1), Value::Text("one".into())),
            (Value::Int(2), Value::Text("two".into())),
        ]);
        let encoded = map.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, map);
    }

    #[test]
    fn test_canonical_key_order() {
        // Keys should be sorted by (first_byte, length, raw_bytes)
        let map = Value::Map(vec![
            (Value::Int(10), Value::Bool(true)),
            (Value::Int(1), Value::Bool(false)),
            (Value::Text("z".into()), Value::Int(3)),
        ]);
        let encoded = map.encode();
        let decoded = decode(&encoded).unwrap();
        let entries = decoded.as_map().unwrap();
        // Int(1) encodes as 0x01, Int(10) as 0x0A, Text("z") as 0x61 0x7A
        assert_eq!(entries[0].0, Value::Int(1));
        assert_eq!(entries[1].0, Value::Int(10));
        assert_eq!(entries[2].0, Value::Text("z".into()));
    }

    #[test]
    fn test_decode_from() {
        let mut buf = Value::Int(42).encode();
        buf.extend_from_slice(&Value::Bool(true).encode());
        let (val, rest) = decode_from(&buf).unwrap();
        assert_eq!(val, Value::Int(42));
        let (val2, rest2) = decode_from(rest).unwrap();
        assert_eq!(val2, Value::Bool(true));
        assert!(rest2.is_empty());
    }

    #[test]
    fn test_extraneous_data() {
        let mut buf = Value::Int(1).encode();
        buf.push(0xFF);
        assert!(matches!(decode(&buf), Err(CborError::ExtraneousData)));
    }

    #[test]
    fn test_empty_input() {
        assert!(matches!(decode(b""), Err(CborError::UnexpectedEof)));
    }

    #[test]
    fn test_nested_structure() {
        let val = Value::Map(vec![(
            Value::Int(1),
            Value::Array(vec![
                Value::Bytes(vec![0xDE, 0xAD]),
                Value::Map(vec![(Value::Text("key".into()), Value::Bool(true))]),
            ]),
        )]);
        let encoded = val.encode();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_map_get() {
        let map = Value::Map(vec![
            (Value::Int(1), Value::Text("one".into())),
            (Value::Text("key".into()), Value::Bool(true)),
        ]);
        assert_eq!(map.map_get_int(1), Some(&Value::Text("one".into())));
        assert_eq!(map.map_get_text("key"), Some(&Value::Bool(true)));
        assert_eq!(map.map_get_int(2), None);
    }

    #[test]
    fn test_from_conversions() {
        assert_eq!(Value::from(42i32), Value::Int(42));
        assert_eq!(Value::from(42u32), Value::Int(42));
        assert_eq!(Value::from(true), Value::Bool(true));
        assert_eq!(Value::from("hello"), Value::Text("hello".into()));
        assert_eq!(
            Value::from(b"\x01\x02".as_slice()),
            Value::Bytes(vec![1, 2])
        );
    }
}
