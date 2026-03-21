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

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::tlv;

// TLV tags
pub const TAG_NAME: u32 = 0x71;
pub const TAG_NAME_LIST: u32 = 0x72;
pub const TAG_KEY: u32 = 0x73;
pub const TAG_CHALLENGE: u32 = 0x74;
pub const TAG_RESPONSE: u32 = 0x75;
pub const TAG_TRUNCATED: u32 = 0x76;
pub const TAG_HOTP: u32 = 0x77;
pub const TAG_PROPERTY: u32 = 0x78;
pub const TAG_VERSION: u32 = 0x79;
pub const TAG_IMF: u32 = 0x7A;
pub const TAG_TOUCH: u32 = 0x7C;

// Instruction bytes
pub const INS_LIST: u8 = 0xA1;
pub const INS_PUT: u8 = 0x01;
pub const INS_DELETE: u8 = 0x02;
pub const INS_SET_CODE: u8 = 0x03;
pub const INS_RESET: u8 = 0x04;
pub const INS_RENAME: u8 = 0x05;
pub const INS_CALCULATE: u8 = 0xA2;
pub const INS_VALIDATE: u8 = 0xA3;
pub const INS_CALCULATE_ALL: u8 = 0xA4;
pub const INS_SEND_REMAINING: u8 = 0xA5;

pub const MASK_ALGO: u8 = 0x0F;
pub const MASK_TYPE: u8 = 0xF0;

pub const DEFAULT_PERIOD: u32 = 30;
pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_IMF: u32 = 0;
pub const CHALLENGE_LEN: usize = 8;
pub const HMAC_MINIMUM_KEY_SIZE: usize = 14;

const PROP_REQUIRE_TOUCH: u8 = 0x02;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlgorithm {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

impl HashAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Sha1),
            0x02 => Some(Self::Sha256),
            0x03 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn block_size(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 64,
            HashAlgorithm::Sha256 => 64,
            HashAlgorithm::Sha512 => 128,
        }
    }

    pub fn digest_size(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OathType {
    Hotp = 0x10,
    Totp = 0x20,
}

impl OathType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x10 => Some(Self::Hotp),
            0x20 => Some(Self::Totp),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum OathError {
    #[error("Invalid URI scheme")]
    InvalidUriScheme,
    #[error("Missing OATH type")]
    MissingOathType,
    #[error("Invalid OATH type: {0}")]
    InvalidOathType(String),
    #[error("Missing secret")]
    MissingSecret,
    #[error("Invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),
    #[error("TLV error: {0}")]
    Tlv(#[from] tlv::TlvError),
    #[error("Wrong response MAC")]
    WrongMac,
    #[error("Credential does not belong to this YubiKey")]
    WrongDevice,
}

/// Format a credential ID from its components.
pub fn format_cred_id(
    issuer: Option<&str>,
    name: &str,
    oath_type: OathType,
    period: u32,
) -> Vec<u8> {
    let mut cred_id = String::new();
    if oath_type == OathType::Totp && period != DEFAULT_PERIOD {
        cred_id.push_str(&format!("{}/", period));
    }
    if let Some(issuer) = issuer {
        cred_id.push_str(issuer);
        cred_id.push(':');
    }
    cred_id.push_str(name);
    cred_id.into_bytes()
}

/// Parse a credential ID into (issuer, name, period).
pub fn parse_cred_id(cred_id: &[u8], oath_type: OathType) -> (Option<String>, String, u32) {
    let data = String::from_utf8_lossy(cred_id);
    if oath_type == OathType::Totp {
        // Pattern: [<period>/][[issuer]:]name
        if let Some((prefix, rest)) = data.split_once('/') {
            if let Ok(period) = prefix.parse::<u32>() {
                let (issuer, name) = split_issuer_name(rest);
                return (issuer, name, period);
            }
        }
        let (issuer, name) = split_issuer_name(&data);
        return (issuer, name, DEFAULT_PERIOD);
    }
    let (issuer, name) = split_issuer_name(&data);
    (issuer, name, 0)
}

fn split_issuer_name(data: &str) -> (Option<String>, String) {
    if let Some(idx) = data.find(':') {
        if idx > 0 {
            return (
                Some(data[..idx].to_string()),
                data[idx + 1..].to_string(),
            );
        }
    }
    (None, data.to_string())
}

/// Get device ID from salt (SHA-256, base64 without padding).
pub fn get_device_id(salt: &[u8]) -> String {
    let hash = Sha256::digest(salt);
    let b64 = base64_encode(&hash[..16]);
    b64.trim_end_matches('=').to_string()
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Compute HMAC-SHA1.
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time HMAC comparison.
pub fn hmac_verify(key: &[u8], message: &[u8], expected: &[u8]) -> bool {
    let computed = hmac_sha1(key, message);
    subtle::ConstantTimeEq::ct_eq(computed.as_slice(), expected).into()
}

/// Derive OATH access key from password and salt.
pub fn derive_key(salt: &[u8], passphrase: &str) -> Vec<u8> {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), salt, 1000, &mut key);
    key.to_vec()
}

/// Shorten HMAC key per RFC 2104.
pub fn hmac_shorten_key(key: &[u8], algo: HashAlgorithm) -> Vec<u8> {
    if key.len() > algo.block_size() {
        match algo {
            HashAlgorithm::Sha1 => Sha1::digest(key).to_vec(),
            HashAlgorithm::Sha256 => Sha256::digest(key).to_vec(),
            HashAlgorithm::Sha512 => {
                use sha2::Sha512;
                Sha512::digest(key).to_vec()
            }
        }
    } else {
        key.to_vec()
    }
}

/// Get TOTP challenge from timestamp and period.
pub fn get_challenge(timestamp: u64, period: u32) -> [u8; 8] {
    let time_step = timestamp / period as u64;
    time_step.to_be_bytes()
}

/// Format an OATH code from truncated response.
pub fn format_code(
    oath_type: OathType,
    period: u32,
    timestamp: u64,
    truncated: &[u8],
) -> (String, u64, u64) {
    let (valid_from, valid_to) = if oath_type == OathType::Totp {
        let time_step = timestamp / period as u64;
        (time_step * period as u64, (time_step + 1) * period as u64)
    } else {
        (timestamp, 0x7FFFFFFFFFFFFFFF)
    };

    let digits = truncated[0] as u32;
    let raw = u32::from_be_bytes([truncated[1], truncated[2], truncated[3], truncated[4]]);
    let code_val = (raw & 0x7FFFFFFF) % 10u32.pow(digits);
    let code = format!("{:0>width$}", code_val, width = digits as usize);

    (code, valid_from, valid_to)
}

/// Build APDU data for put_credential command.
pub fn build_put_data(
    cred_id: &[u8],
    oath_type: OathType,
    hash_algorithm: HashAlgorithm,
    digits: u8,
    secret: &[u8],
    touch_required: bool,
    counter: u32,
) -> Vec<u8> {
    let short_secret = hmac_shorten_key(secret, hash_algorithm);
    let padded_secret = if short_secret.len() < HMAC_MINIMUM_KEY_SIZE {
        let mut s = short_secret;
        s.resize(HMAC_MINIMUM_KEY_SIZE, 0);
        s
    } else {
        short_secret
    };

    let mut key_val = vec![oath_type as u8 | hash_algorithm as u8, digits];
    key_val.extend_from_slice(&padded_secret);

    let mut data = tlv::tlv_encode(TAG_NAME, cred_id);
    data.extend_from_slice(&tlv::tlv_encode(TAG_KEY, &key_val));

    if touch_required {
        data.extend_from_slice(&[TAG_PROPERTY as u8, PROP_REQUIRE_TOUCH]);
    }

    if counter > 0 {
        data.extend_from_slice(&tlv::tlv_encode(TAG_IMF, &counter.to_be_bytes()));
    }

    data
}

/// Build APDU data for set_key command.
pub fn build_set_key_data(key: &[u8], challenge: &[u8]) -> Vec<u8> {
    let response = hmac_sha1(key, challenge);
    let mut key_val = vec![OathType::Totp as u8 | HashAlgorithm::Sha1 as u8];
    key_val.extend_from_slice(key);

    let mut data = tlv::tlv_encode(TAG_KEY, &key_val);
    data.extend_from_slice(&tlv::tlv_encode(TAG_CHALLENGE, challenge));
    data.extend_from_slice(&tlv::tlv_encode(TAG_RESPONSE, &response));
    data
}

/// Build APDU data for validate command.
pub fn build_validate_data(key: &[u8], device_challenge: &[u8], host_challenge: &[u8]) -> Vec<u8> {
    let response = hmac_sha1(key, device_challenge);
    let mut data = tlv::tlv_encode(TAG_RESPONSE, &response);
    data.extend_from_slice(&tlv::tlv_encode(TAG_CHALLENGE, host_challenge));
    data
}

/// Parse a credential entry from LIST response.
pub fn parse_list_entry(data: &[u8]) -> Result<(OathType, Vec<u8>), OathError> {
    let oath_type = OathType::from_u8(MASK_TYPE & data[0])
        .ok_or_else(|| OathError::InvalidOathType(format!("0x{:02x}", data[0] & MASK_TYPE)))?;
    Ok((oath_type, data[1..].to_vec()))
}

/// Parse base32-encoded key (supports unpadded).
pub fn parse_b32_key(key: &str) -> Result<Vec<u8>, OathError> {
    let cleaned = key.to_uppercase().replace(' ', "");
    let padded = {
        let pad = (8 - cleaned.len() % 8) % 8;
        let mut s = cleaned;
        for _ in 0..pad {
            s.push('=');
        }
        s
    };
    base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &padded)
        .ok_or(OathError::InvalidHashAlgorithm("Invalid base32 key".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_parse_cred_id_totp() {
        let id = format_cred_id(Some("GitHub"), "user@example.com", OathType::Totp, 30);
        let (issuer, name, period) = parse_cred_id(&id, OathType::Totp);
        assert_eq!(issuer.as_deref(), Some("GitHub"));
        assert_eq!(name, "user@example.com");
        assert_eq!(period, 30);
    }

    #[test]
    fn test_format_parse_cred_id_totp_custom_period() {
        let id = format_cred_id(Some("Test"), "acct", OathType::Totp, 60);
        assert_eq!(id, b"60/Test:acct");
        let (issuer, name, period) = parse_cred_id(&id, OathType::Totp);
        assert_eq!(issuer.as_deref(), Some("Test"));
        assert_eq!(name, "acct");
        assert_eq!(period, 60);
    }

    #[test]
    fn test_format_parse_cred_id_hotp() {
        let id = format_cred_id(None, "myaccount", OathType::Hotp, 0);
        let (issuer, name, period) = parse_cred_id(&id, OathType::Hotp);
        assert_eq!(issuer, None);
        assert_eq!(name, "myaccount");
        assert_eq!(period, 0);
    }

    #[test]
    fn test_hmac_sha1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let result = hmac_sha1(&key, data);
        assert_eq!(result.len(), 20);
        // RFC 2202 test vector 1: b617318655057264e28bc0b6fb378c8ef146be00
        assert_eq!(result[0], 0xb6);
        assert_eq!(result[1], 0x17);
    }

    #[test]
    fn test_derive_key() {
        let salt = b"test_salt";
        let key = derive_key(salt, "password");
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_get_challenge() {
        let challenge = get_challenge(1234567890, 30);
        let time_step = 1234567890u64 / 30;
        assert_eq!(challenge, time_step.to_be_bytes());
    }

    #[test]
    fn test_format_code() {
        let truncated = [6, 0x7F, 0xFF, 0xFF, 0xFF]; // 6 digits, max value
        let (code, _, _) = format_code(OathType::Totp, 30, 1000, &truncated);
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_parse_b32_key() {
        let key = parse_b32_key("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(key, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_device_id() {
        let id = get_device_id(b"some_salt");
        assert!(!id.is_empty());
        assert!(!id.contains('='));
    }
}
