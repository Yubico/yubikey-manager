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
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::Version;
use crate::core::patch_version;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol};
use crate::tlv::{TlvError, parse_tlv_list, tlv_encode, tlv_get, tlv_unpack};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[non_exhaustive]
pub enum OathError {
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Wrong response MAC")]
    WrongMac,
    #[error("Credential does not belong to this YubiKey")]
    WrongDevice,
    #[error("Connection error: {0}")]
    Connection(SmartCardError),
}

impl From<SmartCardError> for OathError {
    fn from(e: SmartCardError) -> Self {
        match e {
            SmartCardError::ApplicationNotAvailable => {
                OathError::NotSupported("Application not available".into())
            }
            SmartCardError::NotSupported(msg) => OathError::NotSupported(msg),
            SmartCardError::InvalidData(msg) => OathError::InvalidData(msg),
            other => OathError::Connection(other),
        }
    }
}

impl From<TlvError> for OathError {
    fn from(e: TlvError) -> Self {
        OathError::InvalidData(e.to_string())
    }
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
        if let Some((prefix, rest)) = data.split_once('/')
            && let Ok(period) = prefix.parse::<u32>()
        {
            let (issuer, name) = split_issuer_name(rest);
            return (issuer, name, period);
        }
        let (issuer, name) = split_issuer_name(&data);
        return (issuer, name, DEFAULT_PERIOD);
    }
    let (issuer, name) = split_issuer_name(&data);
    (issuer, name, 0)
}

fn split_issuer_name(data: &str) -> (Option<String>, String) {
    if let Some(idx) = data.find(':')
        && idx > 0
    {
        return (Some(data[..idx].to_string()), data[idx + 1..].to_string());
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
pub fn derive_key(salt: &[u8], passphrase: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), salt, 1000, &mut key);
    key
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

    let mut data = tlv_encode(TAG_NAME, cred_id);
    data.extend_from_slice(&tlv_encode(TAG_KEY, &key_val));

    if touch_required {
        data.extend_from_slice(&[TAG_PROPERTY as u8, PROP_REQUIRE_TOUCH]);
    }

    if counter > 0 {
        data.extend_from_slice(&tlv_encode(TAG_IMF, &counter.to_be_bytes()));
    }

    data
}

/// Build APDU data for set_key command.
pub fn build_set_key_data(key: &[u8], challenge: &[u8]) -> Vec<u8> {
    let response = hmac_sha1(key, challenge);
    let mut key_val = vec![OathType::Totp as u8 | HashAlgorithm::Sha1 as u8];
    key_val.extend_from_slice(key);

    let mut data = tlv_encode(TAG_KEY, &key_val);
    data.extend_from_slice(&tlv_encode(TAG_CHALLENGE, challenge));
    data.extend_from_slice(&tlv_encode(TAG_RESPONSE, &response));
    data
}

/// Build APDU data for validate command.
pub fn build_validate_data(key: &[u8], device_challenge: &[u8], host_challenge: &[u8]) -> Vec<u8> {
    let response = hmac_sha1(key, device_challenge);
    let mut data = tlv_encode(TAG_RESPONSE, &response);
    data.extend_from_slice(&tlv_encode(TAG_CHALLENGE, host_challenge));
    data
}

/// Parse a credential entry from LIST response.
pub fn parse_list_entry(data: &[u8]) -> Result<(OathType, Vec<u8>), OathError> {
    let oath_type = OathType::from_u8(MASK_TYPE & data[0])
        .ok_or_else(|| OathError::InvalidData(format!("0x{:02x}", data[0] & MASK_TYPE)))?;
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
        .ok_or(OathError::InvalidData("Invalid base32 key".into()))
}

// ---------------------------------------------------------------------------
// Credential / Code types
// ---------------------------------------------------------------------------

/// An OATH credential on the device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Credential {
    pub device_id: String,
    pub id: Vec<u8>,
    pub issuer: Option<String>,
    pub name: String,
    pub oath_type: OathType,
    pub period: u32,
    pub touch_required: Option<bool>,
}

/// A computed OATH code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub value: String,
    pub valid_from: u64,
    pub valid_to: u64,
}

/// Data needed to create a credential.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CredentialData {
    #[zeroize(skip)]
    pub name: String,
    #[zeroize(skip)]
    pub oath_type: OathType,
    #[zeroize(skip)]
    pub hash_algorithm: HashAlgorithm,
    pub secret: Vec<u8>,
    #[zeroize(skip)]
    pub digits: u8,
    #[zeroize(skip)]
    pub period: u32,
    #[zeroize(skip)]
    pub counter: u32,
    #[zeroize(skip)]
    pub issuer: Option<String>,
}

impl CredentialData {
    /// Get the credential ID for this data.
    pub fn get_id(&self) -> Vec<u8> {
        format_cred_id(
            self.issuer.as_deref(),
            &self.name,
            self.oath_type,
            self.period,
        )
    }
}

// ---------------------------------------------------------------------------
// Parse SELECT response
// ---------------------------------------------------------------------------

fn parse_select(response: &[u8]) -> Result<(Version, Vec<u8>, Option<Vec<u8>>), OathError> {
    let tlvs = parse_tlv_list(response)?;
    let version_data = tlv_get(&tlvs, TAG_VERSION)
        .ok_or_else(|| OathError::InvalidData("Missing version in SELECT".into()))?;
    let version = Version::from_bytes(version_data);

    let salt = tlv_get(&tlvs, TAG_NAME)
        .ok_or_else(|| OathError::InvalidData("Missing salt in SELECT".into()))?
        .to_vec();

    let challenge = tlv_get(&tlvs, TAG_CHALLENGE).map(|c| c.to_vec());

    Ok((version, salt, challenge))
}

// ---------------------------------------------------------------------------
// OathSession — full session over SmartCardProtocol
// ---------------------------------------------------------------------------

/// A session with the OATH application on a YubiKey.
pub struct OathSession<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
    salt: Vec<u8>,
    challenge: Option<Vec<u8>>,
    device_id: String,
    has_key: bool,
}

impl<C: SmartCardConnection> OathSession<C> {
    /// Open an OATH session on the given connection.
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new(connection: C) -> Result<Self, (SmartCardError, C)> {
        let mut protocol =
            SmartCardProtocol::new(connection).with_ins_send_remaining(INS_SEND_REMAINING);
        let resp = match protocol.select(Aid::OATH) {
            Ok(resp) => resp,
            Err(e) => return Err((e, protocol.into_connection())),
        };
        Self::init(protocol, &resp)
    }

    /// Open an OATH session with SCP (Secure Channel Protocol).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, (SmartCardError, C)> {
        let mut protocol =
            SmartCardProtocol::new(connection).with_ins_send_remaining(INS_SEND_REMAINING);
        let resp = match protocol.select(Aid::OATH) {
            Ok(resp) => resp,
            Err(e) => return Err((e, protocol.into_connection())),
        };
        if let Err(e) = protocol.init_scp(scp_key_params) {
            return Err((e, protocol.into_connection()));
        }
        Self::init(protocol, &resp)
    }

    fn init(
        mut protocol: SmartCardProtocol<C>,
        select_response: &[u8],
    ) -> Result<Self, (SmartCardError, C)> {
        log::debug!("Opening OathSession");
        let (version, salt, challenge) = match parse_select(select_response) {
            Ok(v) => v,
            Err(e) => {
                return Err((
                    SmartCardError::InvalidData(e.to_string()),
                    protocol.into_connection(),
                ));
            }
        };
        let version = patch_version(version);
        protocol.configure(version);

        let has_key = challenge.is_some();
        let device_id = get_device_id(&salt);

        Ok(Self {
            protocol,
            version,
            salt,
            challenge,
            device_id,
            has_key,
        })
    }

    /// The OATH application version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// A random static identifier, re-generated on reset.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Whether an access key is configured.
    pub fn has_key(&self) -> bool {
        self.has_key
    }

    /// Whether the session is currently locked.
    pub fn locked(&self) -> bool {
        self.challenge.is_some()
    }

    /// Get a reference to the underlying protocol.
    pub fn protocol(&self) -> &SmartCardProtocol<C> {
        &self.protocol
    }

    /// Get a mutable reference to the underlying protocol.
    pub fn protocol_mut(&mut self) -> &mut SmartCardProtocol<C> {
        &mut self.protocol
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        self.protocol.into_connection()
    }

    /// Factory reset the OATH application.
    pub fn reset(&mut self) -> Result<(), OathError> {
        self.protocol.send_apdu(0, INS_RESET, 0xDE, 0xAD, &[])?;
        let resp = self.protocol.select(Aid::OATH)?;
        let (_, salt, challenge) =
            parse_select(&resp).map_err(|e| OathError::InvalidData(e.to_string()))?;
        self.salt = salt;
        self.challenge = challenge;
        self.has_key = false;
        self.device_id = get_device_id(&self.salt);
        Ok(())
    }

    /// Derive an access key from a password.
    pub fn derive_key(&self, password: &str) -> [u8; 16] {
        derive_key(&self.salt, password)
    }

    /// Validate (unlock) the session with an access key.
    pub fn validate(&mut self, key: &[u8]) -> Result<(), OathError> {
        let challenge = self
            .challenge
            .as_ref()
            .ok_or_else(|| OathError::InvalidData("Session is not locked".into()))?;

        let host_challenge: [u8; 8] = rand_bytes();
        let data = build_validate_data(key, challenge, &host_challenge);
        let resp = self.protocol.send_apdu(0, INS_VALIDATE, 0, 0, &data)?;

        let resp_value = tlv_unpack(TAG_RESPONSE, &resp)?;
        if !hmac_verify(key, &host_challenge, &resp_value) {
            return Err(OathError::InvalidData(
                "Response from validation does not match verification".into(),
            ));
        }

        self.challenge = None;
        Ok(())
    }

    /// Set an access key.
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), OathError> {
        let challenge: [u8; 8] = rand_bytes();
        let data = build_set_key_data(key, &challenge);
        self.protocol.send_apdu(0, INS_SET_CODE, 0, 0, &data)?;
        self.has_key = true;
        Ok(())
    }

    /// Remove the access key.
    pub fn unset_key(&mut self) -> Result<(), OathError> {
        let data = tlv_encode(TAG_KEY, &[]);
        self.protocol.send_apdu(0, INS_SET_CODE, 0, 0, &data)?;
        self.has_key = false;
        Ok(())
    }

    /// Add a credential.
    pub fn put_credential(
        &mut self,
        cred_data: &CredentialData,
        touch_required: bool,
    ) -> Result<Credential, OathError> {
        let cred_id = cred_data.get_id();
        let data = build_put_data(
            &cred_id,
            cred_data.oath_type,
            cred_data.hash_algorithm,
            cred_data.digits,
            &cred_data.secret,
            touch_required,
            cred_data.counter,
        );
        self.protocol.send_apdu(0, INS_PUT, 0, 0, &data)?;

        Ok(Credential {
            device_id: self.device_id.clone(),
            id: cred_id,
            issuer: cred_data.issuer.clone(),
            name: cred_data.name.clone(),
            oath_type: cred_data.oath_type,
            period: cred_data.period,
            touch_required: Some(touch_required),
        })
    }

    /// Rename a credential (requires YubiKey 5.3.1+).
    pub fn rename_credential(
        &mut self,
        credential_id: &[u8],
        name: &str,
        issuer: Option<&str>,
    ) -> Result<Vec<u8>, OathError> {
        if self.version < Version(5, 3, 1) {
            return Err(OathError::NotSupported(
                "Rename requires YubiKey 5.3.1 or later".into(),
            ));
        }
        let (_, _, period) = parse_cred_id(credential_id, OathType::Totp);
        let new_id = format_cred_id(issuer, name, OathType::Totp, period);
        let mut data = tlv_encode(TAG_NAME, credential_id);
        data.extend_from_slice(&tlv_encode(TAG_NAME, &new_id));
        self.protocol.send_apdu(0, INS_RENAME, 0, 0, &data)?;
        Ok(new_id)
    }

    /// List all credentials.
    pub fn list_credentials(&mut self) -> Result<Vec<Credential>, OathError> {
        let resp = self.protocol.send_apdu(0, INS_LIST, 0, 0, &[])?;
        let tlvs = parse_tlv_list(&resp)?;

        let mut creds = Vec::new();
        for (tag, value) in &tlvs {
            if *tag != TAG_NAME_LIST {
                continue;
            }
            let oath_type = OathType::from_u8(MASK_TYPE & value[0])
                .ok_or_else(|| OathError::InvalidData("Invalid OATH type".into()))?;
            let cred_id = &value[1..];
            let (issuer, name, period) = parse_cred_id(cred_id, oath_type);
            creds.push(Credential {
                device_id: self.device_id.clone(),
                id: cred_id.to_vec(),
                issuer,
                name,
                oath_type,
                period,
                touch_required: None,
            });
        }
        Ok(creds)
    }

    /// Perform a raw calculate for a credential.
    pub fn calculate(
        &mut self,
        credential_id: &[u8],
        challenge: &[u8],
    ) -> Result<Vec<u8>, OathError> {
        let mut data = tlv_encode(TAG_NAME, credential_id);
        data.extend_from_slice(&tlv_encode(TAG_CHALLENGE, challenge));
        let resp = self.protocol.send_apdu(0, INS_CALCULATE, 0, 0, &data)?;
        let value = tlv_unpack(TAG_RESPONSE, &resp)?;
        // Skip the first byte (digits indicator)
        Ok(value[1..].to_vec())
    }

    /// Delete a credential.
    pub fn delete_credential(&mut self, credential_id: &[u8]) -> Result<(), OathError> {
        let data = tlv_encode(TAG_NAME, credential_id);
        self.protocol.send_apdu(0, INS_DELETE, 0, 0, &data)?;
        Ok(())
    }

    /// Calculate codes for all credentials. Returns (credential, optional code) pairs.
    pub fn calculate_all(
        &mut self,
        timestamp: u64,
    ) -> Result<Vec<(Credential, Option<Code>)>, OathError> {
        let challenge = get_challenge(timestamp, DEFAULT_PERIOD);
        let mut data = tlv_encode(TAG_CHALLENGE, &challenge);
        let _ = &data; // suppress warning
        let resp = self
            .protocol
            .send_apdu(0, INS_CALCULATE_ALL, 0, 0x01, &data)?;
        data = resp; // reuse variable

        let tlvs = parse_tlv_list(&data)?;

        let mut entries = Vec::new();
        let mut iter = tlvs.into_iter();
        while let Some((tag, value)) = iter.next() {
            if tag != TAG_NAME {
                continue;
            }
            let cred_id = value;
            let (resp_tag, resp_value) = iter
                .next()
                .ok_or_else(|| OathError::InvalidData("Missing response TLV".into()))?;

            let oath_type = if resp_tag == TAG_HOTP {
                OathType::Hotp
            } else {
                OathType::Totp
            };
            let touch = resp_tag == TAG_TOUCH;
            let (issuer, name, period) = parse_cred_id(&cred_id, oath_type);

            let credential = Credential {
                device_id: self.device_id.clone(),
                id: cred_id,
                issuer,
                name,
                oath_type,
                period,
                touch_required: Some(touch),
            };

            let code = if resp_tag == TAG_TRUNCATED {
                if period == DEFAULT_PERIOD {
                    let (val, vf, vt) = format_code(oath_type, period, timestamp, &resp_value);
                    Some(Code {
                        value: val,
                        valid_from: vf,
                        valid_to: vt,
                    })
                } else {
                    // Non-standard period: recalculate
                    Some(self.calculate_code(&credential, timestamp)?)
                }
            } else {
                None
            };

            entries.push((credential, code));
        }

        Ok(entries)
    }

    /// Calculate code for a specific credential.
    pub fn calculate_code(
        &mut self,
        credential: &Credential,
        timestamp: u64,
    ) -> Result<Code, OathError> {
        if credential.device_id != self.device_id {
            return Err(OathError::InvalidData(
                "Credential does not belong to this YubiKey".into(),
            ));
        }

        let challenge = if credential.oath_type == OathType::Totp {
            get_challenge(timestamp, credential.period).to_vec()
        } else {
            Vec::new()
        };

        let mut data = tlv_encode(TAG_NAME, &credential.id);
        data.extend_from_slice(&tlv_encode(TAG_CHALLENGE, &challenge));
        let resp = self.protocol.send_apdu(0, INS_CALCULATE, 0, 0x01, &data)?;

        let response = tlv_unpack(TAG_TRUNCATED, &resp)?;

        let (val, vf, vt) = format_code(
            credential.oath_type,
            credential.period,
            timestamp,
            &response,
        );
        Ok(Code {
            value: val,
            valid_from: vf,
            valid_to: vt,
        })
    }
}

/// Generate random bytes (uses getrandom for cross-platform support).
fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("getrandom failed");
    buf
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
