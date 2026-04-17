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

//! YubiHSM Auth application for symmetric key storage and derivation.
//!
//! This module manages credentials on the YubiHSM Auth applet, which stores
//! symmetric keys used for establishing secure sessions with a YubiHSM 2.
//! The main entry point is [`HsmAuthSession`](crate::hsmauth::HsmAuthSession), which wraps a
//! [`SmartCardConnection`](crate::smartcard::SmartCardConnection).
//!
//! # Example
//!
//! ```no_run
//! use yubikit::device::list_devices;
//! use yubikit::management::UsbInterface;
//! use yubikit::hsmauth::HsmAuthSession;
//!
//! let devices = list_devices(UsbInterface::CCID)?;
//! let dev = devices.first().expect("no YubiKey found");
//! let conn = dev.open_smartcard()?;
//! let mut session = HsmAuthSession::new(conn).map_err(|(e, _)| e)?;
//!
//! for cred in session.list_credentials()? {
//!     println!("{}: {:?}", cred.label, cred.algorithm);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::Version;
use crate::core::patch_version;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol};
use crate::tlv::{parse_tlv_list, tlv_encode};

// ---------------------------------------------------------------------------
// TLV tags
// ---------------------------------------------------------------------------

const TAG_LABEL: u32 = 0x71;
const TAG_LABEL_LIST: u32 = 0x72;
const TAG_CREDENTIAL_PASSWORD: u32 = 0x73;
const TAG_ALGORITHM: u32 = 0x74;
const TAG_KEY_ENC: u32 = 0x75;
const TAG_KEY_MAC: u32 = 0x76;
const TAG_CONTEXT: u32 = 0x77;
const TAG_RESPONSE: u32 = 0x78;
const TAG_VERSION: u32 = 0x79;
const TAG_TOUCH: u32 = 0x7A;
const TAG_MANAGEMENT_KEY: u32 = 0x7B;
const TAG_PUBLIC_KEY: u32 = 0x7C;
const TAG_PRIVATE_KEY: u32 = 0x7D;

// ---------------------------------------------------------------------------
// Instruction bytes
// ---------------------------------------------------------------------------

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_CALCULATE: u8 = 0x03;
const INS_GET_CHALLENGE: u8 = 0x04;
const INS_LIST: u8 = 0x05;
const INS_RESET: u8 = 0x06;
#[allow(dead_code)]
const INS_GET_VERSION: u8 = 0x07;
const INS_PUT_MANAGEMENT_KEY: u8 = 0x08;
const INS_GET_MANAGEMENT_KEY_RETRIES: u8 = 0x09;
const INS_GET_PUBLIC_KEY: u8 = 0x0A;
const INS_CHANGE_CREDENTIAL_PASSWORD: u8 = 0x0B;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of the management key in bytes.
const MANAGEMENT_KEY_LEN: usize = 16;
/// Length of the credential password in bytes.
const CREDENTIAL_PASSWORD_LEN: usize = 16;
/// Minimum length of a credential label in bytes.
const MIN_LABEL_LEN: usize = 1;
/// Maximum length of a credential label in bytes.
const MAX_LABEL_LEN: usize = 64;

/// The default management key (all zeros).
#[allow(dead_code)]
const DEFAULT_MANAGEMENT_KEY: [u8; MANAGEMENT_KEY_LEN] = [0u8; MANAGEMENT_KEY_LEN];
/// The initial retry counter value for new credentials.
const INITIAL_RETRY_COUNTER: u32 = 8;

// ---------------------------------------------------------------------------
// Algorithm
// ---------------------------------------------------------------------------

/// The cryptographic algorithm used by an HSM Auth credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    /// AES-128 Yubico authentication.
    Aes128YubicoAuthentication = 38,
    /// EC P-256 Yubico authentication.
    EcP256YubicoAuthentication = 39,
}

impl Algorithm {
    /// Convert a raw byte value to an [`Algorithm`], returning `None` for unknown values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            38 => Some(Self::Aes128YubicoAuthentication),
            39 => Some(Self::EcP256YubicoAuthentication),
            _ => None,
        }
    }

    /// Return the key length in bytes for this algorithm.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128YubicoAuthentication => 16,
            Self::EcP256YubicoAuthentication => 32,
        }
    }
}

// ---------------------------------------------------------------------------
// Credential
// ---------------------------------------------------------------------------

/// An HSM Auth credential stored on the YubiKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The human-readable label identifying this credential.
    pub label: String,
    /// The algorithm used by this credential.
    pub algorithm: Algorithm,
    /// The remaining retry counter for this credential.
    pub counter: u32,
    /// Whether touch confirmation is required to use this credential.
    pub touch_required: bool,
}

// ---------------------------------------------------------------------------
// SessionKeys
// ---------------------------------------------------------------------------

/// A set of SCP03 session keys derived from an HSM Auth calculation.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// The session encryption key (S-ENC).
    pub key_senc: [u8; 16],
    /// The session MAC key (S-MAC).
    pub key_smac: [u8; 16],
    /// The session response MAC key (S-RMAC).
    pub key_srmac: [u8; 16],
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("key_senc", &"<redacted>")
            .field("key_smac", &"<redacted>")
            .field("key_srmac", &"<redacted>")
            .finish()
    }
}

impl SessionKeys {
    /// Parse session keys from a raw APDU response.
    pub fn parse(response: &[u8]) -> Result<Self, HsmAuthError> {
        if response.len() < 48 {
            return Err(HsmAuthError::InvalidData(
                "Session key response too short".into(),
            ));
        }
        Ok(Self {
            key_senc: response[..16].try_into().unwrap(),
            key_smac: response[16..32].try_into().unwrap(),
            key_srmac: response[32..48].try_into().unwrap(),
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during HSM Auth operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HsmAuthError {
    /// The requested feature is not supported by the device.
    #[error("Not supported: {0}")]
    NotSupported(String),
    /// The provided data is invalid or malformed.
    #[error("Invalid data: {0}")]
    InvalidData(String),
    /// The PIN was incorrect; the inner value is the number of remaining attempts.
    #[error("Invalid PIN, {0} attempts remaining")]
    InvalidPin(u32),
    /// A communication error occurred with the smart card.
    #[error("Connection error: {0}")]
    Connection(SmartCardError),
}

impl From<SmartCardError> for HsmAuthError {
    fn from(e: SmartCardError) -> Self {
        match e {
            SmartCardError::ApplicationNotAvailable => {
                HsmAuthError::NotSupported("Application not available".into())
            }
            SmartCardError::NotSupported(msg) => HsmAuthError::NotSupported(msg),
            SmartCardError::InvalidData(msg) => HsmAuthError::InvalidData(msg),
            other => HsmAuthError::Connection(other),
        }
    }
}

impl From<crate::tlv::TlvError> for HsmAuthError {
    fn from(e: crate::tlv::TlvError) -> Self {
        HsmAuthError::InvalidData(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_label(label: &str) -> Result<Vec<u8>, HsmAuthError> {
    let bytes = label.as_bytes();
    if bytes.len() < MIN_LABEL_LEN || bytes.len() > MAX_LABEL_LEN {
        return Err(HsmAuthError::InvalidData(format!(
            "Label must be between {MIN_LABEL_LEN} and {MAX_LABEL_LEN} bytes long"
        )));
    }
    Ok(bytes.to_vec())
}

fn parse_credential_password(password: &[u8]) -> Result<[u8; 16], HsmAuthError> {
    password.try_into().map_err(|_| {
        HsmAuthError::InvalidData(format!(
            "Credential password must be {CREDENTIAL_PASSWORD_LEN} bytes long"
        ))
    })
}

/// Convert a string password into a 16-byte credential password,
/// padding with zeros or truncating as needed.
pub fn credential_password_from_str(password: &str) -> [u8; 16] {
    let mut pw = [0u8; 16];
    let bytes = password.as_bytes();
    let len = bytes.len().min(16);
    pw[..len].copy_from_slice(&bytes[..len]);
    pw
}

fn password_to_key(password: &str) -> ([u8; 16], [u8; 16]) {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), b"Yubico", 10000, &mut key);
    let key_enc: [u8; 16] = key[..16].try_into().unwrap();
    let key_mac: [u8; 16] = key[16..].try_into().unwrap();
    key.zeroize();
    (key_enc, key_mac)
}

fn retries_from_sw(sw: u16) -> Option<u32> {
    if sw & 0xFFF0 == 0x63C0 {
        Some((sw & !0xFFF0) as u32)
    } else {
        None
    }
}

fn require_version(version: Version, required: Version, feature: &str) -> Result<(), HsmAuthError> {
    crate::core::require_version(version, required, feature).map_err(HsmAuthError::NotSupported)
}

fn validate_management_key(key: &[u8]) -> Result<(), HsmAuthError> {
    if key.len() != MANAGEMENT_KEY_LEN {
        return Err(HsmAuthError::InvalidData(format!(
            "Management key must be {MANAGEMENT_KEY_LEN} bytes long"
        )));
    }
    Ok(())
}

/// Map APDU errors to InvalidPin where applicable, otherwise propagate.
fn map_pin_error(e: SmartCardError) -> HsmAuthError {
    if let Some(sw) = e.sw()
        && let Some(retries) = retries_from_sw(sw)
    {
        return HsmAuthError::InvalidPin(retries);
    }
    HsmAuthError::Connection(e)
}

// ---------------------------------------------------------------------------
// HsmAuthSession
// ---------------------------------------------------------------------------

/// A session for interacting with the YubiHSM Auth application on a YubiKey.
pub struct HsmAuthSession<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
}

impl<C: SmartCardConnection> HsmAuthSession<C> {
    /// Open an HSM Auth session on the given connection.
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new(connection: C) -> Result<Self, (HsmAuthError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let select_response = match protocol.select(Aid::HSMAUTH) {
            Ok(v) => v,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        Self::init(protocol, &select_response)
    }

    /// Open an HSM Auth session with SCP (Secure Channel Protocol).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, (HsmAuthError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let select_response = match protocol.select(Aid::HSMAUTH) {
            Ok(v) => v,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        if let Err(e) = protocol.init_scp(scp_key_params) {
            return Err((e.into(), protocol.into_connection()));
        }
        Self::init(protocol, &select_response)
    }

    fn init(
        mut protocol: SmartCardProtocol<C>,
        select_response: &[u8],
    ) -> Result<Self, (HsmAuthError, C)> {
        log::debug!("Opening HsmAuthSession");
        // Parse version from TAG_VERSION in select response
        let entries = match parse_tlv_list(select_response) {
            Ok(v) => v,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        let version_data = match entries
            .iter()
            .find(|(tag, _)| *tag == TAG_VERSION)
            .map(|(_, v)| v.as_slice())
        {
            Some(v) => v,
            None => {
                return Err((
                    HsmAuthError::InvalidData("Missing version tag in SELECT response".into()),
                    protocol.into_connection(),
                ));
            }
        };
        let version = patch_version(Version::from_bytes(version_data));
        protocol.configure(version);

        Ok(Self { protocol, version })
    }

    /// Return the firmware version of the YubiKey.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get a mutable reference to the underlying protocol.
    pub fn protocol_mut(&mut self) -> &mut SmartCardProtocol<C> {
        &mut self.protocol
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        self.protocol.into_connection()
    }

    /// Reset the HSM Auth application to its factory state.
    pub fn reset(&mut self) -> Result<(), HsmAuthError> {
        self.protocol.send_apdu(0, INS_RESET, 0xDE, 0xAD, &[])?;
        Ok(())
    }

    /// List all credentials stored on the YubiKey.
    pub fn list_credentials(&mut self) -> Result<Vec<Credential>, HsmAuthError> {
        let response = self.protocol.send_apdu(0, INS_LIST, 0, 0, &[])?;
        let entries = parse_tlv_list(&response)?;

        let mut creds = Vec::new();
        for (tag, value) in &entries {
            if *tag != TAG_LABEL_LIST {
                continue;
            }
            if value.len() < 3 {
                return Err(HsmAuthError::InvalidData(
                    "Credential entry too short".into(),
                ));
            }
            let algorithm = Algorithm::from_u8(value[0]).ok_or_else(|| {
                HsmAuthError::InvalidData(format!("Unknown algorithm: {}", value[0]))
            })?;
            let touch_required = value[1] != 0;
            // Label is bytes [2..len-1], counter is last byte
            let label_bytes = &value[2..value.len() - 1];
            let counter = *value.last().unwrap() as u32;
            let label = String::from_utf8(label_bytes.to_vec())
                .map_err(|e| HsmAuthError::InvalidData(e.to_string()))?;
            creds.push(Credential {
                label,
                algorithm,
                counter,
                touch_required,
            });
        }
        Ok(creds)
    }

    fn put_credential(
        &mut self,
        management_key: &[u8],
        label: &str,
        key: &[u8],
        algorithm: Algorithm,
        credential_password: &[u8],
        touch_required: bool,
    ) -> Result<Credential, HsmAuthError> {
        validate_management_key(management_key)?;
        let parsed_label = parse_label(label)?;
        let parsed_password = parse_credential_password(credential_password)?;

        let mut data = Vec::new();
        data.extend_from_slice(&tlv_encode(TAG_MANAGEMENT_KEY, management_key));
        data.extend_from_slice(&tlv_encode(TAG_LABEL, &parsed_label));
        data.extend_from_slice(&tlv_encode(TAG_ALGORITHM, &[algorithm as u8]));

        match algorithm {
            Algorithm::Aes128YubicoAuthentication => {
                data.extend_from_slice(&tlv_encode(TAG_KEY_ENC, &key[..16]));
                data.extend_from_slice(&tlv_encode(TAG_KEY_MAC, &key[16..]));
            }
            Algorithm::EcP256YubicoAuthentication => {
                data.extend_from_slice(&tlv_encode(TAG_PRIVATE_KEY, key));
            }
        }

        data.extend_from_slice(&tlv_encode(TAG_CREDENTIAL_PASSWORD, &parsed_password));
        data.extend_from_slice(&tlv_encode(
            TAG_TOUCH,
            &[if touch_required { 1 } else { 0 }],
        ));

        self.protocol
            .send_apdu(0, INS_PUT, 0, 0, &data)
            .map_err(map_pin_error)?;

        Ok(Credential {
            label: label.to_string(),
            algorithm,
            counter: INITIAL_RETRY_COUNTER,
            touch_required,
        })
    }

    /// Store an AES-128 symmetric credential with explicit encryption and MAC keys.
    pub fn put_credential_symmetric(
        &mut self,
        management_key: &[u8],
        label: &str,
        key_enc: &[u8],
        key_mac: &[u8],
        credential_password: &[u8],
        touch_required: bool,
    ) -> Result<Credential, HsmAuthError> {
        let aes_key_len = Algorithm::Aes128YubicoAuthentication.key_len();
        if key_enc.len() != aes_key_len || key_mac.len() != aes_key_len {
            return Err(HsmAuthError::InvalidData(format!(
                "Encryption and MAC key must be {aes_key_len} bytes long"
            )));
        }

        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(key_enc);
        key.extend_from_slice(key_mac);

        self.put_credential(
            management_key,
            label,
            &key,
            Algorithm::Aes128YubicoAuthentication,
            credential_password,
            touch_required,
        )
    }

    /// Store an AES-128 symmetric credential with keys derived from a password.
    pub fn put_credential_derived(
        &mut self,
        management_key: &[u8],
        label: &str,
        derivation_password: &str,
        credential_password: &[u8],
        touch_required: bool,
    ) -> Result<Credential, HsmAuthError> {
        let (key_enc, key_mac) = password_to_key(derivation_password);
        self.put_credential_symmetric(
            management_key,
            label,
            &key_enc,
            &key_mac,
            credential_password,
            touch_required,
        )
    }

    /// Store an EC P-256 asymmetric credential from an existing private key.
    ///
    /// Requires firmware version 5.6.0 or later.
    pub fn put_credential_asymmetric(
        &mut self,
        management_key: &[u8],
        label: &str,
        private_key: &p256::SecretKey,
        credential_password: &[u8],
        touch_required: bool,
    ) -> Result<Credential, HsmAuthError> {
        require_version(self.version, Version(5, 6, 0), "put_credential_asymmetric")?;
        let key_bytes = private_key.to_bytes();
        self.put_credential(
            management_key,
            label,
            key_bytes.as_slice(),
            Algorithm::EcP256YubicoAuthentication,
            credential_password,
            touch_required,
        )
    }

    /// Generate an EC P-256 asymmetric credential on the device.
    ///
    /// The private key is generated on-device and never leaves the YubiKey.
    /// Requires firmware version 5.6.0 or later.
    pub fn generate_credential_asymmetric(
        &mut self,
        management_key: &[u8],
        label: &str,
        credential_password: &[u8],
        touch_required: bool,
    ) -> Result<Credential, HsmAuthError> {
        require_version(
            self.version,
            Version(5, 6, 0),
            "generate_credential_asymmetric",
        )?;
        self.put_credential(
            management_key,
            label,
            &[], // Empty key triggers on-device generation
            Algorithm::EcP256YubicoAuthentication,
            credential_password,
            touch_required,
        )
    }

    /// Retrieve the public key associated with an asymmetric credential.
    ///
    /// Requires firmware version 5.6.0 or later.
    pub fn get_public_key(&mut self, label: &str) -> Result<p256::PublicKey, HsmAuthError> {
        require_version(self.version, Version(5, 6, 0), "get_public_key")?;
        let data = tlv_encode(TAG_LABEL, &parse_label(label)?);
        let response = self
            .protocol
            .send_apdu(0, INS_GET_PUBLIC_KEY, 0, 0, &data)?;

        parse_p256_public_key(&response)
    }

    /// Delete a credential from the YubiKey.
    pub fn delete_credential(
        &mut self,
        management_key: &[u8],
        label: &str,
    ) -> Result<(), HsmAuthError> {
        validate_management_key(management_key)?;
        let mut data = Vec::new();
        data.extend_from_slice(&tlv_encode(TAG_MANAGEMENT_KEY, management_key));
        data.extend_from_slice(&tlv_encode(TAG_LABEL, &parse_label(label)?));

        self.protocol
            .send_apdu(0, INS_DELETE, 0, 0, &data)
            .map_err(map_pin_error)?;
        Ok(())
    }

    fn change_credential_password_inner(
        &mut self,
        data: &[u8],
        use_management_key: bool,
    ) -> Result<(), HsmAuthError> {
        require_version(self.version, Version(5, 8, 0), "change_credential_password")?;
        let p1 = if use_management_key { 1 } else { 0 };
        self.protocol
            .send_apdu(0, INS_CHANGE_CREDENTIAL_PASSWORD, p1, 0, data)
            .map_err(map_pin_error)?;
        Ok(())
    }

    /// Change the password protecting a credential, authenticating with the current password.
    ///
    /// Requires firmware version 5.8.0 or later.
    pub fn change_credential_password(
        &mut self,
        label: &str,
        credential_password: &[u8],
        new_credential_password: &[u8],
    ) -> Result<(), HsmAuthError> {
        let parsed_pw = parse_credential_password(credential_password)?;
        let parsed_new_pw = parse_credential_password(new_credential_password)?;

        let mut data = Vec::new();
        data.extend_from_slice(&tlv_encode(TAG_LABEL, &parse_label(label)?));
        data.extend_from_slice(&tlv_encode(TAG_CREDENTIAL_PASSWORD, &parsed_pw));
        data.extend_from_slice(&tlv_encode(TAG_CREDENTIAL_PASSWORD, &parsed_new_pw));

        self.change_credential_password_inner(&data, false)
    }

    /// Change the password protecting a credential, authenticating with the management key.
    ///
    /// Requires firmware version 5.8.0 or later.
    pub fn change_credential_password_admin(
        &mut self,
        management_key: &[u8],
        label: &str,
        new_credential_password: &[u8],
    ) -> Result<(), HsmAuthError> {
        validate_management_key(management_key)?;
        let parsed_new_pw = parse_credential_password(new_credential_password)?;

        let mut data = Vec::new();
        data.extend_from_slice(&tlv_encode(TAG_LABEL, &parse_label(label)?));
        data.extend_from_slice(&tlv_encode(TAG_MANAGEMENT_KEY, management_key));
        data.extend_from_slice(&tlv_encode(TAG_CREDENTIAL_PASSWORD, &parsed_new_pw));

        self.change_credential_password_inner(&data, true)
    }

    /// Replace the management key with a new one.
    pub fn put_management_key(
        &mut self,
        management_key: &[u8],
        new_management_key: &[u8],
    ) -> Result<(), HsmAuthError> {
        validate_management_key(management_key)?;
        validate_management_key(new_management_key)?;

        let mut data = Vec::new();
        data.extend_from_slice(&tlv_encode(TAG_MANAGEMENT_KEY, management_key));
        data.extend_from_slice(&tlv_encode(TAG_MANAGEMENT_KEY, new_management_key));

        self.protocol
            .send_apdu(0, INS_PUT_MANAGEMENT_KEY, 0, 0, &data)
            .map_err(map_pin_error)?;
        Ok(())
    }

    /// Get the number of remaining retry attempts for the management key.
    pub fn get_management_key_retries(&mut self) -> Result<u32, HsmAuthError> {
        let response = self
            .protocol
            .send_apdu(0, INS_GET_MANAGEMENT_KEY_RETRIES, 0, 0, &[])?;
        if response.is_empty() {
            return Err(HsmAuthError::InvalidData(
                "Empty response for management key retries".into(),
            ));
        }
        // Decode big-endian integer
        let mut value: u32 = 0;
        for &b in &response {
            value = (value << 8) | b as u32;
        }
        Ok(value)
    }

    fn calculate_session_keys_inner(
        &mut self,
        label: &str,
        context: &[u8],
        credential_password: &[u8],
        card_crypto: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, HsmAuthError> {
        let parsed_pw = parse_credential_password(credential_password)?;

        let mut data = Vec::new();
        data.extend_from_slice(&tlv_encode(TAG_LABEL, &parse_label(label)?));
        data.extend_from_slice(&tlv_encode(TAG_CONTEXT, context));

        if let Some(pk) = public_key {
            data.extend_from_slice(&tlv_encode(TAG_PUBLIC_KEY, pk));
        }

        if let Some(cc) = card_crypto {
            data.extend_from_slice(&tlv_encode(TAG_RESPONSE, cc));
        }

        data.extend_from_slice(&tlv_encode(TAG_CREDENTIAL_PASSWORD, &parsed_pw));

        let response = self
            .protocol
            .send_apdu(0, INS_CALCULATE, 0, 0, &data)
            .map_err(map_pin_error)?;
        Ok(response)
    }

    /// Calculate SCP03 session keys using a symmetric (AES-128) credential.
    pub fn calculate_session_keys_symmetric(
        &mut self,
        label: &str,
        context: &[u8],
        credential_password: &[u8],
        card_crypto: Option<&[u8]>,
    ) -> Result<SessionKeys, HsmAuthError> {
        let response = self.calculate_session_keys_inner(
            label,
            context,
            credential_password,
            card_crypto,
            None,
        )?;
        SessionKeys::parse(&response)
    }

    /// Calculate SCP03 session keys using an asymmetric (EC P-256) credential.
    ///
    /// Requires firmware version 5.6.0 or later.
    pub fn calculate_session_keys_asymmetric(
        &mut self,
        label: &str,
        context: &[u8],
        peer_public_key: &p256::PublicKey,
        credential_password: &[u8],
        card_crypto: &[u8],
    ) -> Result<SessionKeys, HsmAuthError> {
        require_version(
            self.version,
            Version(5, 6, 0),
            "calculate_session_keys_asymmetric",
        )?;

        // Encode as SEC1 uncompressed point (0x04 || x || y)
        let encoded = p256::EncodedPoint::from(peer_public_key);
        let public_key_data = encoded.as_bytes().to_vec();

        let response = self.calculate_session_keys_inner(
            label,
            context,
            credential_password,
            Some(card_crypto),
            Some(&public_key_data),
        )?;
        SessionKeys::parse(&response)
    }

    /// Get a challenge from the YubiKey for an asymmetric credential.
    ///
    /// Requires firmware version 5.6.0 or later.
    pub fn get_challenge(
        &mut self,
        label: &str,
        credential_password: Option<&[u8]>,
    ) -> Result<Vec<u8>, HsmAuthError> {
        require_version(self.version, Version(5, 6, 0), "get_challenge")?;

        let mut data = tlv_encode(TAG_LABEL, &parse_label(label)?);

        if let Some(pw) = credential_password
            && (self.version >= Version(5, 7, 1) || self.version.0 == 0)
        {
            let parsed_pw = parse_credential_password(pw)?;
            data.extend_from_slice(&tlv_encode(TAG_CREDENTIAL_PASSWORD, &parsed_pw));
        }

        let response = self.protocol.send_apdu(0, INS_GET_CHALLENGE, 0, 0, &data)?;
        Ok(response)
    }
}

fn parse_p256_public_key(data: &[u8]) -> Result<p256::PublicKey, HsmAuthError> {
    use elliptic_curve::sec1::FromEncodedPoint;

    // Try parsing as SEC1 (with 0x04 prefix) or raw 64-byte coordinates
    let encoded = if data.len() == 64 {
        let mut buf = Vec::with_capacity(65);
        buf.push(0x04);
        buf.extend_from_slice(data);
        buf
    } else {
        data.to_vec()
    };

    let point = p256::EncodedPoint::from_bytes(&encoded)
        .map_err(|e| HsmAuthError::InvalidData(format!("Invalid EC point: {e}")))?;

    Option::from(p256::PublicKey::from_encoded_point(&point))
        .ok_or_else(|| HsmAuthError::InvalidData("Invalid EC public key".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_u8() {
        assert_eq!(
            Algorithm::from_u8(38),
            Some(Algorithm::Aes128YubicoAuthentication)
        );
        assert_eq!(
            Algorithm::from_u8(39),
            Some(Algorithm::EcP256YubicoAuthentication)
        );
        assert_eq!(Algorithm::from_u8(0), None);
    }

    #[test]
    fn test_algorithm_key_len() {
        assert_eq!(Algorithm::Aes128YubicoAuthentication.key_len(), 16);
        assert_eq!(Algorithm::EcP256YubicoAuthentication.key_len(), 32);
    }

    #[test]
    fn test_parse_label() {
        assert!(parse_label("").is_err());
        assert!(parse_label("a").is_ok());
        assert!(parse_label(&"a".repeat(64)).is_ok());
        assert!(parse_label(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_parse_credential_password() {
        assert!(parse_credential_password(&[0u8; 16]).is_ok());
        assert!(parse_credential_password(&[0u8; 15]).is_err());
        assert!(parse_credential_password(&[0u8; 17]).is_err());
    }

    #[test]
    fn test_credential_password_from_str() {
        let pw = credential_password_from_str("hello");
        assert_eq!(pw.len(), 16);
        assert_eq!(&pw[..5], b"hello");
        assert_eq!(&pw[5..], &[0u8; 11]);
    }

    #[test]
    fn test_password_to_key() {
        let (enc, mac) = password_to_key("password");
        assert_eq!(enc.len(), 16);
        assert_eq!(mac.len(), 16);
    }

    #[test]
    fn test_retries_from_sw() {
        assert_eq!(retries_from_sw(0x63C5), Some(5));
        assert_eq!(retries_from_sw(0x63C0), Some(0));
        assert_eq!(retries_from_sw(0x9000), None);
    }

    #[test]
    fn test_session_keys_parse() {
        let data = vec![0u8; 48];
        let keys = SessionKeys::parse(&data).unwrap();
        assert_eq!(keys.key_senc.len(), 16);
        assert_eq!(keys.key_smac.len(), 16);
        assert_eq!(keys.key_srmac.len(), 16);

        assert!(SessionKeys::parse(&[0u8; 47]).is_err());
    }

    #[test]
    fn test_validate_management_key() {
        assert!(validate_management_key(&[0u8; 16]).is_ok());
        assert!(validate_management_key(&[0u8; 15]).is_err());
    }

    #[test]
    fn test_parse_p256_public_key_sec1() {
        // Generate a key and round-trip it
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        let encoded = p256::EncodedPoint::from(public);
        let bytes = encoded.as_bytes();

        let parsed = parse_p256_public_key(bytes).unwrap();
        assert_eq!(parsed, public);
    }

    #[test]
    fn test_parse_p256_public_key_raw_64() {
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        let encoded = p256::EncodedPoint::from(public);
        // Strip the 0x04 prefix
        let raw = &encoded.as_bytes()[1..];
        assert_eq!(raw.len(), 64);

        let parsed = parse_p256_public_key(raw).unwrap();
        assert_eq!(parsed, public);
    }
}
