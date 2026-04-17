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

//! YubiOTP application protocol.
//!
//! Provides configuration and challenge-response for the two OTP slots on a
//! YubiKey, accessible over both SmartCard (CCID) and HID OTP transports.
//!
//! The main entry point is [`YubiOtpSession`](crate::yubiotp::YubiOtpSession), which can be opened over
//! either transport. Use [`SlotConfiguration`](crate::yubiotp::SlotConfiguration) to program OTP slot behavior.
//!
//! # Example
//!
//! ```no_run
//! use yubikit::device::list_devices;
//! use yubikit::management::UsbInterface;
//! use yubikit::yubiotp::{YubiOtpSession, Slot};
//!
//! // Over SmartCard (CCID)
//! let devices = list_devices(UsbInterface::CCID)?;
//! let dev = devices.first().expect("no YubiKey found");
//! let conn = dev.open_smartcard()?;
//! let mut session = YubiOtpSession::new(conn).map_err(|(e, _)| e)?;
//!
//! let status = session.get_config_state()?;
//! println!("Slot 1 configured: {}", status.is_configured(Slot::One)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use sha1::{Digest, Sha1};
use thiserror::Error;

use crate::core::Version;
use crate::core::patch_version;
use std::fmt;

use crate::core::Connection;
use crate::otp::OtpError;
use crate::otp::calculate_crc;
#[cfg(test)]
use crate::otp::check_crc;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol};

/// Re-export of OTP transport types.
pub use crate::otp::{OtpConnection, OtpProtocol};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Session-level error for YubiOTP operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum YubiOtpError<E: fmt::Debug + fmt::Display = std::convert::Infallible> {
    /// The operation is not supported by the device.
    #[error("Not supported: {0}")]
    NotSupported(String),
    /// The provided data is invalid or malformed.
    #[error("Invalid data: {0}")]
    InvalidData(String),
    /// A connection-level error occurred.
    #[error("Connection error: {0}")]
    Connection(E),
}

impl YubiOtpError {
    /// Widen an infallible error into any concrete connection-error type.
    fn widen<E: fmt::Debug + fmt::Display>(self) -> YubiOtpError<E> {
        match self {
            YubiOtpError::NotSupported(msg) => YubiOtpError::NotSupported(msg),
            YubiOtpError::InvalidData(msg) => YubiOtpError::InvalidData(msg),
            YubiOtpError::Connection(e) => match e {},
        }
    }
}

impl From<SmartCardError> for YubiOtpError<SmartCardError> {
    fn from(e: SmartCardError) -> Self {
        match e {
            SmartCardError::ApplicationNotAvailable => {
                YubiOtpError::NotSupported("Application not available".into())
            }
            SmartCardError::NotSupported(msg) => YubiOtpError::NotSupported(msg),
            SmartCardError::InvalidData(msg) => YubiOtpError::InvalidData(msg),
            other => YubiOtpError::Connection(other),
        }
    }
}

impl From<OtpError> for YubiOtpError<OtpError> {
    fn from(e: OtpError) -> Self {
        match e {
            OtpError::BadResponse(msg) => YubiOtpError::InvalidData(msg),
            other => YubiOtpError::Connection(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum size of the fixed (public identity) field in bytes.
pub const FIXED_SIZE: usize = 16;
/// Size of the private identity (UID) field in bytes.
pub const UID_SIZE: usize = 6;
/// Size of the AES key in bytes.
pub const KEY_SIZE: usize = 16;
/// Size of the access code in bytes.
pub const ACC_CODE_SIZE: usize = 6;

/// Size of a serialized slot configuration in bytes.
const CONFIG_SIZE: usize = 52;
/// Maximum size of NDEF data payload in bytes.
const NDEF_DATA_SIZE: usize = 54;
/// Size of the HMAC-SHA1 key in bytes.
const HMAC_KEY_SIZE: usize = 20;
/// Maximum HMAC challenge size in bytes.
const HMAC_CHALLENGE_SIZE: usize = 64;
/// Size of the HMAC-SHA1 response in bytes.
const HMAC_RESPONSE_SIZE: usize = 20;
/// Size of the keyboard scan codes map.
const SCAN_CODES_SIZE: usize = FIXED_SIZE + UID_SIZE + KEY_SIZE; // 38

const SHA1_BLOCK_SIZE: usize = 64;

const INS_CONFIG: u8 = 0x01;
const INS_YK2_STATUS: u8 = 0x03;

/// Default NDEF URI programmed on new YubiKeys.
const DEFAULT_NDEF_URI: &str = "https://my.yubico.com/yk/#";

const NDEF_URL_PREFIXES: &[&str] = &[
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    "tel:",
    "mailto:",
    "ftp://anonymous:anonymous@",
    "ftp://ftp.",
    "ftps://",
    "sftp://",
    "smb://",
    "nfs://",
    "ftp://",
    "dav://",
    "news:",
    "telnet://",
    "imap:",
    "rtsp://",
    "urn:",
    "pop:",
    "sip:",
    "sips:",
    "tftp:",
    "btspp://",
    "btl2cap://",
    "btgoep://",
    "tcpobex://",
    "irdaobex://",
    "file://",
    "urn:epc:id:",
    "urn:epc:tag:",
    "urn:epc:pat:",
    "urn:epc:raw:",
    "urn:epc:",
    "urn:nfc:",
];

// ---------------------------------------------------------------------------
// Slot / ConfigSlot enums
// ---------------------------------------------------------------------------

/// OTP slot identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Slot {
    /// OTP slot 1.
    One = 1,
    /// OTP slot 2.
    Two = 2,
}

impl Slot {
    /// Returns `one` for [`Slot::One`], `two` for [`Slot::Two`].
    pub fn map<T>(self, one: T, two: T) -> T {
        match self {
            Slot::One => one,
            Slot::Two => two,
        }
    }
}

/// Low-level configuration slot numbers sent to the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfigSlot {
    /// Write configuration for slot 1.
    Config1 = 0x01,
    /// Write NAV configuration.
    Nav = 0x02,
    /// Write configuration for slot 2.
    Config2 = 0x03,
    /// Update slot 1 without overwriting secrets.
    Update1 = 0x04,
    /// Update slot 2 without overwriting secrets.
    Update2 = 0x05,
    /// Swap the two slot configurations.
    Swap = 0x06,
    /// Write NDEF record for slot 1.
    Ndef1 = 0x08,
    /// Write NDEF record for slot 2.
    Ndef2 = 0x09,
    /// Read the device serial number.
    DeviceSerial = 0x10,
    /// Read or write device configuration.
    DeviceConfig = 0x11,
    /// Write the keyboard scan-code map.
    ScanMap = 0x12,
    /// Read YubiKey 4+ capability flags.
    Yk4Capabilities = 0x13,
    /// Set device info on YubiKey 4+.
    Yk4SetDeviceInfo = 0x15,
    /// Challenge-response with Yubico OTP for slot 1.
    ChalOtp1 = 0x20,
    /// Challenge-response with Yubico OTP for slot 2.
    ChalOtp2 = 0x28,
    /// Challenge-response with HMAC-SHA1 for slot 1.
    ChalHmac1 = 0x30,
    /// Challenge-response with HMAC-SHA1 for slot 2.
    ChalHmac2 = 0x38,
}

// ---------------------------------------------------------------------------
// Bitflag types
// ---------------------------------------------------------------------------

/// Ticket flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TktFlag(pub u8);

impl TktFlag {
    /// Send tab keystroke before OTP.
    pub const TAB_FIRST: Self = Self(0x01);
    /// Append tab after first part.
    pub const APPEND_TAB1: Self = Self(0x02);
    /// Append tab after second part.
    pub const APPEND_TAB2: Self = Self(0x04);
    /// Append 0.5s delay after first part.
    pub const APPEND_DELAY1: Self = Self(0x08);
    /// Append 0.5s delay after second part.
    pub const APPEND_DELAY2: Self = Self(0x10);
    /// Append carriage return after OTP.
    pub const APPEND_CR: Self = Self(0x20);
    /// Slot is configured for OATH-HOTP.
    pub const OATH_HOTP: Self = Self(0x40);
    /// Slot is configured for challenge-response.
    pub const CHAL_RESP: Self = Self(0x40);
    /// Protect slot 2 from accidental overwrite.
    pub const PROTECT_CFG2: Self = Self(0x80);
}

impl std::ops::BitOr for TktFlag {
    type Output = u8;
    fn bitor(self, rhs: Self) -> u8 {
        self.0 | rhs.0
    }
}

/// Configuration flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgFlag(pub u8);

impl CfgFlag {
    /// Send reference string (0x00–0x0F) before OTP.
    pub const SEND_REF: Self = Self(0x01);
    /// Send truncated ticket for static password.
    pub const SHORT_TICKET: Self = Self(0x02);
    /// Add 10 ms delay between keystrokes.
    pub const PACING_10MS: Self = Self(0x04);
    /// Add 20 ms delay between keystrokes.
    pub const PACING_20MS: Self = Self(0x08);
    /// Include upper-case and digits in static password.
    pub const STRONG_PW1: Self = Self(0x10);
    /// Generate a static ticket (no time/counter component).
    pub const STATIC_TICKET: Self = Self(0x20);
    /// Include special characters in static password.
    pub const STRONG_PW2: Self = Self(0x40);
    /// Allow configuration update without access code.
    pub const MAN_UPDATE: Self = Self(0x80);

    // OATH aliases
    /// Use 8-digit OATH-HOTP output.
    pub const OATH_HOTP8: Self = Self(0x02);
    /// Encode first byte of token ID as ModHex.
    pub const OATH_FIXED_MODHEX1: Self = Self(0x10);
    /// Encode second byte of token ID as ModHex.
    pub const OATH_FIXED_MODHEX2: Self = Self(0x40);
    /// Encode both bytes of token ID as ModHex.
    pub const OATH_FIXED_MODHEX: Self = Self(0x50);
    /// Mask for OATH fixed ModHex flags.
    pub const OATH_FIXED_MASK: Self = Self(0x50);

    // Challenge-response aliases
    /// Challenge-response using Yubico OTP algorithm.
    pub const CHAL_YUBICO: Self = Self(0x20);
    /// Challenge-response using HMAC-SHA1.
    pub const CHAL_HMAC: Self = Self(0x22);
    /// Accept HMAC challenges shorter than 64 bytes.
    pub const HMAC_LT64: Self = Self(0x04);
    /// Require button press for challenge-response.
    pub const CHAL_BTN_TRIG: Self = Self(0x08);
}

impl std::ops::BitOr for CfgFlag {
    type Output = u8;
    fn bitor(self, rhs: Self) -> u8 {
        self.0 | rhs.0
    }
}

/// Extended flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtFlag(pub u8);

impl ExtFlag {
    /// Serial number visible via button sequence.
    pub const SERIAL_BTN_VISIBLE: Self = Self(0x01);
    /// Serial number visible via USB descriptor.
    pub const SERIAL_USB_VISIBLE: Self = Self(0x02);
    /// Serial number readable via API call.
    pub const SERIAL_API_VISIBLE: Self = Self(0x04);
    /// Use numeric keypad for digit output.
    pub const USE_NUMERIC_KEYPAD: Self = Self(0x08);
    /// Faster triggering (shorter press required).
    pub const FAST_TRIG: Self = Self(0x10);
    /// Allow slot configuration to be updated.
    pub const ALLOW_UPDATE: Self = Self(0x20);
    /// Slot is dormant (disabled until re-enabled).
    pub const DORMANT: Self = Self(0x40);
    /// Invert the LED behavior.
    pub const LED_INV: Self = Self(0x80);
}

impl std::ops::BitOr for ExtFlag {
    type Output = u8;
    fn bitor(self, rhs: Self) -> u8 {
        self.0 | rhs.0
    }
}

// Flag masks valid for update operations
const TKTFLAG_UPDATE_MASK: u8 = TktFlag::TAB_FIRST.0
    | TktFlag::APPEND_TAB1.0
    | TktFlag::APPEND_TAB2.0
    | TktFlag::APPEND_DELAY1.0
    | TktFlag::APPEND_DELAY2.0
    | TktFlag::APPEND_CR.0;

const CFGFLAG_UPDATE_MASK: u8 = CfgFlag::PACING_10MS.0 | CfgFlag::PACING_20MS.0;

// ---------------------------------------------------------------------------
// NdefType
// ---------------------------------------------------------------------------

/// NDEF record type for NFC tap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NdefType {
    /// NDEF Text record.
    Text = b'T',
    /// NDEF URI record.
    Uri = b'U',
}

// ---------------------------------------------------------------------------
// CfgState / ConfigState
// ---------------------------------------------------------------------------

/// Configuration state bitflags from the status response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgState(pub u8);

impl CfgState {
    /// Slot 1 has a valid configuration.
    pub const SLOT1_VALID: Self = Self(0x01);
    /// Slot 2 has a valid configuration.
    pub const SLOT2_VALID: Self = Self(0x02);
    /// Slot 1 requires touch to trigger.
    pub const SLOT1_TOUCH: Self = Self(0x04);
    /// Slot 2 requires touch to trigger.
    pub const SLOT2_TOUCH: Self = Self(0x08);
    /// LED behavior is inverted.
    pub const LED_INV: Self = Self(0x10);

    const ALL_MASK: u8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;
}

/// Parsed configuration state of the YubiOTP application.
#[derive(Debug, Clone)]
pub struct ConfigState {
    /// Firmware version of the YubiKey.
    pub version: Version,
    /// Raw configuration state bitflags.
    pub flags: u8,
}

impl ConfigState {
    /// Create a new [`ConfigState`] from a firmware version and raw touch-level word.
    pub fn new(version: Version, touch_level: u16) -> Self {
        Self {
            version,
            flags: CfgState::ALL_MASK & (touch_level as u8),
        }
    }

    /// Check if the given slot is programmed.
    pub fn is_configured(&self, slot: Slot) -> Result<bool, YubiOtpError> {
        require_version(self.version, Version(2, 1, 0), "is_configured")?;
        let flag = slot.map(CfgState::SLOT1_VALID.0, CfgState::SLOT2_VALID.0);
        Ok(self.flags & flag != 0)
    }

    /// Check if the given slot is triggered by touch (requires YubiKey 3+).
    pub fn is_touch_triggered(&self, slot: Slot) -> Result<bool, YubiOtpError> {
        require_version(self.version, Version(3, 0, 0), "is_touch_triggered")?;
        let flag = slot.map(CfgState::SLOT1_TOUCH.0, CfgState::SLOT2_TOUCH.0);
        Ok(self.flags & flag != 0)
    }

    /// Check if the LED behavior is inverted.
    pub fn is_led_inverted(&self) -> bool {
        self.flags & CfgState::LED_INV.0 != 0
    }
}

fn require_version(version: Version, required: Version, feature: &str) -> Result<(), YubiOtpError> {
    crate::core::require_version(version, required, feature).map_err(YubiOtpError::NotSupported)
}

// ---------------------------------------------------------------------------
// Helper: shorten HMAC key
// ---------------------------------------------------------------------------

fn shorten_hmac_key(key: &[u8]) -> Result<Vec<u8>, YubiOtpError> {
    if key.len() > SHA1_BLOCK_SIZE {
        let mut hasher = Sha1::new();
        hasher.update(key);
        Ok(hasher.finalize().to_vec())
    } else if key.len() > HMAC_KEY_SIZE {
        Err(YubiOtpError::NotSupported(format!(
            "Key lengths > {HMAC_KEY_SIZE} bytes not supported"
        )))
    } else {
        Ok(key.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Config building helpers
// ---------------------------------------------------------------------------

/// Build a 52-byte configuration block with CRC.
fn build_config(
    fixed: &[u8],
    uid: &[u8],
    key: &[u8],
    ext: u8,
    tkt: u8,
    cfg: u8,
    acc_code: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CONFIG_SIZE);

    // fixed (padded to FIXED_SIZE)
    buf.extend_from_slice(fixed);
    buf.resize(FIXED_SIZE, 0);

    // uid (UID_SIZE)
    buf.extend_from_slice(uid);

    // key (KEY_SIZE)
    buf.extend_from_slice(key);

    // acc_code (ACC_CODE_SIZE)
    match acc_code {
        Some(ac) => buf.extend_from_slice(ac),
        None => buf.extend_from_slice(&[0u8; ACC_CODE_SIZE]),
    }

    // fixed_len, ext, tkt, cfg (big-endian style, 4 bytes)
    buf.push(fixed.len() as u8);
    buf.push(ext);
    buf.push(tkt);
    buf.push(cfg);

    // RFU (2 bytes)
    buf.extend_from_slice(&[0u8; 2]);

    // CRC (2 bytes, little-endian)
    let crc = !calculate_crc(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    debug_assert_eq!(buf.len(), CONFIG_SIZE);
    buf
}

/// Build a config for an update operation (restricted flags).
#[allow(dead_code)]
fn build_update(
    ext: u8,
    tkt: u8,
    cfg: u8,
    acc_code: Option<&[u8]>,
) -> Result<Vec<u8>, YubiOtpError> {
    // All ext flags are valid for update (EXTFLAG_UPDATE_MASK == 0xFF)
    let _ = ext;
    if tkt & !TKTFLAG_UPDATE_MASK != 0 {
        return Err(YubiOtpError::InvalidData(
            "Unsupported tkt flags for update".into(),
        ));
    }
    if cfg & !CFGFLAG_UPDATE_MASK != 0 {
        return Err(YubiOtpError::InvalidData(
            "Unsupported cfg flags for update".into(),
        ));
    }
    Ok(build_config(
        &[],
        &[0u8; UID_SIZE],
        &[0u8; KEY_SIZE],
        ext,
        tkt,
        cfg,
        acc_code,
    ))
}

/// Build a 56-byte NDEF configuration payload.
fn build_ndef_config(value: Option<&str>, ndef_type: NdefType) -> Result<Vec<u8>, YubiOtpError> {
    let data = match ndef_type {
        NdefType::Uri => {
            let uri = value.unwrap_or(DEFAULT_NDEF_URI);
            let (id_code, remainder) = NDEF_URL_PREFIXES
                .iter()
                .enumerate()
                .find_map(|(i, prefix)| uri.strip_prefix(prefix).map(|rest| ((i + 1) as u8, rest)))
                .unwrap_or((0, uri));
            let mut d = vec![id_code];
            d.extend_from_slice(remainder.as_bytes());
            d
        }
        NdefType::Text => {
            let text = value.unwrap_or("");
            let mut d = vec![0x02, b'e', b'n'];
            d.extend_from_slice(text.as_bytes());
            d
        }
    };

    if data.len() > NDEF_DATA_SIZE {
        return Err(YubiOtpError::InvalidData("URI payload too large".into()));
    }

    let mut buf = vec![data.len() as u8, ndef_type as u8];
    buf.extend_from_slice(&data);
    buf.resize(2 + NDEF_DATA_SIZE, 0); // pad to 56 bytes total
    Ok(buf)
}

// ---------------------------------------------------------------------------
// SlotConfiguration
// ---------------------------------------------------------------------------

/// A configuration to be written to an OTP slot.
///
/// Use one of the constructors ([`SlotConfiguration::yubiotp`],
/// [`SlotConfiguration::hmac_sha1`], etc.) to create a configuration, then
/// chain builder methods to customise flags.
#[derive(Debug, Clone)]
pub struct SlotConfiguration {
    fixed: Vec<u8>,
    uid: [u8; UID_SIZE],
    key: [u8; KEY_SIZE],
    ext_flags: u8,
    tkt_flags: u8,
    cfg_flags: u8,
    kind: SlotConfigKind,
}

/// Tracks which constructor was used, for version gating and update semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotConfigKind {
    YubiOtp,
    HmacSha1,
    Hotp,
    StaticPassword,
    StaticTicket,
    Update,
}

impl SlotConfiguration {
    // -- internal helpers --------------------------------------------------

    fn new_base() -> Self {
        Self {
            fixed: Vec::new(),
            uid: [0u8; UID_SIZE],
            key: [0u8; KEY_SIZE],
            ext_flags: ExtFlag::SERIAL_API_VISIBLE.0 | ExtFlag::ALLOW_UPDATE.0,
            tkt_flags: 0,
            cfg_flags: 0,
            kind: SlotConfigKind::YubiOtp,
        }
    }

    fn new_keyboard_base() -> Self {
        let mut s = Self::new_base();
        s.tkt_flags |= TktFlag::APPEND_CR.0;
        s.ext_flags |= ExtFlag::FAST_TRIG.0;
        s
    }

    fn set_flag_ext(&mut self, flag: ExtFlag, value: bool) {
        if value {
            self.ext_flags |= flag.0;
        } else {
            self.ext_flags &= !flag.0;
        }
    }

    fn set_flag_tkt(&mut self, flag: TktFlag, value: bool) {
        if value {
            self.tkt_flags |= flag.0;
        } else {
            self.tkt_flags &= !flag.0;
        }
    }

    fn set_flag_cfg(&mut self, flag: CfgFlag, value: bool) {
        if value {
            self.cfg_flags |= flag.0;
        } else {
            self.cfg_flags &= !flag.0;
        }
    }

    // -- constructors ------------------------------------------------------

    /// Standard Yubico OTP configuration.
    pub fn yubiotp(
        fixed: &[u8],
        uid: &[u8; UID_SIZE],
        key: &[u8; KEY_SIZE],
    ) -> Result<Self, YubiOtpError> {
        if fixed.len() > FIXED_SIZE {
            return Err(YubiOtpError::InvalidData(format!(
                "fixed must be <= {FIXED_SIZE} bytes"
            )));
        }
        let mut s = Self::new_keyboard_base();
        s.kind = SlotConfigKind::YubiOtp;
        s.fixed = fixed.to_vec();
        s.uid = *uid;
        s.key = *key;
        Ok(s)
    }

    /// HMAC-SHA1 challenge-response configuration.
    pub fn hmac_sha1(key: &[u8]) -> Result<Self, YubiOtpError> {
        let key = shorten_hmac_key(key)?;
        let mut s = Self::new_base();
        s.kind = SlotConfigKind::HmacSha1;

        // Key is packed into key and uid fields
        let key_part = &key[..KEY_SIZE.min(key.len())];
        s.key[..key_part.len()].copy_from_slice(key_part);
        if key.len() > KEY_SIZE {
            let uid_part = &key[KEY_SIZE..];
            s.uid[..uid_part.len()].copy_from_slice(uid_part);
        }

        s.tkt_flags |= TktFlag::CHAL_RESP.0;
        s.cfg_flags |= CfgFlag::CHAL_HMAC.0 | CfgFlag::HMAC_LT64.0;
        Ok(s)
    }

    /// HOTP (OATH-HOTP) configuration.
    pub fn hotp(key: &[u8]) -> Result<Self, YubiOtpError> {
        let key = shorten_hmac_key(key)?;
        let mut s = Self::new_keyboard_base();
        s.kind = SlotConfigKind::Hotp;

        let key_part = &key[..KEY_SIZE.min(key.len())];
        s.key[..key_part.len()].copy_from_slice(key_part);
        if key.len() > KEY_SIZE {
            let uid_part = &key[KEY_SIZE..];
            s.uid[..uid_part.len()].copy_from_slice(uid_part);
        }

        s.tkt_flags |= TktFlag::OATH_HOTP.0;
        s.cfg_flags |= CfgFlag::OATH_FIXED_MODHEX2.0;
        Ok(s)
    }

    /// Static password configuration (scan codes packed into fixed+uid+key).
    pub fn static_password(scan_codes: &[u8]) -> Result<Self, YubiOtpError> {
        if scan_codes.len() > SCAN_CODES_SIZE {
            return Err(YubiOtpError::NotSupported("Password is too long".into()));
        }
        let mut padded = [0u8; SCAN_CODES_SIZE];
        padded[..scan_codes.len()].copy_from_slice(scan_codes);

        let mut s = Self::new_keyboard_base();
        s.kind = SlotConfigKind::StaticPassword;
        s.fixed = padded[..FIXED_SIZE].to_vec();
        s.uid
            .copy_from_slice(&padded[FIXED_SIZE..FIXED_SIZE + UID_SIZE]);
        s.key.copy_from_slice(&padded[FIXED_SIZE + UID_SIZE..]);
        s.cfg_flags |= CfgFlag::SHORT_TICKET.0;
        Ok(s)
    }

    /// Static ticket configuration.
    pub fn static_ticket(
        fixed: &[u8],
        uid: &[u8; UID_SIZE],
        key: &[u8; KEY_SIZE],
    ) -> Result<Self, YubiOtpError> {
        if fixed.len() > FIXED_SIZE {
            return Err(YubiOtpError::InvalidData(format!(
                "fixed must be <= {FIXED_SIZE} bytes"
            )));
        }
        let mut s = Self::new_keyboard_base();
        s.kind = SlotConfigKind::StaticTicket;
        s.fixed = fixed.to_vec();
        s.uid = *uid;
        s.key = *key;
        s.cfg_flags |= CfgFlag::STATIC_TICKET.0;
        Ok(s)
    }

    /// Update configuration (only flags that are valid for update).
    pub fn update() -> Self {
        let mut s = Self::new_keyboard_base();
        s.kind = SlotConfigKind::Update;
        s.fixed = vec![0u8; FIXED_SIZE];
        s.uid = [0u8; UID_SIZE];
        s.key = [0u8; KEY_SIZE];
        s
    }

    // -- version support check ---------------------------------------------

    /// Check if this configuration is supported by the given firmware version.
    pub fn is_supported_by(&self, version: Version) -> bool {
        match self.kind {
            SlotConfigKind::HmacSha1
            | SlotConfigKind::Hotp
            | SlotConfigKind::StaticPassword
            | SlotConfigKind::Update => version >= Version(2, 2, 0),
            SlotConfigKind::YubiOtp | SlotConfigKind::StaticTicket => true,
        }
    }

    // -- config serialization ----------------------------------------------

    /// Serialize the configuration to bytes (52 bytes with CRC).
    pub fn get_config(&self, acc_code: Option<&[u8]>) -> Vec<u8> {
        build_config(
            &self.fixed,
            &self.uid,
            &self.key,
            self.ext_flags,
            self.tkt_flags,
            self.cfg_flags,
            acc_code,
        )
    }

    // -- common builder methods (SlotConfiguration) ------------------------

    /// Set whether the serial number is readable via API.
    pub fn serial_api_visible(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::SERIAL_API_VISIBLE, value);
        self
    }

    /// Set whether the serial number is visible via USB descriptor.
    pub fn serial_usb_visible(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::SERIAL_USB_VISIBLE, value);
        self
    }

    /// Set whether the slot configuration can be updated.
    pub fn allow_update(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::ALLOW_UPDATE, value);
        self
    }

    /// Set whether the slot is dormant (disabled).
    pub fn dormant(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::DORMANT, value);
        self
    }

    /// Set whether to invert the LED behavior.
    pub fn invert_led(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::LED_INV, value);
        self
    }

    /// Set whether to protect slot 2 from accidental overwrite.
    pub fn protect_slot2(mut self, value: bool) -> Result<Self, YubiOtpError> {
        if self.kind == SlotConfigKind::Update {
            return Err(YubiOtpError::InvalidData(
                "protect_slot2 cannot be applied to UpdateConfiguration".into(),
            ));
        }
        self.set_flag_tkt(TktFlag::PROTECT_CFG2, value);
        Ok(self)
    }

    // -- HMAC-SHA1 builder methods -----------------------------------------

    /// Set challenge-response button trigger (HMAC-SHA1 only).
    pub fn require_touch(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::CHAL_BTN_TRIG, value);
        self
    }

    /// Set HMAC less-than-64 flag (HMAC-SHA1 only).
    pub fn lt64(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::HMAC_LT64, value);
        self
    }

    // -- keyboard configuration builder methods ----------------------------

    /// Set whether to append a carriage return after the OTP output.
    pub fn append_cr(mut self, value: bool) -> Self {
        self.set_flag_tkt(TktFlag::APPEND_CR, value);
        self
    }

    /// Set whether to use faster triggering (shorter button press).
    pub fn fast_trigger(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::FAST_TRIG, value);
        self
    }

    /// Set keystroke pacing delays (10 ms and/or 20 ms between keystrokes).
    pub fn pacing(mut self, pacing_10ms: bool, pacing_20ms: bool) -> Self {
        self.set_flag_cfg(CfgFlag::PACING_10MS, pacing_10ms);
        self.set_flag_cfg(CfgFlag::PACING_20MS, pacing_20ms);
        self
    }

    /// Set whether to use the numeric keypad for digit output.
    pub fn use_numeric(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::USE_NUMERIC_KEYPAD, value);
        self
    }

    // -- HOTP builder methods ----------------------------------------------

    /// Set 8-digit HOTP output.
    pub fn digits8(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::OATH_HOTP8, value);
        self
    }

    /// Set HOTP token ID (written to the fixed field).
    pub fn token_id(
        mut self,
        token_id: &[u8],
        fixed_modhex1: bool,
        fixed_modhex2: bool,
    ) -> Result<Self, YubiOtpError> {
        if token_id.len() > FIXED_SIZE {
            return Err(YubiOtpError::InvalidData(format!(
                "token_id must be <= {FIXED_SIZE} bytes"
            )));
        }
        self.fixed = token_id.to_vec();
        self.set_flag_cfg(CfgFlag::OATH_FIXED_MODHEX1, fixed_modhex1);
        self.set_flag_cfg(CfgFlag::OATH_FIXED_MODHEX2, fixed_modhex2);
        Ok(self)
    }

    /// Set initial moving factor for HOTP.
    pub fn imf(mut self, imf: u32) -> Result<Self, YubiOtpError> {
        if !imf.is_multiple_of(16) || imf > 0xFFFF0 {
            return Err(YubiOtpError::InvalidData(
                "imf should be between 0 and 1048560, evenly divisible by 16".into(),
            ));
        }
        let encoded = ((imf >> 4) as u16).to_be_bytes();
        self.uid[4] = encoded[0];
        self.uid[5] = encoded[1];
        Ok(self)
    }

    // -- YubiOTP / StaticTicket builder methods ----------------------------

    /// Set tab insertion (YubiOTP / StaticTicket / Update).
    pub fn tabs(mut self, before: bool, after_first: bool, after_second: bool) -> Self {
        self.set_flag_tkt(TktFlag::TAB_FIRST, before);
        self.set_flag_tkt(TktFlag::APPEND_TAB1, after_first);
        self.set_flag_tkt(TktFlag::APPEND_TAB2, after_second);
        self
    }

    /// Set delay insertion (YubiOTP / StaticTicket / Update).
    pub fn delay(mut self, after_first: bool, after_second: bool) -> Self {
        self.set_flag_tkt(TktFlag::APPEND_DELAY1, after_first);
        self.set_flag_tkt(TktFlag::APPEND_DELAY2, after_second);
        self
    }

    /// Set send reference (YubiOTP only).
    pub fn send_reference(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::SEND_REF, value);
        self
    }

    // -- StaticTicket builder methods --------------------------------------

    /// Set whether to send a truncated (short) ticket for static password.
    pub fn short_ticket(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::SHORT_TICKET, value);
        self
    }

    /// Configure strong-password character classes (upper-case, digits, special characters).
    pub fn strong_password(mut self, upper_case: bool, digit: bool, special: bool) -> Self {
        self.set_flag_cfg(CfgFlag::STRONG_PW1, upper_case);
        self.set_flag_cfg(CfgFlag::STRONG_PW2, digit || special);
        self.set_flag_cfg(CfgFlag::SEND_REF, special);
        self
    }

    /// Set whether to allow manual configuration update without access code.
    pub fn manual_update(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::MAN_UPDATE, value);
        self
    }

    // -- UpdateConfiguration flag validation ------------------------------

    /// Set a flag with update-mode validation (for Update configs).
    /// Returns error if an unsupported flag is used in update mode.
    pub fn set_update_tkt_flag(mut self, flag: TktFlag, value: bool) -> Result<Self, YubiOtpError> {
        if self.kind == SlotConfigKind::Update && (flag.0 & !TKTFLAG_UPDATE_MASK) != 0 {
            return Err(YubiOtpError::InvalidData(
                "Unsupported TKT flag for update".into(),
            ));
        }
        self.set_flag_tkt(flag, value);
        Ok(self)
    }

    /// Set a configuration flag with update-mode validation.
    pub fn set_update_cfg_flag(mut self, flag: CfgFlag, value: bool) -> Result<Self, YubiOtpError> {
        if self.kind == SlotConfigKind::Update && (flag.0 & !CFGFLAG_UPDATE_MASK) != 0 {
            return Err(YubiOtpError::InvalidData(
                "Unsupported CFG flag for update".into(),
            ));
        }
        self.set_flag_cfg(flag, value);
        Ok(self)
    }
}

// ---------------------------------------------------------------------------
// YubiOtpOps (private, object-safe trait for internal dispatch)
// ---------------------------------------------------------------------------

/// Object-safe trait for transport-specific YubiOTP operations.
///
/// Each transport (CCID, OTP HID) implements this trait. The public
/// [`YubiOtpSession`] dispatches through this.
trait YubiOtpOps<E: std::error::Error + Send + Sync + 'static>: Send {
    fn version(&self) -> Version;
    fn status(&self) -> &[u8];
    fn write_config(
        &mut self,
        slot: ConfigSlot,
        config: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<E>>;
    fn send_and_receive(
        &mut self,
        slot: ConfigSlot,
        data: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, YubiOtpError<E>>;
    fn calculate_hmac_sha1_with_cancel(
        &mut self,
        slot: Slot,
        challenge: &[u8],
        cancel: Option<&dyn Fn() -> bool>,
        on_keepalive: Option<&dyn Fn(u8)>,
    ) -> Result<Vec<u8>, YubiOtpError<E>>;
    fn into_connection_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

// ---------------------------------------------------------------------------
// YubiOtpSession
// ---------------------------------------------------------------------------

/// YubiOTP session for configuring OTP slots.
///
/// Generic over the connection type `C`. Construct with [`YubiOtpSession::new`]
/// for SmartCard (CCID) or [`YubiOtpSession::new_otp`] for OTP HID.
pub struct YubiOtpSession<C: Connection> {
    inner: Box<dyn YubiOtpOps<C::Error>>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: Connection + 'static> YubiOtpSession<C> {
    /// The firmware version of the YubiKey.
    pub fn version(&self) -> Version {
        self.inner.version()
    }

    /// Access the raw status bytes.
    pub fn status(&self) -> &[u8] {
        self.inner.status()
    }

    /// Write raw config bytes to a config slot.
    pub fn write_config(
        &mut self,
        slot: ConfigSlot,
        config: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<C::Error>> {
        self.inner.write_config(slot, config, cur_acc_code)
    }

    /// Send a command and receive a response of expected length.
    pub fn send_and_receive(
        &mut self,
        slot: ConfigSlot,
        data: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, YubiOtpError<C::Error>> {
        self.inner.send_and_receive(slot, data, expected_len)
    }

    /// Perform an HMAC-SHA1 challenge-response operation.
    pub fn calculate_hmac_sha1(
        &mut self,
        slot: Slot,
        challenge: &[u8],
    ) -> Result<Vec<u8>, YubiOtpError<C::Error>> {
        self.calculate_hmac_sha1_with_cancel(slot, challenge, None, None)
    }

    /// Perform an HMAC-SHA1 challenge-response with optional cancellation and keepalive.
    pub fn calculate_hmac_sha1_with_cancel(
        &mut self,
        slot: Slot,
        challenge: &[u8],
        cancel: Option<&dyn Fn() -> bool>,
        on_keepalive: Option<&dyn Fn(u8)>,
    ) -> Result<Vec<u8>, YubiOtpError<C::Error>> {
        self.inner
            .calculate_hmac_sha1_with_cancel(slot, challenge, cancel, on_keepalive)
    }

    /// Get the serial number of the YubiKey.
    pub fn get_serial(&mut self) -> Result<u32, YubiOtpError<C::Error>> {
        let resp = self.send_and_receive(ConfigSlot::DeviceSerial, &[], 4)?;
        Ok(u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]))
    }

    /// Get the current configuration state.
    pub fn get_config_state(&self) -> ConfigState {
        let touch_level = if self.status().len() >= 6 {
            u16::from_le_bytes([self.status()[4], self.status()[5]])
        } else {
            0
        };
        ConfigState::new(self.version(), touch_level)
    }

    /// Write a configuration to a slot.
    pub fn put_configuration(
        &mut self,
        slot: Slot,
        config: &SlotConfiguration,
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<C::Error>> {
        if !config.is_supported_by(self.version()) {
            return Err(YubiOtpError::NotSupported(
                "This configuration is not supported on this YubiKey version".into(),
            ));
        }
        let config_slot = slot.map(ConfigSlot::Config1, ConfigSlot::Config2);
        self.write_config(config_slot, &config.get_config(acc_code), cur_acc_code)
    }

    /// Update an existing configuration in a slot.
    pub fn update_configuration(
        &mut self,
        slot: Slot,
        config: &SlotConfiguration,
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<C::Error>> {
        if !config.is_supported_by(self.version()) {
            return Err(YubiOtpError::NotSupported(
                "This configuration is not supported on this YubiKey version".into(),
            ));
        }
        if acc_code != cur_acc_code
            && self.version() >= Version(4, 3, 2)
            && self.version() < Version(4, 3, 6)
        {
            return Err(YubiOtpError::NotSupported(
                "The access code cannot be updated on this YubiKey. \
                 Instead, delete the slot and configure it anew."
                    .into(),
            ));
        }
        let config_slot = slot.map(ConfigSlot::Update1, ConfigSlot::Update2);
        self.write_config(config_slot, &config.get_config(acc_code), cur_acc_code)
    }

    /// Swap the two slot configurations.
    pub fn swap_slots(&mut self) -> Result<(), YubiOtpError<C::Error>> {
        self.write_config(ConfigSlot::Swap, &[], None)
    }

    /// Delete the configuration stored in a slot.
    pub fn delete_slot(
        &mut self,
        slot: Slot,
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<C::Error>> {
        let config_slot = slot.map(ConfigSlot::Config1, ConfigSlot::Config2);
        self.write_config(config_slot, &[0u8; CONFIG_SIZE], cur_acc_code)
    }

    /// Update scan-code map on the YubiKey.
    pub fn set_scan_map(
        &mut self,
        scan_map: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<C::Error>> {
        self.write_config(ConfigSlot::ScanMap, scan_map, cur_acc_code)
    }

    /// Configure a slot to be used over NDEF (NFC).
    pub fn set_ndef_configuration(
        &mut self,
        slot: Slot,
        uri: Option<&str>,
        cur_acc_code: Option<&[u8]>,
        ndef_type: NdefType,
    ) -> Result<(), YubiOtpError<C::Error>> {
        let config_slot = slot.map(ConfigSlot::Ndef1, ConfigSlot::Ndef2);
        let ndef_data = build_ndef_config(uri, ndef_type).map_err(YubiOtpError::widen)?;
        self.write_config(config_slot, &ndef_data, cur_acc_code)
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        *self
            .inner
            .into_connection_any()
            .downcast::<C>()
            .expect("YubiOtpSession inner type mismatch (this is a bug)")
    }

    fn from_inner(inner: Box<dyn YubiOtpOps<C::Error>>) -> Self {
        Self {
            inner,
            _phantom: std::marker::PhantomData,
        }
    }
}

// SmartCard (CCID) constructors
impl<C: SmartCardConnection + Send + 'static> YubiOtpSession<C> {
    /// Open a YubiOTP session over SmartCard (CCID).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new(connection: C) -> Result<Self, (YubiOtpError<SmartCardError>, C)> {
        CcidYubiOtp::open(connection).map(|inner| Self::from_inner(Box::new(inner)))
    }

    /// Open a YubiOTP session with SCP (Secure Channel Protocol).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::smartcard::ScpKeyParams,
    ) -> Result<Self, (YubiOtpError<SmartCardError>, C)> {
        CcidYubiOtp::open_with_scp(connection, scp_key_params)
            .map(|inner| Self::from_inner(Box::new(inner)))
    }
}

// OTP HID constructors
impl<T: OtpConnection + Send + 'static> YubiOtpSession<T> {
    /// Open a YubiOTP session over OTP HID.
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_otp(connection: T) -> Result<Self, (YubiOtpError<OtpError>, T)> {
        OtpYubiOtp::open(connection).map(|inner| Self::from_inner(Box::new(inner)))
    }
}

// ---------------------------------------------------------------------------
// CcidYubiOtp — SmartCard backend (internal)
// ---------------------------------------------------------------------------

struct CcidYubiOtp<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
    status: Vec<u8>,
    prog_seq: u8,
}

impl<C: SmartCardConnection> CcidYubiOtp<C> {
    fn open(connection: C) -> Result<Self, (YubiOtpError<SmartCardError>, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let status = match protocol.select(Aid::OTP) {
            Ok(v) => v,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        Self::init(protocol, &status)
    }

    fn open_with_scp(
        connection: C,
        scp_key_params: &crate::smartcard::ScpKeyParams,
    ) -> Result<Self, (YubiOtpError<SmartCardError>, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let status = match protocol.select(Aid::OTP) {
            Ok(v) => v,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        if let Err(e) = protocol.init_scp(scp_key_params) {
            return Err((e.into(), protocol.into_connection()));
        }
        Self::init(protocol, &status)
    }

    fn init(
        mut protocol: SmartCardProtocol<C>,
        status: &[u8],
    ) -> Result<Self, (YubiOtpError<SmartCardError>, C)> {
        log::debug!("Opening CcidYubiOtp (SmartCard)");
        let version = patch_version(Version::from_bytes(&status[..3]));
        let prog_seq = *status.get(3).unwrap_or(&0);
        protocol.configure(version);

        Ok(Self {
            protocol,
            version,
            status: status.to_vec(),
            prog_seq,
        })
    }

    fn write_update(
        &mut self,
        slot: ConfigSlot,
        data: &[u8],
    ) -> Result<Vec<u8>, YubiOtpError<SmartCardError>> {
        let mut status = self
            .protocol
            .send_apdu(0, INS_CONFIG, slot as u8, 0, data)?;
        if status.is_empty() {
            status = self.protocol.send_apdu(0, INS_YK2_STATUS, 0, 0, &[])?;
        }

        let prev_prog_seq = self.prog_seq;
        self.prog_seq = *status.get(3).unwrap_or(&0);
        self.status = status.clone();

        if self.prog_seq == prev_prog_seq.wrapping_add(1) {
            return Ok(status);
        }
        if self.prog_seq == 0 && prev_prog_seq > 0 {
            let version = Version::from_bytes(&status[..3]);
            if status.get(4).is_none_or(|&b| b & 0x1F == 0) {
                return Ok(status);
            }
            if version >= Version(5, 0, 0) && version < Version(5, 4, 3) {
                return Ok(status);
            }
        }
        Err(YubiOtpError::InvalidData("Not updated".into()))
    }
}

impl<C: SmartCardConnection + Send + 'static> YubiOtpOps<SmartCardError> for CcidYubiOtp<C> {
    fn version(&self) -> Version {
        self.version
    }

    fn status(&self) -> &[u8] {
        &self.status
    }

    fn write_config(
        &mut self,
        slot: ConfigSlot,
        config: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<SmartCardError>> {
        let mut data = config.to_vec();
        match cur_acc_code {
            Some(ac) => data.extend_from_slice(ac),
            None => data.extend_from_slice(&[0u8; ACC_CODE_SIZE]),
        }
        self.write_update(slot, &data)?;
        Ok(())
    }

    fn send_and_receive(
        &mut self,
        slot: ConfigSlot,
        data: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, YubiOtpError<SmartCardError>> {
        let response = self
            .protocol
            .send_apdu(0, INS_CONFIG, slot as u8, 0, data)?;
        if response.len() == expected_len {
            Ok(response)
        } else {
            Err(YubiOtpError::InvalidData(format!(
                "Unexpected response length: expected {expected_len}, got {}",
                response.len()
            )))
        }
    }

    fn calculate_hmac_sha1_with_cancel(
        &mut self,
        slot: Slot,
        challenge: &[u8],
        _cancel: Option<&dyn Fn() -> bool>,
        _on_keepalive: Option<&dyn Fn(u8)>,
    ) -> Result<Vec<u8>, YubiOtpError<SmartCardError>> {
        // SmartCard transport does not support cancellation or keepalives.
        require_version(self.version, Version(2, 2, 0), "calculate_hmac_sha1")
            .map_err(YubiOtpError::widen)?;
        let config_slot = slot.map(ConfigSlot::ChalHmac1, ConfigSlot::ChalHmac2);

        let pad_byte = if challenge.last() == Some(&0) {
            1u8
        } else {
            0u8
        };
        let mut padded = [pad_byte; HMAC_CHALLENGE_SIZE];
        let copy_len = challenge.len().min(HMAC_CHALLENGE_SIZE);
        padded[..copy_len].copy_from_slice(&challenge[..copy_len]);

        self.send_and_receive(config_slot, &padded, HMAC_RESPONSE_SIZE)
    }

    fn into_connection_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        Box::new(self.protocol.into_connection())
    }
}

// ---------------------------------------------------------------------------
// OtpYubiOtp — HID OTP backend (internal)
// ---------------------------------------------------------------------------

struct OtpYubiOtp<T: OtpConnection> {
    protocol: OtpProtocol<T>,
    status: Vec<u8>,
    version: Version,
}

impl<T: OtpConnection> OtpYubiOtp<T> {
    fn open(connection: T) -> Result<Self, (YubiOtpError<OtpError>, T)> {
        log::debug!("Opening OtpYubiOtp (HID)");
        let mut protocol = match OtpProtocol::new(connection) {
            Ok(p) => p,
            Err((e, conn)) => return Err((e.into(), conn)),
        };
        let status = match protocol.read_status() {
            Ok(s) => s,
            Err(e) => return Err((e.into(), protocol.into_connection())),
        };
        let version = patch_version(protocol.version);

        Ok(Self {
            protocol,
            status,
            version,
        })
    }
}

impl<T: OtpConnection + Send + 'static> YubiOtpOps<OtpError> for OtpYubiOtp<T> {
    fn version(&self) -> Version {
        self.version
    }

    fn status(&self) -> &[u8] {
        &self.status
    }

    fn write_config(
        &mut self,
        slot: ConfigSlot,
        config: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError<OtpError>> {
        let mut data = config.to_vec();
        match cur_acc_code {
            Some(ac) => data.extend_from_slice(ac),
            None => data.extend_from_slice(&[0u8; ACC_CODE_SIZE]),
        }
        self.protocol
            .send_and_receive(slot as u8, Some(&data), None)?;
        self.status = self.protocol.read_status()?;
        Ok(())
    }

    fn send_and_receive(
        &mut self,
        slot: ConfigSlot,
        data: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, YubiOtpError<OtpError>> {
        let send_data = if data.is_empty() { None } else { Some(data) };
        self.protocol
            .send_and_receive(slot as u8, send_data, Some(expected_len as i32))?
            .ok_or_else(|| YubiOtpError::InvalidData("Expected data response, got status".into()))
    }

    fn calculate_hmac_sha1_with_cancel(
        &mut self,
        slot: Slot,
        challenge: &[u8],
        cancel: Option<&dyn Fn() -> bool>,
        on_keepalive: Option<&dyn Fn(u8)>,
    ) -> Result<Vec<u8>, YubiOtpError<OtpError>> {
        require_version(self.version, Version(2, 2, 0), "calculate_hmac_sha1")
            .map_err(YubiOtpError::widen)?;
        let config_slot = slot.map(ConfigSlot::ChalHmac1, ConfigSlot::ChalHmac2);

        let pad_byte = if challenge.last() == Some(&0) {
            1u8
        } else {
            0u8
        };
        let mut padded = [pad_byte; HMAC_CHALLENGE_SIZE];
        let copy_len = challenge.len().min(HMAC_CHALLENGE_SIZE);
        padded[..copy_len].copy_from_slice(&challenge[..copy_len]);

        let response = self.protocol.send_and_receive_with_cancel(
            config_slot as u8,
            Some(&padded),
            Some(HMAC_RESPONSE_SIZE as i32),
            cancel,
            on_keepalive,
        )?;

        response.ok_or_else(|| YubiOtpError::InvalidData("No data in HMAC response".into()))
    }

    fn into_connection_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        Box::new(self.protocol.into_connection())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_config_size() {
        let cfg = build_config(b"test", &[0u8; UID_SIZE], &[0u8; KEY_SIZE], 0, 0, 0, None);
        assert_eq!(cfg.len(), CONFIG_SIZE);
    }

    #[test]
    fn test_build_config_crc_valid() {
        let cfg = build_config(b"", &[0u8; UID_SIZE], &[0u8; KEY_SIZE], 0, 0, 0, None);
        // The CRC should be valid over the whole buffer
        assert!(check_crc(&cfg));
    }

    #[test]
    fn test_build_config_with_acc_code() {
        let acc = [1u8, 2, 3, 4, 5, 6];
        let cfg = build_config(b"", &[0u8; UID_SIZE], &[0u8; KEY_SIZE], 0, 0, 0, Some(&acc));
        assert_eq!(cfg.len(), CONFIG_SIZE);
        assert!(check_crc(&cfg));
        // acc_code is at offset FIXED_SIZE + UID_SIZE + KEY_SIZE = 38
        assert_eq!(&cfg[38..44], &acc);
    }

    #[test]
    fn test_build_config_fixed_len_stored() {
        let fixed = b"hello";
        let cfg = build_config(
            fixed,
            &[0u8; UID_SIZE],
            &[0u8; KEY_SIZE],
            0x24,
            0x20,
            0x01,
            None,
        );
        // fixed_len at offset 44
        assert_eq!(cfg[44], 5);
        // ext at offset 45
        assert_eq!(cfg[45], 0x24);
        // tkt at offset 46
        assert_eq!(cfg[46], 0x20);
        // cfg at offset 47
        assert_eq!(cfg[47], 0x01);
    }

    #[test]
    fn test_build_update_validates_flags() {
        // Valid flags
        assert!(
            build_update(
                ExtFlag::ALLOW_UPDATE.0,
                TktFlag::APPEND_CR.0,
                CfgFlag::PACING_10MS.0,
                None
            )
            .is_ok()
        );

        // All ext flags are valid for update, so test tkt and cfg invalid flags
        assert!(build_update(0, TktFlag::PROTECT_CFG2.0, 0, None).is_err());
        assert!(build_update(0, 0, CfgFlag::STATIC_TICKET.0, None).is_err());
    }

    #[test]
    fn test_build_ndef_uri() {
        let ndef = build_ndef_config(Some("https://example.com"), NdefType::Uri).unwrap();
        assert_eq!(ndef.len(), 2 + NDEF_DATA_SIZE); // 56 bytes
        // "https://" is prefix index 3 (0-based), so id_code = 4
        assert_eq!(ndef[0], 12); // length: 1 (id_code) + 11 (example.com)
        assert_eq!(ndef[1], b'U');
        assert_eq!(ndef[2], 4); // prefix index for "https://"
        assert_eq!(&ndef[3..14], b"example.com");
    }

    #[test]
    fn test_build_ndef_text() {
        let ndef = build_ndef_config(Some("Hello"), NdefType::Text).unwrap();
        assert_eq!(ndef.len(), 2 + NDEF_DATA_SIZE);
        assert_eq!(ndef[0], 8); // length: 3 ("\x02en") + 5 ("Hello")
        assert_eq!(ndef[1], b'T');
        assert_eq!(ndef[2], 0x02);
        assert_eq!(&ndef[3..5], b"en");
        assert_eq!(&ndef[5..10], b"Hello");
    }

    #[test]
    fn test_build_ndef_default_uri() {
        let ndef = build_ndef_config(None, NdefType::Uri).unwrap();
        // DEFAULT_NDEF_URI = "https://my.yubico.com/yk/#"
        // "https://" is prefix index 3 → id_code = 4
        assert_eq!(ndef[2], 4);
        assert_eq!(
            &ndef[3..3 + "my.yubico.com/yk/#".len()],
            b"my.yubico.com/yk/#"
        );
    }

    #[test]
    fn test_slot_configuration_yubiotp() {
        let uid = [1u8; UID_SIZE];
        let key = [2u8; KEY_SIZE];
        let cfg = SlotConfiguration::yubiotp(b"abc", &uid, &key).unwrap();
        let data = cfg.get_config(None);
        assert_eq!(data.len(), CONFIG_SIZE);
        assert!(check_crc(&data));
        // Check fixed field
        assert_eq!(&data[..3], b"abc");
        // uid
        assert_eq!(&data[FIXED_SIZE..FIXED_SIZE + UID_SIZE], &uid);
        // key
        assert_eq!(
            &data[FIXED_SIZE + UID_SIZE..FIXED_SIZE + UID_SIZE + KEY_SIZE],
            &key
        );
    }

    #[test]
    fn test_slot_configuration_hmac_sha1() {
        let key = [0xABu8; HMAC_KEY_SIZE];
        let cfg = SlotConfiguration::hmac_sha1(&key).unwrap();
        assert!(cfg.is_supported_by(Version(2, 2, 0)));
        assert!(!cfg.is_supported_by(Version(2, 1, 0)));
        let data = cfg.get_config(None);
        assert_eq!(data.len(), CONFIG_SIZE);
        assert!(check_crc(&data));
    }

    #[test]
    fn test_slot_configuration_hmac_long_key() {
        // Key > 64 bytes should be SHA1-hashed
        let key = [0xCC; 65];
        let cfg = SlotConfiguration::hmac_sha1(&key).unwrap();
        let data = cfg.get_config(None);
        assert!(check_crc(&data));
    }

    #[test]
    fn test_slot_configuration_hmac_invalid_key_len() {
        // Key of 21-64 bytes is invalid (not supported, not > SHA1_BLOCK_SIZE)
        let key = [0xAA; 21];
        assert!(SlotConfiguration::hmac_sha1(&key).is_err());
    }

    #[test]
    fn test_slot_configuration_hotp() {
        let key = [0x42u8; HMAC_KEY_SIZE];
        let cfg = SlotConfiguration::hotp(&key).unwrap();
        assert!(cfg.is_supported_by(Version(2, 2, 0)));
        let data = cfg.get_config(None);
        assert_eq!(data.len(), CONFIG_SIZE);
        assert!(check_crc(&data));
    }

    #[test]
    fn test_slot_configuration_static_password() {
        let scan_codes = [0x04u8; 20];
        let cfg = SlotConfiguration::static_password(&scan_codes).unwrap();
        assert!(cfg.is_supported_by(Version(2, 2, 0)));
        let data = cfg.get_config(None);
        assert_eq!(data.len(), CONFIG_SIZE);
        assert!(check_crc(&data));
    }

    #[test]
    fn test_slot_configuration_static_password_too_long() {
        let scan_codes = [0x04u8; SCAN_CODES_SIZE + 1];
        assert!(SlotConfiguration::static_password(&scan_codes).is_err());
    }

    #[test]
    fn test_slot_configuration_update() {
        let cfg = SlotConfiguration::update();
        assert!(cfg.is_supported_by(Version(2, 2, 0)));
        let data = cfg.get_config(None);
        assert_eq!(data.len(), CONFIG_SIZE);
        assert!(check_crc(&data));
    }

    #[test]
    fn test_config_state() {
        let state = ConfigState::new(Version(3, 0, 0), 0x01 | 0x04);
        assert!(state.is_configured(Slot::One).unwrap());
        assert!(!state.is_configured(Slot::Two).unwrap());
        assert!(state.is_touch_triggered(Slot::One).unwrap());
        assert!(!state.is_touch_triggered(Slot::Two).unwrap());
        assert!(!state.is_led_inverted());
    }

    #[test]
    fn test_config_state_version_check() {
        let state = ConfigState::new(Version(2, 0, 0), 0x01);
        assert!(state.is_configured(Slot::One).is_err());
    }

    #[test]
    fn test_slot_map() {
        assert_eq!(Slot::One.map("one", "two"), "one");
        assert_eq!(Slot::Two.map("one", "two"), "two");
    }

    #[test]
    fn test_hotp_imf() {
        let key = [0x42u8; HMAC_KEY_SIZE];
        let cfg = SlotConfiguration::hotp(&key).unwrap().imf(1024).unwrap();
        // IMF 1024 → 1024 >> 4 = 64 → big-endian u16 = [0, 64]
        let data = cfg.get_config(None);
        // uid is at FIXED_SIZE..FIXED_SIZE+UID_SIZE, bytes 4 and 5 of uid
        assert_eq!(data[FIXED_SIZE + 4], 0);
        assert_eq!(data[FIXED_SIZE + 5], 64);
    }

    #[test]
    fn test_hotp_imf_invalid() {
        let key = [0x42u8; HMAC_KEY_SIZE];
        let cfg = SlotConfiguration::hotp(&key).unwrap();
        // Not divisible by 16
        assert!(cfg.clone().imf(17).is_err());
        // Too large
        assert!(cfg.imf(0xFFFF1).is_err());
    }

    #[test]
    fn test_builder_chaining() {
        let uid = [0u8; UID_SIZE];
        let key = [0u8; KEY_SIZE];
        let cfg = SlotConfiguration::yubiotp(b"", &uid, &key)
            .unwrap()
            .serial_api_visible(true)
            .allow_update(false)
            .invert_led(true)
            .append_cr(true)
            .tabs(true, false, true);
        let data = cfg.get_config(None);
        assert_eq!(data.len(), CONFIG_SIZE);
        assert!(check_crc(&data));
    }

    #[test]
    fn test_protect_slot2_rejected_for_update() {
        let cfg = SlotConfiguration::update();
        assert!(cfg.protect_slot2(true).is_err());
    }
}
