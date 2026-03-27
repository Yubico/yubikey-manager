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

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use sha1::{Digest, Sha1};

use crate::core_types::patch_version;
use crate::otp::calculate_crc;
#[cfg(test)]
use crate::otp::check_crc;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardProtocol, Version};
use crate::transport::otphid::OtpConnection;

// Re-export types that were moved to otp_protocol for backwards compatibility.
pub use crate::otp::{OtpProtocol, OtpTransport, YubiOtpError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const FIXED_SIZE: usize = 16;
pub const UID_SIZE: usize = 6;
pub const KEY_SIZE: usize = 16;
pub const ACC_CODE_SIZE: usize = 6;
pub const CONFIG_SIZE: usize = 52;
pub const NDEF_DATA_SIZE: usize = 54;
pub const HMAC_KEY_SIZE: usize = 20;
pub const HMAC_CHALLENGE_SIZE: usize = 64;
pub const HMAC_RESPONSE_SIZE: usize = 20;
pub const SCAN_CODES_SIZE: usize = FIXED_SIZE + UID_SIZE + KEY_SIZE; // 38

const SHA1_BLOCK_SIZE: usize = 64;

const INS_CONFIG: u8 = 0x01;
const INS_YK2_STATUS: u8 = 0x03;

pub const DEFAULT_NDEF_URI: &str = "https://my.yubico.com/yk/#";

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
    One = 1,
    Two = 2,
}

impl Slot {
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
    Config1 = 0x01,
    Nav = 0x02,
    Config2 = 0x03,
    Update1 = 0x04,
    Update2 = 0x05,
    Swap = 0x06,
    Ndef1 = 0x08,
    Ndef2 = 0x09,
    DeviceSerial = 0x10,
    DeviceConfig = 0x11,
    ScanMap = 0x12,
    Yk4Capabilities = 0x13,
    Yk4SetDeviceInfo = 0x15,
    ChalOtp1 = 0x20,
    ChalOtp2 = 0x28,
    ChalHmac1 = 0x30,
    ChalHmac2 = 0x38,
}

// ---------------------------------------------------------------------------
// Bitflag types
// ---------------------------------------------------------------------------

/// Ticket flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TktFlag(pub u8);

impl TktFlag {
    pub const TAB_FIRST: Self = Self(0x01);
    pub const APPEND_TAB1: Self = Self(0x02);
    pub const APPEND_TAB2: Self = Self(0x04);
    pub const APPEND_DELAY1: Self = Self(0x08);
    pub const APPEND_DELAY2: Self = Self(0x10);
    pub const APPEND_CR: Self = Self(0x20);
    pub const OATH_HOTP: Self = Self(0x40);
    pub const CHAL_RESP: Self = Self(0x40);
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
    pub const SEND_REF: Self = Self(0x01);
    pub const SHORT_TICKET: Self = Self(0x02);
    pub const PACING_10MS: Self = Self(0x04);
    pub const PACING_20MS: Self = Self(0x08);
    pub const STRONG_PW1: Self = Self(0x10);
    pub const STATIC_TICKET: Self = Self(0x20);
    pub const STRONG_PW2: Self = Self(0x40);
    pub const MAN_UPDATE: Self = Self(0x80);

    // OATH aliases
    pub const OATH_HOTP8: Self = Self(0x02);
    pub const OATH_FIXED_MODHEX1: Self = Self(0x10);
    pub const OATH_FIXED_MODHEX2: Self = Self(0x40);
    pub const OATH_FIXED_MODHEX: Self = Self(0x50);
    pub const OATH_FIXED_MASK: Self = Self(0x50);

    // Challenge-response aliases
    pub const CHAL_YUBICO: Self = Self(0x20);
    pub const CHAL_HMAC: Self = Self(0x22);
    pub const HMAC_LT64: Self = Self(0x04);
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
    pub const SERIAL_BTN_VISIBLE: Self = Self(0x01);
    pub const SERIAL_USB_VISIBLE: Self = Self(0x02);
    pub const SERIAL_API_VISIBLE: Self = Self(0x04);
    pub const USE_NUMERIC_KEYPAD: Self = Self(0x08);
    pub const FAST_TRIG: Self = Self(0x10);
    pub const ALLOW_UPDATE: Self = Self(0x20);
    pub const DORMANT: Self = Self(0x40);
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
    Text = b'T',
    Uri = b'U',
}

// ---------------------------------------------------------------------------
// CfgState / ConfigState
// ---------------------------------------------------------------------------

/// Configuration state bitflags from the status response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgState(pub u8);

impl CfgState {
    pub const SLOT1_VALID: Self = Self(0x01);
    pub const SLOT2_VALID: Self = Self(0x02);
    pub const SLOT1_TOUCH: Self = Self(0x04);
    pub const SLOT2_TOUCH: Self = Self(0x08);
    pub const LED_INV: Self = Self(0x10);

    const ALL_MASK: u8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;
}

/// Parsed configuration state of the YubiOTP application.
#[derive(Debug, Clone)]
pub struct ConfigState {
    pub version: Version,
    pub flags: u8,
}

impl ConfigState {
    pub fn new(version: Version, touch_level: u16) -> Self {
        Self {
            version,
            flags: CfgState::ALL_MASK & (touch_level as u8),
        }
    }

    /// Check if the given slot is programmed.
    pub fn is_configured(&self, slot: Slot) -> Result<bool, YubiOtpError> {
        require_version(self.version, Version(2, 1, 0))?;
        let flag = slot.map(CfgState::SLOT1_VALID.0, CfgState::SLOT2_VALID.0);
        Ok(self.flags & flag != 0)
    }

    /// Check if the given slot is triggered by touch (requires YubiKey 3+).
    pub fn is_touch_triggered(&self, slot: Slot) -> Result<bool, YubiOtpError> {
        require_version(self.version, Version(3, 0, 0))?;
        let flag = slot.map(CfgState::SLOT1_TOUCH.0, CfgState::SLOT2_TOUCH.0);
        Ok(self.flags & flag != 0)
    }

    /// Check if the LED behavior is inverted.
    pub fn is_led_inverted(&self) -> bool {
        self.flags & CfgState::LED_INV.0 != 0
    }
}

fn require_version(version: Version, required: Version) -> Result<(), YubiOtpError> {
    if version < required {
        return Err(YubiOtpError::NotSupported(format!(
            "This operation requires version {required} or later (device has {version})"
        )));
    }
    Ok(())
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
pub fn build_config(
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
pub fn build_update(
    ext: u8,
    tkt: u8,
    cfg: u8,
    acc_code: Option<&[u8]>,
) -> Result<Vec<u8>, YubiOtpError> {
    // All ext flags are valid for update (EXTFLAG_UPDATE_MASK == 0xFF)
    let _ = ext;
    if tkt & !TKTFLAG_UPDATE_MASK != 0 {
        return Err(YubiOtpError::InvalidParameter(
            "Unsupported tkt flags for update".into(),
        ));
    }
    if cfg & !CFGFLAG_UPDATE_MASK != 0 {
        return Err(YubiOtpError::InvalidParameter(
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
pub fn build_ndef_config(
    value: Option<&str>,
    ndef_type: NdefType,
) -> Result<Vec<u8>, YubiOtpError> {
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
        return Err(YubiOtpError::InvalidParameter(
            "URI payload too large".into(),
        ));
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
        let mut s = Self {
            fixed: Vec::new(),
            uid: [0u8; UID_SIZE],
            key: [0u8; KEY_SIZE],
            ext_flags: ExtFlag::SERIAL_API_VISIBLE.0 | ExtFlag::ALLOW_UPDATE.0,
            tkt_flags: 0,
            cfg_flags: 0,
            kind: SlotConfigKind::YubiOtp,
        };
        // kind will be overwritten by actual constructors
        let _ = &mut s;
        s
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
            return Err(YubiOtpError::InvalidParameter(format!(
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
            return Err(YubiOtpError::InvalidParameter(format!(
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
        if self.kind == SlotConfigKind::Update {
            // Update uses the restricted builder path, but still calls build_config.
            // Validation already happened in the flag setters.
            build_config(
                &self.fixed,
                &self.uid,
                &self.key,
                self.ext_flags,
                self.tkt_flags,
                self.cfg_flags,
                acc_code,
            )
        } else {
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
    }

    // -- common builder methods (SlotConfiguration) ------------------------

    pub fn serial_api_visible(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::SERIAL_API_VISIBLE, value);
        self
    }

    pub fn serial_usb_visible(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::SERIAL_USB_VISIBLE, value);
        self
    }

    pub fn allow_update(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::ALLOW_UPDATE, value);
        self
    }

    pub fn dormant(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::DORMANT, value);
        self
    }

    pub fn invert_led(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::LED_INV, value);
        self
    }

    pub fn protect_slot2(mut self, value: bool) -> Result<Self, YubiOtpError> {
        if self.kind == SlotConfigKind::Update {
            return Err(YubiOtpError::InvalidParameter(
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

    pub fn append_cr(mut self, value: bool) -> Self {
        self.set_flag_tkt(TktFlag::APPEND_CR, value);
        self
    }

    pub fn fast_trigger(mut self, value: bool) -> Self {
        self.set_flag_ext(ExtFlag::FAST_TRIG, value);
        self
    }

    pub fn pacing(mut self, pacing_10ms: bool, pacing_20ms: bool) -> Self {
        self.set_flag_cfg(CfgFlag::PACING_10MS, pacing_10ms);
        self.set_flag_cfg(CfgFlag::PACING_20MS, pacing_20ms);
        self
    }

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
            return Err(YubiOtpError::InvalidParameter(format!(
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
            return Err(YubiOtpError::InvalidParameter(
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

    pub fn short_ticket(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::SHORT_TICKET, value);
        self
    }

    pub fn strong_password(mut self, upper_case: bool, digit: bool, special: bool) -> Self {
        self.set_flag_cfg(CfgFlag::STRONG_PW1, upper_case);
        self.set_flag_cfg(CfgFlag::STRONG_PW2, digit || special);
        self.set_flag_cfg(CfgFlag::SEND_REF, special);
        self
    }

    pub fn manual_update(mut self, value: bool) -> Self {
        self.set_flag_cfg(CfgFlag::MAN_UPDATE, value);
        self
    }

    // -- UpdateConfiguration flag validation ------------------------------

    /// Set a flag with update-mode validation (for Update configs).
    /// Returns error if an unsupported flag is used in update mode.
    pub fn set_update_tkt_flag(mut self, flag: TktFlag, value: bool) -> Result<Self, YubiOtpError> {
        if self.kind == SlotConfigKind::Update && (flag.0 & !TKTFLAG_UPDATE_MASK) != 0 {
            return Err(YubiOtpError::InvalidParameter(
                "Unsupported TKT flag for update".into(),
            ));
        }
        self.set_flag_tkt(flag, value);
        Ok(self)
    }

    pub fn set_update_cfg_flag(mut self, flag: CfgFlag, value: bool) -> Result<Self, YubiOtpError> {
        if self.kind == SlotConfigKind::Update && (flag.0 & !CFGFLAG_UPDATE_MASK) != 0 {
            return Err(YubiOtpError::InvalidParameter(
                "Unsupported CFG flag for update".into(),
            ));
        }
        self.set_flag_cfg(flag, value);
        Ok(self)
    }
}

// ---------------------------------------------------------------------------
// YubiOtpSession — SmartCard backend
// ---------------------------------------------------------------------------

/// A session with the YubiOTP application over a SmartCard connection.
pub struct YubiOtpSession<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
    status: Vec<u8>,
    prog_seq: u8,
}

impl<C: SmartCardConnection> YubiOtpSession<C> {
    /// Open a YubiOTP session on the given SmartCard connection.
    pub fn new(connection: C) -> Result<Self, YubiOtpError> {
        let mut protocol = SmartCardProtocol::new(connection);
        let status = protocol.select(Aid::OTP)?;
        Self::init(protocol, &status)
    }

    /// Open a YubiOTP session with SCP (Secure Channel Protocol).
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, YubiOtpError> {
        let mut protocol = SmartCardProtocol::new(connection);
        let status = protocol.select(Aid::OTP)?;
        protocol.init_scp(scp_key_params)?;
        Self::init(protocol, &status)
    }

    fn init(mut protocol: SmartCardProtocol<C>, status: &[u8]) -> Result<Self, YubiOtpError> {
        log::debug!("Opening YubiOtpSession (SmartCard)");
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

    /// The firmware version of the YubiKey.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Override the firmware version (used for dev devices).
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    /// Get the serial number of the YubiKey.
    pub fn get_serial(&mut self) -> Result<u32, YubiOtpError> {
        let resp = self.send_and_receive(ConfigSlot::DeviceSerial, &[], 4)?;
        Ok(u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]))
    }

    /// Get the current configuration state.
    pub fn get_config_state(&self) -> ConfigState {
        let touch_level = if self.status.len() >= 6 {
            u16::from_le_bytes([self.status[4], self.status[5]])
        } else {
            0
        };
        ConfigState::new(self.version, touch_level)
    }

    /// Write a configuration to a slot.
    pub fn put_configuration(
        &mut self,
        slot: Slot,
        config: &SlotConfiguration,
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
        if !config.is_supported_by(self.version) {
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
    ) -> Result<(), YubiOtpError> {
        if !config.is_supported_by(self.version) {
            return Err(YubiOtpError::NotSupported(
                "This configuration is not supported on this YubiKey version".into(),
            ));
        }
        if acc_code != cur_acc_code
            && self.version >= Version(4, 3, 2)
            && self.version < Version(4, 3, 6)
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
    pub fn swap_slots(&mut self) -> Result<(), YubiOtpError> {
        self.write_config(ConfigSlot::Swap, &[], None)
    }

    /// Delete the configuration stored in a slot.
    pub fn delete_slot(
        &mut self,
        slot: Slot,
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
        let config_slot = slot.map(ConfigSlot::Config1, ConfigSlot::Config2);
        self.write_config(config_slot, &[0u8; CONFIG_SIZE], cur_acc_code)
    }

    /// Update scan-code map on the YubiKey.
    pub fn set_scan_map(
        &mut self,
        scan_map: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
        self.write_config(ConfigSlot::ScanMap, scan_map, cur_acc_code)
    }

    /// Configure a slot to be used over NDEF (NFC).
    pub fn set_ndef_configuration(
        &mut self,
        slot: Slot,
        uri: Option<&str>,
        cur_acc_code: Option<&[u8]>,
        ndef_type: NdefType,
    ) -> Result<(), YubiOtpError> {
        let config_slot = slot.map(ConfigSlot::Ndef1, ConfigSlot::Ndef2);
        let ndef_data = build_ndef_config(uri, ndef_type)?;
        self.write_config(config_slot, &ndef_data, cur_acc_code)
    }

    /// Perform an HMAC-SHA1 challenge-response operation.
    pub fn calculate_hmac_sha1(
        &mut self,
        slot: Slot,
        challenge: &[u8],
    ) -> Result<Vec<u8>, YubiOtpError> {
        require_version(self.version, Version(2, 2, 0))?;
        let config_slot = slot.map(ConfigSlot::ChalHmac1, ConfigSlot::ChalHmac2);

        // Pad challenge to HMAC_CHALLENGE_SIZE with a byte different from the last
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

    /// Access the underlying SmartCardProtocol.
    pub fn protocol(&self) -> &SmartCardProtocol<C> {
        &self.protocol
    }

    /// Access the underlying SmartCardProtocol mutably.
    pub fn protocol_mut(&mut self) -> &mut SmartCardProtocol<C> {
        &mut self.protocol
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        self.protocol.into_connection()
    }

    // -- internal (pub for PyO3 wrapper) -------------------------------------

    /// Write raw config bytes to a config slot (SmartCard).
    pub fn write_config(
        &mut self,
        slot: ConfigSlot,
        config: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
        let mut data = config.to_vec();
        match cur_acc_code {
            Some(ac) => data.extend_from_slice(ac),
            None => data.extend_from_slice(&[0u8; ACC_CODE_SIZE]),
        }
        self.write_update(slot, &data)?;
        Ok(())
    }

    fn write_update(&mut self, slot: ConfigSlot, data: &[u8]) -> Result<Vec<u8>, YubiOtpError> {
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
        Err(YubiOtpError::CommandRejected("Not updated".into()))
    }

    /// Send a command and receive a response of expected length.
    pub fn send_and_receive(
        &mut self,
        slot: ConfigSlot,
        data: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, YubiOtpError> {
        let response = self
            .protocol
            .send_apdu(0, INS_CONFIG, slot as u8, 0, data)?;
        if response.len() == expected_len {
            Ok(response)
        } else {
            Err(YubiOtpError::BadResponse(format!(
                "Unexpected response length: expected {expected_len}, got {}",
                response.len()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// YubiOtpOtpSession — HID OTP backend
// ---------------------------------------------------------------------------

/// A session with the YubiOTP application over an OTP HID connection.
pub struct YubiOtpOtpSession {
    protocol: OtpProtocol<OtpConnection>,
    status: Vec<u8>,
    version: Version,
}

impl YubiOtpOtpSession {
    /// Open a YubiOTP session on the given HID connection.
    pub fn new(connection: OtpConnection) -> Result<Self, YubiOtpError> {
        log::debug!("Opening YubiOtpOtpSession (HID)");
        let protocol = OtpProtocol::new(connection)?;
        let status = protocol.read_status()?;
        let version = patch_version(protocol.version);

        Ok(Self {
            protocol,
            status,
            version,
        })
    }

    /// The firmware version of the YubiKey.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Override the firmware version (used for dev devices).
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    /// Get the serial number of the YubiKey.
    pub fn get_serial(&self) -> Result<u32, YubiOtpError> {
        let resp = self.send_and_receive(ConfigSlot::DeviceSerial, &[], 4)?;
        Ok(u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]))
    }

    /// Get the current configuration state.
    pub fn get_config_state(&self) -> ConfigState {
        let touch_level = if self.status.len() >= 6 {
            u16::from_le_bytes([self.status[4], self.status[5]])
        } else {
            0
        };
        ConfigState::new(self.version, touch_level)
    }

    /// Write a configuration to a slot.
    pub fn put_configuration(
        &mut self,
        slot: Slot,
        config: &SlotConfiguration,
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
        if !config.is_supported_by(self.version) {
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
    ) -> Result<(), YubiOtpError> {
        if !config.is_supported_by(self.version) {
            return Err(YubiOtpError::NotSupported(
                "This configuration is not supported on this YubiKey version".into(),
            ));
        }
        if acc_code != cur_acc_code
            && self.version >= Version(4, 3, 2)
            && self.version < Version(4, 3, 6)
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
    pub fn swap_slots(&mut self) -> Result<(), YubiOtpError> {
        self.write_config(ConfigSlot::Swap, &[], None)
    }

    /// Delete the configuration stored in a slot.
    pub fn delete_slot(
        &mut self,
        slot: Slot,
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
        let config_slot = slot.map(ConfigSlot::Config1, ConfigSlot::Config2);
        self.write_config(config_slot, &[0u8; CONFIG_SIZE], cur_acc_code)
    }

    /// Update scan-code map on the YubiKey.
    pub fn set_scan_map(
        &mut self,
        scan_map: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
        self.write_config(ConfigSlot::ScanMap, scan_map, cur_acc_code)
    }

    /// Configure a slot to be used over NDEF (NFC).
    pub fn set_ndef_configuration(
        &mut self,
        slot: Slot,
        uri: Option<&str>,
        cur_acc_code: Option<&[u8]>,
        ndef_type: NdefType,
    ) -> Result<(), YubiOtpError> {
        let config_slot = slot.map(ConfigSlot::Ndef1, ConfigSlot::Ndef2);
        let ndef_data = build_ndef_config(uri, ndef_type)?;
        self.write_config(config_slot, &ndef_data, cur_acc_code)
    }

    /// Perform an HMAC-SHA1 challenge-response operation.
    pub fn calculate_hmac_sha1(
        &mut self,
        slot: Slot,
        challenge: &[u8],
        cancel: Option<Arc<AtomicBool>>,
        on_keepalive: Option<&dyn Fn(u8)>,
    ) -> Result<Vec<u8>, YubiOtpError> {
        require_version(self.version, Version(2, 2, 0))?;
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
            cancel.as_ref().map(|a| a.as_ref()),
            on_keepalive,
        )?;

        response.ok_or_else(|| YubiOtpError::BadResponse("No data in HMAC response".into()))
    }

    // -- internal (pub for PyO3 wrapper) -------------------------------------

    /// Write raw config bytes to a config slot (HID/OTP).
    pub fn write_config(
        &mut self,
        slot: ConfigSlot,
        config: &[u8],
        cur_acc_code: Option<&[u8]>,
    ) -> Result<(), YubiOtpError> {
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
        &self,
        slot: ConfigSlot,
        data: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, YubiOtpError> {
        let send_data = if data.is_empty() { None } else { Some(data) };
        self.protocol
            .send_and_receive(slot as u8, send_data, Some(expected_len as i32))?
            .ok_or_else(|| YubiOtpError::BadResponse("Expected data response, got status".into()))
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
