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

//! Management application protocol.
//!
//! Provides device configuration, capability queries, and mode setting for
//! YubiKeys accessible over SmartCard (CCID).

use std::collections::HashMap;
use std::fmt;

use crate::core::{Transport, Version, bytes2int, patch_version};
use crate::fido::FidoConnection;
use crate::otp::{
    OtpConnection, OtpProtocol, STATUS_OFFSET_PROG_SEQ, YubiOtpError, verify_and_strip_crc,
};
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol};
use crate::tlv::{int2bytes, parse_tlv_dict, tlv_encode};
use crate::transport::ctaphid::CtapHidTransportError;
use crate::yubiotp::ConfigSlot;

// ---------------------------------------------------------------------------
// APDU instruction constants
// ---------------------------------------------------------------------------

const INS_SET_MODE: u8 = 0x16;
const INS_READ_CONFIG: u8 = 0x1D;
const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_DEVICE_RESET: u8 = 0x1F;
const P1_DEVICE_CONFIG: u8 = 0x11;

// OTP slot constant for NEO mode set
const CONFIG_SLOT_DEVICE_CONFIG: u8 = 0x11;

// ---------------------------------------------------------------------------
// TLV Tags
// ---------------------------------------------------------------------------

const TAG_USB_SUPPORTED: u32 = 0x01;
const TAG_SERIAL: u32 = 0x02;
const TAG_USB_ENABLED: u32 = 0x03;
const TAG_FORM_FACTOR: u32 = 0x04;
const TAG_VERSION: u32 = 0x05;
const TAG_AUTO_EJECT_TIMEOUT: u32 = 0x06;
const TAG_CHALRESP_TIMEOUT: u32 = 0x07;
const TAG_DEVICE_FLAGS: u32 = 0x08;
#[allow(dead_code)]
const TAG_APP_VERSIONS: u32 = 0x09;
const TAG_CONFIG_LOCK: u32 = 0x0A;
const TAG_UNLOCK: u32 = 0x0B;
const TAG_REBOOT: u32 = 0x0C;
const TAG_NFC_SUPPORTED: u32 = 0x0D;
const TAG_NFC_ENABLED: u32 = 0x0E;
#[allow(dead_code)]
const TAG_IAP_DETECTION: u32 = 0x0F;
const TAG_MORE_DATA: u32 = 0x10;
#[allow(dead_code)]
const TAG_FREE_FORM: u32 = 0x11;
#[allow(dead_code)]
const TAG_HID_INIT_DELAY: u32 = 0x12;
const TAG_PART_NUMBER: u32 = 0x13;
const TAG_FIPS_CAPABLE: u32 = 0x14;
const TAG_FIPS_APPROVED: u32 = 0x15;
const TAG_PIN_COMPLEXITY: u32 = 0x16;
const TAG_NFC_RESTRICTED: u32 = 0x17;
const TAG_RESET_BLOCKED: u32 = 0x18;
const TAG_VERSION_QUALIFIER: u32 = 0x19;
const TAG_FPS_VERSION: u32 = 0x20;
const TAG_STM_VERSION: u32 = 0x21;

// ---------------------------------------------------------------------------
// Capability (bitflags)
// ---------------------------------------------------------------------------

/// YubiKey application capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capability(pub u16);

impl Capability {
    pub const OTP: Self = Self(0x01);
    pub const U2F: Self = Self(0x02);
    pub const OPENPGP: Self = Self(0x08);
    pub const PIV: Self = Self(0x10);
    pub const OATH: Self = Self(0x20);
    pub const HSMAUTH: Self = Self(0x100);
    pub const FIDO2: Self = Self(0x200);
    pub const NONE: Self = Self(0);

    /// Decode FIPS capability bitmask to [`Capability`] flags.
    pub fn from_fips(fips: u16) -> Self {
        let mut c = 0u16;
        if fips & (1 << 0) != 0 {
            c |= Self::FIDO2.0;
        }
        if fips & (1 << 1) != 0 {
            c |= Self::PIV.0;
        }
        if fips & (1 << 2) != 0 {
            c |= Self::OPENPGP.0;
        }
        if fips & (1 << 3) != 0 {
            c |= Self::OATH.0;
        }
        if fips & (1 << 4) != 0 {
            c |= Self::HSMAUTH.0;
        }
        Self(c)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// All known capabilities in display order.
    pub const ALL: &[Self] = &[
        Self::OTP,
        Self::U2F,
        Self::FIDO2,
        Self::OATH,
        Self::PIV,
        Self::OPENPGP,
        Self::HSMAUTH,
    ];

    /// Human-readable display name for this capability.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::OTP => "Yubico OTP",
            Self::U2F => "FIDO U2F",
            Self::FIDO2 => "FIDO2",
            Self::OATH => "OATH",
            Self::PIV => "PIV",
            Self::OPENPGP => "OpenPGP",
            Self::HSMAUTH => "YubiHSM Auth",
            _ => "Unknown",
        }
    }
}

impl std::ops::BitOr for Capability {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for Capability {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for Capability {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for Capability {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: &[(Self, &str)] = &[
            (Self::OTP, "OTP"),
            (Self::U2F, "U2F"),
            (Self::OPENPGP, "OPENPGP"),
            (Self::PIV, "PIV"),
            (Self::OATH, "OATH"),
            (Self::HSMAUTH, "HSMAUTH"),
            (Self::FIDO2, "FIDO2"),
        ];
        let mut parts = Vec::new();
        for &(cap, name) in names {
            if self.0 & cap.0 != 0 {
                parts.push(name);
            }
        }
        if parts.is_empty() {
            write!(f, "None: 0x00")
        } else {
            write!(f, "{}: {:#06x}", parts.join("|"), self.0)
        }
    }
}

// ---------------------------------------------------------------------------
// FormFactor
// ---------------------------------------------------------------------------

/// YubiKey device form factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FormFactor {
    Unknown = 0x00,
    UsbAKeychain = 0x01,
    UsbANano = 0x02,
    UsbCKeychain = 0x03,
    UsbCNano = 0x04,
    UsbCLightning = 0x05,
    UsbABio = 0x06,
    UsbCBio = 0x07,
}

impl FormFactor {
    /// Decode a form factor byte, masking to bottom 4 bits.
    pub fn from_code(code: u8) -> Self {
        match code & 0x0F {
            0x01 => Self::UsbAKeychain,
            0x02 => Self::UsbANano,
            0x03 => Self::UsbCKeychain,
            0x04 => Self::UsbCNano,
            0x05 => Self::UsbCLightning,
            0x06 => Self::UsbABio,
            0x07 => Self::UsbCBio,
            _ => Self::Unknown,
        }
    }

    pub fn is_bio(self) -> bool {
        matches!(self, Self::UsbABio | Self::UsbCBio)
    }
}

impl fmt::Display for FormFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UsbAKeychain => write!(f, "Keychain (USB-A)"),
            Self::UsbANano => write!(f, "Nano (USB-A)"),
            Self::UsbCKeychain => write!(f, "Keychain (USB-C)"),
            Self::UsbCNano => write!(f, "Nano (USB-C)"),
            Self::UsbCLightning => write!(f, "Keychain (USB-C, Lightning)"),
            Self::UsbABio => write!(f, "Bio (USB-A)"),
            Self::UsbCBio => write!(f, "Bio (USB-C)"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceFlag (bitflags)
// ---------------------------------------------------------------------------

/// Device configuration flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceFlag(pub u8);

impl DeviceFlag {
    pub const REMOTE_WAKEUP: Self = Self(0x40);
    pub const EJECT: Self = Self(0x80);
    pub const NONE: Self = Self(0);

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for DeviceFlag {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for DeviceFlag {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for DeviceFlag {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl fmt::Display for DeviceFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:02x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// ReleaseType
// ---------------------------------------------------------------------------

/// YubiKey release type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReleaseType {
    Alpha = 0,
    Beta = 1,
    Final = 2,
}

impl ReleaseType {
    pub fn from_value(v: u8) -> Self {
        match v {
            0 => Self::Alpha,
            1 => Self::Beta,
            _ => Self::Final,
        }
    }
}

impl fmt::Display for ReleaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alpha => write!(f, "alpha"),
            Self::Beta => write!(f, "beta"),
            Self::Final => write!(f, "final"),
        }
    }
}

// ---------------------------------------------------------------------------
// VersionQualifier
// ---------------------------------------------------------------------------

/// Fully qualified YubiKey version (version + release type + iteration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionQualifier {
    pub version: Version,
    pub release_type: ReleaseType,
    pub iteration: u8,
}

impl VersionQualifier {
    pub fn new(version: Version, release_type: ReleaseType, iteration: u8) -> Self {
        Self {
            version,
            release_type,
            iteration,
        }
    }

    pub fn final_release(version: Version) -> Self {
        Self {
            version,
            release_type: ReleaseType::Final,
            iteration: 0,
        }
    }
}

impl fmt::Display for VersionQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            self.version, self.release_type, self.iteration
        )
    }
}

// ---------------------------------------------------------------------------
// USB Interface / Mode
// ---------------------------------------------------------------------------

/// USB interface flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbInterface(pub u8);

impl UsbInterface {
    pub const OTP: Self = Self(0x01);
    pub const CCID: Self = Self(0x02);
    pub const FIDO: Self = Self(0x04);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for UsbInterface {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for UsbInterface {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl fmt::Display for UsbInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.0 & Self::OTP.0 != 0 {
            parts.push("OTP");
        }
        if self.0 & Self::FIDO.0 != 0 {
            parts.push("FIDO");
        }
        if self.0 & Self::CCID.0 != 0 {
            parts.push("CCID");
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// Predefined USB interface mode combinations.
const MODES: [UsbInterface; 7] = [
    UsbInterface::OTP,                                         // 0
    UsbInterface::CCID,                                        // 1
    UsbInterface(UsbInterface::OTP.0 | UsbInterface::CCID.0),  // 2
    UsbInterface::FIDO,                                        // 3
    UsbInterface(UsbInterface::OTP.0 | UsbInterface::FIDO.0),  // 4
    UsbInterface(UsbInterface::FIDO.0 | UsbInterface::CCID.0), // 5
    UsbInterface(UsbInterface::OTP.0 | UsbInterface::FIDO.0 | UsbInterface::CCID.0), // 6
];

/// YubiKey USB Mode configuration for use with YubiKey NEO and 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    pub code: u8,
    pub interfaces: UsbInterface,
}

impl Mode {
    pub fn new(interfaces: UsbInterface) -> Option<Self> {
        MODES
            .iter()
            .position(|m| m.0 == interfaces.0)
            .map(|code| Self {
                code: code as u8,
                interfaces,
            })
    }

    /// Decode a mode from its code byte (bottom 3 bits).
    pub fn from_code(code: u8) -> Option<Self> {
        let idx = (code & 0x07) as usize;
        MODES.get(idx).map(|&interfaces| Self {
            code: idx as u8,
            interfaces,
        })
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.interfaces.0 & UsbInterface::OTP.0 != 0 {
            parts.push("OTP");
        }
        if self.interfaces.0 & UsbInterface::CCID.0 != 0 {
            parts.push("CCID");
        }
        if self.interfaces.0 & UsbInterface::FIDO.0 != 0 {
            parts.push("FIDO");
        }
        write!(f, "{}", parts.join("+"))
    }
}

// ---------------------------------------------------------------------------
// DeviceConfig
// ---------------------------------------------------------------------------

/// Management settings for YubiKey which can be configured by the user.
#[derive(Debug, Clone, Default)]
pub struct DeviceConfig {
    pub enabled_capabilities: HashMap<Transport, Capability>,
    pub auto_eject_timeout: Option<u16>,
    pub challenge_response_timeout: Option<u8>,
    pub device_flags: Option<DeviceFlag>,
    pub nfc_restricted: Option<bool>,
}

impl DeviceConfig {
    /// Serialize to TLV format for write_config APDU.
    pub fn get_bytes(
        &self,
        reboot: bool,
        cur_lock_code: Option<&[u8]>,
        new_lock_code: Option<&[u8]>,
    ) -> Result<Vec<u8>, SmartCardError> {
        let mut buf = Vec::new();

        if reboot {
            buf.extend_from_slice(&tlv_encode(TAG_REBOOT, &[]));
        }
        if let Some(code) = cur_lock_code {
            buf.extend_from_slice(&tlv_encode(TAG_UNLOCK, code));
        }
        if let Some(&usb_enabled) = self.enabled_capabilities.get(&Transport::Usb) {
            buf.extend_from_slice(&tlv_encode(
                TAG_USB_ENABLED,
                &(usb_enabled.0).to_be_bytes()[..2],
            ));
        }
        if let Some(&nfc_enabled) = self.enabled_capabilities.get(&Transport::Nfc) {
            buf.extend_from_slice(&tlv_encode(
                TAG_NFC_ENABLED,
                &(nfc_enabled.0).to_be_bytes()[..2],
            ));
        }
        if let Some(timeout) = self.auto_eject_timeout {
            buf.extend_from_slice(&tlv_encode(TAG_AUTO_EJECT_TIMEOUT, &timeout.to_be_bytes()));
        }
        if let Some(timeout) = self.challenge_response_timeout {
            buf.extend_from_slice(&tlv_encode(
                TAG_CHALRESP_TIMEOUT,
                &int2bytes(timeout as u64),
            ));
        }
        if let Some(flags) = self.device_flags {
            buf.extend_from_slice(&tlv_encode(TAG_DEVICE_FLAGS, &int2bytes(flags.0 as u64)));
        }
        if let Some(code) = new_lock_code {
            buf.extend_from_slice(&tlv_encode(TAG_CONFIG_LOCK, code));
        }
        if self.nfc_restricted == Some(true) {
            buf.extend_from_slice(&tlv_encode(TAG_NFC_RESTRICTED, &[0x01]));
        }

        if buf.len() > 0xFF {
            return Err(SmartCardError::NotSupported(
                "DeviceConfiguration too large".into(),
            ));
        }

        let mut result = int2bytes(buf.len() as u64);
        result.extend_from_slice(&buf);
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// DeviceInfo
// ---------------------------------------------------------------------------

/// Full device information readable from a YubiKey.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub config: DeviceConfig,
    pub serial: Option<u32>,
    pub version: Version,
    pub form_factor: FormFactor,
    pub supported_capabilities: HashMap<Transport, Capability>,
    pub is_locked: bool,
    pub is_fips: bool,
    pub is_sky: bool,
    pub part_number: Option<String>,
    pub fips_capable: Capability,
    pub fips_approved: Capability,
    pub pin_complexity: bool,
    pub reset_blocked: Capability,
    pub fps_version: Option<Version>,
    pub stm_version: Option<Version>,
    pub version_qualifier: VersionQualifier,
}

impl DeviceInfo {
    /// Parse a length-prefixed TLV response into [`DeviceInfo`].
    pub fn parse(encoded: &[u8], default_version: Version) -> Result<Self, SmartCardError> {
        if encoded.is_empty() {
            return Err(SmartCardError::BadResponse("Empty response".into()));
        }
        let expected_len = encoded[0] as usize;
        if encoded.len() - 1 != expected_len {
            return Err(SmartCardError::BadResponse("Invalid length".into()));
        }
        let tlvs = parse_tlv_dict(&encoded[1..])?;
        Self::parse_tlvs(&tlvs, default_version)
    }

    /// Parse a map of tag→value pairs into [`DeviceInfo`].
    pub fn parse_tlvs(
        data: &HashMap<u32, Vec<u8>>,
        default_version: Version,
    ) -> Result<Self, SmartCardError> {
        let locked = data.get(&TAG_CONFIG_LOCK).is_some_and(|v| v == &[0x01]);
        let serial = {
            let raw = bytes2int(data.get(&TAG_SERIAL).map_or(&[0u8][..], |v| v));
            if raw == 0 { None } else { Some(raw as u32) }
        };

        let ff_value = bytes2int(data.get(&TAG_FORM_FACTOR).map_or(&[0u8][..], |v| v)) as u8;
        let form_factor = FormFactor::from_code(ff_value);
        let is_fips = ff_value & 0x80 != 0;
        let is_sky = ff_value & 0x40 != 0;

        let mut version = if let Some(v) = data.get(&TAG_VERSION) {
            Version::from_bytes(v)
        } else {
            default_version
        };

        let auto_eject_to =
            bytes2int(data.get(&TAG_AUTO_EJECT_TIMEOUT).map_or(&[0u8][..], |v| v)) as u16;
        let chal_resp_to =
            bytes2int(data.get(&TAG_CHALRESP_TIMEOUT).map_or(&[0u8][..], |v| v)) as u8;
        let flags =
            DeviceFlag(bytes2int(data.get(&TAG_DEVICE_FLAGS).map_or(&[0u8][..], |v| v)) as u8);

        let mut supported = HashMap::new();
        let mut enabled = HashMap::new();

        // Version 4.2.4 doesn't report USB capabilities correctly
        if version == Version(4, 2, 4) {
            supported.insert(Transport::Usb, Capability(0x3F));
        } else if let Some(v) = data.get(&TAG_USB_SUPPORTED) {
            supported.insert(Transport::Usb, Capability(bytes2int(v) as u16));
        }

        if let Some(v) = data.get(&TAG_USB_ENABLED) {
            // Broken on YK4 (4.0.0 <= version < 5.0.0) — skip
            if !(version >= Version(4, 0, 0) && version < Version(5, 0, 0)) {
                enabled.insert(Transport::Usb, Capability(bytes2int(v) as u16));
            }
        }

        if let Some(v) = data.get(&TAG_NFC_SUPPORTED) {
            supported.insert(Transport::Nfc, Capability(bytes2int(v) as u16));
            if let Some(nfc_en) = data.get(&TAG_NFC_ENABLED) {
                enabled.insert(Transport::Nfc, Capability(bytes2int(nfc_en) as u16));
            }
        }

        let nfc_restricted = data.get(&TAG_NFC_RESTRICTED).is_some_and(|v| v == &[0x01]);

        let part_number = data.get(&TAG_PART_NUMBER).and_then(|v| {
            let s = String::from_utf8(v.clone()).ok()?;
            if s.is_empty() { None } else { Some(s) }
        });

        let fips_capable = Capability::from_fips(bytes2int(
            data.get(&TAG_FIPS_CAPABLE).map_or(&[0u8][..], |v| v),
        ) as u16);
        let fips_approved = Capability::from_fips(bytes2int(
            data.get(&TAG_FIPS_APPROVED).map_or(&[0u8][..], |v| v),
        ) as u16);
        let pin_complexity = data.get(&TAG_PIN_COMPLEXITY).is_some_and(|v| v == &[0x01]);
        let reset_blocked =
            Capability(bytes2int(data.get(&TAG_RESET_BLOCKED).map_or(&[0u8][..], |v| v)) as u16);

        let version_qualifier = if let Some(vq_data) = data.get(&TAG_VERSION_QUALIFIER) {
            let vq_tlvs = parse_tlv_dict(vq_data)?;
            let vq_version = vq_tlvs
                .get(&0x01)
                .map(|v| Version::from_bytes(v))
                .unwrap_or(version);
            let vq_type = vq_tlvs
                .get(&0x02)
                .map(|v| ReleaseType::from_value(bytes2int(v) as u8))
                .unwrap_or(ReleaseType::Final);
            let vq_iter = vq_tlvs.get(&0x03).map(|v| bytes2int(v) as u8).unwrap_or(0);
            let vq = VersionQualifier::new(vq_version, vq_type, vq_iter);
            // Override behavioral version for non-final releases
            if vq.release_type != ReleaseType::Final {
                version = vq.version;
            }
            vq
        } else {
            VersionQualifier::final_release(version)
        };

        let fps_version = data
            .get(&TAG_FPS_VERSION)
            .map(|v| Version::from_bytes(v))
            .and_then(|v| if v == Version(0, 0, 0) { None } else { Some(v) });
        let stm_version = data
            .get(&TAG_STM_VERSION)
            .map(|v| Version::from_bytes(v))
            .and_then(|v| if v == Version(0, 0, 0) { None } else { Some(v) });

        let config = DeviceConfig {
            enabled_capabilities: enabled,
            auto_eject_timeout: Some(auto_eject_to),
            challenge_response_timeout: Some(chal_resp_to),
            device_flags: Some(flags),
            nfc_restricted: Some(nfc_restricted),
        };

        Ok(Self {
            config,
            serial,
            version,
            form_factor,
            supported_capabilities: supported,
            is_locked: locked,
            is_fips,
            is_sky,
            part_number,
            fips_capable,
            fips_approved,
            pin_complexity,
            reset_blocked,
            fps_version,
            stm_version,
            version_qualifier,
        })
    }

    pub fn has_transport(&self, transport: Transport) -> bool {
        self.supported_capabilities.contains_key(&transport)
    }

    pub fn version_name(&self) -> String {
        if self.version_qualifier.release_type != ReleaseType::Final {
            self.version_qualifier.to_string()
        } else if self.version != Version(0, 0, 0) {
            self.version.to_string()
        } else {
            "unknown".into()
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Read device info by iterating config pages via the supplied reader closure.
fn read_device_info_from_config(
    version: Version,
    read_config: &mut dyn FnMut(u8) -> Result<Vec<u8>, SmartCardError>,
) -> Result<DeviceInfo, SmartCardError> {
    let mut tlvs: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut page: u8 = 0;
    loop {
        let encoded = read_config(page)?;
        if encoded.is_empty() {
            return Err(SmartCardError::BadResponse("Empty config response".into()));
        }
        let expected_len = encoded[0] as usize;
        if encoded.len() - 1 != expected_len {
            return Err(SmartCardError::BadResponse("Invalid length".into()));
        }
        let page_tlvs = parse_tlv_dict(&encoded[1..])?;
        let more_data = page_tlvs.get(&TAG_MORE_DATA).is_some_and(|v| v == &[0x01]);
        for (tag, value) in page_tlvs {
            if tag != TAG_MORE_DATA {
                tlvs.insert(tag, value);
            }
        }
        if !more_data {
            break;
        }
        page += 1;
    }
    DeviceInfo::parse_tlvs(&tlvs, version)
}

/// Serialize a write_device_config call into bytes, with validation.
fn validate_and_serialize_device_config(
    version: Version,
    config: &DeviceConfig,
    reboot: bool,
    cur_lock_code: Option<&[u8]>,
    new_lock_code: Option<&[u8]>,
) -> Result<Vec<u8>, SmartCardError> {
    if version < Version(5, 0, 0) {
        return Err(SmartCardError::NotSupported(
            "write_device_config requires YubiKey 5.0.0 or later".into(),
        ));
    }
    if let Some(code) = cur_lock_code
        && code.len() != 16
    {
        return Err(SmartCardError::BadResponse(
            "Lock code must be 16 bytes".into(),
        ));
    }
    if let Some(code) = new_lock_code
        && code.len() != 16
    {
        return Err(SmartCardError::BadResponse(
            "Lock code must be 16 bytes".into(),
        ));
    }
    config.get_bytes(reboot, cur_lock_code, new_lock_code)
}

// ---------------------------------------------------------------------------
// ManagementSession trait
// ---------------------------------------------------------------------------

/// Common management session operations shared across transports.
pub trait ManagementSession {
    /// The firmware version of the YubiKey.
    fn version(&self) -> Version;

    /// Read a configuration page from the device.
    fn read_config(&mut self, page: u8) -> Result<Vec<u8>, SmartCardError>;

    /// Write configuration data to the device.
    fn write_config(&mut self, config: &[u8]) -> Result<(), SmartCardError>;

    /// Write USB mode configuration (YubiKey NEO/4 style).
    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> Result<(), SmartCardError>;

    /// Get detailed information about the YubiKey.
    fn read_device_info(&mut self) -> Result<DeviceInfo, SmartCardError> {
        log::debug!("Reading device info");
        if self.version() < Version(4, 1, 0) {
            return Err(SmartCardError::NotSupported(
                "DeviceInfo requires YubiKey 4.1.0 or later".into(),
            ));
        }
        self.read_device_info_unchecked()
    }

    /// Read device info without version check (for dev device version override).
    fn read_device_info_unchecked(&mut self) -> Result<DeviceInfo, SmartCardError> {
        read_device_info_from_config(self.version(), &mut |page| self.read_config(page))
    }

    /// Write configuration settings for YubiKey (requires 5.0.0+).
    fn write_device_config(
        &mut self,
        config: &DeviceConfig,
        reboot: bool,
        cur_lock_code: Option<&[u8]>,
        new_lock_code: Option<&[u8]>,
    ) -> Result<(), SmartCardError> {
        let data = validate_and_serialize_device_config(
            self.version(),
            config,
            reboot,
            cur_lock_code,
            new_lock_code,
        )?;
        self.write_config(&data)
    }
}

// ---------------------------------------------------------------------------
// ManagementCcidSession (SmartCard)
// ---------------------------------------------------------------------------

/// Management application session over SmartCard (CCID).
pub struct ManagementCcidSession<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
}

impl<C: SmartCardConnection> ManagementCcidSession<C> {
    /// Open a management session, selecting the management AID.
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new(connection: C) -> Result<Self, (SmartCardError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let select_bytes = match protocol.select(Aid::MANAGEMENT) {
            Ok(v) => v,
            Err(e) => return Err((e, protocol.into_connection())),
        };
        Self::init(protocol, &select_bytes)
    }

    /// Open a management session with SCP (Secure Channel Protocol).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, (SmartCardError, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let select_bytes = match protocol.select(Aid::MANAGEMENT) {
            Ok(v) => v,
            Err(e) => return Err((e, protocol.into_connection())),
        };
        if let Err(e) = protocol.init_scp(scp_key_params) {
            return Err((e, protocol.into_connection()));
        }
        Self::init(protocol, &select_bytes)
    }

    fn init(
        mut protocol: SmartCardProtocol<C>,
        select_bytes: &[u8],
    ) -> Result<Self, (SmartCardError, C)> {
        log::debug!("Opening ManagementCcidSession");
        // YubiKey Edge incorrectly appends SW twice
        let select_bytes =
            if select_bytes.len() >= 2 && select_bytes[select_bytes.len() - 2..] == [0x90, 0x00] {
                &select_bytes[..select_bytes.len() - 2]
            } else {
                select_bytes
            };

        let version_str = match std::str::from_utf8(select_bytes) {
            Ok(v) => v,
            Err(_) => {
                return Err((
                    SmartCardError::BadResponse("Invalid version string".into()),
                    protocol.into_connection(),
                ));
            }
        };
        let version = match parse_version_string(version_str) {
            Ok(v) => v,
            Err(e) => return Err((e, protocol.into_connection())),
        };
        let version = patch_version(version);

        // For YubiKey NEO (v3), switch to OTP applet for further commands
        if version.0 == 3 {
            // Workaround to "de-select" on NEO
            let _ = protocol
                .connection()
                .send_and_receive(&[0xa4, 0x04, 0x00, 0x08]);
            if let Err(e) = protocol.select(Aid::OTP) {
                return Err((e, protocol.into_connection()));
            }
        }

        protocol.configure(version);

        Ok(Self { protocol, version })
    }

    /// Get a mutable reference to the underlying protocol.
    pub fn protocol_mut(&mut self) -> &mut SmartCardProtocol<C> {
        &mut self.protocol
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        self.protocol.into_connection()
    }

    /// Global factory reset (YubiKey Bio only, SmartCard-only).
    pub fn device_reset(&mut self) -> Result<(), SmartCardError> {
        self.protocol.send_apdu(0, INS_DEVICE_RESET, 0, 0, &[])?;
        Ok(())
    }
}

impl<C: SmartCardConnection> ManagementSession for ManagementCcidSession<C> {
    fn version(&self) -> Version {
        self.version
    }

    fn read_config(&mut self, page: u8) -> Result<Vec<u8>, SmartCardError> {
        // YubiKey 4+ and dev devices use INS_READ_CONFIG.
        // YubiKey NEO (v3) also uses INS_READ_CONFIG but against the OTP applet
        // (selected during init).
        self.protocol.send_apdu(0, INS_READ_CONFIG, page, 0, &[])
    }

    fn write_config(&mut self, config: &[u8]) -> Result<(), SmartCardError> {
        self.protocol.send_apdu(0, INS_WRITE_CONFIG, 0, 0, config)?;
        Ok(())
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> Result<(), SmartCardError> {
        let data = [
            mode_code,
            chalresp_timeout,
            (auto_eject_timeout & 0xFF) as u8,
            (auto_eject_timeout >> 8) as u8,
        ];
        if self.version.0 == 3 {
            // NEO: using OTP application, INS=0x01, P1=SLOT_DEVICE_CONFIG
            self.protocol
                .send_apdu(0, 0x01, CONFIG_SLOT_DEVICE_CONFIG, 0, &data)?;
        } else {
            self.protocol
                .send_apdu(0, INS_SET_MODE, P1_DEVICE_CONFIG, 0, &data)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ManagementOtpSession (OTP/HID)
// ---------------------------------------------------------------------------

/// Management operations over the OTP (HID) interface.
pub struct ManagementOtpSession<T: OtpConnection> {
    protocol: OtpProtocol<T>,
    version: Version,
}

impl<T: OtpConnection> ManagementOtpSession<T> {
    /// Open a management session over OTP HID.
    pub fn new(connection: T) -> Result<Self, (YubiOtpError, T)> {
        log::debug!("Opening ManagementOtpSession");
        let protocol = match OtpProtocol::new(connection) {
            Ok(p) => p,
            Err((e, conn)) => return Err((e, conn)),
        };
        let version = patch_version(protocol.version);
        if version >= Version(1, 0, 0) && version < Version(3, 0, 0) {
            return Err((
                YubiOtpError::NotSupported(
                    "Management over OTP not supported for YubiKey v1.x-v2.x".into(),
                ),
                protocol.into_connection(),
            ));
        }
        Ok(Self { protocol, version })
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> T {
        self.protocol.into_connection()
    }
}

impl<T: OtpConnection> ManagementSession for ManagementOtpSession<T> {
    fn version(&self) -> Version {
        self.version
    }

    fn read_config(&mut self, page: u8) -> Result<Vec<u8>, SmartCardError> {
        let data = int2bytes(page as u64);
        let response = self
            .protocol
            .send_and_receive(ConfigSlot::Yk4Capabilities as u8, Some(&data), Some(-1))
            .map_err(otp_to_smartcard_err)?;
        match response {
            Some(raw) => {
                let r_len = raw[0] as usize;
                let checked =
                    verify_and_strip_crc(&raw, r_len + 1).map_err(otp_to_smartcard_err)?;
                Ok(checked)
            }
            None => Err(SmartCardError::BadResponse("Expected data response".into())),
        }
    }

    fn write_config(&mut self, config: &[u8]) -> Result<(), SmartCardError> {
        self.protocol
            .send_and_receive(ConfigSlot::Yk4SetDeviceInfo as u8, Some(config), None)
            .map_err(otp_to_smartcard_err)?;
        Ok(())
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> Result<(), SmartCardError> {
        let data = [
            mode_code,
            chalresp_timeout,
            (auto_eject_timeout & 0xFF) as u8,
            (auto_eject_timeout >> 8) as u8,
        ];
        let empty =
            self.protocol.read_status().map_err(otp_to_smartcard_err)?[STATUS_OFFSET_PROG_SEQ] == 0;
        match self
            .protocol
            .send_and_receive(ConfigSlot::DeviceConfig as u8, Some(&data), None)
        {
            Err(YubiOtpError::CommandRejected(_)) if empty => Ok(()),
            Err(e) => Err(otp_to_smartcard_err(e)),
            Ok(_) => Ok(()),
        }
    }
}

/// Convert a [`YubiOtpError`] into a [`SmartCardError`].
fn otp_to_smartcard_err(e: YubiOtpError) -> SmartCardError {
    match e {
        YubiOtpError::SmartCard(sc) => sc,
        YubiOtpError::BadResponse(msg) => SmartCardError::BadResponse(msg),
        YubiOtpError::NotSupported(msg) => SmartCardError::NotSupported(msg),
        other => SmartCardError::Transport(Box::new(other)),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a version string like "5.7.1" into a [`Version`].
fn parse_version_string(s: &str) -> Result<Version, SmartCardError> {
    // Try exact "X.Y.Z" first
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() == 3
        && let (Ok(a), Ok(b), Ok(c)) = (
            parts[0].parse::<u8>(),
            parts[1].parse::<u8>(),
            parts[2].parse::<u8>(),
        )
    {
        return Ok(Version(a, b, c));
    }
    // Search for N.N.N pattern anywhere in the string
    for window in s.split_whitespace() {
        let segs: Vec<&str> = window.split('.').collect();
        if segs.len() == 3
            && let (Ok(a), Ok(b), Ok(c)) = (
                segs[0].parse::<u8>(),
                segs[1].parse::<u8>(),
                segs[2].parse::<u8>(),
            )
        {
            return Ok(Version(a, b, c));
        }
    }
    Err(SmartCardError::BadResponse(format!(
        "Invalid version string: {s:?}"
    )))
}

// ---------------------------------------------------------------------------
// ManagementFidoSession (CTAP HID / FIDO)
// ---------------------------------------------------------------------------

/// Vendor CTAP commands for YubiKey management.
const CTAP_VENDOR_FIRST: u8 = 0x40;
const CTAP_YUBIKEY_DEVICE_CONFIG: u8 = CTAP_VENDOR_FIRST;
const CTAP_READ_CONFIG: u8 = CTAP_VENDOR_FIRST + 2;
const CTAP_WRITE_CONFIG: u8 = CTAP_VENDOR_FIRST + 3;

/// Management operations over the FIDO (CTAP HID) interface.
pub struct ManagementFidoSession<C: FidoConnection> {
    connection: C,
    version: Version,
}

impl<C: FidoConnection> ManagementFidoSession<C> {
    /// Open a management session over FIDO HID.
    pub fn new(connection: C) -> Result<Self, (SmartCardError, C)> {
        log::debug!("Opening ManagementFidoSession");
        let (v1, v2, v3) = connection.device_version();
        let mut version = Version(v1, v2, v3);
        // Prior to YK4 the device_version was not firmware version
        if v1 < 4 && (v1, v2, v3) != (0, 0, 1) && !(v1 == 0 && connection.capabilities().has_cbor())
        {
            version = Version(3, 0, 0); // Guess NEO
        }
        version = patch_version(version);
        Ok(Self {
            connection,
            version,
        })
    }

    /// Get a reference to the underlying connection.
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// Close the session and return the underlying connection.
    pub fn into_connection(self) -> C {
        self.connection
    }
}

impl<C: FidoConnection> ManagementSession for ManagementFidoSession<C> {
    fn version(&self) -> Version {
        self.version
    }

    fn read_config(&mut self, page: u8) -> Result<Vec<u8>, SmartCardError> {
        let data = int2bytes(page as u64);
        self.connection
            .call(CTAP_READ_CONFIG, &data)
            .map_err(fido_to_smartcard_err)
    }

    fn write_config(&mut self, config: &[u8]) -> Result<(), SmartCardError> {
        self.connection
            .call(CTAP_WRITE_CONFIG, config)
            .map_err(fido_to_smartcard_err)?;
        Ok(())
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> Result<(), SmartCardError> {
        let data = [
            mode_code,
            chalresp_timeout,
            (auto_eject_timeout & 0xFF) as u8,
            (auto_eject_timeout >> 8) as u8,
        ];
        self.connection
            .call(CTAP_YUBIKEY_DEVICE_CONFIG, &data)
            .map_err(fido_to_smartcard_err)?;
        Ok(())
    }
}

/// Convert a [`CtapHidTransportError`] into a [`SmartCardError`].
fn fido_to_smartcard_err(e: CtapHidTransportError) -> SmartCardError {
    SmartCardError::Transport(Box::new(e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_bitflags() {
        let c = Capability::OTP | Capability::FIDO2;
        assert!(c.contains(Capability::OTP));
        assert!(c.contains(Capability::FIDO2));
        assert!(!c.contains(Capability::PIV));
        assert_eq!(c.0, 0x201);

        let masked = c & Capability::OTP;
        assert_eq!(masked, Capability::OTP);
    }

    #[test]
    fn test_capability_from_fips() {
        let c = Capability::from_fips(0b11111);
        assert!(c.contains(Capability::FIDO2));
        assert!(c.contains(Capability::PIV));
        assert!(c.contains(Capability::OPENPGP));
        assert!(c.contains(Capability::OATH));
        assert!(c.contains(Capability::HSMAUTH));
    }

    #[test]
    fn test_capability_display() {
        let c = Capability::OTP | Capability::PIV;
        let s = c.to_string();
        assert!(s.contains("OTP"));
        assert!(s.contains("PIV"));
    }

    #[test]
    fn test_form_factor_from_code() {
        assert_eq!(FormFactor::from_code(0x01), FormFactor::UsbAKeychain);
        assert_eq!(FormFactor::from_code(0x07), FormFactor::UsbCBio);
        assert_eq!(FormFactor::from_code(0x00), FormFactor::Unknown);
        // High bits masked off
        assert_eq!(FormFactor::from_code(0x81), FormFactor::UsbAKeychain);
        assert_eq!(FormFactor::from_code(0xC3), FormFactor::UsbCKeychain);
        assert_eq!(FormFactor::from_code(0xFF), FormFactor::Unknown); // 0x0F not a valid form factor
    }

    #[test]
    fn test_form_factor_is_bio() {
        assert!(FormFactor::UsbABio.is_bio());
        assert!(FormFactor::UsbCBio.is_bio());
        assert!(!FormFactor::UsbAKeychain.is_bio());
    }

    #[test]
    fn test_device_flag_operations() {
        let f = DeviceFlag::REMOTE_WAKEUP | DeviceFlag::EJECT;
        assert_eq!(f.0, 0xC0);
        assert!(!f.is_empty());
        assert!(DeviceFlag::NONE.is_empty());
    }

    #[test]
    fn test_mode_from_code() {
        let m = Mode::from_code(0).unwrap();
        assert_eq!(m.interfaces, UsbInterface::OTP);
        assert_eq!(m.code, 0);

        let m = Mode::from_code(6).unwrap();
        assert_eq!(
            m.interfaces.0,
            UsbInterface::OTP.0 | UsbInterface::FIDO.0 | UsbInterface::CCID.0
        );

        // Bottom 3 bits only
        let m = Mode::from_code(0x83).unwrap();
        assert_eq!(m.interfaces, UsbInterface::FIDO);

        assert!(Mode::from_code(7).is_none());
    }

    #[test]
    fn test_device_config_get_bytes_empty() {
        let config = DeviceConfig::default();
        let bytes = config.get_bytes(false, None, None).unwrap();
        // Length prefix only: [0x00] (zero-length payload)
        assert_eq!(bytes, vec![0x00]);
    }

    #[test]
    fn test_device_config_get_bytes_with_reboot() {
        let config = DeviceConfig::default();
        let bytes = config.get_bytes(true, None, None).unwrap();
        // Length prefix + TAG_REBOOT TLV (tag=0x0C, len=0x00)
        assert_eq!(bytes[0] as usize, bytes.len() - 1);
        assert_eq!(bytes[1], TAG_REBOOT as u8);
        assert_eq!(bytes[2], 0x00);
    }

    #[test]
    fn test_device_config_get_bytes_with_capabilities() {
        let mut config = DeviceConfig::default();
        config
            .enabled_capabilities
            .insert(Transport::Usb, Capability(0x003F));
        let bytes = config.get_bytes(false, None, None).unwrap();
        assert_eq!(bytes[0] as usize, bytes.len() - 1);
        // Should contain TAG_USB_ENABLED
        assert_eq!(bytes[1], TAG_USB_ENABLED as u8);
        assert_eq!(bytes[2], 0x02); // length 2 bytes
        assert_eq!(bytes[3], 0x00);
        assert_eq!(bytes[4], 0x3F);
    }

    #[test]
    fn test_device_info_parse() {
        // Build a minimal TLV response: version=5.7.1, serial=12345678, form_factor=USB_C_KEYCHAIN,
        // usb_supported=0x023F, usb_enabled=0x023F
        let mut payload = Vec::new();
        payload.extend_from_slice(&tlv_encode(TAG_VERSION, &[5, 7, 1]));
        payload.extend_from_slice(&tlv_encode(TAG_SERIAL, &0x00BC614Eu32.to_be_bytes()));
        payload.extend_from_slice(&tlv_encode(TAG_FORM_FACTOR, &[0x03]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_SUPPORTED, &[0x02, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_ENABLED, &[0x02, 0x3F]));

        let mut encoded = vec![payload.len() as u8];
        encoded.extend_from_slice(&payload);

        let info = DeviceInfo::parse(&encoded, Version(0, 0, 0)).unwrap();
        assert_eq!(info.version, Version(5, 7, 1));
        assert_eq!(info.serial, Some(12345678));
        assert_eq!(info.form_factor, FormFactor::UsbCKeychain);
        assert_eq!(
            info.supported_capabilities.get(&Transport::Usb),
            Some(&Capability(0x023F))
        );
        assert_eq!(
            info.config.enabled_capabilities.get(&Transport::Usb),
            Some(&Capability(0x023F))
        );
        assert!(!info.is_fips);
        assert!(!info.is_sky);
        assert!(!info.is_locked);
    }

    #[test]
    fn test_device_info_parse_fips_sky_flags() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&tlv_encode(TAG_VERSION, &[5, 4, 3]));
        // form_factor with FIPS (0x80) and SKY (0x40) flags + USB_C_KEYCHAIN (0x03)
        payload.extend_from_slice(&tlv_encode(TAG_FORM_FACTOR, &[0xC3]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_SUPPORTED, &[0x00, 0x3F]));

        let mut encoded = vec![payload.len() as u8];
        encoded.extend_from_slice(&payload);

        let info = DeviceInfo::parse(&encoded, Version(0, 0, 0)).unwrap();
        assert!(info.is_fips);
        assert!(info.is_sky);
        assert_eq!(info.form_factor, FormFactor::UsbCKeychain);
    }

    #[test]
    fn test_device_info_parse_v424_workaround() {
        // Version 4.2.4 should hardcode USB supported to 0x3F
        let mut payload = Vec::new();
        payload.extend_from_slice(&tlv_encode(TAG_VERSION, &[4, 2, 4]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_SUPPORTED, &[0xFF, 0xFF])); // Wrong value
        payload.extend_from_slice(&tlv_encode(TAG_USB_ENABLED, &[0x00, 0x3F]));

        let mut encoded = vec![payload.len() as u8];
        encoded.extend_from_slice(&payload);

        let info = DeviceInfo::parse(&encoded, Version(0, 0, 0)).unwrap();
        // Supported should be overridden to 0x3F
        assert_eq!(
            info.supported_capabilities.get(&Transport::Usb),
            Some(&Capability(0x3F))
        );
        // USB enabled should be skipped for YK4
        assert!(
            !info
                .config
                .enabled_capabilities
                .contains_key(&Transport::Usb)
        );
    }

    #[test]
    fn test_device_info_parse_yk4_usb_enabled_skip() {
        // YK4 (4.x.x < 5.0.0): USB_ENABLED should be ignored
        let mut payload = Vec::new();
        payload.extend_from_slice(&tlv_encode(TAG_VERSION, &[4, 3, 7]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_SUPPORTED, &[0x00, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_ENABLED, &[0x00, 0x3F]));

        let mut encoded = vec![payload.len() as u8];
        encoded.extend_from_slice(&payload);

        let info = DeviceInfo::parse(&encoded, Version(0, 0, 0)).unwrap();
        assert!(
            !info
                .config
                .enabled_capabilities
                .contains_key(&Transport::Usb)
        );
    }

    #[test]
    fn test_device_info_parse_with_nfc() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&tlv_encode(TAG_VERSION, &[5, 2, 0]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_SUPPORTED, &[0x02, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_ENABLED, &[0x02, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_NFC_SUPPORTED, &[0x02, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_NFC_ENABLED, &[0x00, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_NFC_RESTRICTED, &[0x01]));

        let mut encoded = vec![payload.len() as u8];
        encoded.extend_from_slice(&payload);

        let info = DeviceInfo::parse(&encoded, Version(0, 0, 0)).unwrap();
        assert!(info.has_transport(Transport::Nfc));
        assert_eq!(
            info.supported_capabilities.get(&Transport::Nfc),
            Some(&Capability(0x023F))
        );
        assert_eq!(info.config.nfc_restricted, Some(true));
    }

    #[test]
    fn test_device_info_parse_version_qualifier() {
        let mut vq_inner = Vec::new();
        vq_inner.extend_from_slice(&tlv_encode(0x01, &[5, 8, 0]));
        vq_inner.extend_from_slice(&tlv_encode(0x02, &[0x00])); // Alpha
        vq_inner.extend_from_slice(&tlv_encode(0x03, &[0x03])); // iteration 3

        let mut payload = Vec::new();
        payload.extend_from_slice(&tlv_encode(TAG_VERSION, &[5, 7, 1]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_SUPPORTED, &[0x02, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_VERSION_QUALIFIER, &vq_inner));

        let mut encoded = vec![payload.len() as u8];
        encoded.extend_from_slice(&payload);

        let info = DeviceInfo::parse(&encoded, Version(0, 0, 0)).unwrap();
        // Version should be overridden for non-final releases
        assert_eq!(info.version, Version(5, 8, 0));
        assert_eq!(info.version_qualifier.release_type, ReleaseType::Alpha);
        assert_eq!(info.version_qualifier.iteration, 3);
    }

    #[test]
    fn test_device_info_parse_part_number_and_fips() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&tlv_encode(TAG_VERSION, &[5, 7, 1]));
        payload.extend_from_slice(&tlv_encode(TAG_USB_SUPPORTED, &[0x02, 0x3F]));
        payload.extend_from_slice(&tlv_encode(TAG_PART_NUMBER, b"YK5C"));
        payload.extend_from_slice(&tlv_encode(TAG_FIPS_CAPABLE, &[0x07])); // bits 0,1,2 = FIDO2,PIV,OPENPGP
        payload.extend_from_slice(&tlv_encode(TAG_FIPS_APPROVED, &[0x03])); // bits 0,1 = FIDO2,PIV
        payload.extend_from_slice(&tlv_encode(TAG_PIN_COMPLEXITY, &[0x01]));
        payload.extend_from_slice(&tlv_encode(TAG_CONFIG_LOCK, &[0x01]));

        let mut encoded = vec![payload.len() as u8];
        encoded.extend_from_slice(&payload);

        let info = DeviceInfo::parse(&encoded, Version(0, 0, 0)).unwrap();
        assert_eq!(info.part_number.as_deref(), Some("YK5C"));
        assert!(info.fips_capable.contains(Capability::FIDO2));
        assert!(info.fips_capable.contains(Capability::PIV));
        assert!(info.fips_capable.contains(Capability::OPENPGP));
        assert!(info.fips_approved.contains(Capability::FIDO2));
        assert!(info.fips_approved.contains(Capability::PIV));
        assert!(!info.fips_approved.contains(Capability::OPENPGP));
        assert!(info.pin_complexity);
        assert!(info.is_locked);
    }

    #[test]
    fn test_version_qualifier_display() {
        let vq = VersionQualifier::new(Version(5, 8, 0), ReleaseType::Alpha, 3);
        assert_eq!(vq.to_string(), "5.8.0.alpha.3");
    }

    #[test]
    fn test_parse_version_string() {
        assert_eq!(parse_version_string("5.7.1").unwrap(), Version(5, 7, 1));
        assert_eq!(parse_version_string("4.2.4").unwrap(), Version(4, 2, 4));
        assert!(parse_version_string("invalid").is_err());
        assert!(parse_version_string("5.7").is_err());
    }

    #[test]
    fn test_bytes2int() {
        assert_eq!(bytes2int(&[]), 0);
        assert_eq!(bytes2int(&[0x01]), 1);
        assert_eq!(bytes2int(&[0x01, 0x00]), 256);
        assert_eq!(bytes2int(&[0x00, 0xBC, 0x61, 0x4E]), 12345678);
    }

    #[test]
    fn test_release_type_display() {
        assert_eq!(ReleaseType::Alpha.to_string(), "alpha");
        assert_eq!(ReleaseType::Beta.to_string(), "beta");
        assert_eq!(ReleaseType::Final.to_string(), "final");
    }
}
