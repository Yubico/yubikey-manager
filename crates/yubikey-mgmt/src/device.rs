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

//! High-level device enumeration for YubiKeys.
//!
//! This module provides a convenient API for discovering connected YubiKeys
//! and opening sessions with them.
//!
//! # Example
//!
//! ```no_run
//! use yubikey_mgmt::device::list_devices;
//!
//! let devices = list_devices().unwrap();
//! for dev in &devices {
//!     println!("{} (serial: {:?})", dev.name(), dev.serial());
//! }
//! ```

use std::collections::HashSet;
use std::fmt;

use crate::iso7816::{SmartCardError, Transport, Version};
use crate::management::{Capability, DeviceInfo, FormFactor, ManagementSession};
use crate::transport::hid::{HidConnection, HidDeviceInfo, HidError, list_otp_devices};
use crate::transport::pcsc::{PcscConnection, PcscError, list_readers};

// ---------------------------------------------------------------------------
// DeviceError
// ---------------------------------------------------------------------------

/// Errors that can occur during device enumeration or connection.
#[derive(Debug)]
pub enum DeviceError {
    /// A SmartCard protocol error.
    SmartCard(SmartCardError),
    /// A PC/SC transport error.
    Pcsc(PcscError),
    /// A HID transport error.
    Hid(HidError),
    /// No YubiKey device was found.
    NoDeviceFound,
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SmartCard(e) => write!(f, "SmartCard error: {e}"),
            Self::Pcsc(e) => write!(f, "PC/SC error: {e}"),
            Self::Hid(e) => write!(f, "HID error: {e}"),
            Self::NoDeviceFound => write!(f, "No YubiKey device found"),
        }
    }
}

impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SmartCard(e) => Some(e),
            Self::Pcsc(e) => Some(e),
            Self::Hid(e) => Some(e),
            Self::NoDeviceFound => None,
        }
    }
}

impl From<SmartCardError> for DeviceError {
    fn from(e: SmartCardError) -> Self {
        Self::SmartCard(e)
    }
}

impl From<PcscError> for DeviceError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<HidError> for DeviceError {
    fn from(e: HidError) -> Self {
        Self::Hid(e)
    }
}

// ---------------------------------------------------------------------------
// YubiKeyDevice
// ---------------------------------------------------------------------------

/// A discovered YubiKey that can open connections.
///
/// Represents a physical YubiKey found via PC/SC (CCID) and/or HID enumeration.
/// Use [`list_devices`] to discover connected devices.
#[derive(Debug, Clone)]
pub struct YubiKeyDevice {
    reader_name: Option<String>,
    hid_path: Option<String>,
    info: DeviceInfo,
}

impl YubiKeyDevice {
    /// Returns the [`DeviceInfo`] for this device.
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    /// Returns the serial number, if available.
    pub fn serial(&self) -> Option<u32> {
        self.info.serial
    }

    /// Returns the firmware version.
    pub fn version(&self) -> Version {
        self.info.version
    }

    /// Returns the product name derived from device info.
    pub fn name(&self) -> String {
        get_name(&self.info)
    }

    /// Returns the PC/SC reader name, if this device was found over CCID.
    pub fn reader_name(&self) -> Option<&str> {
        self.reader_name.as_deref()
    }

    /// Returns the HID device path, if this device was found over HID.
    pub fn hid_path(&self) -> Option<&str> {
        self.hid_path.as_deref()
    }

    /// Open a SmartCard (PC/SC) connection to this device.
    pub fn open_smartcard(&self) -> Result<PcscConnection, DeviceError> {
        let reader = self
            .reader_name
            .as_deref()
            .ok_or(DeviceError::NoDeviceFound)?;
        Ok(PcscConnection::new(reader, false)?)
    }

    /// Open an OTP HID connection to this device.
    pub fn open_otp(&self) -> Result<HidConnection, DeviceError> {
        let path = self
            .hid_path
            .as_deref()
            .ok_or(DeviceError::NoDeviceFound)?;
        Ok(HidConnection::new(path)?)
    }
}

impl fmt::Display for YubiKeyDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())?;
        if let Some(serial) = self.serial() {
            write!(f, " (serial: {serial})")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Device enumeration
// ---------------------------------------------------------------------------

/// Discover all connected YubiKeys.
///
/// Scans PC/SC readers and HID devices, reads [`DeviceInfo`] from each,
/// and returns a unified list of discovered YubiKeys. Devices visible over
/// both PC/SC and HID (matched by serial number) are merged into a single
/// entry.
pub fn list_devices() -> Result<Vec<YubiKeyDevice>, DeviceError> {
    let mut devices = Vec::new();
    let mut seen_serials = HashSet::new();

    // Scan PC/SC readers
    if let Ok(readers) = list_readers() {
        for reader in readers {
            if !reader.to_ascii_lowercase().contains("yubi") {
                continue;
            }
            {
                if let Ok(info) = read_info(&reader) {
                    if let Some(serial) = info.serial {
                        seen_serials.insert(serial);
                    }
                    devices.push(YubiKeyDevice {
                        reader_name: Some(reader),
                        hid_path: None,
                        info,
                    });
                }
            }
        }
    }

    // Scan HID OTP devices, merging with existing PC/SC entries
    if let Ok(hid_devices) = list_otp_devices() {
        for hid in hid_devices {
            // If there is exactly one CCID device without a HID path, merge them.
            let should_merge = devices.len() == 1 && devices[0].hid_path.is_none();
            if should_merge {
                devices[0].hid_path = Some(hid.path);
            } else {
                let info = synthetic_hid_info(&hid);
                devices.push(YubiKeyDevice {
                    reader_name: None,
                    hid_path: Some(hid.path),
                    info,
                });
            }
        }
    }

    Ok(devices)
}

/// Build a minimal synthetic [`DeviceInfo`] for an HID-only device.
fn synthetic_hid_info(hid: &HidDeviceInfo) -> DeviceInfo {
    use std::collections::HashMap;

    let version = pid_to_version(hid.pid);
    let mut supported = HashMap::new();
    supported.insert(Transport::Usb, Capability::OTP);

    DeviceInfo {
        config: crate::management::DeviceConfig {
            enabled_capabilities: HashMap::new(),
            auto_eject_timeout: None,
            challenge_response_timeout: None,
            device_flags: None,
            nfc_restricted: None,
        },
        serial: None,
        version,
        form_factor: FormFactor::Unknown,
        supported_capabilities: supported,
        is_locked: false,
        is_fips: false,
        is_sky: false,
        part_number: None,
        fips_capable: Capability::NONE,
        fips_approved: Capability::NONE,
        pin_complexity: false,
        reset_blocked: Capability::NONE,
        fps_version: None,
        stm_version: None,
        version_qualifier: crate::management::VersionQualifier::final_release(version),
    }
}

/// Best-effort version guess from USB PID.
fn pid_to_version(pid: u16) -> Version {
    match pid {
        0x0110..=0x0113 => Version(3, 0, 0), // NEO family
        0x0116..=0x0120 => Version(3, 0, 0),
        0x0401..=0x0405 => Version(4, 0, 0), // YK4 family
        0x0406..=0x0410 => Version(5, 0, 0), // YK5 family
        _ => Version(0, 0, 0),
    }
}

// ---------------------------------------------------------------------------
// read_info
// ---------------------------------------------------------------------------

/// Read device info from a PC/SC reader.
///
/// Opens a fresh [`PcscConnection`] and uses [`ManagementSession`] to read
/// [`DeviceInfo`]. This works for YubiKey 4.1+ devices. For older devices a
/// fallback that scans individual applets would be needed (not yet implemented).
pub fn read_info(reader_name: &str) -> Result<DeviceInfo, DeviceError> {
    let conn = PcscConnection::new(reader_name, false)?;
    let mut session = ManagementSession::new(conn)?;
    // Use unchecked variant — dev devices report version 0.0.1 but still
    // support the DeviceInfo protocol.
    let info = session.read_device_info_unchecked()?;
    Ok(info)
}

// ---------------------------------------------------------------------------
// Product name logic
// ---------------------------------------------------------------------------

/// Preview firmware version ranges.
const PREVIEW_RANGES: &[(Version, Version)] = &[
    (Version(5, 0, 0), Version(5, 1, 0)),
    (Version(5, 2, 0), Version(5, 2, 3)),
    (Version(5, 5, 0), Version(5, 5, 2)),
];

fn is_preview(version: Version) -> bool {
    PREVIEW_RANGES
        .iter()
        .any(|(start, end)| version >= *start && version < *end)
}

fn fido_only(cap: Capability) -> bool {
    let non_fido = Capability::OTP.0
        | Capability::OATH.0
        | Capability::PIV.0
        | Capability::OPENPGP.0
        | Capability::HSMAUTH.0;
    let fido = Capability::U2F.0 | Capability::FIDO2.0;
    // No non-FIDO capabilities, but at least one FIDO capability
    (cap.0 & non_fido == 0) && (cap.0 & fido != 0)
}

/// Determine the product name of a YubiKey from its [`DeviceInfo`].
///
/// Ports the naming logic from the Python `yubikit.support.get_name`.
pub fn get_name(info: &DeviceInfo) -> String {
    let usb_supported = info
        .supported_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);

    let major = info.version.0;

    // Pre-YK4 devices
    if major < 4 {
        return if major == 0 {
            format!("YubiKey ({})", info.version)
        } else if major == 3 {
            "YubiKey NEO".to_string()
        } else {
            "YubiKey".to_string()
        };
    }

    // YK4 era
    if major == 4 {
        if info.is_fips {
            return "YubiKey FIPS (4 Series)".to_string();
        }
        if usb_supported == Capability(Capability::OTP.0 | Capability::U2F.0) {
            return "YubiKey Edge".to_string();
        }
        return "YubiKey 4".to_string();
    }

    // Preview firmware
    if is_preview(info.version) {
        return "YubiKey Preview".to_string();
    }

    // SKY without FIDO2 (SKY 1)
    if info.is_sky && !usb_supported.contains(Capability::FIDO2) {
        return "FIDO U2F Security Key".to_string();
    }

    // YK5+ dynamic naming (5.1.0+)
    if info.version >= Version(5, 1, 0) {
        return build_yk5_name(info, usb_supported);
    }

    // Fallback for 5.0.x
    if info.is_sky {
        "Security Key".to_string()
    } else {
        "YubiKey 5".to_string()
    }
}

fn build_yk5_name(info: &DeviceInfo, usb_supported: Capability) -> String {
    let is_nano = matches!(
        info.form_factor,
        FormFactor::UsbANano | FormFactor::UsbCNano
    );
    let is_bio = info.form_factor.is_bio();
    let is_c = matches!(
        info.form_factor,
        FormFactor::UsbCKeychain | FormFactor::UsbCNano | FormFactor::UsbCBio
    );
    let has_nfc = info.supported_capabilities.contains_key(&Transport::Nfc);

    let mut parts: Vec<&str> = Vec::new();

    // Base name
    if info.is_sky {
        parts.push("Security Key");
    } else {
        parts.push("YubiKey");
        if !is_bio {
            parts.push("5");
        }
    }

    // Connector type
    if is_c {
        parts.push("C");
    } else if info.form_factor == FormFactor::UsbCLightning {
        parts.push("Ci");
    }

    // Form factor / transport suffix
    if is_nano {
        parts.push("Nano");
    } else if has_nfc {
        parts.push("NFC");
    } else if info.form_factor == FormFactor::UsbAKeychain {
        parts.push("A");
    } else if is_bio {
        parts.push("Bio");
    }

    // Edition suffix
    if info.is_fips {
        parts.push("FIPS");
    } else if is_bio {
        if fido_only(usb_supported) {
            parts.push("- FIDO Edition");
        } else if usb_supported.contains(Capability::PIV) {
            parts.push("- Multi-protocol Edition");
        }
    } else if info.is_sky && info.serial.is_some() {
        parts.push("- Enterprise Edition");
    } else if info.pin_complexity && !info.is_sky {
        parts.push("- Enhanced PIN");
    }

    parts
        .join(" ")
        .replace("5 C", "5C")
        .replace("5 A", "5A")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_info(
        version: Version,
        form_factor: FormFactor,
        is_sky: bool,
        is_fips: bool,
        serial: Option<u32>,
        nfc: bool,
        usb_cap: Capability,
        pin_complexity: bool,
    ) -> DeviceInfo {
        let mut supported = HashMap::new();
        supported.insert(Transport::Usb, usb_cap);
        if nfc {
            supported.insert(Transport::Nfc, usb_cap);
        }
        DeviceInfo {
            config: crate::management::DeviceConfig {
                enabled_capabilities: HashMap::new(),
                auto_eject_timeout: None,
                challenge_response_timeout: None,
                device_flags: None,
                nfc_restricted: None,
            },
            serial,
            version,
            form_factor,
            supported_capabilities: supported,
            is_locked: false,
            is_fips,
            is_sky,
            part_number: None,
            fips_capable: Capability::NONE,
            fips_approved: Capability::NONE,
            pin_complexity,
            reset_blocked: Capability::NONE,
            fps_version: None,
            stm_version: None,
            version_qualifier: crate::management::VersionQualifier::final_release(version),
        }
    }

    #[test]
    fn test_neo() {
        let info = make_info(
            Version(3, 5, 0),
            FormFactor::Unknown,
            false, false, Some(123), true,
            Capability(Capability::OTP.0 | Capability::OATH.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey NEO");
    }

    #[test]
    fn test_yk4() {
        let info = make_info(
            Version(4, 3, 7),
            FormFactor::UsbAKeychain,
            false, false, Some(456), false,
            Capability(Capability::OTP.0 | Capability::PIV.0 | Capability::OATH.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey 4");
    }

    #[test]
    fn test_yk4_fips() {
        let info = make_info(
            Version(4, 4, 5),
            FormFactor::UsbAKeychain,
            false, true, Some(789), false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey FIPS (4 Series)");
    }

    #[test]
    fn test_yk5_nfc() {
        let info = make_info(
            Version(5, 2, 4),
            FormFactor::UsbAKeychain,
            false, false, Some(100), true,
            Capability(Capability::OTP.0 | Capability::PIV.0 | Capability::FIDO2.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey 5 NFC");
    }

    #[test]
    fn test_yk5c_nano() {
        let info = make_info(
            Version(5, 4, 3),
            FormFactor::UsbCNano,
            false, false, Some(200), false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey 5C Nano");
    }

    #[test]
    fn test_yk5ci() {
        let info = make_info(
            Version(5, 2, 4),
            FormFactor::UsbCLightning,
            false, false, Some(300), false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey 5Ci");
    }

    #[test]
    fn test_security_key_nfc() {
        let info = make_info(
            Version(5, 2, 8),
            FormFactor::UsbAKeychain,
            true, false, None, true,
            Capability(Capability::U2F.0 | Capability::FIDO2.0),
            false,
        );
        assert_eq!(get_name(&info), "Security Key NFC");
    }

    #[test]
    fn test_bio_fido() {
        let info = make_info(
            Version(5, 5, 6),
            FormFactor::UsbABio,
            false, false, Some(400), false,
            Capability(Capability::U2F.0 | Capability::FIDO2.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey Bio - FIDO Edition");
    }

    #[test]
    fn test_bio_multi_protocol() {
        let info = make_info(
            Version(5, 6, 0),
            FormFactor::UsbCBio,
            false, false, Some(500), false,
            Capability(Capability::PIV.0 | Capability::FIDO2.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey C Bio - Multi-protocol Edition");
    }

    #[test]
    fn test_preview() {
        let info = make_info(
            Version(5, 0, 1),
            FormFactor::UsbAKeychain,
            false, false, Some(600), false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey Preview");
    }

    #[test]
    fn test_sky_enterprise() {
        let info = make_info(
            Version(5, 4, 3),
            FormFactor::UsbAKeychain,
            true, false, Some(700), false,
            Capability(Capability::U2F.0 | Capability::FIDO2.0),
            false,
        );
        assert_eq!(get_name(&info), "Security Key A - Enterprise Edition");
    }

    #[test]
    fn test_yk5a() {
        let info = make_info(
            Version(5, 2, 4),
            FormFactor::UsbAKeychain,
            false, false, Some(800), false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey 5A");
    }

    #[test]
    fn test_fido_only() {
        assert!(fido_only(Capability(Capability::U2F.0 | Capability::FIDO2.0)));
        assert!(fido_only(Capability::FIDO2));
        assert!(!fido_only(Capability(Capability::FIDO2.0 | Capability::PIV.0)));
        assert!(!fido_only(Capability::NONE));
    }

    #[test]
    fn test_is_preview() {
        assert!(is_preview(Version(5, 0, 0)));
        assert!(is_preview(Version(5, 0, 1)));
        assert!(!is_preview(Version(5, 1, 0)));
        assert!(is_preview(Version(5, 2, 0)));
        assert!(is_preview(Version(5, 2, 2)));
        assert!(!is_preview(Version(5, 2, 3)));
        assert!(is_preview(Version(5, 5, 0)));
        assert!(is_preview(Version(5, 5, 1)));
        assert!(!is_preview(Version(5, 5, 2)));
        assert!(!is_preview(Version(5, 4, 0)));
    }

    #[test]
    fn test_enhanced_pin() {
        let info = make_info(
            Version(5, 7, 0),
            FormFactor::UsbCKeychain,
            false, false, Some(900), false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            true,
        );
        assert_eq!(get_name(&info), "YubiKey 5C - Enhanced PIN");
    }
}
