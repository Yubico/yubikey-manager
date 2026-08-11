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

//! High-level device enumeration for YubiKeys.
//!
//! This module provides a convenient API for discovering connected YubiKeys
//! and opening sessions with them.
//!
//! # Example
//!
//! ```no_run
//! use yubikit::platform::device::list_devices;
//! use yubikit::management::UsbInterface;
//!
//! let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO).unwrap();
//! for dev in &devices {
//!     println!("{} (serial: {:?})", dev.name(), dev.info().serial);
//! }
//! ```

use crate::core::{Transport, set_override_version};
use crate::fido::FidoConnection;
use crate::management::{BoxedManagementError, Capability, DeviceInfo, FormFactor, UsbInterface};
use crate::otp::OtpConnection;
use crate::smartcard::{SmartCardConnection, SmartCardError};

// ---------------------------------------------------------------------------
// DeviceError
// ---------------------------------------------------------------------------

/// Errors that can occur during device enumeration or connection.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// A SmartCard protocol error.
    #[error("SmartCard error: {0}")]
    SmartCard(#[from] SmartCardError),
    /// A management session error.
    #[error("Management error: {0}")]
    Management(#[source] BoxedManagementError),
    /// A transport-level error (PC/SC, HID, or FIDO).
    #[error("Transport error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// No YubiKey device was found.
    #[error("No YubiKey device found")]
    NoDeviceFound,
    /// The card is not a YubiKey.
    #[error("Not a YubiKey")]
    NotYubiKey,
    /// The operation was cancelled by the caller.
    #[error("Operation cancelled")]
    Cancelled,
    /// A different YubiKey was inserted or removed during reinsert.
    #[error("A different YubiKey was inserted/removed")]
    WrongDevice,
    /// The operation requires a disabled Cargo feature.
    #[error("Operation requires the '{0}' feature")]
    UnsupportedFeature(&'static str),
}

/// Status updates during a device reinsert operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinsertStatus {
    /// The device should be removed (USB: unplug, NFC: remove from reader).
    Remove,
    /// The device has been removed and should be reinserted (USB: plug in, NFC: place on reader).
    Reinsert,
}

impl From<crate::fido::FidoError> for DeviceError {
    fn from(e: crate::fido::FidoError) -> Self {
        Self::Transport(Box::new(e))
    }
}

// ---------------------------------------------------------------------------
// Device trait
// ---------------------------------------------------------------------------

/// Abstract interface to a YubiKey device.
///
/// Provides access to device metadata and the ability to open connections.
/// Implemented by [`crate::platform::device::LocalYubiKeyDevice`] for local devices and can be implemented
/// by RPC proxy types for remote access.
pub trait YubiKeyDevice {
    /// Returns the [`DeviceInfo`] for this device.
    fn info(&self) -> &DeviceInfo;
    /// Returns the transport type (USB or NFC).
    fn transport(&self) -> Transport;
    /// Returns the product name derived from device info.
    fn name(&self) -> String;
    /// Returns the USB Product ID, if known.
    fn pid(&self) -> Option<u16> {
        None
    }
    /// Returns the PC/SC reader name, if this device has a smartcard reader.
    fn reader_name(&self) -> Option<&str> {
        None
    }
    /// Returns the USB interfaces available on this device.
    fn usb_interfaces(&self) -> UsbInterface;
    /// Open a SmartCard (CCID) connection, returning a trait object.
    fn open_smartcard(&self) -> Result<Box<dyn SmartCardConnection + Send>, DeviceError>;
    /// Open a FIDO HID (CTAP) connection, returning a trait object.
    fn open_fido(&self) -> Result<Box<dyn FidoConnection + Send>, DeviceError>;
    /// Open an OTP HID connection, returning a trait object.
    fn open_otp(&self) -> Result<Box<dyn OtpConnection + Send>, DeviceError>;
    /// Wait for the user to remove and reinsert this YubiKey.
    fn reinsert(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError>;
    /// Clone this device into a boxed trait object.
    fn clone_box(&self) -> Box<dyn YubiKeyDevice>;
}

impl YubiKeyDevice for Box<dyn YubiKeyDevice> {
    fn info(&self) -> &DeviceInfo {
        (**self).info()
    }
    fn transport(&self) -> Transport {
        (**self).transport()
    }
    fn name(&self) -> String {
        (**self).name()
    }
    fn pid(&self) -> Option<u16> {
        (**self).pid()
    }
    fn reader_name(&self) -> Option<&str> {
        (**self).reader_name()
    }
    fn usb_interfaces(&self) -> UsbInterface {
        (**self).usb_interfaces()
    }
    fn open_smartcard(&self) -> Result<Box<dyn SmartCardConnection + Send>, DeviceError> {
        (**self).open_smartcard()
    }
    fn open_fido(&self) -> Result<Box<dyn FidoConnection + Send>, DeviceError> {
        (**self).open_fido()
    }
    fn open_otp(&self) -> Result<Box<dyn OtpConnection + Send>, DeviceError> {
        (**self).open_otp()
    }
    fn reinsert(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        (**self).reinsert(status_cb, cancelled)
    }
    fn clone_box(&self) -> Box<dyn YubiKeyDevice> {
        (**self).clone_box()
    }
}

// ---------------------------------------------------------------------------
// Device naming
// ---------------------------------------------------------------------------

use crate::core::Version;
use crate::management::{DeviceConfig, ManagementSession, ReleaseType};
use crate::yubiotp::YubiOtpSession;

/// Derive USB interface flags from a Yubico USB Product ID.
pub fn usb_interfaces_from_pid(pid: u16) -> UsbInterface {
    match pid {
        // NEO PIDs
        0x0110 => UsbInterface::OTP,
        0x0111 => UsbInterface::OTP | UsbInterface::CCID,
        0x0112 => UsbInterface::CCID,
        0x0113 => UsbInterface::FIDO,
        0x0114 => UsbInterface::OTP | UsbInterface::FIDO,
        0x0115 => UsbInterface::FIDO | UsbInterface::CCID,
        0x0116 => UsbInterface::OTP | UsbInterface::FIDO | UsbInterface::CCID,
        // YK4+ PIDs
        0x0401 => UsbInterface::OTP,
        0x0402 => UsbInterface::FIDO,
        0x0403 => UsbInterface::OTP | UsbInterface::FIDO,
        0x0404 => UsbInterface::CCID,
        0x0405 => UsbInterface::OTP | UsbInterface::CCID,
        0x0406 => UsbInterface::FIDO | UsbInterface::CCID,
        0x0407 => UsbInterface::OTP | UsbInterface::FIDO | UsbInterface::CCID,
        // SKY
        0x0120 => UsbInterface::FIDO,
        // YK Plus
        0x0410 => UsbInterface::OTP | UsbInterface::FIDO,
        // YK Standard
        0x0010 => UsbInterface::OTP,
        _ => UsbInterface(0),
    }
}

/// Preview firmware version ranges.
const PREVIEW_RANGES: &[(Version, Version)] = &[
    (Version(5, 0, 0), Version(5, 1, 0)),
    (Version(5, 2, 0), Version(5, 2, 3)),
    (Version(5, 5, 0), Version(5, 5, 2)),
];

pub(crate) fn is_preview(version: Version) -> bool {
    PREVIEW_RANGES
        .iter()
        .any(|(start, end)| version >= *start && version < *end)
}

pub(crate) fn fido_only(cap: Capability) -> bool {
    let non_fido = Capability::OTP.0
        | Capability::OATH.0
        | Capability::PIV.0
        | Capability::OPENPGP.0
        | Capability::HSMAUTH.0;
    let fido = Capability::U2F.0 | Capability::FIDO2.0;
    (cap.0 & non_fido == 0) && (cap.0 & fido != 0)
}

/// Determine the product name of a YubiKey from its [`DeviceInfo`].
pub fn get_name(info: &DeviceInfo) -> String {
    let usb_supported = info
        .supported_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);

    let major = info.version.0;

    // SKY devices are handled separately — they never get "YubiKey Preview"
    // even on preview firmware, matching the Python behavior where key_type
    // is determined from PID before the preview check.
    if info.is_sky {
        if info.version >= Version(5, 1, 0) {
            return build_yk5_name(info, usb_supported);
        }
        if !usb_supported.contains(Capability::FIDO2) {
            return "FIDO U2F Security Key".to_string();
        }
        return "Security Key by Yubico".to_string();
    }

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

    // Preview firmware (non-SKY only)
    if is_preview(info.version) {
        return "YubiKey Preview".to_string();
    }

    // YK5+ dynamic naming (5.1.0+)
    if info.version >= Version(5, 1, 0) {
        return build_yk5_name(info, usb_supported);
    }

    // Fallback for 5.0.x
    "YubiKey 5".to_string()
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

    parts.join(" ").replace("5 C", "5C").replace("5 A", "5A")
}

/// Synthesize device info based on PID and version
fn synthesize_info(pid: u16, version: Version, serial: Option<u32>) -> DeviceInfo {
    let mut supported = std::collections::HashMap::new();
    let mut enabled = std::collections::HashMap::new();
    let mut capabilities: Capability;

    if pid == 0x0010 {
        // YubiKey Standard (1-2)
        capabilities = Capability::OTP;
    } else if pid == 0x0120 {
        // SKY
        capabilities = Capability::U2F;
    } else if pid == 0x0410 {
        // YubiKey Plus
        capabilities = Capability::OTP | Capability::U2F;
    } else {
        // NEO
        capabilities = Capability::OTP | Capability::OATH | Capability::OPENPGP;
        if version >= Version(3, 3, 0) || usb_interfaces_from_pid(pid).contains(UsbInterface::FIDO)
        {
            capabilities |= Capability::U2F;
        }
        supported.insert(Transport::Nfc, capabilities);
        enabled.insert(Transport::Nfc, capabilities);
    }
    supported.insert(Transport::Usb, capabilities);
    enabled.insert(Transport::Usb, capabilities);

    DeviceInfo {
        config: DeviceConfig {
            enabled_capabilities: enabled,
            auto_eject_timeout: None,
            challenge_response_timeout: None,
            device_flags: None,
            nfc_restricted: None,
        },
        serial,
        version,
        form_factor: FormFactor::Unknown,
        supported_capabilities: supported,
        is_locked: false,
        is_fips: false,
        is_sky: pid == 0x0120,
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

/// Read [`DeviceInfo`] from an open smart card connection.
///
/// Falls back to probing individual applets on older devices that lack
/// the management applet. Returns an error if the card is not a YubiKey
/// (no supported capabilities detected). Returns the connection for reuse.
pub fn read_info_ccid<C: SmartCardConnection + Send + 'static>(
    conn: C,
    pid: Option<u16>,
) -> Result<(DeviceInfo, C), DeviceError> {
    let mut session = match ManagementSession::new(conn) {
        Ok(s) => s,
        Err((e, conn)) => {
            log::debug!("Management session init failed ({e}), synthesizing info");
            // NEO and other old devices don't have the management applet.
            // Try to get the version and serial from the OTP applet
            let (version, serial, conn) = match YubiOtpSession::new(conn) {
                Ok(mut otp_session) => {
                    let version = otp_session.version();
                    let serial = otp_session.get_serial().ok();
                    (version, serial, otp_session.into_connection())
                }
                Err((e, conn)) => {
                    log::debug!("Couldn't open YubiOTP session: {e}");
                    // Assume a minimum version
                    (Version(3, 0, 0), None, conn)
                }
            };
            // Default to NEO CCID if we have no PID
            return Ok((
                synthesize_info(pid.unwrap_or(0x0112), version, serial),
                conn,
            ));
        }
    };

    match session.read_device_info() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            let conn = session.into_connection();
            check_yubikey_info(info, conn)
        }
        Err(e) => Err(DeviceError::Management(e.erase())),
    }
}

/// Read [`DeviceInfo`] via OTP HID from an open connection.
///
/// Returns the connection for reuse. On error the connection is returned
/// when possible.
pub fn read_info_otp<T: OtpConnection + Send + 'static>(
    mut conn: T,
    pid: u16,
) -> Result<(DeviceInfo, T), (DeviceError, Option<T>)> {
    // Read the version directly from the connection
    let version = conn
        .otp_receive()
        .ok()
        .filter(|r| r.len() >= 4)
        .map(|r| Version::from_bytes(&r[1..4]))
        .unwrap_or(Version(0, 0, 0));

    // Older key, synthesize info
    if version != Version(0, 0, 1) && version < Version(4, 1, 0) {
        let (serial, conn) = match YubiOtpSession::new_otp(conn) {
            Ok(mut session) => {
                let serial = session.get_serial().ok();
                (serial, session.into_connection())
            }
            Err((e, conn)) => {
                log::debug!("Couldn't open YubiOTP session to read serial: {e}");
                (None, conn)
            }
        };
        return Ok((synthesize_info(pid, version, serial), conn));
    }

    let mut session = ManagementSession::new_otp(conn)
        .map_err(|(e, conn)| (DeviceError::Management(e.erase()), Some(conn)))?;
    match session.read_device_info() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            Ok((info, session.into_connection()))
        }
        Err(e) => Err((
            DeviceError::Management(e.erase()),
            Some(session.into_connection()),
        )),
    }
}

/// Read [`DeviceInfo`] via FIDO HID (CTAP) from an open connection.
///
/// Returns the connection for reuse. On error the connection is returned
/// when possible.
pub fn read_info_fido<C: FidoConnection + 'static>(
    conn: C,
    pid: u16,
) -> Result<(DeviceInfo, C), (DeviceError, Option<C>)> {
    let version = conn.device_version();

    // Older key, synthesize info
    if version != Version(0, 0, 1) && version < Version(4, 1, 0) {
        return Ok((synthesize_info(pid, version, None), conn));
    }

    let mut session = ManagementSession::new_fido(conn)
        .map_err(|(e, conn)| (DeviceError::Management(e.erase()), Some(conn)))?;
    match session.read_device_info() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            Ok((info, session.into_connection()))
        }
        Err(e) => Err((
            DeviceError::Management(e.erase()),
            Some(session.into_connection()),
        )),
    }
}

fn check_yubikey_info<C>(info: DeviceInfo, conn: C) -> Result<(DeviceInfo, C), DeviceError> {
    let has_caps = info
        .supported_capabilities
        .values()
        .any(|c| *c != Capability::NONE);
    if has_caps {
        Ok((info, conn))
    } else {
        Err(DeviceError::NotYubiKey)
    }
}

/// Apply standard fixups for known device quirks.
fn apply_device_info_fixups(info: &mut DeviceInfo) {
    // Override version from version qualifier for non-final (dev) firmware
    if info.version_qualifier.release_type != ReleaseType::Final {
        log::debug!(
            "Overriding version {} with qualifier version {}",
            info.version,
            info.version_qualifier.version
        );
        info.version = info.version_qualifier.version;
        set_override_version(info.version);
    }

    // YK4-based FIPS (4.4.x)
    if info.version >= Version(4, 4, 0) && info.version < Version(4, 5, 0) {
        info.is_fips = true;
    }

    // Infer SKY for older firmware that doesn't set the flag.
    // Devices before 5.2.8 with no serial and FIDO-only capabilities are SKY.
    if !info.is_sky
        && info.serial.is_none()
        && info.version < Version(5, 2, 8)
        && info
            .supported_capabilities
            .get(&Transport::Usb)
            .is_some_and(|c| fido_only(*c))
    {
        info.is_sky = true;
    }

    // Fix NFC: set enabled if missing
    if info.has_transport(Transport::Nfc) {
        if !info
            .config
            .enabled_capabilities
            .contains_key(&Transport::Nfc)
            && let Some(&nfc_sup) = info.supported_capabilities.get(&Transport::Nfc)
        {
            info.config
                .enabled_capabilities
                .insert(Transport::Nfc, nfc_sup);
        }
        // Remove NFC for form factors known to not have NFC
        let remove_nfc = matches!(
            info.form_factor,
            FormFactor::UsbANano | FormFactor::UsbCNano | FormFactor::UsbCLightning
        ) || (info.form_factor == FormFactor::UsbCKeychain
            && info.version < Version(5, 2, 4));

        if remove_nfc {
            info.supported_capabilities.remove(&Transport::Nfc);
            info.config.enabled_capabilities.remove(&Transport::Nfc);
        }
    }

    // Fix USB: set enabled if missing (pre-YubiKey 5)
    if info.has_transport(Transport::Usb)
        && !info
            .config
            .enabled_capabilities
            .contains_key(&Transport::Usb)
        && let Some(&usb_sup) = info.supported_capabilities.get(&Transport::Usb)
    {
        info.config
            .enabled_capabilities
            .insert(Transport::Usb, usb_sup);
    }
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
            config: DeviceConfig {
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
            false,
            false,
            Some(123),
            true,
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
            false,
            false,
            Some(456),
            false,
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
            false,
            true,
            Some(789),
            false,
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
            false,
            false,
            Some(100),
            true,
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
            false,
            false,
            Some(200),
            false,
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
            false,
            false,
            Some(300),
            false,
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
            true,
            false,
            None,
            true,
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
            false,
            false,
            Some(400),
            false,
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
            false,
            false,
            Some(500),
            false,
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
            false,
            false,
            Some(600),
            false,
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
            true,
            false,
            Some(700),
            false,
            Capability(Capability::U2F.0 | Capability::FIDO2.0),
            false,
        );
        assert_eq!(get_name(&info), "Security Key A - Enterprise Edition");
    }

    #[test]
    fn test_sky_nfc_inferred() {
        let mut info = make_info(
            Version(5, 1, 2),
            FormFactor::UsbAKeychain,
            false,
            false,
            None,
            true,
            Capability(Capability::U2F.0 | Capability::FIDO2.0),
            false,
        );
        apply_device_info_fixups(&mut info);
        assert!(info.is_sky);
        assert_eq!(get_name(&info), "Security Key NFC");
    }

    #[test]
    fn test_sky_inference_not_applied_with_serial() {
        let mut info = make_info(
            Version(5, 1, 2),
            FormFactor::UsbAKeychain,
            false,
            false,
            Some(123),
            true,
            Capability(Capability::U2F.0 | Capability::FIDO2.0),
            false,
        );
        apply_device_info_fixups(&mut info);
        assert!(!info.is_sky);
    }

    #[test]
    fn test_yk5a() {
        let info = make_info(
            Version(5, 2, 4),
            FormFactor::UsbAKeychain,
            false,
            false,
            Some(800),
            false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        );
        assert_eq!(get_name(&info), "YubiKey 5A");
    }

    #[test]
    fn test_fido_only() {
        assert!(fido_only(Capability(
            Capability::U2F.0 | Capability::FIDO2.0
        )));
        assert!(fido_only(Capability::FIDO2));
        assert!(!fido_only(Capability(
            Capability::FIDO2.0 | Capability::PIV.0
        )));
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
            false,
            false,
            Some(900),
            false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            true,
        );
        assert_eq!(get_name(&info), "YubiKey 5C - Enhanced PIN");
    }

    #[test]
    fn test_sky_preview_firmware() {
        let mut info = make_info(
            Version(5, 0, 2),
            FormFactor::UsbAKeychain,
            false,
            false,
            None,
            false,
            Capability(Capability::U2F.0 | Capability::FIDO2.0),
            false,
        );
        apply_device_info_fixups(&mut info);
        assert!(info.is_sky);
        assert_eq!(get_name(&info), "Security Key by Yubico");
    }

    #[test]
    fn test_sky_u2f_only() {
        let info = make_info(
            Version(0, 0, 0),
            FormFactor::Unknown,
            true,
            false,
            None,
            false,
            Capability::U2F,
            false,
        );
        assert_eq!(get_name(&info), "FIDO U2F Security Key");
    }
}
