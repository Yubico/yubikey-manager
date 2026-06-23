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

use std::fmt;

use crate::core::{Transport, set_override_version};
use crate::fido::FidoConnection;
use crate::management::{BoxedManagementError, Capability, DeviceInfo, FormFactor, UsbInterface};
use crate::otp::OtpConnection;
use crate::smartcard::{SmartCardConnection, SmartCardError};

// ---------------------------------------------------------------------------
// DeviceError
// ---------------------------------------------------------------------------

/// Errors that can occur during device enumeration or connection.
#[derive(Debug)]
pub enum DeviceError {
    /// A SmartCard protocol error.
    SmartCard(SmartCardError),
    /// A management session error.
    Management(BoxedManagementError),
    /// A transport-level error (PC/SC, HID, or FIDO).
    Transport(Box<dyn std::error::Error + Send + Sync>),
    /// No YubiKey device was found.
    NoDeviceFound,
    /// The card is not a YubiKey.
    NotYubiKey,
    /// The operation was cancelled by the caller.
    Cancelled,
    /// A different YubiKey was inserted or removed during reinsert.
    WrongDevice,
    /// The operation requires a disabled Cargo feature.
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

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SmartCard(e) => write!(f, "SmartCard error: {e}"),
            Self::Management(e) => write!(f, "Management error: {e}"),
            Self::Transport(e) => write!(f, "Transport error: {e}"),
            Self::NoDeviceFound => write!(f, "No YubiKey device found"),
            Self::NotYubiKey => write!(f, "Not a YubiKey"),
            Self::Cancelled => write!(f, "Operation cancelled"),
            Self::WrongDevice => write!(f, "A different YubiKey was inserted/removed"),
            Self::UnsupportedFeature(feature) => {
                write!(f, "Operation requires the '{feature}' feature")
            }
        }
    }
}

impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SmartCard(e) => Some(e),
            Self::Management(e) => Some(e),
            Self::Transport(e) => Some(e.as_ref()),
            Self::NoDeviceFound
            | Self::NotYubiKey
            | Self::Cancelled
            | Self::WrongDevice
            | Self::UnsupportedFeature(_) => None,
        }
    }
}

impl From<SmartCardError> for DeviceError {
    fn from(e: SmartCardError) -> Self {
        Self::SmartCard(e)
    }
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
use crate::smartcard::{Aid, SmartCardProtocol};
use crate::yubiotp::YubiOtpSession;

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

/// Read [`DeviceInfo`] from an open smart card connection.
///
/// Falls back to probing individual applets on older devices that lack
/// the management applet. Returns an error if the card is not a YubiKey
/// (no supported capabilities detected). Returns the connection for reuse.
pub fn read_info_ccid<C: SmartCardConnection + Send + 'static>(
    conn: C,
) -> Result<(DeviceInfo, C), DeviceError> {
    let mut session = match ManagementSession::new(conn) {
        Ok(s) => s,
        Err((e, conn)) => {
            // NEO and other old devices don't have the management applet.
            // Fall back to probing individual applets.
            log::debug!("Management session init failed ({e}), synthesizing info");
            let (info, conn) = synthesize_info_ccid(conn, Version(0, 0, 0))?;
            return check_yubikey_info(info, conn);
        }
    };
    let version = session.version();

    match session.read_device_info() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            let conn = session.into_connection();
            check_yubikey_info(info, conn)
        }
        Err(_) if version < Version(4, 1, 0) => {
            log::debug!("Management read_device_info not supported, synthesizing");
            let conn = session.into_connection();
            let (info, conn) = synthesize_info_ccid(conn, version)?;
            check_yubikey_info(info, conn)
        }
        Err(e) => Err(DeviceError::Management(e.erase())),
    }
}

/// Read [`DeviceInfo`] via OTP HID from an open connection.
///
/// Returns the connection for reuse. On error the connection is returned
/// when possible.
pub fn read_info_otp<T: OtpConnection + 'static>(
    conn: T,
) -> Result<(DeviceInfo, T), (DeviceError, Option<T>)> {
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
) -> Result<(DeviceInfo, C), (DeviceError, Option<C>)> {
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

/// Applets to scan when synthesizing DeviceInfo for older keys.
const SCAN_APPLETS: &[(&[u8], Capability)] = &[
    (Aid::FIDO, Capability::U2F),
    (Aid::PIV, Capability::PIV),
    (Aid::OPENPGP, Capability::OPENPGP),
    (Aid::OATH, Capability::OATH),
];

/// Synthesize DeviceInfo for older YubiKeys (NEO) over CCID by probing applets.
fn synthesize_info_ccid<C: SmartCardConnection + Send + 'static>(
    conn: C,
    mut version: Version,
) -> Result<(DeviceInfo, C), DeviceError> {
    use std::collections::HashMap;

    let mut capabilities = Capability::NONE;

    // Try to read serial and version from OTP application
    let mut serial = None;
    let conn = match YubiOtpSession::new(conn) {
        Ok(mut otp_session) => {
            capabilities |= Capability::OTP;
            if version == Version(0, 0, 0) {
                version = otp_session.version();
            }
            match otp_session.get_serial() {
                Ok(s) => serial = Some(s),
                Err(e) => log::debug!("Unable to read serial over OTP: {e}"),
            }
            otp_session.into_connection()
        }
        Err((e, conn)) => {
            log::debug!("Couldn't select OTP application: {e}");
            conn
        }
    };

    // Scan remaining applets
    let mut protocol = SmartCardProtocol::new(conn);
    for (aid, cap) in SCAN_APPLETS {
        match protocol.select(aid) {
            Ok(_) => {
                capabilities |= *cap;
                log::debug!("Found applet: capability {:?}", cap);
            }
            Err(e) => {
                log::debug!("Missing applet: capability {:?}: {e}", cap);
            }
        }
    }
    let conn = protocol.into_connection();

    // Assume U2F on devices >= 3.3.0
    if version >= Version(3, 3, 0) {
        capabilities |= Capability::U2F;
    }

    let mut supported = HashMap::new();
    supported.insert(Transport::Usb, capabilities);
    supported.insert(Transport::Nfc, capabilities);

    let mut info = DeviceInfo {
        config: DeviceConfig {
            enabled_capabilities: HashMap::new(),
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
        is_sky: false,
        part_number: None,
        fips_capable: Capability::NONE,
        fips_approved: Capability::NONE,
        pin_complexity: false,
        reset_blocked: Capability::NONE,
        fps_version: None,
        stm_version: None,
        version_qualifier: crate::management::VersionQualifier::final_release(version),
    };
    apply_device_info_fixups(&mut info);
    Ok((info, conn))
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
pub(crate) fn apply_device_info_fixups(info: &mut DeviceInfo) {
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
