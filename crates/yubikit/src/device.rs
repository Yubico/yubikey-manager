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

use crate::core::Transport;
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
        }
    }
}

impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SmartCard(e) => Some(e),
            Self::Management(e) => Some(e),
            Self::Transport(e) => Some(e.as_ref()),
            Self::NoDeviceFound | Self::NotYubiKey | Self::Cancelled | Self::WrongDevice => None,
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
/// Implemented by [`LocalYubiKeyDevice`] for local devices and can be implemented
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
// DeviceSource trait
// ---------------------------------------------------------------------------

/// A source of YubiKey devices.
///
/// Abstracts over local enumeration (USB/NFC) and remote access via the
/// ykman-svc service, allowing callers to enumerate devices without caring
/// about the underlying transport.
pub trait DeviceSource {
    /// List all currently connected YubiKey devices.
    fn list_devices(&mut self) -> Result<Vec<Box<dyn YubiKeyDevice>>, DeviceError>;

    /// Select a YubiKey by touch via CTAP2 authenticator selection.
    ///
    /// Waits for the user to touch a connected YubiKey and returns it.
    fn select_fido(
        &mut self,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Box<dyn YubiKeyDevice>, DeviceError>;

    /// Whether this source is backed by a remote service.
    fn is_service(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Device naming
// ---------------------------------------------------------------------------

use crate::core::Version;

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
