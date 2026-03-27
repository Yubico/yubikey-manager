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
//! use yubikit::device::list_devices;
//!
//! let devices = list_devices().unwrap();
//! for dev in &devices {
//!     println!("{} (serial: {:?})", dev.name(), dev.serial());
//! }
//! ```

use std::collections::HashSet;
use std::fmt;

use crate::management::{
    Capability, DeviceConfig, DeviceInfo, FormFactor, ManagementFidoSession, ManagementOtpSession,
    ManagementSession, UsbInterface,
};
use crate::smartcard::{Aid, SmartCardError, SmartCardProtocol, Transport, Version};
use crate::transport::ctaphid::{FidoConnection, FidoDeviceInfo, list_fido_devices};
use crate::transport::otphid::{HidDeviceInfo, HidError, OtpConnection, list_otp_devices};
pub use crate::transport::pcsc::list_readers;
use crate::transport::pcsc::{PcscConnection, PcscError};
use crate::yubiotp::YubiOtpSession;

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
    fido_path: Option<String>,
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

    /// Returns the FIDO HID device path, if this device was found over FIDO.
    pub fn fido_path(&self) -> Option<&str> {
        self.fido_path.as_deref()
    }

    /// Returns detected USB interfaces based on enabled capabilities.
    pub fn usb_interfaces(&self) -> UsbInterface {
        // Derive from enabled USB capabilities in the device info
        if let Some(&usb_caps) = self.info.config.enabled_capabilities.get(&Transport::Usb) {
            let mut ifaces = UsbInterface(0);
            if usb_caps.contains(Capability::OTP) {
                ifaces = ifaces | UsbInterface::OTP;
            }
            if usb_caps.contains(Capability::FIDO2) || usb_caps.contains(Capability::U2F) {
                ifaces = ifaces | UsbInterface::FIDO;
            }
            // CCID: any of PIV, OATH, OpenPGP, HSMAUTH, or Management
            if usb_caps.contains(Capability::PIV)
                || usb_caps.contains(Capability::OATH)
                || usb_caps.contains(Capability::OPENPGP)
                || usb_caps.contains(Capability::HSMAUTH)
            {
                ifaces = ifaces | UsbInterface::CCID;
            }
            ifaces
        } else {
            // Fallback: infer from which transports were discovered
            let mut ifaces = UsbInterface(0);
            if self.reader_name.is_some() {
                ifaces = ifaces | UsbInterface::CCID;
                ifaces = ifaces | UsbInterface::FIDO;
            }
            if self.hid_path.is_some() {
                ifaces = ifaces | UsbInterface::OTP;
            }
            ifaces
        }
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
    pub fn open_otp(&self) -> Result<OtpConnection, DeviceError> {
        let path = self.hid_path.as_deref().ok_or(DeviceError::NoDeviceFound)?;
        Ok(OtpConnection::new(path)?)
    }

    /// Open a FIDO HID (CTAP) connection to this device.
    pub fn open_fido(&self) -> Result<FidoConnection, DeviceError> {
        let path = self
            .fido_path
            .as_deref()
            .ok_or(DeviceError::NoDeviceFound)?;
        // Find the matching FIDO device info from enumeration
        let fido_devs = list_fido_devices()
            .map_err(|e| DeviceError::SmartCard(SmartCardError::Transport(Box::new(e))))?;
        let info = fido_devs
            .into_iter()
            .find(|d| d.path == path)
            .ok_or(DeviceError::NoDeviceFound)?;
        FidoConnection::open(&info)
            .map_err(|e| DeviceError::SmartCard(SmartCardError::Transport(Box::new(e))))
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

/// Open a device on a specific PC/SC reader by name.
///
/// Unlike [`list_devices`], this does not filter by reader name, so it works
/// for external NFC readers.
pub fn open_reader(reader_name: &str) -> Result<YubiKeyDevice, DeviceError> {
    let info = read_info(reader_name)?;
    Ok(YubiKeyDevice {
        reader_name: Some(reader_name.to_string()),
        hid_path: None,
        fido_path: None,
        info,
    })
}

/// Discover connected YubiKeys over CCID (PC/SC) only.
///
/// Unlike [`list_devices`], this does not scan HID devices.
/// Use when the command only needs SmartCard connections.
pub fn list_devices_ccid() -> Result<Vec<YubiKeyDevice>, DeviceError> {
    log::debug!("Listing YubiKey devices (CCID only)");
    let mut devices = Vec::new();

    if let Ok(readers) = list_readers() {
        log::debug!("Found {} PC/SC reader(s)", readers.len());
        for reader in readers {
            if !reader.to_ascii_lowercase().contains("yubi") {
                continue;
            }
            log::debug!("Checking PC/SC reader: {reader}");
            if let Ok(info) = read_info(&reader) {
                devices.push(YubiKeyDevice {
                    reader_name: Some(reader),
                    hid_path: None,
                    fido_path: None,
                    info,
                });
            }
        }
    }

    Ok(devices)
}

/// Discover all connected YubiKeys.
///
/// Scans PC/SC readers and HID devices, reads [`DeviceInfo`] from each,
/// and returns a unified list of discovered YubiKeys. Devices visible over
/// both PC/SC and HID (matched by serial number) are merged into a single
/// entry.
pub fn list_devices() -> Result<Vec<YubiKeyDevice>, DeviceError> {
    log::debug!("Listing YubiKey devices");
    let mut devices = Vec::new();
    let mut seen_serials = HashSet::new();

    // Scan PC/SC readers
    if let Ok(readers) = list_readers() {
        log::debug!("Found {} PC/SC reader(s)", readers.len());
        for reader in readers {
            if !reader.to_ascii_lowercase().contains("yubi") {
                continue;
            }
            log::debug!("Checking PC/SC reader: {reader}");
            {
                if let Ok(info) = read_info(&reader) {
                    if let Some(serial) = info.serial {
                        seen_serials.insert(serial);
                    }
                    devices.push(YubiKeyDevice {
                        reader_name: Some(reader),
                        hid_path: None,
                        fido_path: None,
                        info,
                    });
                }
            }
        }
    }

    // Scan HID OTP devices, merging with existing PC/SC entries by serial
    if let Ok(hid_devices) = list_otp_devices() {
        for hid in hid_devices {
            // If there's exactly one unmatched CCID device, just merge by path
            // without opening the OTP connection (avoids NEO CCID lockout)
            let unmatched_ccid: Vec<_> = devices
                .iter()
                .enumerate()
                .filter(|(_, d)| d.hid_path.is_none())
                .collect();
            if unmatched_ccid.len() == 1 {
                let idx = unmatched_ccid[0].0;
                devices[idx].hid_path = Some(hid.path.clone());
                continue;
            }

            // Multiple or zero unmatched: need OTP info to match
            let hid_info = read_info_otp(&hid.path).ok();
            let hid_serial = hid_info.as_ref().and_then(|i| i.serial);

            // Try to merge with an existing PCSC entry by serial
            let merged = if let Some(serial) = hid_serial {
                if let Some(dev) = devices
                    .iter_mut()
                    .find(|d| d.serial() == Some(serial) && d.hid_path.is_none())
                {
                    dev.hid_path = Some(hid.path.clone());
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !merged {
                let info = hid_info.unwrap_or_else(|| synthetic_hid_info(&hid));
                if let Some(serial) = info.serial {
                    if !seen_serials.contains(&serial) {
                        seen_serials.insert(serial);
                        devices.push(YubiKeyDevice {
                            reader_name: None,
                            hid_path: Some(hid.path),
                            fido_path: None,
                            info,
                        });
                    }
                } else {
                    devices.push(YubiKeyDevice {
                        reader_name: None,
                        hid_path: Some(hid.path),
                        fido_path: None,
                        info,
                    });
                }
            }
        }
    }

    // Scan FIDO HID devices, merging with existing entries by serial
    if let Ok(fido_devs) = list_fido_devices() {
        for fido in fido_devs {
            // If there's exactly one unmatched device, just merge by path
            let unmatched: Vec<_> = devices
                .iter()
                .enumerate()
                .filter(|(_, d)| d.fido_path.is_none())
                .collect();
            if unmatched.len() == 1 {
                let idx = unmatched[0].0;
                devices[idx].fido_path = Some(fido.path.clone());
                continue;
            }

            let fido_info = read_info_fido(&fido).ok();
            let fido_serial = fido_info.as_ref().and_then(|i| i.serial);

            let merged = if let Some(serial) = fido_serial {
                if let Some(dev) = devices
                    .iter_mut()
                    .find(|d| d.serial() == Some(serial) && d.fido_path.is_none())
                {
                    dev.fido_path = Some(fido.path.clone());
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !merged {
                let info = fido_info.unwrap_or_else(|| synthetic_fido_info(&fido));
                if let Some(serial) = info.serial {
                    if !seen_serials.contains(&serial) {
                        seen_serials.insert(serial);
                        devices.push(YubiKeyDevice {
                            reader_name: None,
                            hid_path: None,
                            fido_path: Some(fido.path),
                            info,
                        });
                    }
                } else {
                    devices.push(YubiKeyDevice {
                        reader_name: None,
                        hid_path: None,
                        fido_path: Some(fido.path),
                        info,
                    });
                }
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

/// Build a minimal synthetic [`DeviceInfo`] for a FIDO-only device.
fn synthetic_fido_info(fido: &FidoDeviceInfo) -> DeviceInfo {
    use std::collections::HashMap;

    let version = pid_to_version(fido.pid);
    let mut supported = HashMap::new();
    supported.insert(Transport::Usb, Capability::FIDO2);

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

/// Discover YubiKeys using only OTP HID.
///
/// Scans HID devices only (no PC/SC), returning devices that have OTP HID
/// interfaces. Use this for OTP-preferred commands to avoid opening CCID
/// connections unnecessarily.
pub fn list_devices_otp() -> Result<Vec<YubiKeyDevice>, DeviceError> {
    log::debug!("Listing YubiKey devices (OTP HID only)");
    let mut devices = Vec::new();

    if let Ok(hid_devices) = list_otp_devices() {
        for hid in hid_devices {
            let info = read_info_otp(&hid.path).unwrap_or_else(|_| synthetic_hid_info(&hid));
            devices.push(YubiKeyDevice {
                reader_name: None,
                hid_path: Some(hid.path),
                fido_path: None,
                info,
            });
        }
    }

    Ok(devices)
}

// ---------------------------------------------------------------------------
// read_info
// ---------------------------------------------------------------------------

/// Read device info from a PC/SC reader.
///
/// Opens a fresh [`PcscConnection`] and uses [`ManagementSession`] to read
/// [`DeviceInfo`]. For older devices (NEO, etc.) that don't support the
/// management protocol, synthesizes DeviceInfo by probing individual applets.
pub fn read_info(reader_name: &str) -> Result<DeviceInfo, DeviceError> {
    let conn = PcscConnection::new(reader_name, false)?;
    let mut session = ManagementSession::new(conn)?;
    let version = session.version();

    match session.read_device_info_unchecked() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            Ok(info)
        }
        Err(_) if version < Version(4, 1, 0) => {
            log::debug!("Management read_device_info not supported, synthesizing");
            // Reclaim the connection from the session
            let conn = session.into_connection();
            synthesize_info_ccid(conn, version)
        }
        Err(e) => Err(DeviceError::SmartCard(e)),
    }
}

/// Read device info via OTP HID.
///
/// Opens an [`OtpConnection`] and uses [`ManagementOtpSession`] to read
/// [`DeviceInfo`]. Applies standard fixups for known device quirks.
pub fn read_info_otp(hid_path: &str) -> Result<DeviceInfo, DeviceError> {
    let conn = OtpConnection::new(hid_path)?;
    let mut session = ManagementOtpSession::new(conn)
        .map_err(|e| DeviceError::SmartCard(SmartCardError::BadResponse(e.to_string())))?;
    // Use unchecked variant — dev devices report version 0.0.1 but still
    // support the DeviceInfo protocol.
    let mut info = session
        .read_device_info_unchecked()
        .map_err(DeviceError::SmartCard)?;
    apply_device_info_fixups(&mut info);
    Ok(info)
}

/// Read device info via FIDO HID (CTAP).
///
/// Opens a [`FidoConnection`] and uses [`ManagementFidoSession`] to read
/// [`DeviceInfo`]. Applies standard fixups for known device quirks.
pub fn read_info_fido(fido_info: &FidoDeviceInfo) -> Result<DeviceInfo, DeviceError> {
    let conn = FidoConnection::open(fido_info)
        .map_err(|e| DeviceError::SmartCard(SmartCardError::Transport(Box::new(e))))?;
    let mut session = ManagementFidoSession::new(conn).map_err(DeviceError::SmartCard)?;
    let mut info = session
        .read_device_info_unchecked()
        .map_err(DeviceError::SmartCard)?;
    apply_device_info_fixups(&mut info);
    Ok(info)
}

/// List Yubico FIDO HID devices with device info.
pub fn list_devices_fido() -> Result<Vec<YubiKeyDevice>, DeviceError> {
    log::debug!("Listing YubiKey devices (FIDO HID only)");
    let mut devices = Vec::new();

    if let Ok(fido_devs) = list_fido_devices() {
        for fido in fido_devs {
            let info = read_info_fido(&fido).unwrap_or_else(|_| synthetic_fido_info(&fido));
            devices.push(YubiKeyDevice {
                reader_name: None,
                hid_path: None,
                fido_path: Some(fido.path),
                info,
            });
        }
    }

    Ok(devices)
}

/// Applets to scan when synthesizing DeviceInfo for older keys.
const SCAN_APPLETS: &[(&[u8], Capability)] = &[
    (Aid::FIDO, Capability::U2F),
    (Aid::PIV, Capability::PIV),
    (Aid::OPENPGP, Capability::OPENPGP),
    (Aid::OATH, Capability::OATH),
];

/// Synthesize DeviceInfo for older YubiKeys (NEO) over CCID by probing applets.
fn synthesize_info_ccid(conn: PcscConnection, version: Version) -> Result<DeviceInfo, DeviceError> {
    use std::collections::HashMap;

    let mut capabilities = Capability::NONE;

    // Try to read serial from OTP application
    let mut serial = None;
    match YubiOtpSession::new(conn) {
        Ok(mut otp_session) => {
            capabilities |= Capability::OTP;
            match otp_session.get_serial() {
                Ok(s) => serial = Some(s),
                Err(e) => log::debug!("Unable to read serial over OTP: {e}"),
            }
            // Reclaim the connection
            let conn = otp_session.into_connection();

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
        }
        Err(e) => {
            log::debug!("Couldn't select OTP application: {e}");
        }
    }

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
    Ok(info)
}

/// Apply standard fixups for known device quirks.
///
/// This corrects issues with certain YubiKey firmware versions that
/// report incorrect or incomplete information.
pub fn apply_device_info_fixups(info: &mut DeviceInfo) {
    // YK4-based FIPS (4.4.x)
    if info.version >= Version(4, 4, 0) && info.version < Version(4, 5, 0) {
        info.is_fips = true;
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

    parts.join(" ").replace("5 C", "5C").replace("5 A", "5A")
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
}
