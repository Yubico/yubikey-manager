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
//! use yubikit::device::{list_devices, list_devices_ccid, list_devices_otp, list_devices_fido};
//!
//! let devices = list_devices(&[list_devices_ccid, list_devices_otp, list_devices_fido]).unwrap();
//! for dev in &devices {
//!     println!("{} (serial: {:?})", dev.name(), dev.serial());
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::thread;
use std::time::Duration;

use crate::core::set_override_version;
use crate::fido::FidoConnection;
use crate::management::{
    Capability, DeviceConfig, DeviceInfo, FormFactor, ManagementCcidSession, ManagementFidoSession,
    ManagementOtpSession, ManagementSession, ReleaseType, UsbInterface,
};
use crate::otp::OtpConnection;
use crate::smartcard::{
    Aid, SmartCardConnection, SmartCardError, SmartCardProtocol, Transport, Version,
};
use crate::transport::ctaphid::{FidoDeviceInfo, HidFidoConnection, list_fido_devices};
use crate::transport::otphid::{HidDeviceInfo, HidError, HidOtpConnection, list_otp_devices};
pub use crate::transport::pcsc::list_readers;
use crate::transport::pcsc::{PcscError, PcscSmartCardConnection};
use crate::yubiotp::{YubiOtpCcidSession, YubiOtpSession};

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
    /// The operation was cancelled by the caller.
    Cancelled,
    /// A different YubiKey was inserted or removed during reinsert.
    WrongDevice,
}

/// Status updates during a device reinsert operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReinsertStatus {
    /// The device should be removed.
    Remove,
    /// The device has been removed and should be reinserted.
    Reinsert,
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SmartCard(e) => write!(f, "SmartCard error: {e}"),
            Self::Pcsc(e) => write!(f, "PC/SC error: {e}"),
            Self::Hid(e) => write!(f, "HID error: {e}"),
            Self::NoDeviceFound => write!(f, "No YubiKey device found"),
            Self::Cancelled => write!(f, "Operation cancelled"),
            Self::WrongDevice => write!(f, "A different YubiKey was inserted/removed"),
        }
    }
}

impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SmartCard(e) => Some(e),
            Self::Pcsc(e) => Some(e),
            Self::Hid(e) => Some(e),
            Self::NoDeviceFound | Self::Cancelled | Self::WrongDevice => None,
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
    pid: Option<u16>,
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

    /// Returns the USB Product ID, if available.
    pub fn pid(&self) -> Option<u16> {
        self.pid
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
    ///
    /// On YubiKey NEO, opening an OTP or FIDO connection ejects the virtual
    /// smartcard. It reappears after a few seconds. This method retries for
    /// up to 4 seconds if the card is temporarily absent.
    pub fn open_smartcard(&self) -> Result<PcscSmartCardConnection, DeviceError> {
        let reader = self
            .reader_name
            .as_deref()
            .ok_or(DeviceError::NoDeviceFound)?;

        let mut last_err = None;
        for attempt in 0..9 {
            match PcscSmartCardConnection::new(reader, false) {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    if attempt < 8 && e.is_no_card() {
                        log::debug!(
                            "SmartCard not ready (attempt {}), retrying in 500ms...",
                            attempt + 1
                        );
                        thread::sleep(Duration::from_millis(500));
                        last_err = Some(e);
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
        Err(last_err.unwrap().into())
    }

    /// Open an OTP HID connection to this device.
    pub fn open_otp(&self) -> Result<HidOtpConnection, DeviceError> {
        let path = self.hid_path.as_deref().ok_or(DeviceError::NoDeviceFound)?;
        Ok(HidOtpConnection::new(path)?)
    }

    /// Open a FIDO HID (CTAP) connection to this device.
    pub fn open_fido(&self) -> Result<HidFidoConnection, DeviceError> {
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
        HidFidoConnection::open(&info)
            .map_err(|e| DeviceError::SmartCard(SmartCardError::Transport(Box::new(e))))
    }

    /// Absorb transport paths from another `YubiKeyDevice` representing the
    /// same physical key. Fills in any `None` fields from `other`.
    fn merge_from(&mut self, other: YubiKeyDevice) {
        if self.reader_name.is_none() {
            self.reader_name = other.reader_name;
        }
        if self.hid_path.is_none() {
            self.hid_path = other.hid_path;
        }
        if self.fido_path.is_none() {
            self.fido_path = other.fido_path;
        }
        if self.pid.is_none() {
            self.pid = other.pid;
        }
        // Prefer the info with a serial number, or with a higher firmware
        // version (synthesized info from OTP may report 3.0.0 instead of the
        // real version).
        if self.info.serial.is_none() && other.info.serial.is_some()
            || self.info.serial == other.info.serial && other.info.version > self.info.version
        {
            self.info = other.info;
        }
    }

    /// Wait for the user to remove and reinsert this YubiKey.
    ///
    /// Polls `scan_devices` to detect removal, then `list_devices` to find
    /// the device again after reinsertion. On success, updates this device's
    /// transport paths to reflect the new enumeration.
    ///
    /// * `enumerators` – the same set of [`EnumerateFn`]s used to discover
    ///   this device (passed through to [`list_devices`]).
    /// * `status_cb` – called with [`ReinsertStatus::Remove`] immediately,
    ///   then [`ReinsertStatus::Reinsert`] once the device is removed.
    /// * `cancelled` – checked every 500 ms; return `true` to cancel.
    pub fn reinsert(
        &mut self,
        enumerators: &[EnumerateFn],
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        let (pids, mut state) = scan_devices();
        let n_devs: usize = pids.values().sum();
        let my_serial = self.info.serial;
        let my_version = self.info.version;
        let mut removed = false;

        log::debug!("Waiting for removal of device serial={my_serial:?}");
        status_cb(ReinsertStatus::Remove);

        loop {
            thread::sleep(Duration::from_millis(250));
            if cancelled() {
                return Err(DeviceError::Cancelled);
            }

            let (new_pids, new_state) = scan_devices();
            if new_state == state {
                continue;
            }
            state = new_state;

            let devs = list_devices(enumerators)?;

            if !removed {
                if new_pids == pids {
                    continue;
                }
                let new_n: usize = new_pids.values().sum();
                if new_n + 1 != n_devs
                    || devs
                        .iter()
                        .any(|d| d.info.serial == my_serial && d.info.version == my_version)
                {
                    return Err(DeviceError::WrongDevice);
                }
                removed = true;
                log::debug!("Device removed, waiting for reinsertion");
                status_cb(ReinsertStatus::Reinsert);
            } else {
                let new_n: usize = new_pids.values().sum();
                if new_n != n_devs {
                    return Err(DeviceError::WrongDevice);
                }
                match devs
                    .into_iter()
                    .find(|d| d.info.serial == my_serial && d.info.version == my_version)
                {
                    Some(found) => {
                        log::debug!("Device reinserted");
                        self.reader_name = found.reader_name;
                        self.hid_path = found.hid_path;
                        self.fido_path = found.fido_path;
                        self.pid = found.pid;
                        self.info = found.info;
                        return Ok(());
                    }
                    None => {
                        return Err(DeviceError::WrongDevice);
                    }
                }
            }
        }
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
// PID derivation
// ---------------------------------------------------------------------------

/// Derive a USB Product ID from a PC/SC reader name.
///
/// Parses interface indicators (OTP, CCID, FIDO/U2F) from the reader name
/// and maps to the corresponding Yubico PID.
fn pid_from_reader_name(name: &str) -> Option<u16> {
    let lower = name.to_ascii_lowercase();
    if !lower.contains("yubi") {
        return None;
    }

    let mut interfaces = UsbInterface(0);
    if name.contains("OTP") {
        interfaces = interfaces | UsbInterface::OTP;
    }
    if name.contains("CCID") {
        interfaces = interfaces | UsbInterface::CCID;
    }
    if name.contains("FIDO") || name.contains("U2F") {
        interfaces = interfaces | UsbInterface::FIDO;
    }

    let is_neo = name.contains("NEO");
    pid_from_interfaces(interfaces, is_neo)
}

/// Map USB interfaces and key type to a PID value.
fn pid_from_interfaces(interfaces: UsbInterface, is_neo: bool) -> Option<u16> {
    let otp = (interfaces & UsbInterface::OTP).0 != 0;
    let fido = (interfaces & UsbInterface::FIDO).0 != 0;
    let ccid = (interfaces & UsbInterface::CCID).0 != 0;

    if is_neo {
        match (otp, fido, ccid) {
            (true, false, false) => Some(0x0110),
            (true, false, true) => Some(0x0111),
            (false, false, true) => Some(0x0112),
            (false, true, false) => Some(0x0113),
            (true, true, false) => Some(0x0114),
            (false, true, true) => Some(0x0115),
            (true, true, true) => Some(0x0116),
            _ => None,
        }
    } else {
        match (otp, fido, ccid) {
            (true, false, false) => Some(0x0401),
            (false, true, false) => Some(0x0402),
            (true, true, false) => Some(0x0403),
            (false, false, true) => Some(0x0404),
            (true, false, true) => Some(0x0405),
            (false, true, true) => Some(0x0406),
            (true, true, true) => Some(0x0407),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Device enumeration
// ---------------------------------------------------------------------------

/// Scan USB for attached YubiKeys without opening any connections.
///
/// Returns a mapping of PID to device count, and a state value that changes
/// whenever the set of attached devices changes (useful for polling).
pub fn scan_devices() -> (HashMap<u16, usize>, u64) {
    let mut counts: HashMap<u16, usize> = HashMap::new();
    let mut fingerprints: Vec<String> = Vec::new();

    // Scan PC/SC readers
    let mut transport_counts: HashMap<u16, usize> = HashMap::new();
    if let Ok(readers) = list_readers() {
        for reader in readers {
            if let Some(pid) = pid_from_reader_name(&reader) {
                *transport_counts.entry(pid).or_insert(0) += 1;
                fingerprints.push(reader);
            }
        }
    }
    for (pid, count) in &transport_counts {
        let entry = counts.entry(*pid).or_insert(0);
        *entry = (*entry).max(*count);
    }

    // Scan HID OTP devices
    transport_counts.clear();
    if let Ok(hid_devices) = list_otp_devices() {
        for hid in hid_devices {
            *transport_counts.entry(hid.pid).or_insert(0) += 1;
            fingerprints.push(hid.path);
        }
    }
    for (pid, count) in &transport_counts {
        let entry = counts.entry(*pid).or_insert(0);
        *entry = (*entry).max(*count);
    }

    // Scan FIDO HID devices
    transport_counts.clear();
    if let Ok(fido_devs) = list_fido_devices() {
        for fido in fido_devs {
            *transport_counts.entry(fido.pid).or_insert(0) += 1;
            fingerprints.push(fido.path);
        }
    }
    for (pid, count) in &transport_counts {
        let entry = counts.entry(*pid).or_insert(0);
        *entry = (*entry).max(*count);
    }

    // Compute a stable hash of fingerprints for change detection
    fingerprints.sort();
    let mut hasher = std::hash::DefaultHasher::new();
    fingerprints.hash(&mut hasher);
    let state = hasher.finish();

    (counts, state)
}

/// Open a device on a specific PC/SC reader by name.
///
/// Unlike [`list_devices`], this does not filter by reader name, so it works
/// for external NFC readers.
pub fn open_reader(reader_name: &str) -> Result<YubiKeyDevice, DeviceError> {
    let pid = pid_from_reader_name(reader_name);
    let info = read_info(reader_name)?;
    Ok(YubiKeyDevice {
        reader_name: Some(reader_name.to_string()),
        hid_path: None,
        fido_path: None,
        pid,
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
                let pid = pid_from_reader_name(&reader);
                devices.push(YubiKeyDevice {
                    reader_name: Some(reader),
                    hid_path: None,
                    fido_path: None,
                    pid,
                    info,
                });
            }
        }
    }

    Ok(devices)
}

/// Type alias for device enumeration functions.
pub type EnumerateFn = fn() -> Result<Vec<YubiKeyDevice>, DeviceError>;

/// Discover connected YubiKeys using the provided enumeration functions.
///
/// Each function typically enumerates a single transport (CCID, OTP HID, or
/// FIDO HID) and returns partial [`YubiKeyDevice`] objects. This function
/// calls each enumerator, then merges results so that a single physical
/// YubiKey is represented by exactly one `YubiKeyDevice` with all of its
/// transport paths populated.
///
/// Merging uses two strategies:
/// 1. **PID uniqueness** – if only one device exists for a given USB PID,
///    all partial devices with that PID must be the same physical key.
/// 2. **Identity match** – devices sharing the same firmware version *and*
///    serial number (or both lacking a serial) are the same key.
pub fn list_devices(enumerators: &[EnumerateFn]) -> Result<Vec<YubiKeyDevice>, DeviceError> {
    log::debug!(
        "Listing YubiKey devices with {} enumerator(s)",
        enumerators.len()
    );

    // Collect partial device lists from each enumerator.
    // Each enumerator may fail (e.g. permission issues); we silently skip
    // failures since the user told us a transport either works for all
    // devices or not at all.
    let mut groups: Vec<Vec<YubiKeyDevice>> = Vec::new();
    for enumerate in enumerators {
        match enumerate() {
            Ok(devs) => {
                log::debug!("Enumerator returned {} device(s)", devs.len());
                groups.push(devs);
            }
            Err(e) => {
                log::debug!("Enumerator failed: {e}");
            }
        }
    }

    if groups.is_empty() {
        return Ok(Vec::new());
    }

    // Start with the first group as the base set.
    let mut merged = groups.remove(0);

    // Merge each subsequent group into the base set.
    for group in groups {
        merge_devices(&mut merged, group);
    }

    Ok(merged)
}

/// Merge `incoming` partial devices into `base`, combining entries that
/// represent the same physical YubiKey.
fn merge_devices(base: &mut Vec<YubiKeyDevice>, incoming: Vec<YubiKeyDevice>) {
    // Count how many devices per PID across both sets.
    let mut pid_counts: HashMap<u16, usize> = HashMap::new();
    for dev in base.iter().chain(incoming.iter()) {
        if let Some(pid) = dev.pid {
            *pid_counts.entry(pid).or_insert(0) += 1;
        }
    }

    for inc in incoming {
        // Strategy 1: PID uniqueness – if only one device of this PID
        // exists in total, find the matching base entry and merge.
        if let Some(pid) = inc.pid
            && pid_counts.get(&pid) == Some(&2)
        {
            // Exactly 2 means one in base + one incoming = same device.
            if let Some(target) = base.iter_mut().find(|d| d.pid == Some(pid)) {
                target.merge_from(inc);
                continue;
            }
        }

        // Strategy 2: Match by (version, serial).
        let identity = (inc.info.version, inc.info.serial);
        if let Some(target) = base
            .iter_mut()
            .find(|d| (d.info.version, d.info.serial) == identity)
        {
            target.merge_from(inc);
            continue;
        }

        // No match found – this is a new device only visible over
        // this transport.
        base.push(inc);
    }
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
            let info = HidOtpConnection::new(&hid.path)
                .ok()
                .and_then(|conn| read_info_otp(conn).ok())
                .map(|(info, _conn)| info)
                .unwrap_or_else(|| synthetic_hid_info(&hid));
            devices.push(YubiKeyDevice {
                reader_name: None,
                hid_path: Some(hid.path.clone()),
                fido_path: None,
                pid: Some(hid.pid),
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
/// Opens a fresh [`PcscSmartCardConnection`] and uses [`ManagementCcidSession`] to read
/// [`DeviceInfo`]. For older devices (NEO, etc.) that don't support the
/// management protocol, synthesizes DeviceInfo by probing individual applets.
///
/// On YubiKey NEO, the virtual smartcard may be temporarily ejected after
/// an OTP or FIDO connection. This function retries for up to 4 seconds.
pub fn read_info(reader_name: &str) -> Result<DeviceInfo, DeviceError> {
    let mut last_err = None;
    for attempt in 0..9 {
        match PcscSmartCardConnection::new(reader_name, false) {
            Ok(conn) => {
                let (info, _conn) = read_info_ccid(conn)?;
                return Ok(info);
            }
            Err(e) if e.is_no_card() && attempt < 8 => {
                log::debug!(
                    "SmartCard not ready for read_info (attempt {}), retrying in 500ms...",
                    attempt + 1
                );
                thread::sleep(Duration::from_millis(500));
                last_err = Some(e);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_err.unwrap().into())
}

/// Read device info from an open smart card connection.
///
/// Uses [`ManagementCcidSession`] to read [`DeviceInfo`]. For older devices
/// (NEO, etc.) that don't support the management protocol, synthesizes
/// DeviceInfo by probing individual applets.
///
/// Returns the info and the connection so it can be reused.
pub fn read_info_ccid<C: SmartCardConnection>(conn: C) -> Result<(DeviceInfo, C), DeviceError> {
    let mut session = ManagementCcidSession::new(conn).map_err(|(e, _)| e)?;
    let version = session.version();

    match session.read_device_info_unchecked() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            let conn = session.into_connection();
            Ok((info, conn))
        }
        Err(_) if version < Version(4, 1, 0) => {
            log::debug!("Management read_device_info not supported, synthesizing");
            let conn = session.into_connection();
            let (info, conn) = synthesize_info_ccid(conn, version)?;
            Ok((info, conn))
        }
        Err(e) => Err(DeviceError::SmartCard(e)),
    }
}

/// Read device info via OTP HID from an open connection.
///
/// Uses [`ManagementOtpSession`] to read [`DeviceInfo`].
/// Applies standard fixups for known device quirks.
/// Returns the info and the connection for reuse.
/// The connection is returned when possible, even on error.
pub fn read_info_otp<T: OtpConnection>(
    conn: T,
) -> Result<(DeviceInfo, T), (DeviceError, Option<T>)> {
    let mut session = ManagementOtpSession::new(conn).map_err(|(e, conn)| {
        (
            DeviceError::SmartCard(SmartCardError::BadResponse(e.to_string())),
            Some(conn),
        )
    })?;
    match session.read_device_info_unchecked() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            Ok((info, session.into_connection()))
        }
        Err(e) => Err((DeviceError::SmartCard(e), Some(session.into_connection()))),
    }
}

/// Read device info via FIDO HID (CTAP) from an open connection.
///
/// Uses [`ManagementFidoSession`] to read [`DeviceInfo`].
/// Applies standard fixups for known device quirks.
/// Returns the info and the connection for reuse.
/// The connection is returned when possible, even on error.
pub fn read_info_fido<C: FidoConnection>(
    conn: C,
) -> Result<(DeviceInfo, C), (DeviceError, Option<C>)> {
    let mut session = ManagementFidoSession::new(conn)
        .map_err(|(e, conn)| (DeviceError::SmartCard(e), Some(conn)))?;
    match session.read_device_info_unchecked() {
        Ok(mut info) => {
            apply_device_info_fixups(&mut info);
            Ok((info, session.into_connection()))
        }
        Err(e) => Err((DeviceError::SmartCard(e), Some(session.into_connection()))),
    }
}

/// List Yubico FIDO HID devices with device info.
pub fn list_devices_fido() -> Result<Vec<YubiKeyDevice>, DeviceError> {
    log::debug!("Listing YubiKey devices (FIDO HID only)");
    let mut devices = Vec::new();

    if let Ok(fido_devs) = list_fido_devices() {
        for fido in fido_devs {
            let info = HidFidoConnection::open(&fido)
                .ok()
                .and_then(|conn| read_info_fido(conn).ok())
                .map(|(info, _conn)| info)
                .unwrap_or_else(|| synthetic_fido_info(&fido));
            devices.push(YubiKeyDevice {
                reader_name: None,
                hid_path: None,
                fido_path: Some(fido.path),
                pid: Some(fido.pid),
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
fn synthesize_info_ccid<C: SmartCardConnection>(
    conn: C,
    version: Version,
) -> Result<(DeviceInfo, C), DeviceError> {
    use std::collections::HashMap;

    let mut capabilities = Capability::NONE;

    // Try to read serial from OTP application
    let mut serial = None;
    let conn = match YubiOtpCcidSession::new(conn) {
        Ok(mut otp_session) => {
            capabilities |= Capability::OTP;
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

/// Apply standard fixups for known device quirks.
///
/// This corrects issues with certain YubiKey firmware versions that
/// report incorrect or incomplete information.
pub fn apply_device_info_fixups(info: &mut DeviceInfo) {
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

    // SKY without FIDO2 (SKY 1), only for pre-5.1.0
    if info.is_sky && !usb_supported.contains(Capability::FIDO2) && info.version < Version(5, 1, 0)
    {
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

    fn make_device(
        reader_name: Option<&str>,
        hid_path: Option<&str>,
        fido_path: Option<&str>,
        pid: Option<u16>,
        version: Version,
        serial: Option<u32>,
    ) -> YubiKeyDevice {
        let info = make_info(
            version,
            FormFactor::UsbAKeychain,
            false,
            false,
            serial,
            false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        );
        YubiKeyDevice {
            reader_name: reader_name.map(String::from),
            hid_path: hid_path.map(String::from),
            fido_path: fido_path.map(String::from),
            pid,
            info,
        }
    }

    #[test]
    fn test_merge_by_pid_uniqueness() {
        // Three enumerators each find one device with the same PID → merge.
        fn enum_ccid() -> Result<Vec<YubiKeyDevice>, DeviceError> {
            Ok(vec![make_device(
                Some("Yubico YubiKey OTP+FIDO+CCID 00"),
                None,
                None,
                Some(0x0407),
                Version(5, 4, 3),
                Some(12345),
            )])
        }
        fn enum_otp() -> Result<Vec<YubiKeyDevice>, DeviceError> {
            Ok(vec![make_device(
                None,
                Some("/dev/hidraw0"),
                None,
                Some(0x0407),
                Version(5, 4, 3),
                Some(12345),
            )])
        }
        fn enum_fido() -> Result<Vec<YubiKeyDevice>, DeviceError> {
            Ok(vec![make_device(
                None,
                None,
                Some("/dev/hidraw1"),
                Some(0x0407),
                Version(5, 4, 3),
                Some(12345),
            )])
        }

        let result = list_devices(&[enum_ccid, enum_otp, enum_fido]).unwrap();
        assert_eq!(result.len(), 1, "Should merge into a single device");
        let dev = &result[0];
        assert_eq!(dev.reader_name(), Some("Yubico YubiKey OTP+FIDO+CCID 00"));
        assert_eq!(dev.hid_path(), Some("/dev/hidraw0"));
        assert_eq!(dev.fido_path(), Some("/dev/hidraw1"));
        assert_eq!(dev.pid(), Some(0x0407));
    }

    #[test]
    fn test_merge_by_identity() {
        // Two devices with same PID but different serials are NOT merged.
        fn enum_ccid() -> Result<Vec<YubiKeyDevice>, DeviceError> {
            Ok(vec![
                make_device(
                    Some("reader0"),
                    None,
                    None,
                    Some(0x0407),
                    Version(5, 4, 3),
                    Some(111),
                ),
                make_device(
                    Some("reader1"),
                    None,
                    None,
                    Some(0x0407),
                    Version(5, 4, 3),
                    Some(222),
                ),
            ])
        }
        fn enum_otp() -> Result<Vec<YubiKeyDevice>, DeviceError> {
            Ok(vec![
                make_device(
                    None,
                    Some("/dev/h0"),
                    None,
                    Some(0x0407),
                    Version(5, 4, 3),
                    Some(111),
                ),
                make_device(
                    None,
                    Some("/dev/h1"),
                    None,
                    Some(0x0407),
                    Version(5, 4, 3),
                    Some(222),
                ),
            ])
        }

        let result = list_devices(&[enum_ccid, enum_otp]).unwrap();
        assert_eq!(result.len(), 2, "Should remain as two devices");
        // Each should have merged with its identity match
        let d1 = result.iter().find(|d| d.serial() == Some(111)).unwrap();
        assert!(d1.reader_name().is_some());
        assert!(d1.hid_path().is_some());
        let d2 = result.iter().find(|d| d.serial() == Some(222)).unwrap();
        assert!(d2.reader_name().is_some());
        assert!(d2.hid_path().is_some());
    }

    #[test]
    fn test_merge_failed_enumerator() {
        // A failing enumerator is silently skipped.
        fn enum_ok() -> Result<Vec<YubiKeyDevice>, DeviceError> {
            Ok(vec![make_device(
                Some("reader"),
                None,
                None,
                Some(0x0407),
                Version(5, 4, 3),
                Some(100),
            )])
        }
        fn enum_fail() -> Result<Vec<YubiKeyDevice>, DeviceError> {
            Err(DeviceError::NoDeviceFound)
        }

        let result = list_devices(&[enum_ok, enum_fail]).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_merge_no_enumerators() {
        let result = list_devices(&[]).unwrap();
        assert!(result.is_empty());
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
