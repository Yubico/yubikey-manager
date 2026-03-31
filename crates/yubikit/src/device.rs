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
//! use yubikit::management::UsbInterface;
//!
//! let devices = list_devices(UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO).unwrap();
//! for dev in &devices {
//!     println!("{} (serial: {:?})", dev.name(), dev.serial());
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::thread;
use std::time::Duration;

use crate::core::{Transport, Version, set_override_version};
use crate::fido::FidoConnection;
use crate::management::{
    Capability, DeviceConfig, DeviceInfo, FormFactor, ManagementCcidSession, ManagementFidoSession,
    ManagementOtpSession, ManagementSession, ReleaseType, UsbInterface,
};
use crate::otp::OtpConnection;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol};
use crate::transport::ctaphid::{FidoDeviceInfo, HidFidoConnection, list_fido_devices};
#[cfg(windows)]
use crate::transport::otphid::list_all_hid_devices;
use crate::transport::otphid::{HidDeviceInfo, HidError, HidOtpConnection, list_otp_devices};
pub use crate::transport::pcsc::list_readers;
use crate::transport::pcsc::{PcscError, PcscSmartCardConnection, is_reader_usb};
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
    /// The device should be removed (USB: unplug, NFC: remove from reader).
    Remove,
    /// The device has been removed and should be reinserted (USB: plug in, NFC: place on reader).
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
    transport: Transport,
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

    /// Returns the transport type (USB or NFC).
    pub fn transport(&self) -> Transport {
        self.transport
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
    /// Requires that this device was discovered over CCID (i.e. has a reader
    /// name). Attempts exclusive access first, falling back to shared.
    pub fn open_smartcard(&self) -> Result<PcscSmartCardConnection, DeviceError> {
        let reader = self
            .reader_name
            .as_deref()
            .ok_or(DeviceError::NoDeviceFound)?;

        let mut last_err = None;
        for attempt in 0..9 {
            match PcscSmartCardConnection::open(reader) {
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
    /// On success, updates this device's transport paths and info.
    ///
    /// * `status_cb` – called with [`ReinsertStatus`] variants to indicate
    ///   what the user should do.
    /// * `cancelled` – checked periodically; return `true` to cancel.
    pub fn reinsert(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        match self.transport {
            Transport::Usb => self.reinsert_usb(status_cb, cancelled),
            Transport::Nfc => self.reinsert_nfc(status_cb, cancelled),
        }
    }

    fn reinsert_usb(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        // Build interface set based on which transports this device was found on.
        let mut interfaces = UsbInterface(0);
        if self.reader_name.is_some() {
            interfaces = interfaces | UsbInterface::CCID;
        }
        if self.hid_path.is_some() {
            interfaces = interfaces | UsbInterface::OTP;
        }
        if self.fido_path.is_some() {
            interfaces = interfaces | UsbInterface::FIDO;
        }

        let (pids, mut state) = scan_usb_devices();
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

            let (new_pids, new_state) = scan_usb_devices();
            if new_state == state {
                continue;
            }
            state = new_state;

            let devs = list_devices(interfaces)?;

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

    fn reinsert_nfc(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        let reader = self
            .reader_name
            .as_deref()
            .ok_or(DeviceError::NoDeviceFound)?;
        let my_serial = self.info.serial;
        let my_version = self.info.version;
        let mut removed = false;

        log::debug!("NFC reinsert: waiting for card removal from reader {reader}");
        status_cb(ReinsertStatus::Remove);

        loop {
            thread::sleep(Duration::from_millis(500));
            if cancelled() {
                return Err(DeviceError::Cancelled);
            }

            if !removed {
                // Try to connect — if it fails with "no card", the card was removed
                match PcscSmartCardConnection::open(reader) {
                    Ok(_conn) => continue, // Card still present
                    Err(e) if e.is_no_card() => {
                        removed = true;
                        log::debug!("NFC card removed, waiting for tap");
                        status_cb(ReinsertStatus::Reinsert);
                    }
                    Err(e) => return Err(e.into()),
                }
            } else {
                // Wait for card to reappear and verify it's the same device
                match read_info(reader) {
                    Ok((info, _transport)) => {
                        if info.serial == my_serial && info.version == my_version {
                            log::debug!("NFC card reinserted successfully");
                            self.info = info;
                            // Give the card a moment to settle
                            thread::sleep(Duration::from_secs(1));
                            return Ok(());
                        }
                        return Err(DeviceError::WrongDevice);
                    }
                    Err(_) => continue, // Card not ready yet
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
    if !is_reader_usb(name) {
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
/// Only checks USB-connected devices (Yubico readers, OTP HID, FIDO HID).
/// NFC readers are excluded since they are not USB-attached YubiKeys.
///
/// Returns a mapping of PID to device count, and a state value that changes
/// whenever the set of attached devices changes (useful for polling).
pub fn scan_usb_devices() -> (HashMap<u16, usize>, u64) {
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

    // On Windows, non-admin users cannot open FIDO devices. Supplement
    // the scan with a raw HID enumeration so those devices still show up.
    #[cfg(windows)]
    {
        if let Ok(all_hid) = list_all_hid_devices() {
            for dev in all_hid {
                // Only add PIDs not already found via normal enumeration
                if !counts.contains_key(&dev.pid) {
                    *counts.entry(dev.pid).or_insert(0) += 1;
                    fingerprints.push(dev.path);
                }
            }
        }
    }

    // Compute a stable hash of fingerprints for change detection
    fingerprints.sort();
    let mut hasher = std::hash::DefaultHasher::new();
    fingerprints.hash(&mut hasher);
    let state = hasher.finish();

    (counts, state)
}

/// Discover connected YubiKeys over the requested USB interfaces.
///
/// `interfaces` is a bitmask of [`UsbInterface`] values indicating which
/// transports the caller is interested in. [`UsbInterface::CCID`] covers
/// both USB and NFC readers.
///
/// Each physical YubiKey is returned as a single [`YubiKeyDevice`] with
/// transport paths populated for every interface that was discovered. When
/// only one device is present per USB Product ID the merge is trivial;
/// multiple devices sharing a PID are matched by firmware version and serial.
pub fn list_devices(interfaces: UsbInterface) -> Result<Vec<YubiKeyDevice>, DeviceError> {
    log::debug!("Listing YubiKey devices (interfaces: {interfaces})");

    let want_ccid = interfaces.contains(UsbInterface::CCID);
    let want_otp = interfaces.contains(UsbInterface::OTP);
    let want_fido = interfaces.contains(UsbInterface::FIDO);

    // ── Phase 1: cheap discovery (no connections opened) ──────────
    // For each transport, collect (PID, path/reader_name).
    let mut usb_readers: Vec<(u16, String)> = Vec::new(); // PID → reader_name
    let mut nfc_readers: Vec<String> = Vec::new();
    if want_ccid && let Ok(readers) = list_readers() {
        for reader in readers {
            if is_reader_usb(&reader) {
                if let Some(pid) = pid_from_reader_name(&reader) {
                    usb_readers.push((pid, reader));
                }
            } else {
                nfc_readers.push(reader);
            }
        }
    }

    let mut otp_devs: Vec<HidDeviceInfo> = Vec::new();
    if want_otp && let Ok(devs) = list_otp_devices() {
        otp_devs = devs;
    }

    let mut fido_devs: Vec<FidoDeviceInfo> = Vec::new();
    if want_fido && let Ok(devs) = list_fido_devices() {
        fido_devs = devs;
    }

    // Count devices per PID across all transports.
    let mut pid_counts: HashMap<u16, usize> = HashMap::new();
    for &(pid, _) in &usb_readers {
        *pid_counts.entry(pid).or_insert(0) += 1;
    }
    for hid in &otp_devs {
        let entry = pid_counts.entry(hid.pid).or_insert(0);
        *entry = (*entry).max(1); // HID is 1-per-PID in practice
    }
    for fido in &fido_devs {
        let entry = pid_counts.entry(fido.pid).or_insert(0);
        *entry = (*entry).max(1);
    }

    let n_usb: usize = pid_counts.values().sum();
    log::debug!(
        "Fast scan: {n_usb} USB device(s) across {} PID(s)",
        pid_counts.len()
    );

    // ── Phase 2: open connections and build device list ───────────
    let mut devices: Vec<YubiKeyDevice> = Vec::new();

    // For each PID, decide whether we need full multi-transport enumeration.
    for (&pid, &count) in &pid_counts {
        if count <= 1 {
            // Single device for this PID — open one connection only.
            if let Some(dev) = open_single_usb(pid, &usb_readers, &otp_devs, &fido_devs) {
                devices.push(dev);
            }
        } else {
            // Multiple devices with this PID — enumerate all requested
            // interfaces and merge by identity.
            let mut base: Vec<YubiKeyDevice> = Vec::new();

            if want_ccid {
                for &(p, ref reader) in &usb_readers {
                    if p == pid
                        && let Ok((info, transport)) = read_info(reader)
                    {
                        base.push(YubiKeyDevice {
                            reader_name: Some(reader.clone()),
                            hid_path: None,
                            fido_path: None,
                            pid: Some(pid),
                            transport,
                            info,
                        });
                    }
                }
            }

            if want_otp {
                let mut otp_group = Vec::new();
                for hid in &otp_devs {
                    if hid.pid == pid {
                        let info = HidOtpConnection::new(&hid.path)
                            .ok()
                            .and_then(|conn| read_info_otp(conn).ok())
                            .map(|(info, _)| info)
                            .unwrap_or_else(|| synthetic_hid_info(hid));
                        otp_group.push(YubiKeyDevice {
                            reader_name: None,
                            hid_path: Some(hid.path.clone()),
                            fido_path: None,
                            pid: Some(pid),
                            transport: Transport::Usb,
                            info,
                        });
                    }
                }
                if base.is_empty() {
                    base = otp_group;
                } else {
                    merge_devices(&mut base, otp_group);
                }
            }

            if want_fido {
                let mut fido_group = Vec::new();
                for fido in &fido_devs {
                    if fido.pid == pid {
                        let info = HidFidoConnection::open(fido)
                            .ok()
                            .and_then(|conn| read_info_fido(conn).ok())
                            .map(|(info, _)| info)
                            .unwrap_or_else(|| synthetic_fido_info(fido));
                        fido_group.push(YubiKeyDevice {
                            reader_name: None,
                            hid_path: None,
                            fido_path: Some(fido.path.clone()),
                            pid: Some(pid),
                            transport: Transport::Usb,
                            info,
                        });
                    }
                }
                if base.is_empty() {
                    base = fido_group;
                } else {
                    merge_devices(&mut base, fido_group);
                }
            }

            devices.extend(base);
        }
    }

    // ── Phase 3: NFC devices (no merging needed) ─────────────────
    for reader in &nfc_readers {
        log::debug!("Checking NFC reader: {reader}");
        match read_info(reader) {
            Ok((info, transport)) => {
                devices.push(YubiKeyDevice {
                    reader_name: Some(reader.clone()),
                    hid_path: None,
                    fido_path: None,
                    pid: pid_from_reader_name(reader),
                    transport,
                    info,
                });
            }
            Err(e) => {
                log::debug!("Skipping NFC reader {reader}: {e}");
            }
        }
    }

    Ok(devices)
}

/// Open a single USB device, preferring CCID > OTP > FIDO.
///
/// Since there is exactly one device for this PID, any transport yields the
/// same physical key. We open only one connection and populate the paths from
/// the fast-scan data.
fn open_single_usb(
    pid: u16,
    usb_readers: &[(u16, String)],
    otp_devs: &[HidDeviceInfo],
    fido_devs: &[FidoDeviceInfo],
) -> Option<YubiKeyDevice> {
    let reader = usb_readers.iter().find(|(p, _)| *p == pid).map(|(_, r)| r);
    let otp = otp_devs.iter().find(|h| h.pid == pid);
    let fido = fido_devs.iter().find(|f| f.pid == pid);

    // Try CCID first (gives the most complete info).
    if let Some(reader_name) = reader
        && let Ok((info, transport)) = read_info(reader_name)
    {
        return Some(YubiKeyDevice {
            reader_name: Some(reader_name.clone()),
            hid_path: otp.map(|h| h.path.clone()),
            fido_path: fido.map(|f| f.path.clone()),
            pid: Some(pid),
            transport,
            info,
        });
    }

    // Fall back to OTP HID.
    if let Some(hid) = otp {
        let info = HidOtpConnection::new(&hid.path)
            .ok()
            .and_then(|conn| read_info_otp(conn).ok())
            .map(|(info, _)| info)
            .unwrap_or_else(|| synthetic_hid_info(hid));
        return Some(YubiKeyDevice {
            reader_name: None,
            hid_path: Some(hid.path.clone()),
            fido_path: fido.map(|f| f.path.clone()),
            pid: Some(pid),
            transport: Transport::Usb,
            info,
        });
    }

    // Fall back to FIDO HID.
    if let Some(f) = fido {
        let info = HidFidoConnection::open(f)
            .ok()
            .and_then(|conn| read_info_fido(conn).ok())
            .map(|(info, _)| info)
            .unwrap_or_else(|| synthetic_fido_info(f));
        return Some(YubiKeyDevice {
            reader_name: None,
            hid_path: None,
            fido_path: Some(f.path.clone()),
            pid: Some(pid),
            transport: Transport::Usb,
            info,
        });
    }

    None
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

// ---------------------------------------------------------------------------
// read_info
// ---------------------------------------------------------------------------

/// Open a PC/SC connection and read [`DeviceInfo`] from a YubiKey.
///
/// For older devices (NEO, etc.) that lack the management applet,
/// synthesizes DeviceInfo by probing individual applets.
///
/// Returns the device info and the detected transport (USB or NFC).
pub fn read_info(reader_name: &str) -> Result<(DeviceInfo, Transport), DeviceError> {
    let conn = PcscSmartCardConnection::open(reader_name)?;
    let transport = conn.transport();
    let (info, _conn) = read_info_ccid(conn)?;
    Ok((info, transport))
}

/// Read [`DeviceInfo`] from an open smart card connection.
///
/// Falls back to probing individual applets on older devices that lack
/// the management applet. Returns the connection for reuse.
pub fn read_info_ccid<C: SmartCardConnection>(conn: C) -> Result<(DeviceInfo, C), DeviceError> {
    let mut session = match ManagementCcidSession::new(conn) {
        Ok(s) => s,
        Err((e, conn)) => {
            // NEO and other old devices don't have the management applet.
            // Fall back to probing individual applets.
            log::debug!("Management session init failed ({e}), synthesizing info");
            let (info, conn) = synthesize_info_ccid(conn, Version(0, 0, 0))?;
            return Ok((info, conn));
        }
    };
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

/// Read [`DeviceInfo`] via OTP HID from an open connection.
///
/// Returns the connection for reuse. On error the connection is returned
/// when possible.
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

/// Read [`DeviceInfo`] via FIDO HID (CTAP) from an open connection.
///
/// Returns the connection for reuse. On error the connection is returned
/// when possible.
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
    mut version: Version,
) -> Result<(DeviceInfo, C), DeviceError> {
    use std::collections::HashMap;

    let mut capabilities = Capability::NONE;

    // Try to read serial and version from OTP application
    let mut serial = None;
    let conn = match YubiOtpCcidSession::new(conn) {
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

/// Apply standard fixups for known device quirks.
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
            transport: Transport::Usb,
            info,
        }
    }

    #[test]
    fn test_merge_by_pid_uniqueness() {
        // Three groups each with one device sharing the same PID → merge.
        let ccid = vec![make_device(
            Some("Yubico YubiKey OTP+FIDO+CCID 00"),
            None,
            None,
            Some(0x0407),
            Version(5, 4, 3),
            Some(12345),
        )];
        let otp = vec![make_device(
            None,
            Some("/dev/hidraw0"),
            None,
            Some(0x0407),
            Version(5, 4, 3),
            Some(12345),
        )];
        let fido = vec![make_device(
            None,
            None,
            Some("/dev/hidraw1"),
            Some(0x0407),
            Version(5, 4, 3),
            Some(12345),
        )];

        let mut result = ccid;
        merge_devices(&mut result, otp);
        merge_devices(&mut result, fido);
        assert_eq!(result.len(), 1, "Should merge into a single device");
        let dev = &result[0];
        assert_eq!(dev.reader_name(), Some("Yubico YubiKey OTP+FIDO+CCID 00"));
        assert_eq!(dev.hid_path(), Some("/dev/hidraw0"));
        assert_eq!(dev.fido_path(), Some("/dev/hidraw1"));
        assert_eq!(dev.pid(), Some(0x0407));
    }

    #[test]
    fn test_merge_by_identity() {
        // Two devices with same PID but different serials are NOT merged by PID,
        // but merged by identity when serial matches.
        let ccid = vec![
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
        ];
        let otp = vec![
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
        ];

        let mut result = ccid;
        merge_devices(&mut result, otp);
        assert_eq!(result.len(), 2, "Should remain as two devices");
        let d1 = result.iter().find(|d| d.serial() == Some(111)).unwrap();
        assert!(d1.reader_name().is_some());
        assert!(d1.hid_path().is_some());
        let d2 = result.iter().find(|d| d.serial() == Some(222)).unwrap();
        assert!(d2.reader_name().is_some());
        assert!(d2.hid_path().is_some());
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
        // Older SKY devices (< 5.2.8) don't set the is_sky flag.
        // is_sky should be inferred from no serial + FIDO-only capabilities.
        let mut info = make_info(
            Version(5, 1, 2),
            FormFactor::UsbAKeychain,
            false, // is_sky NOT set by device
            false,
            None, // no serial
            true, // has NFC
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
            Some(123), // has serial — not a SKY
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
}
