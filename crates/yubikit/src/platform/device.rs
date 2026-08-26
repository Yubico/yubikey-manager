//! Local device enumeration and connection management.
//!
//! Contains [`LocalYubiKeyDevice`](crate::platform::device::LocalYubiKeyDevice) and related functions for discovering
//! YubiKeys over USB HID and PC/SC.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::thread;
use std::time::Duration;

use crate::core::Transport;
#[cfg(feature = "pcsc")]
use crate::device::read_info_ccid;
use crate::device::{DeviceError, ReinsertStatus, YubiKeyDevice, usb_interfaces_from_pid};
#[cfg(feature = "hid")]
use crate::device::{read_info_fido, read_info_otp};

use crate::fido::FidoConnection;
use crate::management::{Capability, DeviceInfo, UsbInterface};
use crate::otp::OtpConnection;
use crate::smartcard::SmartCardConnection;

#[cfg(feature = "hid")]
use super::hidapi::{
    FidoDeviceInfo, HidDeviceInfo, HidError, HidFidoConnection, HidOtpConnection,
    list_fido_devices, list_otp_devices,
};
#[cfg(feature = "pcsc")]
use super::pcsc::{
    PcscError, PcscSmartCardConnection, is_reader_usb, list_readers, list_readers_with_state,
};
#[cfg(windows)]
use super::setupdi::list_setupdi_devices;

#[cfg(not(feature = "hid"))]
#[derive(Debug, Clone)]
struct HidDeviceInfo {
    pid: u16,
}

#[cfg(not(feature = "hid"))]
#[derive(Debug, Clone)]
struct FidoDeviceInfo {
    pid: u16,
}

// From conversions for platform-specific errors into DeviceError
#[cfg(feature = "pcsc")]
impl From<PcscError> for DeviceError {
    fn from(e: PcscError) -> Self {
        Self::Transport(Box::new(e))
    }
}

#[cfg(feature = "hid")]
impl From<HidError> for DeviceError {
    fn from(e: HidError) -> Self {
        Self::Transport(Box::new(e))
    }
}

/// A discovered YubiKey that can open connections.
///
/// Represents a physical YubiKey found via PC/SC (CCID) and/or HID enumeration.
/// Use [`list_devices`] to discover connected devices.
#[derive(Debug, Clone)]
pub struct LocalYubiKeyDevice {
    /// The PC/SC reader name, if available.
    pub reader_name: Option<String>,
    /// The HID path, if available.
    pub hid_path: Option<String>,
    /// The FIDO path, if available.
    pub fido_path: Option<String>,
    pid: Option<u16>,
    transport: Transport,
    info: DeviceInfo,
}

impl LocalYubiKeyDevice {
    /// Returns the [`DeviceInfo`] for this device.
    pub fn info(&self) -> &DeviceInfo {
        &self.info
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

    /// Construct a device from already-known transport paths and info.
    ///
    /// Used by the device monitor's aggregation layer to build a merged
    /// device from a set of discovered [`DeviceNode`](crate::platform::monitor::DeviceNode)s.
    pub(crate) fn from_parts(
        reader_name: Option<String>,
        hid_path: Option<String>,
        fido_path: Option<String>,
        pid: Option<u16>,
        transport: Transport,
        info: DeviceInfo,
    ) -> Self {
        LocalYubiKeyDevice {
            reader_name,
            hid_path,
            fido_path,
            pid,
            transport,
            info,
        }
    }

    /// Open a device from a PC/SC reader name.
    ///
    /// Connects to the given reader, reads device info, and returns a
    /// `LocalYubiKeyDevice`. Useful for NFC readers where the device is
    /// not discovered via USB enumeration.
    #[cfg(feature = "pcsc")]
    pub fn open_reader(reader_name: &str) -> Result<Self, DeviceError> {
        let (info, transport) = read_info_reader(reader_name)?;
        Ok(LocalYubiKeyDevice {
            reader_name: Some(reader_name.to_string()),
            hid_path: None,
            fido_path: None,
            pid: None,
            transport,
            info,
        })
    }

    /// Open a device from a PC/SC reader name.
    #[cfg(not(feature = "pcsc"))]
    pub fn open_reader(_reader_name: &str) -> Result<Self, DeviceError> {
        Err(DeviceError::UnsupportedFeature("pcsc"))
    }

    /// Open a SmartCard (PC/SC) connection to this device.
    ///
    /// Requires that this device was discovered over CCID (i.e. has a reader
    /// name). Attempts exclusive access first, falling back to shared.
    #[cfg(feature = "pcsc")]
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

    /// Open a SmartCard (PC/SC) connection to this device.
    #[cfg(not(feature = "pcsc"))]
    pub fn open_smartcard(&self) -> Result<Box<dyn SmartCardConnection + Send>, DeviceError> {
        Err(DeviceError::UnsupportedFeature("pcsc"))
    }

    /// Open an OTP HID connection to this device.
    #[cfg(feature = "hid")]
    pub fn open_otp(&self) -> Result<HidOtpConnection, DeviceError> {
        let path = self.hid_path.as_deref().ok_or(DeviceError::NoDeviceFound)?;
        Ok(HidOtpConnection::new(path)?)
    }

    /// Open an OTP HID connection to this device.
    #[cfg(not(feature = "hid"))]
    pub fn open_otp(&self) -> Result<Box<dyn OtpConnection + Send>, DeviceError> {
        Err(DeviceError::UnsupportedFeature("hid"))
    }

    /// Open a FIDO HID (CTAP) connection to this device.
    #[cfg(feature = "hid")]
    pub fn open_fido(&self) -> Result<HidFidoConnection, DeviceError> {
        let path = self
            .fido_path
            .as_deref()
            .ok_or(DeviceError::NoDeviceFound)?;
        // Find the matching FIDO device info from enumeration
        let fido_devs = list_fido_devices()?;
        let info = fido_devs
            .into_iter()
            .find(|d| d.path == path)
            .ok_or(DeviceError::NoDeviceFound)?;
        Ok(HidFidoConnection::open(&info)?)
    }

    /// Open a FIDO HID (CTAP) connection to this device.
    #[cfg(not(feature = "hid"))]
    pub fn open_fido(&self) -> Result<Box<dyn FidoConnection + Send>, DeviceError> {
        Err(DeviceError::UnsupportedFeature("hid"))
    }

    /// Absorb transport paths from another `LocalYubiKeyDevice` representing the
    /// same physical key. Fills in any `None` fields from `other`.
    #[cfg(any(feature = "hid", test))]
    fn merge_from(&mut self, other: LocalYubiKeyDevice) {
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
        // version.
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

            let devs = match list_devices(interfaces) {
                Ok(devs) => devs,
                Err(e) if is_transient_reinsert_error(&e) => {
                    log::debug!("Ignoring transient reinsert enumeration error: {e}");
                    Vec::new()
                }
                Err(e) => return Err(e),
            };

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
                // The device may not be fully ready yet (interfaces still
                // initializing), so we may fail to read info. Only match
                // once we can confirm serial; keep waiting otherwise.
                let mut found_different = false;
                for d in &devs {
                    if d.info.serial == my_serial && d.info.version == my_version {
                        log::debug!("Device reinserted");
                        let found = d;
                        self.reader_name = found.reader_name.clone();
                        self.hid_path = found.hid_path.clone();
                        self.fido_path = found.fido_path.clone();
                        self.pid = found.pid;
                        self.info = found.info.clone();
                        return Ok(());
                    }
                    if d.info.serial.is_some() {
                        found_different = true;
                    }
                }
                // If a device with a different serial was found, it's wrong.
                // If serial couldn't be read, keep waiting for it to settle.
                if found_different {
                    return Err(DeviceError::WrongDevice);
                }
            }
        }
    }

    fn reinsert_nfc(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        #[cfg(not(feature = "pcsc"))]
        {
            let _ = (status_cb, cancelled);
            Err(DeviceError::UnsupportedFeature("pcsc"))
        }
        #[cfg(feature = "pcsc")]
        {
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
                    match read_info_reader(reader) {
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
}

fn is_transient_reinsert_error(e: &DeviceError) -> bool {
    #[cfg(feature = "pcsc")]
    if let DeviceError::Transport(source) = e {
        return source
            .downcast_ref::<PcscError>()
            .is_some_and(|e| e.is_unavailable() || e.is_no_card());
    }

    let _ = e;
    false
}

impl YubiKeyDevice for LocalYubiKeyDevice {
    fn info(&self) -> &DeviceInfo {
        self.info()
    }

    fn transport(&self) -> Transport {
        self.transport()
    }

    fn name(&self) -> String {
        self.name()
    }

    fn pid(&self) -> Option<u16> {
        self.pid
    }

    fn reader_name(&self) -> Option<&str> {
        self.reader_name.as_deref()
    }

    fn usb_interfaces(&self) -> UsbInterface {
        self.pid.map(usb_interfaces_from_pid).unwrap_or_else(|| {
            // Derive from enabled USB capabilities in the device info
            if let Some(&usb_caps) = self.info.config.enabled_capabilities.get(&Transport::Usb) {
                let mut ifaces = UsbInterface(0);
                if usb_caps.contains(Capability::OTP) {
                    ifaces = ifaces | UsbInterface::OTP;
                }
                if usb_caps.contains(Capability::FIDO2) || usb_caps.contains(Capability::U2F) {
                    ifaces = ifaces | UsbInterface::FIDO;
                }
                if usb_caps.contains(Capability::PIV)
                    || usb_caps.contains(Capability::OATH)
                    || usb_caps.contains(Capability::OPENPGP)
                    || usb_caps.contains(Capability::HSMAUTH)
                {
                    ifaces = ifaces | UsbInterface::CCID;
                }
                ifaces
            } else {
                UsbInterface(0)
            }
        })
    }

    fn open_smartcard(&self) -> Result<Box<dyn SmartCardConnection + Send>, DeviceError> {
        #[cfg(feature = "pcsc")]
        {
            Ok(Box::new(self.open_smartcard()?))
        }
        #[cfg(not(feature = "pcsc"))]
        {
            Err(DeviceError::UnsupportedFeature("pcsc"))
        }
    }

    fn open_fido(&self) -> Result<Box<dyn FidoConnection + Send>, DeviceError> {
        #[cfg(feature = "hid")]
        {
            Ok(Box::new(self.open_fido()?))
        }
        #[cfg(not(feature = "hid"))]
        {
            Err(DeviceError::UnsupportedFeature("hid"))
        }
    }

    fn open_otp(&self) -> Result<Box<dyn OtpConnection + Send>, DeviceError> {
        #[cfg(feature = "hid")]
        {
            Ok(Box::new(self.open_otp()?))
        }
        #[cfg(not(feature = "hid"))]
        {
            Err(DeviceError::UnsupportedFeature("hid"))
        }
    }

    fn reinsert(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        self.reinsert(status_cb, cancelled)
    }

    fn clone_box(&self) -> Box<dyn YubiKeyDevice> {
        Box::new(self.clone())
    }
}

impl fmt::Display for LocalYubiKeyDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())?;
        if let Some(serial) = self.info.serial {
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
#[cfg(feature = "pcsc")]
pub(crate) fn pid_from_reader_name(name: &str) -> Option<u16> {
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
#[cfg(feature = "pcsc")]
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
    #[cfg(feature = "pcsc")]
    if let Ok(readers) = list_readers_with_state() {
        for (reader, card_present) in readers {
            if let Some(pid) = pid_from_reader_name(&reader) {
                // USB-connected YubiKey reader: track by name (reader appears/disappears with key)
                *transport_counts.entry(pid).or_insert(0) += 1;
                fingerprints.push(reader);
            } else {
                // NFC reader: always include name + card-present state so
                // tapping/removing a card changes the fingerprint
                fingerprints.push(format!(
                    "{reader}:{}",
                    if card_present { "present" } else { "absent" }
                ));
            }
        }
    }
    for (pid, count) in &transport_counts {
        let entry = counts.entry(*pid).or_insert(0);
        *entry = (*entry).max(*count);
    }

    // Scan HID OTP devices
    transport_counts.clear();
    #[cfg(feature = "hid")]
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
    #[cfg(feature = "hid")]
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
    // the scan with SetupDi enumeration so those devices still show up.
    #[cfg(windows)]
    {
        for dev in list_setupdi_devices() {
            // Only add PIDs not already found via normal enumeration
            if !counts.contains_key(&dev.pid) {
                *counts.entry(dev.pid).or_insert(0) += 1;
                fingerprints.push(dev.path);
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
/// Each physical YubiKey is returned as a single [`LocalYubiKeyDevice`] with
/// transport paths populated for every interface that was discovered. When
/// only one device is present per USB Product ID the merge is trivial;
/// multiple devices sharing a PID are matched by firmware version and serial.
pub fn list_devices(interfaces: UsbInterface) -> Result<Vec<LocalYubiKeyDevice>, DeviceError> {
    log::debug!("Listing YubiKey devices (interfaces: {interfaces})");

    let want_ccid = interfaces.contains(UsbInterface::CCID);
    let want_otp = interfaces.contains(UsbInterface::OTP);
    let want_fido = interfaces.contains(UsbInterface::FIDO);

    if want_ccid && !cfg!(feature = "pcsc") {
        return Err(DeviceError::UnsupportedFeature("pcsc"));
    }
    if (want_otp || want_fido) && !cfg!(feature = "hid") {
        return Err(DeviceError::UnsupportedFeature("hid"));
    }

    // ── Phase 1: cheap discovery (no connections opened) ──────────
    // For each transport, collect (PID, path/reader_name).
    #[cfg(feature = "pcsc")]
    let mut usb_readers: Vec<(u16, String)> = Vec::new(); // PID → reader_name
    #[cfg(not(feature = "pcsc"))]
    let usb_readers: Vec<(u16, String)> = Vec::new();
    #[cfg(feature = "pcsc")]
    let mut nfc_readers: Vec<String> = Vec::new();
    #[cfg(feature = "pcsc")]
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

    #[cfg(feature = "hid")]
    let mut otp_devs: Vec<HidDeviceInfo> = Vec::new();
    #[cfg(not(feature = "hid"))]
    let otp_devs: Vec<HidDeviceInfo> = Vec::new();
    #[cfg(feature = "hid")]
    if want_otp && let Ok(devs) = list_otp_devices() {
        otp_devs = devs;
    }

    #[cfg(feature = "hid")]
    let mut fido_devs: Vec<FidoDeviceInfo> = Vec::new();
    #[cfg(not(feature = "hid"))]
    let fido_devs: Vec<FidoDeviceInfo> = Vec::new();
    #[cfg(feature = "hid")]
    if want_fido && let Ok(devs) = list_fido_devices() {
        fido_devs = devs;
    }

    // Count devices per PID across all transports.
    // Take the maximum count across transports (each transport may see
    // multiple physical devices with the same PID).
    let mut pid_counts: HashMap<u16, usize> = HashMap::new();
    {
        let mut ccid_per_pid: HashMap<u16, usize> = HashMap::new();
        for &(pid, _) in &usb_readers {
            *ccid_per_pid.entry(pid).or_insert(0) += 1;
        }
        let mut otp_per_pid: HashMap<u16, usize> = HashMap::new();
        for hid in &otp_devs {
            *otp_per_pid.entry(hid.pid).or_insert(0) += 1;
        }
        let mut fido_per_pid: HashMap<u16, usize> = HashMap::new();
        for fido in &fido_devs {
            *fido_per_pid.entry(fido.pid).or_insert(0) += 1;
        }
        let all_pids: std::collections::HashSet<u16> = ccid_per_pid
            .keys()
            .chain(otp_per_pid.keys())
            .chain(fido_per_pid.keys())
            .copied()
            .collect();
        for pid in all_pids {
            let c = ccid_per_pid.get(&pid).copied().unwrap_or(0);
            let o = otp_per_pid.get(&pid).copied().unwrap_or(0);
            let f = fido_per_pid.get(&pid).copied().unwrap_or(0);
            pid_counts.insert(pid, c.max(o).max(f));
        }
    }

    let n_usb: usize = pid_counts.values().sum();
    log::debug!(
        "Fast scan: {n_usb} USB device(s) across {} PID(s)",
        pid_counts.len()
    );

    // ── Phase 2: open connections and build device list ───────────
    let mut devices: Vec<LocalYubiKeyDevice> = Vec::new();

    // For each PID, decide whether we need full multi-transport enumeration.
    for (&pid, &count) in &pid_counts {
        if count <= 1 {
            // Single device for this PID — open one connection only.
            if let Some(dev) = open_single_usb(pid, &usb_readers, &otp_devs, &fido_devs)? {
                devices.push(dev);
            }
        } else {
            // Multiple devices with this PID — enumerate all requested
            // interfaces and merge by identity.
            let mut base: Vec<LocalYubiKeyDevice> = Vec::new();

            #[cfg(feature = "pcsc")]
            if want_ccid {
                for &(p, ref reader) in &usb_readers {
                    if p == pid
                        && let Ok((info, transport)) = read_info_reader(reader)
                    {
                        base.push(LocalYubiKeyDevice {
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

            #[cfg(feature = "hid")]
            if want_otp {
                let mut otp_group = Vec::new();
                for hid in &otp_devs {
                    if hid.pid == pid {
                        let info = read_info_otp_device(hid)?;
                        otp_group.push(LocalYubiKeyDevice {
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

            #[cfg(feature = "hid")]
            if want_fido {
                let mut fido_group = Vec::new();
                for fido in &fido_devs {
                    if fido.pid == pid {
                        let info = read_info_fido_device(fido)?;
                        fido_group.push(LocalYubiKeyDevice {
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
    #[cfg(feature = "pcsc")]
    for reader in &nfc_readers {
        log::debug!("Checking NFC reader: {reader}");
        match read_info_reader(reader) {
            Ok((info, transport)) => {
                devices.push(LocalYubiKeyDevice {
                    reader_name: Some(reader.clone()),
                    hid_path: None,
                    fido_path: None,
                    pid: None,
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
    _usb_readers: &[(u16, String)],
    _otp_devs: &[HidDeviceInfo],
    _fido_devs: &[FidoDeviceInfo],
) -> Result<Option<LocalYubiKeyDevice>, DeviceError> {
    #[cfg(feature = "pcsc")]
    let reader = _usb_readers.iter().find(|(p, _)| *p == pid).map(|(_, r)| r);
    #[cfg(feature = "hid")]
    let otp = _otp_devs.iter().find(|h| h.pid == pid);
    #[cfg(feature = "hid")]
    let fido = _fido_devs.iter().find(|f| f.pid == pid);
    let mut last_err = None;

    // Try CCID first (gives the most complete info).
    #[cfg(feature = "pcsc")]
    if let Some(reader_name) = reader {
        match read_info_reader(reader_name) {
            Ok((info, transport)) => {
                return Ok(Some(LocalYubiKeyDevice {
                    reader_name: Some(reader_name.clone()),
                    hid_path: {
                        #[cfg(feature = "hid")]
                        {
                            otp.map(|h| h.path.clone())
                        }
                        #[cfg(not(feature = "hid"))]
                        {
                            None
                        }
                    },
                    fido_path: {
                        #[cfg(feature = "hid")]
                        {
                            fido.map(|f| f.path.clone())
                        }
                        #[cfg(not(feature = "hid"))]
                        {
                            None
                        }
                    },
                    pid: Some(pid),
                    transport,
                    info,
                }));
            }
            Err(e) => last_err = Some(e),
        }
    }

    // Fall back to OTP HID.
    #[cfg(feature = "hid")]
    if let Some(hid) = otp {
        match read_info_otp_device(hid) {
            Ok(info) => {
                return Ok(Some(LocalYubiKeyDevice {
                    reader_name: None,
                    hid_path: Some(hid.path.clone()),
                    fido_path: fido.map(|f| f.path.clone()),
                    pid: Some(pid),
                    transport: Transport::Usb,
                    info,
                }));
            }
            Err(e) => last_err = Some(e),
        }
    }

    // Fall back to FIDO HID.
    #[cfg(feature = "hid")]
    if let Some(f) = fido {
        match read_info_fido_device(f) {
            Ok(info) => {
                return Ok(Some(LocalYubiKeyDevice {
                    reader_name: None,
                    hid_path: None,
                    fido_path: Some(f.path.clone()),
                    pid: Some(pid),
                    transport: Transport::Usb,
                    info,
                }));
            }
            Err(e) => last_err = Some(e),
        }
    }

    if let Some(e) = last_err {
        Err(e)
    } else {
        Ok(None)
    }
}

/// Merge `incoming` partial devices into `base`, combining entries that
/// represent the same physical YubiKey.
#[cfg(any(feature = "hid", test))]
fn merge_devices(base: &mut Vec<LocalYubiKeyDevice>, incoming: Vec<LocalYubiKeyDevice>) {
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

// ---------------------------------------------------------------------------
// read_info_reader
// ---------------------------------------------------------------------------

/// Open a PC/SC connection and read [`DeviceInfo`] from a YubiKey.
///
/// For older devices (NEO, etc.) that lack the management applet,
/// synthesizes DeviceInfo by probing individual applets.
///
/// Returns the device info and the detected transport (USB or NFC).
#[cfg(feature = "pcsc")]
fn read_info_reader(reader_name: &str) -> Result<(DeviceInfo, Transport), DeviceError> {
    let conn = PcscSmartCardConnection::open(reader_name)?;
    let transport = conn.transport();
    let pid = pid_from_reader_name(reader_name);
    let (info, _conn) = read_info_ccid(conn, pid)?;
    Ok((info, transport))
}

/// Open an OTP HID device and read [`DeviceInfo`].
#[cfg(feature = "hid")]
fn read_info_otp_device(hid: &HidDeviceInfo) -> Result<DeviceInfo, DeviceError> {
    let conn = HidOtpConnection::new(&hid.path)?;
    read_info_otp(conn, hid.pid)
        .map(|(info, _)| info)
        .map_err(|(e, _)| e)
}

/// Open a FIDO HID device and read [`DeviceInfo`].
#[cfg(feature = "hid")]
fn read_info_fido_device(fido: &FidoDeviceInfo) -> Result<DeviceInfo, DeviceError> {
    let conn = HidFidoConnection::open(fido)?;
    read_info_fido(conn, fido.pid)
        .map(|(info, _)| info)
        .map_err(|(e, _)| e)
}

/// Select a YubiKey by touch via CTAP2 authenticator selection.
///
/// Lists all FIDO HID devices, sends a CTAP2 `authenticatorSelection` command
/// to each, and returns the first device the user touches. Polls for newly
/// inserted devices until one is selected or the operation is cancelled.
///
/// The returned [`LocalYubiKeyDevice`] includes full device info from all
/// available transports (CCID, OTP, FIDO), merged as in [`list_devices`].
#[cfg(feature = "hid")]
pub fn select_fido(cancel: Option<&dyn Fn() -> bool>) -> Result<LocalYubiKeyDevice, DeviceError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::ctap::CtapSession;
    use crate::ctap2::Ctap2Session;

    let is_cancelled = || cancel.is_some_and(|f| f());

    let fido_devs = list_fido_devices()?;

    let done = Arc::new(AtomicBool::new(false));
    let selected_path: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut active: Vec<(String, thread::JoinHandle<()>)> = Vec::new();

    let spawn_select = |info: FidoDeviceInfo,
                        done: Arc<AtomicBool>,
                        selected: Arc<Mutex<Option<String>>>|
     -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let Ok(conn) = HidFidoConnection::open(&info) else {
                return;
            };
            let Ok(ctap) = CtapSession::new_fido(conn) else {
                return;
            };
            let Ok(mut session) = Ctap2Session::new(ctap) else {
                return;
            };
            let d = done.clone();
            if session
                .selection(None, Some(&move || d.load(Ordering::Relaxed)))
                .is_ok()
                && !done.swap(true, Ordering::Relaxed)
            {
                *selected.lock().unwrap() = Some(info.path);
            }
        })
    };

    for dev in fido_devs {
        let path = dev.path.clone();
        let handle = spawn_select(dev, done.clone(), selected_path.clone());
        active.push((path, handle));
    }

    while !done.load(Ordering::Relaxed) && !is_cancelled() {
        thread::sleep(Duration::from_millis(250));

        // Remove finished threads so their paths can be re-used
        active.retain(|(_, h)| !h.is_finished());

        if let Ok(devs) = list_fido_devices() {
            for dev in devs {
                if !active.iter().any(|(p, _)| *p == dev.path) {
                    let path = dev.path.clone();
                    let handle = spawn_select(dev, done.clone(), selected_path.clone());
                    active.push((path, handle));
                }
            }
        }
    }

    done.store(true, Ordering::Relaxed);

    for (_, h) in active {
        let _ = h.join();
    }

    if is_cancelled() {
        return Err(DeviceError::Cancelled);
    }

    let path = selected_path
        .lock()
        .unwrap()
        .take()
        .ok_or(DeviceError::NoDeviceFound)?;

    // Find the selected device in a full enumeration
    let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
    let devices = list_devices(all)?;

    // Read device info from the selected FIDO path to identify it
    let fido_devs = list_fido_devices()?;
    if let Some(fido_info) = fido_devs.iter().find(|d| d.path == path) {
        let info = read_info_fido_device(fido_info)?;
        // Match by serial and version
        if let Some(dev) = devices
            .into_iter()
            .find(|d| d.info().serial == info.serial && d.info().version == info.version)
        {
            return Ok(dev);
        }
    }

    Err(DeviceError::NoDeviceFound)
}

// ---------------------------------------------------------------------------
// Product name logic
// ---------------------------------------------------------------------------
// Device naming (delegated to crate::device)
// ---------------------------------------------------------------------------

pub use crate::device::get_name;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::core::Version;
    use crate::management::FormFactor;

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
            name: None,
        }
    }

    fn make_device(
        reader_name: Option<&str>,
        hid_path: Option<&str>,
        fido_path: Option<&str>,
        pid: Option<u16>,
        version: Version,
        serial: Option<u32>,
    ) -> LocalYubiKeyDevice {
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
        LocalYubiKeyDevice {
            reader_name: reader_name.map(String::from),
            hid_path: hid_path.map(String::from),
            fido_path: fido_path.map(String::from),
            pid,
            transport: Transport::Usb,
            info,
        }
    }

    #[cfg(all(feature = "hid", not(feature = "pcsc")))]
    #[test]
    fn test_list_devices_ccid_requires_pcsc() {
        assert!(matches!(
            list_devices(UsbInterface::CCID),
            Err(DeviceError::UnsupportedFeature("pcsc"))
        ));
    }

    #[cfg(all(feature = "pcsc", not(feature = "hid")))]
    #[test]
    fn test_list_devices_hid_interfaces_require_hid() {
        assert!(matches!(
            list_devices(UsbInterface::OTP),
            Err(DeviceError::UnsupportedFeature("hid"))
        ));
        assert!(matches!(
            list_devices(UsbInterface::FIDO),
            Err(DeviceError::UnsupportedFeature("hid"))
        ));
    }

    #[cfg(all(feature = "pcsc", not(feature = "hid")))]
    #[test]
    fn test_open_fido_requires_hid() {
        let dev = make_device(
            None,
            None,
            None,
            Some(0x0402),
            Version(5, 4, 3),
            Some(12345),
        );
        assert!(matches!(
            dev.open_fido(),
            Err(DeviceError::UnsupportedFeature("hid"))
        ));
    }

    #[cfg(all(feature = "hid", not(feature = "pcsc")))]
    #[test]
    fn test_open_smartcard_requires_pcsc() {
        let dev = make_device(
            None,
            None,
            None,
            Some(0x0404),
            Version(5, 4, 3),
            Some(12345),
        );
        assert!(matches!(
            dev.open_smartcard(),
            Err(DeviceError::UnsupportedFeature("pcsc"))
        ));
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
        assert!(dev.reader_name.is_some());
        assert!(dev.hid_path.is_some());
        assert!(dev.fido_path.is_some());
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
        let d1 = result
            .iter()
            .find(|d| d.info().serial == Some(111))
            .unwrap();
        assert!(d1.reader_name.is_some());
        assert!(d1.hid_path.is_some());
        let d2 = result
            .iter()
            .find(|d| d.info().serial == Some(222))
            .unwrap();
        assert!(d2.reader_name.is_some());
        assert!(d2.hid_path.is_some());
    }
}
