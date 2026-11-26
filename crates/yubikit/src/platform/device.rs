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
use super::usb_id::UsbDeviceId;
#[cfg(feature = "hid")]
use super::usb_id::hid_usb_device_id;
#[cfg(feature = "pcsc")]
use super::usb_id::{connection_usb_device_id, reader_usb_device_id};

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

    /// Read current device information using an available transport.
    ///
    /// Call only when no application connections to this device are active.
    pub fn refresh_info(&mut self) -> Result<(), DeviceError> {
        self.refresh_info_with_reader(|device| {
            #[cfg(feature = "pcsc")]
            if device.reader_name.is_some() {
                return read_info_ccid(device.open_smartcard()?, device.pid).map(|(info, _)| info);
            }
            #[cfg(feature = "hid")]
            if device.hid_path.is_some() {
                return read_info_otp(
                    device.open_otp()?,
                    device.pid.ok_or(DeviceError::NoDeviceFound)?,
                )
                .map(|(info, _)| info)
                .map_err(|(error, _)| error);
            }
            #[cfg(feature = "hid")]
            if device.fido_path.is_some() {
                return read_info_fido(
                    device.open_fido()?,
                    device.pid.ok_or(DeviceError::NoDeviceFound)?,
                )
                .map(|(info, _)| info)
                .map_err(|(error, _)| error);
            }
            let _ = device;
            Err(DeviceError::NoDeviceFound)
        })
    }

    fn refresh_info_with_reader(
        &mut self,
        read: impl FnOnce(&Self) -> Result<DeviceInfo, DeviceError>,
    ) -> Result<(), DeviceError> {
        let info = read(self)?;
        if info.serial != self.info.serial || info.version != self.info.version {
            return Err(DeviceError::WrongDevice);
        }
        self.info = info;
        Ok(())
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
    /// Not part of the public API; exposed for tests in dependent crates.
    #[doc(hidden)]
    pub fn from_parts(
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
        let (info, transport, _) = read_info_reader(reader_name)?;
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
            .ok_or(DeviceError::CcidUnavailable)?;

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
                    } else if e.is_sharing_violation() {
                        return Err(DeviceError::CcidUnavailable);
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

    /// Wait for the user to remove and reinsert this YubiKey.
    ///
    /// On success, updates this device's transport paths and info. Active
    /// device monitors reuse the verified info for serial-numbered keys
    /// instead of probing the same interfaces concurrently.
    ///
    /// * `status_cb` – called with [`ReinsertStatus`] variants to indicate
    ///   what the user should do.
    /// * `cancelled` – checked periodically; return `true` to cancel.
    pub fn reinsert(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        super::monitor::with_paused_monitors(|| {
            match self.transport {
                Transport::Usb => self.reinsert_usb(status_cb, cancelled)?,
                Transport::Nfc => self.reinsert_nfc(status_cb, cancelled)?,
            }
            Ok(self.clone())
        })
    }

    fn reinsert_usb(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        self.reinsert_usb_with_discovery(
            status_cb,
            cancelled,
            scan_usb_devices,
            list_devices,
            || thread::sleep(Duration::from_millis(250)),
        )
    }

    fn reinsert_usb_with_discovery(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        cancelled: &dyn Fn() -> bool,
        mut scan: impl FnMut() -> (HashMap<u16, usize>, u64),
        mut discover: impl FnMut(UsbInterface) -> Result<Vec<Self>, DeviceError>,
        wait: impl Fn(),
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

        let (pids, mut state) = scan();
        let n_devs: usize = pids.values().sum();
        let my_serial = self.info.serial;
        let my_version = self.info.version;
        let mut removed = false;

        log::debug!("Waiting for removal of device serial={my_serial:?}");
        status_cb(ReinsertStatus::Remove);

        'reinsert: loop {
            wait();
            if cancelled() {
                return Err(DeviceError::Cancelled);
            }

            let (new_pids, new_state) = scan();
            // Interface probes can recover without a topology change.
            if new_state == state && (!removed || new_pids.values().sum::<usize>() != n_devs) {
                continue;
            }
            state = new_state;

            let devs = match discover(interfaces) {
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
                // once we can confirm serial and recover every previously
                // available interface; HID can appear before the PC/SC reader.
                let mut found_different = false;
                for d in &devs {
                    if d.info.serial == my_serial && d.info.version == my_version {
                        if !d.has_usb_paths(interfaces) {
                            continue 'reinsert;
                        }
                        log::debug!("Device reinserted");
                        let found = d;
                        self.reader_name = found.reader_name.clone();
                        self.hid_path = found.hid_path.clone();
                        self.fido_path = found.fido_path.clone();
                        self.pid = found.pid;
                        self.info = found.info.clone();
                        return Ok(());
                    }
                    if d.info.serial.is_some()
                        && (d.info.serial != my_serial || d.info.version != my_version)
                    {
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

    fn has_usb_paths(&self, interfaces: UsbInterface) -> bool {
        (!interfaces.contains(UsbInterface::CCID) || self.reader_name.is_some())
            && (!interfaces.contains(UsbInterface::OTP) || self.hid_path.is_some())
            && (!interfaces.contains(UsbInterface::FIDO) || self.fido_path.is_some())
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
                        Ok((info, _transport, _)) => {
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
/// transport paths populated for every interface that was discovered.
/// Interfaces are grouped into physical devices using the USB device the OS
/// reports them under (see [`usb_id`](super::usb_id)), reading device info
/// only once per device where possible. Where the OS offers no such mapping,
/// interfaces are grouped by USB Product ID when only one device with that
/// Product ID is present, and by serial number otherwise.
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
    // Readers first: CCID gives the most complete info and is preferred as
    // the single interface to read per device.
    let mut interfaces: Vec<ScannedInterface> = Vec::new();
    #[cfg(feature = "pcsc")]
    for (pid, reader) in &usb_readers {
        interfaces.push(ScannedInterface {
            kind: InterfaceKind::Reader,
            path: reader.clone(),
            pid: *pid,
            usb_id: reader_usb_device_id(reader),
        });
    }
    #[cfg(feature = "hid")]
    for hid in &otp_devs {
        interfaces.push(ScannedInterface {
            kind: InterfaceKind::Otp,
            path: hid.path.clone(),
            pid: hid.pid,
            usb_id: hid_usb_device_id(&hid.path),
        });
    }
    #[cfg(feature = "hid")]
    for fido in &fido_devs {
        interfaces.push(ScannedInterface {
            kind: InterfaceKind::Fido,
            path: fido.path.clone(),
            pid: fido.pid,
            usb_id: hid_usb_device_id(&fido.path),
        });
    }
    #[cfg(not(feature = "pcsc"))]
    let _ = usb_readers;
    #[cfg(not(feature = "hid"))]
    let _ = (otp_devs, fido_devs);

    let mut devices = assemble_usb_devices(interfaces, &pid_counts, |iface| match iface.kind {
        InterfaceKind::Reader => {
            #[cfg(feature = "pcsc")]
            {
                read_info_reader(&iface.path)
            }
            #[cfg(not(feature = "pcsc"))]
            {
                Err(DeviceError::UnsupportedFeature("pcsc"))
            }
        }
        InterfaceKind::Otp => {
            #[cfg(feature = "hid")]
            {
                let hid = otp_devs
                    .iter()
                    .find(|h| h.path == iface.path)
                    .expect("scanned OTP device");
                read_info_otp_device(hid).map(|info| (info, Transport::Usb, None))
            }
            #[cfg(not(feature = "hid"))]
            {
                Err(DeviceError::UnsupportedFeature("hid"))
            }
        }
        InterfaceKind::Fido => {
            #[cfg(feature = "hid")]
            {
                let fido = fido_devs
                    .iter()
                    .find(|f| f.path == iface.path)
                    .expect("scanned FIDO device");
                read_info_fido_device(fido).map(|info| (info, Transport::Usb, None))
            }
            #[cfg(not(feature = "hid"))]
            {
                Err(DeviceError::UnsupportedFeature("hid"))
            }
        }
    })?;

    // ── Phase 3: NFC devices (no merging needed) ─────────────────
    #[cfg(feature = "pcsc")]
    for reader in &nfc_readers {
        log::debug!("Checking NFC reader: {reader}");
        match read_info_reader(reader) {
            Ok((info, transport, _)) => {
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

/// A USB interface found during the fast scan, before any connection is opened.
#[derive(Debug, Clone)]
struct ScannedInterface {
    kind: InterfaceKind,
    /// Reader name or HID path.
    path: String,
    pid: u16,
    /// The USB device the OS reports this interface under, if available.
    usb_id: Option<UsbDeviceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceKind {
    Reader,
    Otp,
    Fido,
}

/// A physical USB device being assembled from its interfaces.
struct UsbGroup {
    usb_id: Option<UsbDeviceId>,
    device: LocalYubiKeyDevice,
}

impl UsbGroup {
    /// Whether `usb_id` could belong to this group: either identity is
    /// unknown, or both are equal.
    fn identity_compatible(&self, usb_id: &Option<UsbDeviceId>) -> bool {
        match (&self.usb_id, usb_id) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
    }

    fn add_interface(&mut self, iface: &ScannedInterface) {
        let slot = match iface.kind {
            InterfaceKind::Reader => &mut self.device.reader_name,
            InterfaceKind::Otp => &mut self.device.hid_path,
            InterfaceKind::Fido => &mut self.device.fido_path,
        };
        if slot.is_none() {
            *slot = Some(iface.path.clone());
        }
        if self.usb_id.is_none() {
            self.usb_id = iface.usb_id.clone();
        }
    }
}

/// Group scanned USB interfaces into physical devices, reading device info
/// through `read` only where an interface cannot be attributed to a device
/// that has already been read.
///
/// An interface joins an existing device without being read if the OS
/// reports it under the same USB device, or if it is the only device with
/// its PID. Otherwise its info is read and matched by serial number, never
/// against a device the OS attributes to a different USB device.
///
/// `counts` is the number of physical devices per PID (the maximum number of
/// interfaces of one kind sharing that PID). Interfaces are processed in
/// order, so callers should list the preferred interface to read first.
///
/// A reader that cannot be read is tolerated if its device is identified
/// through another interface; a HID interface that cannot be read is an error.
fn assemble_usb_devices(
    interfaces: Vec<ScannedInterface>,
    counts: &HashMap<u16, usize>,
    mut read: impl FnMut(
        &ScannedInterface,
    ) -> Result<(DeviceInfo, Transport, Option<UsbDeviceId>), DeviceError>,
) -> Result<Vec<LocalYubiKeyDevice>, DeviceError> {
    let mut groups: Vec<UsbGroup> = Vec::new();
    let mut unread_readers: Vec<(ScannedInterface, DeviceError)> = Vec::new();

    let find_group = |groups: &[UsbGroup], iface: &ScannedInterface| -> Option<usize> {
        let unique_pid = counts.get(&iface.pid) == Some(&1);
        groups.iter().position(|g| {
            matches!((&g.usb_id, &iface.usb_id), (Some(a), Some(b)) if a == b)
                || (unique_pid
                    && g.device.pid == Some(iface.pid)
                    && g.identity_compatible(&iface.usb_id))
        })
    };

    for iface in interfaces {
        if let Some(i) = find_group(&groups, &iface) {
            groups[i].add_interface(&iface);
            continue;
        }
        match read(&iface) {
            Ok((info, transport, conn_id)) => {
                let usb_id = iface.usb_id.clone().or(conn_id);
                let by_serial = info.serial.and_then(|serial| {
                    groups.iter().position(|g| {
                        g.device.info.serial == Some(serial) && g.identity_compatible(&usb_id)
                    })
                });
                match by_serial {
                    Some(i) => {
                        let group = &mut groups[i];
                        group.add_interface(&iface);
                        if group.usb_id.is_none() {
                            group.usb_id = usb_id;
                        }
                        if group.device.info.version < info.version {
                            group.device.info = info;
                        }
                    }
                    None => {
                        let mut group = UsbGroup {
                            usb_id,
                            device: LocalYubiKeyDevice {
                                reader_name: None,
                                hid_path: None,
                                fido_path: None,
                                pid: Some(iface.pid),
                                transport,
                                info,
                            },
                        };
                        group.add_interface(&iface);
                        groups.push(group);
                    }
                }
            }
            Err(e) => {
                log::debug!(
                    "Reading info from {:?} '{}' failed: {e}",
                    iface.kind,
                    iface.path
                );
                if iface.kind == InterfaceKind::Reader {
                    unread_readers.push((iface, e));
                } else {
                    return Err(e);
                }
            }
        }
    }

    for (iface, e) in unread_readers {
        match find_group(&groups, &iface) {
            Some(i) => groups[i].add_interface(&iface),
            None => return Err(e),
        }
    }

    Ok(groups.into_iter().map(|g| g.device).collect())
}

// ---------------------------------------------------------------------------
// read_info_reader
// ---------------------------------------------------------------------------

/// Open a PC/SC connection and read [`DeviceInfo`] from a YubiKey.
///
/// For older devices (NEO, etc.) that lack the management applet,
/// synthesizes DeviceInfo by probing individual applets.
///
/// Returns the device info, the detected transport (USB or NFC), and the USB
/// device the reader belongs to when the connection can tell.
#[cfg(feature = "pcsc")]
fn read_info_reader(
    reader_name: &str,
) -> Result<(DeviceInfo, Transport, Option<UsbDeviceId>), DeviceError> {
    let conn = PcscSmartCardConnection::open(reader_name)?;
    let transport = conn.transport();
    let pid = pid_from_reader_name(reader_name);
    let (info, conn) = read_info_ccid(conn, pid)?;
    let usb_id = if transport == Transport::Usb {
        connection_usb_device_id(&conn)
    } else {
        None
    };
    Ok((info, transport, usb_id))
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
    let mut devices = list_devices(all)?;

    if let Some(i) = devices
        .iter()
        .position(|d| d.fido_path.as_deref() == Some(path.as_str()))
    {
        return Ok(devices.swap_remove(i));
    }

    // The selected path was not attributed to any device; identify it by
    // reading its info.
    let fido_devs = list_fido_devices()?;
    if let Some(fido_info) = fido_devs.iter().find(|d| d.path == path) {
        let info = read_info_fido_device(fido_info)?;
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

    #[test]
    fn refresh_updates_configuration_without_losing_transport_paths() {
        let mut device = make_device(
            Some("reader"),
            Some("OTP"),
            Some("FIDO"),
            Some(0x0407),
            Version(5, 7, 0),
            Some(12345),
        );
        let mut info = device.info().clone();
        info.is_locked = true;
        info.config
            .enabled_capabilities
            .insert(Transport::Nfc, Capability::PIV);
        device.refresh_info_with_reader(|_| Ok(info)).unwrap();
        assert!(device.info().is_locked);
        assert_eq!(
            device.info().config.enabled_capabilities[&Transport::Nfc],
            Capability::PIV
        );
        assert_eq!(device.reader_name.as_deref(), Some("reader"));
        assert_eq!(device.hid_path.as_deref(), Some("OTP"));
        assert_eq!(device.fido_path.as_deref(), Some("FIDO"));
    }

    #[test]
    fn failed_refresh_preserves_the_original_snapshot() {
        let mut device = make_device(
            None,
            Some("OTP"),
            None,
            Some(0x0407),
            Version(5, 7, 0),
            Some(12345),
        );
        let error = device
            .refresh_info_with_reader(|_| Err(DeviceError::CcidUnavailable))
            .unwrap_err();
        assert!(matches!(error, DeviceError::CcidUnavailable));
        for change_serial in [true, false] {
            let mut wrong = device.info().clone();
            wrong.is_locked = true;
            if change_serial {
                wrong.serial = Some(54321);
            } else {
                wrong.version = Version(5, 7, 1);
            }
            assert!(matches!(
                device.refresh_info_with_reader(|_| Ok(wrong)),
                Err(DeviceError::WrongDevice)
            ));
            assert_eq!(device.info().serial, Some(12345));
            assert_eq!(device.info().version, Version(5, 7, 0));
            assert!(!device.info().is_locked);
        }
    }

    #[test]
    fn reinsert_retries_partial_discovery_without_a_topology_change() {
        let mut device = make_device(
            Some("old reader"),
            Some("old OTP"),
            Some("old FIDO"),
            Some(0x0407),
            Version(5, 7, 0),
            Some(12345),
        );
        let ready = make_device(
            Some("new reader"),
            Some("new OTP"),
            Some("new FIDO"),
            Some(0x0407),
            Version(5, 7, 0),
            Some(12345),
        );
        let mut partial = ready.clone();
        partial.reader_name = None;
        let mut other = ready.clone();
        other.info.serial = Some(54321);
        let all = HashMap::from([(0x0407, 2)]);
        let removed = HashMap::from([(0x0407, 1)]);
        let mut scans = [
            (all.clone(), 0),
            (removed.clone(), 1),
            (removed, 1),
            (all.clone(), 2),
            (all, 2),
        ]
        .into_iter();
        let mut discoveries = [
            vec![other.clone()],
            vec![other.clone(), partial],
            vec![other, ready.clone()],
        ]
        .into_iter();
        device
            .reinsert_usb_with_discovery(
                &|_| {},
                &|| false,
                || scans.next().expect("reinsertion did not finish"),
                |interfaces| {
                    assert_eq!(
                        interfaces,
                        UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO,
                    );
                    Ok(discoveries.next().expect("unexpected discovery"))
                },
                || {},
            )
            .unwrap();
        assert!(discoveries.next().is_none());
        assert_eq!(device.reader_name, ready.reader_name);
        assert_eq!(device.hid_path, ready.hid_path);
        assert_eq!(device.fido_path, ready.fido_path);
    }

    #[test]
    fn reinsert_rejects_a_different_device() {
        let mut device = make_device(
            None,
            Some("old OTP"),
            None,
            Some(0x0407),
            Version(5, 7, 0),
            Some(12345),
        );
        let mut other = device.clone();
        other.info.serial = Some(54321);
        let present = HashMap::from([(0x0407, 1)]);
        let mut scans = [(present.clone(), 0), (HashMap::new(), 1), (present, 2)].into_iter();
        let mut discoveries = [vec![], vec![other]].into_iter();
        let result = device.reinsert_usb_with_discovery(
            &|_| {},
            &|| false,
            || scans.next().expect("wrong device was not rejected"),
            |_| Ok(discoveries.next().expect("unexpected discovery")),
            || {},
        );
        assert!(matches!(result, Err(DeviceError::WrongDevice)));
    }

    #[test]
    fn reinsert_requires_paths_not_just_advertised_interfaces() {
        let full = make_device(
            Some("Yubico YubiKey OTP+FIDO+CCID 00 00"),
            Some("/dev/hidraw0"),
            Some("/dev/hidraw1"),
            Some(0x0407),
            Version(5, 7, 0),
            Some(12345),
        );
        let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
        assert!(full.has_usb_paths(all));
        for missing in [UsbInterface::CCID, UsbInterface::OTP, UsbInterface::FIDO] {
            let mut partial = full.clone();
            if missing == UsbInterface::CCID {
                partial.reader_name = None;
            } else if missing == UsbInterface::OTP {
                partial.hid_path = None;
            } else {
                partial.fido_path = None;
            }
            assert!(partial.usb_interfaces().contains(all));
            assert!(!partial.has_usb_paths(all));
            assert!(partial.has_usb_paths(UsbInterface(all.0 & !missing.0)));
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

    #[cfg(feature = "pcsc")]
    #[test]
    fn test_open_smartcard_without_reader_reports_ccid_unavailable() {
        let dev = make_device(
            None,
            None,
            Some("/dev/hidraw1"),
            Some(0x0407),
            Version(5, 4, 3),
            Some(12345),
        );
        assert!(matches!(
            dev.open_smartcard(),
            Err(DeviceError::CcidUnavailable)
        ));
    }

    /// Scan helpers for `assemble_usb_devices` tests.
    fn scanned(
        kind: InterfaceKind,
        path: &str,
        pid: u16,
        usb_id: Option<&str>,
    ) -> ScannedInterface {
        ScannedInterface {
            kind,
            path: path.into(),
            pid,
            usb_id: usb_id.map(UsbDeviceId::new),
        }
    }

    fn info_with_serial(serial: Option<u32>) -> DeviceInfo {
        make_info(
            Version(5, 4, 3),
            FormFactor::UsbAKeychain,
            false,
            false,
            serial,
            false,
            Capability(Capability::OTP.0 | Capability::PIV.0),
            false,
        )
    }

    /// Reads info by looking up the interface path in `infos`, counting reads.
    fn reader<'a>(
        infos: &'a [(&'a str, Option<u32>, Option<&'a str>)],
        reads: &'a std::cell::RefCell<Vec<String>>,
    ) -> impl FnMut(
        &ScannedInterface,
    ) -> Result<(DeviceInfo, Transport, Option<UsbDeviceId>), DeviceError>
    + 'a {
        move |iface| {
            reads.borrow_mut().push(iface.path.clone());
            let (_, serial, conn_id) = infos
                .iter()
                .find(|(path, _, _)| *path == iface.path)
                .unwrap_or_else(|| panic!("unexpected read of {}", iface.path));
            Ok((
                info_with_serial(*serial),
                Transport::Usb,
                conn_id.map(UsbDeviceId::new),
            ))
        }
    }

    #[test]
    fn assemble_reads_once_per_usb_device() {
        // Two same-PID keys without serials, fully identified by the OS.
        let interfaces = vec![
            scanned(InterfaceKind::Reader, "reader0", 0x407, Some("a")),
            scanned(InterfaceKind::Reader, "reader1", 0x407, Some("b")),
            scanned(InterfaceKind::Otp, "otp1", 0x407, Some("b")),
            scanned(InterfaceKind::Otp, "otp0", 0x407, Some("a")),
            scanned(InterfaceKind::Fido, "fido0", 0x407, Some("a")),
            scanned(InterfaceKind::Fido, "fido1", 0x407, Some("b")),
        ];
        let infos = [("reader0", None, None), ("reader1", None, None)];
        let reads = std::cell::RefCell::new(Vec::new());
        let devices = assemble_usb_devices(
            interfaces,
            &HashMap::from([(0x407, 2)]),
            reader(&infos, &reads),
        )
        .unwrap();
        assert_eq!(reads.borrow().as_slice(), ["reader0", "reader1"]);
        assert_eq!(devices.len(), 2);
        let a = devices
            .iter()
            .find(|d| d.reader_name.as_deref() == Some("reader0"))
            .unwrap();
        assert_eq!(a.hid_path.as_deref(), Some("otp0"));
        assert_eq!(a.fido_path.as_deref(), Some("fido0"));
        let b = devices
            .iter()
            .find(|d| d.reader_name.as_deref() == Some("reader1"))
            .unwrap();
        assert_eq!(b.hid_path.as_deref(), Some("otp1"));
        assert_eq!(b.fido_path.as_deref(), Some("fido1"));
    }

    #[test]
    fn assemble_uses_connection_identity_for_readers() {
        // Linux: the reader's USB device is only known once connected.
        let interfaces = vec![
            scanned(InterfaceKind::Reader, "reader0", 0x407, None),
            scanned(InterfaceKind::Reader, "reader1", 0x407, None),
            scanned(InterfaceKind::Fido, "fido1", 0x407, Some("b")),
            scanned(InterfaceKind::Fido, "fido0", 0x407, Some("a")),
        ];
        let infos = [("reader0", None, Some("a")), ("reader1", None, Some("b"))];
        let reads = std::cell::RefCell::new(Vec::new());
        let devices = assemble_usb_devices(
            interfaces,
            &HashMap::from([(0x407, 2)]),
            reader(&infos, &reads),
        )
        .unwrap();
        assert_eq!(reads.borrow().len(), 2);
        assert_eq!(devices.len(), 2);
        let a = devices
            .iter()
            .find(|d| d.reader_name.as_deref() == Some("reader0"))
            .unwrap();
        assert_eq!(a.fido_path.as_deref(), Some("fido0"));
        let b = devices
            .iter()
            .find(|d| d.reader_name.as_deref() == Some("reader1"))
            .unwrap();
        assert_eq!(b.fido_path.as_deref(), Some("fido1"));
    }

    #[test]
    fn assemble_single_device_per_pid_without_identity_reads_once() {
        let interfaces = vec![
            scanned(InterfaceKind::Reader, "reader0", 0x407, None),
            scanned(InterfaceKind::Otp, "otp0", 0x407, None),
            scanned(InterfaceKind::Fido, "fido0", 0x407, None),
            scanned(InterfaceKind::Fido, "sky", 0x120, None),
        ];
        let infos = [("reader0", Some(123), None), ("sky", None, None)];
        let reads = std::cell::RefCell::new(Vec::new());
        let counts = HashMap::from([(0x407, 1), (0x120, 1)]);
        let devices = assemble_usb_devices(interfaces, &counts, reader(&infos, &reads)).unwrap();
        assert_eq!(reads.borrow().as_slice(), ["reader0", "sky"]);
        assert_eq!(devices.len(), 2);
        let yk = &devices[0];
        assert_eq!(yk.reader_name.as_deref(), Some("reader0"));
        assert_eq!(yk.hid_path.as_deref(), Some("otp0"));
        assert_eq!(yk.fido_path.as_deref(), Some("fido0"));
        assert_eq!(devices[1].fido_path.as_deref(), Some("sky"));
    }

    #[test]
    fn assemble_falls_back_to_serial_without_identity() {
        // macOS-like: readers have no identity, HID interfaces do.
        let interfaces = vec![
            scanned(InterfaceKind::Reader, "reader0", 0x407, None),
            scanned(InterfaceKind::Reader, "reader1", 0x407, None),
            scanned(InterfaceKind::Otp, "otp0", 0x407, Some("a")),
            scanned(InterfaceKind::Otp, "otp1", 0x407, Some("b")),
            scanned(InterfaceKind::Fido, "fido1", 0x407, Some("b")),
            scanned(InterfaceKind::Fido, "fido0", 0x407, Some("a")),
        ];
        let infos = [
            ("reader0", Some(111), None),
            ("reader1", Some(222), None),
            ("otp0", Some(111), None),
            ("otp1", Some(222), None),
        ];
        let reads = std::cell::RefCell::new(Vec::new());
        let devices = assemble_usb_devices(
            interfaces,
            &HashMap::from([(0x407, 2)]),
            reader(&infos, &reads),
        )
        .unwrap();
        // FIDO interfaces are attached through the OTP interfaces' identity.
        assert_eq!(
            reads.borrow().as_slice(),
            ["reader0", "reader1", "otp0", "otp1"]
        );
        assert_eq!(devices.len(), 2);
        let d1 = devices
            .iter()
            .find(|d| d.info().serial == Some(111))
            .unwrap();
        assert_eq!(d1.reader_name.as_deref(), Some("reader0"));
        assert_eq!(d1.hid_path.as_deref(), Some("otp0"));
        assert_eq!(d1.fido_path.as_deref(), Some("fido0"));
        let d2 = devices
            .iter()
            .find(|d| d.info().serial == Some(222))
            .unwrap();
        assert_eq!(d2.reader_name.as_deref(), Some("reader1"));
        assert_eq!(d2.hid_path.as_deref(), Some("otp1"));
        assert_eq!(d2.fido_path.as_deref(), Some("fido1"));
    }

    #[test]
    fn assemble_keeps_serial_less_devices_apart_when_identified() {
        // Two same-version keys without serials; one hides its serial, the
        // other is a Security Key. Both have a FIDO interface only.
        let interfaces = vec![
            scanned(InterfaceKind::Fido, "fido0", 0x120, Some("a")),
            scanned(InterfaceKind::Fido, "fido1", 0x120, Some("b")),
        ];
        let infos = [("fido0", None, None), ("fido1", None, None)];
        let reads = std::cell::RefCell::new(Vec::new());
        let devices = assemble_usb_devices(
            interfaces,
            &HashMap::from([(0x120, 2)]),
            reader(&infos, &reads),
        )
        .unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn assemble_does_not_merge_matching_serials_across_usb_devices() {
        // The OS identity wins over an (impossible) serial collision.
        let interfaces = vec![
            scanned(InterfaceKind::Reader, "reader0", 0x407, Some("a")),
            scanned(InterfaceKind::Otp, "otp1", 0x407, Some("b")),
        ];
        let infos = [("reader0", Some(1), None), ("otp1", Some(1), None)];
        let reads = std::cell::RefCell::new(Vec::new());
        let devices = assemble_usb_devices(
            interfaces,
            &HashMap::from([(0x407, 2)]),
            reader(&infos, &reads),
        )
        .unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn assemble_tolerates_unreadable_reader_when_identified_otherwise() {
        let interfaces = vec![
            scanned(InterfaceKind::Reader, "reader0", 0x407, Some("a")),
            scanned(InterfaceKind::Otp, "otp0", 0x407, Some("a")),
        ];
        let devices =
            assemble_usb_devices(
                interfaces,
                &HashMap::from([(0x407, 1)]),
                |iface| match iface.kind {
                    InterfaceKind::Reader => Err(DeviceError::CcidUnavailable),
                    _ => Ok((info_with_serial(Some(5)), Transport::Usb, None)),
                },
            )
            .unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].reader_name.as_deref(), Some("reader0"));
        assert_eq!(devices[0].hid_path.as_deref(), Some("otp0"));

        let interfaces = vec![scanned(InterfaceKind::Reader, "reader0", 0x407, Some("a"))];
        let result = assemble_usb_devices(interfaces, &HashMap::from([(0x407, 1)]), |_| {
            Err(DeviceError::CcidUnavailable)
        });
        assert!(matches!(result, Err(DeviceError::CcidUnavailable)));
    }
}
