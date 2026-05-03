//! Device inventory management.
//!
//! Tracks connected YubiKeys, detects changes using scan_usb_devices/list_readers
//! fingerprinting, and provides exclusive device locking across clients.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use serde_json::{Value, json};

use yubikit::device::{LocalYubiKeyDevice, YubiKeyDevice, list_devices, scan_usb_devices};
use yubikit::management::UsbInterface;

use ykman_cli::rpc::device::DeviceNode;
use ykman_cli::rpc::error::RpcError;
use ykman_cli::rpc::node::RpcNode;

/// Manages device inventory and exclusive access.
pub struct DeviceManager {
    state: Mutex<ManagerState>,
}

struct ManagerState {
    /// Last fingerprint from scan_usb_devices for change detection.
    last_fingerprint: u64,
    /// Current device inventory: name → device info for list_children.
    devices: BTreeMap<String, Value>,
    /// Devices that are currently opened by a client session.
    locked_devices: HashSet<String>,
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ManagerState {
                last_fingerprint: 0,
                devices: BTreeMap::new(),
                locked_devices: HashSet::new(),
            }),
        }
    }

    /// Scan for device changes and update the inventory.
    /// Only calls the expensive `list_devices` if the fingerprint changed.
    /// Returns the current device map.
    pub fn update_devices(&self) -> BTreeMap<String, Value> {
        let mut state = self.state.lock().unwrap();

        let (_pid_counts, fingerprint) = scan_usb_devices();

        if fingerprint == state.last_fingerprint && !state.devices.is_empty() {
            log::debug!("No device changes detected");
            return state.devices.clone();
        }

        log::info!("Device state changed, rescanning");
        state.last_fingerprint = fingerprint;

        // Full enumeration
        let interfaces = UsbInterface::CCID | UsbInterface::FIDO | UsbInterface::OTP;
        let devices = match list_devices(interfaces) {
            Ok(devs) => devs,
            Err(e) => {
                log::error!("list_devices failed: {e}");
                return state.devices.clone();
            }
        };

        let mut new_devices = BTreeMap::new();
        let mut serial_counts: HashMap<String, usize> = HashMap::new();

        for dev in &devices {
            let name = device_name(dev, &mut serial_counts);
            let info = dev.info();
            let version = &info.version;
            new_devices.insert(
                name,
                json!({
                    "serial": info.serial,
                    "version": [version.0, version.1, version.2],
                    "name": dev.name(),
                    "usb_interfaces": dev.usb_interfaces().0,
                    "form_factor": info.form_factor as u8,
                }),
            );
        }

        // Remove locks for devices that are no longer present
        state
            .locked_devices
            .retain(|name| new_devices.contains_key(name));

        state.devices = new_devices.clone();
        new_devices
    }

    /// Check if a device name is still in the current inventory.
    pub fn is_device_present(&self, name: &str) -> bool {
        let state = self.state.lock().unwrap();
        state.devices.contains_key(name)
    }

    /// Try to open a device exclusively for a client session.
    pub fn open_device(&self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        let mut state = self.state.lock().unwrap();

        if !state.devices.contains_key(name) {
            return Err(RpcError::no_such_node(name));
        }

        if state.locked_devices.contains(name) {
            return Err(RpcError::new(
                "device-busy",
                format!("Device '{name}' is in use by another client"),
            ));
        }

        // Open the actual device
        let interfaces = UsbInterface::CCID | UsbInterface::FIDO | UsbInterface::OTP;
        let devices = list_devices(interfaces)
            .map_err(|e| RpcError::new("device-error", format!("Failed to list devices: {e}")))?;

        let device = find_device_by_name(&devices, name)
            .ok_or_else(|| RpcError::new("device-error", format!("Device '{name}' not found")))?;

        state.locked_devices.insert(name.to_string());
        Ok(Box::new(DeviceNode::new(device)))
    }

    /// Release a device lock when a client disconnects or closes the device.
    #[allow(dead_code)]
    pub fn release_device(&self, name: &str) {
        let mut state = self.state.lock().unwrap();
        state.locked_devices.remove(name);
        log::debug!("Released device lock: {name}");
    }

    /// Get the set of currently locked device names.
    #[allow(dead_code)]
    pub fn locked_devices(&self) -> HashSet<String> {
        self.state.lock().unwrap().locked_devices.clone()
    }
}

/// Generate a unique name for a device.
/// Uses serial number when available, falls back to PID-based naming.
fn device_name(dev: &LocalYubiKeyDevice, counts: &mut HashMap<String, usize>) -> String {
    let info = dev.info();
    let base = if let Some(serial) = info.serial {
        serial.to_string()
    } else {
        // Use device name which includes the PID
        let name = dev.name();
        // Sanitize for use as a node name
        name.replace(' ', "-").to_lowercase()
    };

    let count = counts.entry(base.clone()).or_insert(0);
    *count += 1;
    if *count > 1 {
        format!("{base}-{}", *count - 1)
    } else {
        base
    }
}

/// Find a device matching a name in the device list.
fn find_device_by_name(devices: &[LocalYubiKeyDevice], name: &str) -> Option<LocalYubiKeyDevice> {
    // Try matching by serial first
    if let Ok(serial) = name.parse::<u32>()
        && let Some(dev) = devices.iter().find(|d| d.info().serial == Some(serial))
    {
        return Some(dev.clone());
    }

    // Fallback: match by generated name
    let mut counts: HashMap<String, usize> = HashMap::new();
    for dev in devices {
        let dev_name = device_name(dev, &mut counts);
        if dev_name == name {
            return Some(dev.clone());
        }
    }

    None
}
