//! Device inventory management.
//!
//! Tracks connected YubiKeys, detects changes using scan_usb_devices/list_readers
//! fingerprinting, and provides exclusive device locking across clients.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use serde_json::{Value, json};

use yubikit::core::Transport;
use yubikit::device::{LocalYubiKeyDevice, YubiKeyDevice, list_devices, scan_usb_devices};
use yubikit::management::UsbInterface;

use ykman::rpc::error::RpcError;
use ykman::rpc::node::RpcNode;

use crate::device::DeviceNode;

/// Manages device inventory and exclusive access.
pub struct DeviceManager {
    state: Mutex<ManagerState>,
}

struct ManagerState {
    /// Last fingerprint from scan_usb_devices for change detection.
    last_fingerprint: u64,
    /// Current device inventory: name → device info for list_children.
    devices: BTreeMap<String, Value>,
    /// Cached device objects for fast re-open without re-enumeration.
    device_objects: BTreeMap<String, LocalYubiKeyDevice>,
    /// Devices that are currently opened by a client session.
    locked_devices: HashSet<String>,
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ManagerState {
                last_fingerprint: 0,
                devices: BTreeMap::new(),
                device_objects: BTreeMap::new(),
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
        let mut new_device_objects: BTreeMap<String, LocalYubiKeyDevice> = BTreeMap::new();
        let mut serial_counts: HashMap<String, usize> = HashMap::new();

        for dev in &devices {
            let name = device_name(dev, &mut serial_counts);
            let info = dev.info();
            let version = &info.version;
            let transport_str = match dev.transport() {
                Transport::Usb => "usb",
                Transport::Nfc => "nfc",
            };
            new_devices.insert(
                name.clone(),
                json!({
                    "pid": dev.pid(),
                    "serial": info.serial,
                    "version": [version.0, version.1, version.2],
                    "name": dev.name(),
                    "reader_name": dev.reader_name(),
                    "usb_interfaces": dev.usb_interfaces().0,
                    "form_factor": info.form_factor as u8,
                    "transport": transport_str,
                }),
            );
            new_device_objects.insert(name, dev.clone());
        }

        // Deduplicate: remove name-based entries (no serial in key) whose
        // firmware version matches a serial-keyed entry. This guards against
        // the same device appearing twice — once via CCID (full info, serial
        // readable) and once via FIDO/OTP fallback (partial info, serial=null).
        let versions_with_serial: HashSet<(u8, u8, u8)> = new_devices
            .iter()
            .filter(|(k, _)| k.parse::<u32>().is_ok())
            .filter_map(|(_, v)| {
                let arr = v.get("version")?.as_array()?;
                if arr.len() == 3 {
                    Some((
                        arr[0].as_u64()? as u8,
                        arr[1].as_u64()? as u8,
                        arr[2].as_u64()? as u8,
                    ))
                } else {
                    None
                }
            })
            .collect();
        new_devices.retain(|name, info| {
            if name.parse::<u32>().is_ok() {
                return true; // always keep serial-keyed entries
            }
            if let Some(arr) = info.get("version").and_then(|v| v.as_array())
                && arr.len() == 3
            {
                let ver = (
                    arr[0].as_u64().unwrap_or(0) as u8,
                    arr[1].as_u64().unwrap_or(0) as u8,
                    arr[2].as_u64().unwrap_or(0) as u8,
                );
                if versions_with_serial.contains(&ver) {
                    log::warn!(
                        "Dropping duplicate device entry '{name}' \
                         (v{}.{}.{} already present under serial key)",
                        ver.0,
                        ver.1,
                        ver.2
                    );
                    new_device_objects.remove(name);
                    return false;
                }
            }
            true
        });

        // Remove locks for devices that are no longer present
        state
            .locked_devices
            .retain(|name| new_devices.contains_key(name));

        state.devices = new_devices.clone();
        state.device_objects = new_device_objects;
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

        let device = state
            .device_objects
            .get(name)
            .ok_or_else(|| RpcError::new("device-error", format!("Device '{name}' not cached")))?
            .clone();

        state.locked_devices.insert(name.to_string());
        log::debug!("Opened device '{name}' from cache");
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
