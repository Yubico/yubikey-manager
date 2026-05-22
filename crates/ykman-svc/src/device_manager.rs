//! Device inventory management.
//!
//! Tracks connected YubiKeys, detects changes via background polling of
//! `scan_usb_devices`, and provides exclusive device locking across clients.
//!
//! While at least one client is connected, a background thread polls
//! `scan_usb_devices` every 500ms. If the fingerprint changes, the state is
//! marked dirty. On `update_devices()` (triggered by a "get" call), a full
//! `list_devices` is only performed when dirty; otherwise a quick fingerprint
//! check is done.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::UsbInterface;
use yubikit::platform::device::{LocalYubiKeyDevice, list_devices, scan_usb_devices};

use ykman::rpc::error::RpcError;
use ykman::rpc::node::RpcNode;

use crate::device::DeviceNode;

/// Manages device inventory and exclusive access.
pub struct DeviceManager {
    state: Mutex<ManagerState>,
    /// Number of connected clients.
    client_count: AtomicUsize,
    /// Whether the device inventory needs a full refresh.
    dirty: AtomicBool,
    /// Used to wake the scanner thread when clients connect.
    wake: Arc<(Mutex<bool>, Condvar)>,
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
    pub fn new() -> Arc<Self> {
        let wake = Arc::new((Mutex::new(false), Condvar::new()));
        let manager = Arc::new(Self {
            state: Mutex::new(ManagerState {
                last_fingerprint: 0,
                devices: BTreeMap::new(),
                device_objects: BTreeMap::new(),
                locked_devices: HashSet::new(),
            }),
            client_count: AtomicUsize::new(0),
            dirty: AtomicBool::new(true),
            wake: wake.clone(),
        });

        // Spawn background scanner thread
        let mgr = Arc::downgrade(&manager);
        thread::spawn(move || {
            let (lock, cvar) = &*wake;
            loop {
                // Wait until there are clients
                {
                    let mut started = lock.lock().unwrap();
                    while !*started {
                        started = cvar.wait(started).unwrap();
                    }
                }

                // Poll while clients are connected
                loop {
                    let Some(mgr) = mgr.upgrade() else {
                        return; // DeviceManager dropped
                    };
                    if mgr.client_count.load(Ordering::Relaxed) == 0 {
                        // No clients, go back to waiting
                        let mut started = lock.lock().unwrap();
                        *started = false;
                        break;
                    }

                    let (_, fingerprint) = scan_usb_devices();
                    {
                        let mut state = mgr.state.lock().unwrap();
                        if fingerprint != state.last_fingerprint {
                            state.last_fingerprint = fingerprint;
                            drop(state);
                            log::debug!("Background scan: device change detected");
                            mgr.dirty.store(true, Ordering::Relaxed);
                        }
                    }
                    drop(mgr);
                    thread::sleep(Duration::from_millis(500));
                }
            }
        });

        manager
    }

    /// Notify that a client has connected. Sets dirty immediately.
    pub fn client_connected(&self) {
        let prev = self.client_count.fetch_add(1, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Relaxed);
        log::debug!("Client connected (count: {})", prev + 1);

        if prev == 0 {
            // Wake the scanner thread
            let (lock, cvar) = &*self.wake;
            let mut started = lock.lock().unwrap();
            *started = true;
            cvar.notify_one();
        }
    }

    /// Notify that a client has disconnected.
    pub fn client_disconnected(&self) {
        let prev = self.client_count.fetch_sub(1, Ordering::Relaxed);
        log::debug!("Client disconnected (count: {})", prev - 1);
    }

    /// Scan for device changes and update the inventory.
    /// Performs a full `list_devices` only if dirty; otherwise does a quick
    /// fingerprint check to see if a rescan is needed.
    /// Returns the current device map.
    pub fn update_devices(&self) -> BTreeMap<String, Value> {
        let mut state = self.state.lock().unwrap();

        if !self.dirty.load(Ordering::Relaxed) {
            // Quick check: has anything changed since last full scan?
            let (_, fingerprint) = scan_usb_devices();
            if fingerprint == state.last_fingerprint && !state.devices.is_empty() {
                log::debug!("No device changes detected");
                return state.devices.clone();
            }
        }

        self.dirty.store(false, Ordering::Relaxed);
        log::info!("Device state changed, rescanning");

        let (_, fingerprint) = scan_usb_devices();
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
