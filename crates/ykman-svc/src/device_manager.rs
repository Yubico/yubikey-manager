//! Device inventory management.
//!
//! Tracks connected YubiKeys via the event-based [`monitor_yubikeys`] monitor
//! and provides exclusive device locking across clients.
//!
//! The monitor is started when the first client connects and is stopped 30
//! seconds after the last client disconnects. While running, it pushes device
//! Added/Changed/Removed events that keep an in-memory inventory up to date;
//! `update_devices()` simply projects that inventory into the RPC device map.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::UsbInterface;
use yubikit::platform::device::LocalYubiKeyDevice;
use yubikit::platform::monitor::{MonitorHandle, YubiKeyEvent, YubiKeyId, monitor_yubikeys};

use ykman::rpc::error::RpcError;
use ykman::rpc::node::RpcNode;

use crate::device::DeviceNode;

const MAX_CLIENTS: usize = 16;

/// How long to keep monitoring after the last client disconnects.
const MONITOR_LINGER: Duration = Duration::from_secs(30);

/// Manages device inventory and exclusive access.
pub struct DeviceManager {
    state: Mutex<ManagerState>,
    /// Number of connected clients.
    client_count: AtomicUsize,
    /// The running device monitor and its stop-scheduling generation.
    monitor: Mutex<MonitorLifecycle>,
    /// Live device inventory, keyed by stable monitor id. Updated by the
    /// monitor's event callback.
    monitored: Arc<Mutex<HashMap<YubiKeyId, LocalYubiKeyDevice>>>,
}

#[derive(Default)]
struct MonitorLifecycle {
    /// The running monitor, if any.
    handle: Option<MonitorHandle>,
    /// Bumped whenever the monitor is (re)started or a pending stop is
    /// cancelled, so stale stop timers become no-ops.
    generation: u64,
}

struct ManagerState {
    /// Current device inventory: name → device info for list_children.
    devices: BTreeMap<String, Value>,
    /// Cached device objects for fast re-open without re-enumeration.
    device_objects: BTreeMap<String, LocalYubiKeyDevice>,
    /// Devices that are currently opened by a client session.
    locked_devices: HashSet<String>,
}

impl DeviceManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ManagerState {
                devices: BTreeMap::new(),
                device_objects: BTreeMap::new(),
                locked_devices: HashSet::new(),
            }),
            client_count: AtomicUsize::new(0),
            monitor: Mutex::new(MonitorLifecycle::default()),
            monitored: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Start the device monitor if it is not already running.
    fn start_monitor(self: &Arc<Self>) {
        let mut lifecycle = recover_lock(self.monitor.lock(), "monitor lifecycle");
        if lifecycle.handle.is_some() {
            return; // Already running (possibly lingering after a disconnect).
        }

        let monitored = Arc::clone(&self.monitored);
        let interfaces = UsbInterface::CCID | UsbInterface::FIDO | UsbInterface::OTP;
        let handle = monitor_yubikeys(interfaces, move |event| {
            let mut inv = recover_lock(monitored.lock(), "monitored inventory");
            match event {
                YubiKeyEvent::Added(yk) | YubiKeyEvent::Changed(yk) => {
                    let id = yk.id();
                    inv.insert(id, yk.into_device());
                }
                YubiKeyEvent::Removed(yk) => {
                    inv.remove(&yk.id());
                }
            }
        });
        lifecycle.handle = Some(handle);
        log::info!("Device monitor started");
    }

    /// Notify that a client has connected.
    pub fn client_connected(self: &Arc<Self>) -> bool {
        let mut current = self.client_count.load(Ordering::Relaxed);
        loop {
            if current >= MAX_CLIENTS {
                log::warn!("Rejecting client; maximum client count ({MAX_CLIENTS}) reached");
                return false;
            }
            match self.client_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(prev) => {
                    current = prev;
                    break;
                }
                Err(actual) => current = actual,
            }
        }
        log::debug!("Client connected (count: {})", current + 1);

        // Cancel any pending stop and ensure the monitor is running.
        {
            let mut lifecycle = recover_lock(self.monitor.lock(), "monitor lifecycle");
            lifecycle.generation += 1;
        }
        self.start_monitor();
        true
    }

    /// Notify that a client has disconnected.
    ///
    /// When the last client leaves, schedules the monitor to stop after
    /// [`MONITOR_LINGER`] unless a client reconnects in the meantime.
    pub fn client_disconnected(self: &Arc<Self>) {
        let prev = self
            .client_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_sub(1)
            });
        let remaining = match prev {
            Ok(count) => {
                log::debug!("Client disconnected (count: {})", count - 1);
                count - 1
            }
            Err(_) => {
                log::warn!("Client disconnect observed with count already at zero");
                return;
            }
        };

        if remaining > 0 {
            return;
        }

        // Last client gone: schedule a delayed stop.
        let generation = {
            let mut lifecycle = recover_lock(self.monitor.lock(), "monitor lifecycle");
            lifecycle.generation += 1;
            lifecycle.generation
        };
        let this = Arc::clone(self);
        thread::spawn(move || {
            thread::sleep(MONITOR_LINGER);
            let handle = {
                let mut lifecycle = recover_lock(this.monitor.lock(), "monitor lifecycle");
                if this.client_count.load(Ordering::Relaxed) == 0
                    && lifecycle.generation == generation
                {
                    lifecycle.handle.take()
                } else {
                    None
                }
            };
            if let Some(handle) = handle {
                handle.stop();
                recover_lock(this.monitored.lock(), "monitored inventory").clear();
                let mut state = recover_lock(this.state.lock(), "device manager state");
                state.devices.clear();
                state.device_objects.clear();
                log::info!("Device monitor stopped after linger");
            }
        });
    }

    /// Project the live monitored inventory into the RPC device map.
    /// Returns the current device map.
    pub fn update_devices(&self) -> BTreeMap<String, Value> {
        // Snapshot the monitored devices, ordered by stable id for
        // deterministic duplicate-naming.
        let mut devices: Vec<(YubiKeyId, LocalYubiKeyDevice)> = {
            let inv = recover_lock(self.monitored.lock(), "monitored inventory");
            inv.iter().map(|(id, dev)| (*id, dev.clone())).collect()
        };
        devices.sort_by_key(|(id, _)| *id);
        let devices: Vec<LocalYubiKeyDevice> = devices.into_iter().map(|(_, dev)| dev).collect();

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

        let mut state = self.lock_state();

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
        let state = self.lock_state();
        state.devices.contains_key(name)
    }

    /// Try to open a device exclusively for a client session.
    pub fn open_device(&self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        let mut state = self.lock_state();

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
        let mut state = self.lock_state();
        state.locked_devices.remove(name);
        log::debug!("Released device lock: {name}");
    }

    /// Get the set of currently locked device names.
    #[allow(dead_code)]
    pub fn locked_devices(&self) -> HashSet<String> {
        self.lock_state().locked_devices.clone()
    }

    fn lock_state(&self) -> MutexGuard<'_, ManagerState> {
        recover_lock(self.state.lock(), "device manager state")
    }
}

fn recover_lock<'a, T>(
    result: std::sync::LockResult<MutexGuard<'a, T>>,
    name: &str,
) -> MutexGuard<'a, T> {
    match result {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::error!("Recovering poisoned {name}");
            poisoned.into_inner()
        }
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
