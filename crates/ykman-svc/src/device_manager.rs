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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::UsbInterface;
use yubikit::platform::device::LocalYubiKeyDevice;
use yubikit::platform::monitor::{MonitorHandle, YubiKeyEvent, YubiKeyId, monitor_yubikeys};

use ykman::rpc::error::RpcError;
use ykman::rpc::node::RpcNode;

use crate::device::{DeviceNode, device_data};

const MAX_CLIENTS: usize = 16;

/// How long to keep monitoring after the last client disconnects.
const MONITOR_LINGER: Duration = Duration::from_secs(30);

/// How long to wait for the monitor's initial device enumeration to complete
/// before letting a connecting client proceed.
const MONITOR_READY_TIMEOUT: Duration = Duration::from_secs(3);

/// Manages device inventory and exclusive access.
pub struct DeviceManager {
    state: Mutex<ManagerState>,
    /// Number of connected clients.
    client_count: AtomicUsize,
    /// The running device monitor and its stop-scheduling generation.
    monitor: Mutex<MonitorLifecycle>,
    /// Live device inventory, keyed by stable monitor id. Updated by the
    /// monitor's event callback.
    monitored: Arc<Mutex<HashMap<YubiKeyId, (LocalYubiKeyDevice, u64)>>>,
    next_revision: Arc<AtomicU64>,
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
    device_revisions: BTreeMap<String, u64>,
    /// Devices that are currently opened by a client session.
    locked_devices: HashMap<String, u64>,
}

pub(crate) struct FidoSelectionGuard {
    manager: Arc<DeviceManager>,
    reserved: Vec<(String, u64)>,
}

impl Drop for FidoSelectionGuard {
    fn drop(&mut self) {
        for (name, revision) in &self.reserved {
            self.manager.release_device(name, *revision);
        }
    }
}

impl DeviceManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ManagerState {
                devices: BTreeMap::new(),
                device_objects: BTreeMap::new(),
                device_revisions: BTreeMap::new(),
                locked_devices: HashMap::new(),
            }),
            client_count: AtomicUsize::new(0),
            monitor: Mutex::new(MonitorLifecycle::default()),
            monitored: Arc::new(Mutex::new(HashMap::new())),
            next_revision: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Start the device monitor if it is not already running.
    fn start_monitor(self: &Arc<Self>) {
        let mut lifecycle = recover_lock(self.monitor.lock(), "monitor lifecycle");
        if lifecycle.handle.is_some() {
            return; // Already running (possibly lingering after a disconnect).
        }

        let monitored = Arc::clone(&self.monitored);
        let next_revision = Arc::clone(&self.next_revision);
        let interfaces = UsbInterface::CCID | UsbInterface::FIDO | UsbInterface::OTP;
        let handle = monitor_yubikeys(interfaces, move |event| {
            let mut inv = recover_lock(monitored.lock(), "monitored inventory");
            match event {
                YubiKeyEvent::Added(yk) | YubiKeyEvent::Changed(yk) => {
                    let id = yk.id();
                    let revision = next_revision.fetch_add(1, Ordering::Relaxed) + 1;
                    inv.insert(id, (yk.into_device(), revision));
                }
                YubiKeyEvent::Removed(yk) => {
                    inv.remove(&yk.id());
                }
            }
        });
        lifecycle.handle = Some(handle);
        log::info!("Device monitor started");

        // Block until the initial device enumeration completes so the inventory
        // is populated before the connecting client queries it. Bounded so a
        // stalled scan can't hang the client indefinitely. This runs only on an
        // actual monitor start (first connect, or after the linger window), so
        // holding the lifecycle lock briefly here is acceptable.
        if let Some(handle) = lifecycle.handle.as_ref()
            && !handle.wait_ready(MONITOR_READY_TIMEOUT)
        {
            log::warn!(
                "Device monitor initial scan did not complete within {MONITOR_READY_TIMEOUT:?}"
            );
        }
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
                state.device_revisions.clear();
                log::info!("Device monitor stopped after linger");
            }
        });
    }

    /// Project the live monitored inventory into the RPC device map.
    /// Returns the current device map.
    pub fn update_devices(&self) -> BTreeMap<String, Value> {
        // Snapshot the monitored devices, ordered by stable id for
        // deterministic duplicate-naming.
        let mut devices: Vec<(YubiKeyId, LocalYubiKeyDevice, u64)> = {
            let inv = recover_lock(self.monitored.lock(), "monitored inventory");
            inv.iter()
                .map(|(id, (dev, revision))| (*id, dev.clone(), *revision))
                .collect()
        };
        devices.sort_by_key(|(id, _, _)| *id);

        let mut new_devices = BTreeMap::new();
        let mut new_device_objects: BTreeMap<String, LocalYubiKeyDevice> = BTreeMap::new();
        let mut new_revisions = BTreeMap::new();
        let mut serial_counts: HashMap<String, usize> = HashMap::new();

        for (_, dev, revision) in &devices {
            let name = device_name(dev, &mut serial_counts);
            new_devices.insert(name.clone(), device_data(dev));
            new_device_objects.insert(name.clone(), dev.clone());
            new_revisions.insert(name, *revision);
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
                    new_revisions.remove(name);
                    return false;
                }
            }
            true
        });

        let mut state = self.lock_state();

        // Remove locks for devices that are no longer present
        state
            .locked_devices
            .retain(|name, revision| new_revisions.get(name) == Some(revision));

        state.devices = new_devices.clone();
        state.device_objects = new_device_objects;
        state.device_revisions = new_revisions;
        new_devices
    }

    /// Return the current monitor revision, refreshing the projected inventory.
    pub fn device_revision(&self, name: &str) -> Option<u64> {
        self.update_devices();
        let state = self.lock_state();
        state.device_revisions.get(name).copied()
    }

    /// Construct a device node without acquiring its exclusive lock.
    pub fn open_device(self: &Arc<Self>, name: &str) -> Result<(Box<dyn RpcNode>, u64), RpcError> {
        let state = self.lock_state();
        let device = state
            .device_objects
            .get(name)
            .ok_or_else(|| RpcError::no_such_node(name))?
            .clone();
        let revision = *state.device_revisions.get(name).ok_or_else(|| {
            RpcError::new("device-error", format!("Device '{name}' has no revision"))
        })?;
        Ok((
            Box::new(DeviceNode::new(
                device,
                Arc::clone(self),
                name.to_string(),
                revision,
            )),
            revision,
        ))
    }

    /// Claim a device on its first connection request in a client session.
    pub fn lock_device(&self, name: &str, revision: u64) -> Result<(), RpcError> {
        let mut state = self.lock_state();
        if state.device_revisions.get(name) != Some(&revision) {
            return Err(RpcError::no_such_node(name));
        }
        if state.locked_devices.contains_key(name) {
            return Err(RpcError::new(
                "device-busy",
                format!("Device '{name}' is in use by another client"),
            ));
        }
        state.locked_devices.insert(name.to_string(), revision);
        Ok(())
    }

    /// Reserve monitored FIDO devices while touch selection opens their connections.
    pub(crate) fn reserve_fido_devices(self: &Arc<Self>) -> Result<FidoSelectionGuard, RpcError> {
        self.update_devices();
        let mut state = self.lock_state();
        let reserved: Vec<(String, u64)> = state
            .device_objects
            .iter()
            .filter(|(_, dev)| {
                dev.transport() == Transport::Usb
                    && dev.usb_interfaces().contains(UsbInterface::FIDO)
            })
            .map(|(name, _)| {
                state
                    .device_revisions
                    .get(name)
                    .map(|revision| (name.clone(), *revision))
                    .ok_or_else(|| RpcError::new("device-error", "Device has no revision"))
            })
            .collect::<Result<_, _>>()?;
        if let Some((name, _)) = reserved
            .iter()
            .find(|(name, _)| state.locked_devices.contains_key(name))
        {
            return Err(RpcError::new(
                "device-busy",
                format!("Device '{name}' is in use by another client"),
            ));
        }
        for (name, revision) in &reserved {
            state.locked_devices.insert(name.clone(), *revision);
        }
        Ok(FidoSelectionGuard {
            manager: Arc::clone(self),
            reserved,
        })
    }

    /// Release a device lock when a client disconnects or closes the device.
    pub fn release_device(&self, name: &str, revision: u64) {
        let mut state = self.lock_state();
        if state.locked_devices.get(name) == Some(&revision) {
            state.locked_devices.remove(name);
            log::debug!("Released device lock: {name}");
        }
    }

    /// Get the set of currently locked device names.
    #[allow(dead_code)]
    pub fn locked_devices(&self) -> HashSet<String> {
        self.lock_state().locked_devices.keys().cloned().collect()
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

#[cfg(test)]
mod tests {
    use super::DeviceManager;

    #[test]
    fn device_locks_are_exclusive_and_revision_scoped() {
        let manager = DeviceManager::new();
        manager
            .lock_state()
            .device_revisions
            .insert("123".into(), 1);
        assert!(manager.lock_device("123", 1).is_ok());
        assert_eq!(
            manager.lock_device("123", 1).unwrap_err().status,
            "device-busy"
        );
        manager.release_device("123", 2);
        assert_eq!(
            manager.lock_device("123", 1).unwrap_err().status,
            "device-busy"
        );
        manager.release_device("123", 1);
        assert!(manager.lock_device("123", 1).is_ok());

        manager
            .lock_state()
            .device_revisions
            .insert("123".into(), 2);
        assert!(manager.lock_device("123", 1).is_err());
        manager.release_device("123", 1);
        assert!(manager.lock_device("123", 2).is_ok());
    }
}
