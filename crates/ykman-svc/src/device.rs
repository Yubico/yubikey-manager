use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use yubikit::core::Transport;
use yubikit::device::{ReinsertStatus, YubiKeyDevice};
use yubikit::management::Capability;
use yubikit::platform::device::LocalYubiKeyDevice;

use ykman::rpc::error::{RpcError, RpcResponse};
use ykman::rpc::node::{RpcNode, SignalFn};

use crate::connection::ConnectionNode;
use crate::device_manager::DeviceManager;

/// Root RPC node representing a single YubiKey device.
pub struct DeviceNode {
    device: LocalYubiKeyDevice,
    manager: Arc<DeviceManager>,
    id: String,
    revision: u64,
    lock_held: bool,
    active_connections: BTreeSet<String>,
    /// Incremented after each reinsert to invalidate cached children.
    generation: u64,
    /// Generation at which each child was created.
    child_generations: BTreeMap<String, u64>,
}

impl DeviceNode {
    pub fn new(
        device: LocalYubiKeyDevice,
        manager: Arc<DeviceManager>,
        id: String,
        revision: u64,
    ) -> Self {
        Self {
            device,
            manager,
            id,
            revision,
            lock_held: false,
            active_connections: BTreeSet::new(),
            generation: 0,
            child_generations: BTreeMap::new(),
        }
    }

    fn acquire_lock(&mut self) -> Result<bool, RpcError> {
        if self.lock_held {
            return Ok(false);
        }
        self.manager.lock_device(&self.id, self.revision)?;
        self.lock_held = true;
        Ok(true)
    }

    fn release_lock(&mut self) {
        if self.lock_held {
            self.manager.release_device(&self.id, self.revision);
            self.lock_held = false;
        }
    }
}

impl Drop for DeviceNode {
    fn drop(&mut self) {
        self.release_lock();
    }
}

pub(crate) fn device_data(device: &LocalYubiKeyDevice) -> Value {
    let info = device.info();
    let version = &info.version;
    let transport = device.transport();

    let cap_to_u16 = |c: &Capability| c.0;
    let cap_map = |map: &std::collections::HashMap<Transport, Capability>| -> Value {
        let mut obj = serde_json::Map::new();
        for (t, c) in map {
            let key = match t {
                Transport::Usb => "usb",
                Transport::Nfc => "nfc",
            };
            obj.insert(key.to_string(), json!(cap_to_u16(c)));
        }
        Value::Object(obj)
    };

    let vq = &info.version_qualifier;
    let version_qualifier = json!({
        "version": [vq.version.0, vq.version.1, vq.version.2],
        "release_type": vq.release_type as u8,
        "iteration": vq.iteration,
    });

    let opt_version = |v: &Option<yubikit::core::Version>| -> Value {
        match v {
            Some(v) => json!([v.0, v.1, v.2]),
            None => Value::Null,
        }
    };

    json!({
        "pid": device.pid(),
        "version": [version.0, version.1, version.2],
        "serial": info.serial,
        "name": device.name(),
        "reader_name": device.reader_name(),
        "transport": match transport {
            Transport::Usb => "usb",
            Transport::Nfc => "nfc",
        },
        "supported_capabilities": cap_map(&info.supported_capabilities),
        "enabled_capabilities": cap_map(&info.config.enabled_capabilities),
        "fips_capable": cap_to_u16(&info.fips_capable),
        "fips_approved": cap_to_u16(&info.fips_approved),
        "reset_blocked": cap_to_u16(&info.reset_blocked),
        "is_fips": info.is_fips,
        "is_sky": info.is_sky,
        "is_locked": info.is_locked,
        "pin_complexity": info.pin_complexity,
        "form_factor": info.form_factor as u8,
        "part_number": info.part_number,
        "fps_version": opt_version(&info.fps_version),
        "stm_version": opt_version(&info.stm_version),
        "version_qualifier": version_qualifier,
        "auto_eject_timeout": info.config.auto_eject_timeout,
        "challenge_response_timeout": info.config.challenge_response_timeout,
        "device_flags": info.config.device_flags.map(|f| f.0),
        "nfc_restricted": info.config.nfc_restricted,
        "usb_interfaces": device.usb_interfaces().0,
    })
}

impl RpcNode for DeviceNode {
    fn get_data(&self) -> Value {
        device_data(&self.device)
    }

    fn list_children(&mut self) -> BTreeMap<String, Value> {
        use yubikit::management::UsbInterface;

        let mut children = BTreeMap::new();
        let transport = self.device.transport();
        let usb_ifaces = self.device.usb_interfaces();

        if transport == Transport::Nfc || usb_ifaces.contains(UsbInterface::CCID) {
            children.insert("ccid".to_string(), json!({}));
        }

        if transport == Transport::Usb && usb_ifaces.contains(UsbInterface::FIDO) {
            children.insert("ctap".to_string(), json!({}));
        }

        if transport == Transport::Usb && usb_ifaces.contains(UsbInterface::OTP) {
            children.insert("otp".to_string(), json!({}));
        }

        children
    }

    fn list_actions(&self) -> Vec<&'static str> {
        vec!["reinsert"]
    }

    fn retains_children(&self) -> bool {
        true
    }

    fn is_child_valid(&self, name: &str) -> bool {
        self.child_generations
            .get(name)
            .is_some_and(|&g| g == self.generation)
    }

    fn call_action(
        &mut self,
        action: &str,
        _params: &Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "reinsert" => {
                let locked_here = self.acquire_lock()?;
                log::debug!("Reinsert requested");
                let result = self.device.reinsert(
                    &|status| match status {
                        ReinsertStatus::Remove => {
                            signal("reinsert", json!({"state": "remove"}));
                        }
                        ReinsertStatus::Reinsert => {
                            signal("reinsert", json!({"state": "insert"}));
                        }
                    },
                    &|| cancel.load(Ordering::Relaxed),
                );
                if locked_here && self.active_connections.is_empty() {
                    self.release_lock();
                }
                result.map_err(|e| RpcError::new("device-error", format!("{e}")))?;
                // Invalidate all cached children since connections are stale.
                self.generation += 1;
                log::info!("Device reinserted, generation {}", self.generation);
                Ok(RpcResponse::new(json!({})))
            }
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        if !matches!(name, "ccid" | "ctap" | "otp") {
            return Err(RpcError::no_such_node(name));
        }
        let locked_here = self.acquire_lock()?;
        log::debug!("Opening {name} connection");
        let child: Result<Box<dyn RpcNode>, RpcError> = match name {
            "ccid" => self
                .device
                .open_smartcard()
                .map(|conn| {
                    Box::new(ConnectionNode::new_ccid(conn, self.device.clone()))
                        as Box<dyn RpcNode>
                })
                .map_err(|e| {
                    RpcError::connection_error(&self.device.name(), "ccid", &format!("{e:?}"))
                }),
            "ctap" => self
                .device
                .open_fido()
                .map(|conn| {
                    Box::new(ConnectionNode::new_ctap(conn, self.device.clone()))
                        as Box<dyn RpcNode>
                })
                .map_err(|e| {
                    RpcError::connection_error(&self.device.name(), "ctap", &format!("{e:?}"))
                }),
            "otp" => self
                .device
                .open_otp()
                .map(|conn| {
                    Box::new(ConnectionNode::new_otp(conn, self.device.clone())) as Box<dyn RpcNode>
                })
                .map_err(|e| {
                    RpcError::connection_error(&self.device.name(), "otp", &format!("{e:?}"))
                }),
            _ => unreachable!(),
        };
        if child.is_err() && locked_here {
            self.release_lock();
        }
        let child = child?;
        self.active_connections.insert(name.to_string());
        self.child_generations
            .insert(name.to_string(), self.generation);
        Ok(child)
    }

    fn on_child_closed(&mut self, name: &str) {
        self.active_connections.remove(name);
        if self.active_connections.is_empty() {
            self.release_lock();
        }
    }
}
