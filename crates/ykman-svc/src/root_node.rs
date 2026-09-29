//! Root RPC node for the ykman-svc service.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use ykman::rpc::error::{RpcError, RpcResponse};
use ykman::rpc::node::{RpcNode, SignalFn};

use crate::device_manager::DeviceManager;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn matches_revision(opened: Option<&u64>, current: Option<u64>) -> bool {
    matches!((opened, current), (Some(opened), Some(current)) if *opened == current)
}

/// Root node of the service RPC tree.
pub struct ServiceRootNode {
    manager: Arc<DeviceManager>,
    /// Cached list of device names for list_children.
    cached_children: BTreeMap<String, Value>,
    /// Device names locked by this session (released on drop).
    opened_devices: Vec<String>,
    opened_revisions: BTreeMap<String, u64>,
}

impl ServiceRootNode {
    pub fn new(manager: Arc<DeviceManager>) -> Self {
        Self {
            manager,
            cached_children: BTreeMap::new(),
            opened_devices: Vec::new(),
            opened_revisions: BTreeMap::new(),
        }
    }
}

impl Drop for ServiceRootNode {
    fn drop(&mut self) {
        for name in &self.opened_devices {
            self.manager.release_device(name);
        }
        if !self.opened_devices.is_empty() {
            log::debug!(
                "Released {} device lock(s) on session end",
                self.opened_devices.len()
            );
        }
    }
}

impl RpcNode for ServiceRootNode {
    fn get_data(&self) -> Value {
        json!({
            "version": VERSION,
        })
    }

    fn on_child_closed(&mut self, name: &str) {
        self.opened_revisions.remove(name);
        if self.opened_devices.contains(&name.to_string()) {
            self.manager.release_device(name);
            self.opened_devices.retain(|n| n != name);
            log::debug!("Released device lock for '{name}'");
        }
    }

    fn list_actions(&self) -> Vec<&'static str> {
        vec!["select_fido"]
    }

    fn list_children(&mut self) -> BTreeMap<String, Value> {
        let children = self.manager.update_devices();
        self.cached_children = children
            .iter()
            .map(|(name, info)| (name.clone(), info.clone()))
            .collect();
        self.cached_children.clone()
    }

    fn retains_children(&self) -> bool {
        true
    }

    fn call_action(
        &mut self,
        action: &str,
        _params: &Value,
        _signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "select_fido" => {
                log::debug!("FIDO selection requested");
                let cancel_fn = || cancel.load(Ordering::Relaxed);
                let device = yubikit::platform::device::select_fido(Some(&cancel_fn))
                    .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

                // Find the device name in our inventory
                let devices = self.manager.update_devices();
                let info = device.info();
                let matches = devices
                    .iter()
                    .filter(|(_name, data)| {
                        let version_matches = data
                            .get("version")
                            .and_then(|v| v.as_array())
                            .is_some_and(|arr| {
                                arr.len() == 3
                                    && arr[0].as_u64() == Some(info.version.0 as u64)
                                    && arr[1].as_u64() == Some(info.version.1 as u64)
                                    && arr[2].as_u64() == Some(info.version.2 as u64)
                            });
                        if !version_matches {
                            return false;
                        }
                        match info.serial {
                            Some(serial) => {
                                data.get("serial").and_then(|v| v.as_u64()) == Some(serial as u64)
                            }
                            None => {
                                data.get("serial").is_none_or(Value::is_null)
                                    && data.get("pid").and_then(|v| v.as_u64())
                                        == device.pid().map(u64::from)
                                    && data.get("name").and_then(|v| v.as_str())
                                        == Some(device.name().as_str())
                            }
                        }
                    })
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>();
                let name = match matches.as_slice() {
                    [name] => name.clone(),
                    [] => {
                        return Err(RpcError::new(
                            "device-error",
                            "Selected device not found in inventory",
                        ));
                    }
                    _ => {
                        return Err(RpcError::new(
                            "device-error",
                            "Selected device is ambiguous in service inventory",
                        ));
                    }
                };

                Ok(RpcResponse::new(json!({"name": name})))
            }
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        let (node, revision) = self.manager.open_device(name)?;
        self.opened_devices.push(name.to_string());
        self.opened_revisions.insert(name.to_string(), revision);
        Ok(node)
    }

    fn is_child_valid(&self, name: &str) -> bool {
        matches_revision(
            self.opened_revisions.get(name),
            self.manager.device_revision(name),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::matches_revision;

    #[test]
    fn reconnected_device_invalidates_cached_child_with_same_name() {
        assert!(matches_revision(Some(&1), Some(1)));
        assert!(!matches_revision(Some(&1), Some(2)));
        assert!(!matches_revision(Some(&1), None));
        assert!(!matches_revision(None, None));
    }
}
