use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use yubikit::core::Transport;
use yubikit::device::{ReinsertStatus, YubiKeyDevice};
use yubikit::management::Capability;
use yubikit::smartcard::ScpKeyParams;

use super::connection::ConnectionNode;
use super::error::{RpcError, RpcResponse};
use super::rpc::{RpcNode, SignalFn};

/// Root RPC node representing a single YubiKey device.
pub struct DeviceNode {
    device: YubiKeyDevice,
    scp_params: Option<ScpKeyParams>,
    /// Incremented after each reinsert to invalidate cached children.
    generation: u64,
    /// Generation at which each child was created.
    child_generations: BTreeMap<String, u64>,
}

impl DeviceNode {
    pub fn new(device: YubiKeyDevice, scp_params: Option<ScpKeyParams>) -> Self {
        Self {
            device,
            scp_params,
            generation: 0,
            child_generations: BTreeMap::new(),
        }
    }
}

impl RpcNode for DeviceNode {
    fn get_data(&self) -> Value {
        let info = self.device.info();
        let version = &info.version;
        let transport = self.device.transport();
        let fido2_supported = info
            .supported_capabilities
            .get(&transport)
            .is_some_and(|caps| caps.contains(Capability::FIDO2));
        json!({
            "version": [version.0, version.1, version.2],
            "serial": info.serial,
            "name": self.device.name(),
            "transport": match transport {
                Transport::Usb => "usb",
                Transport::Nfc => "nfc",
            },
            "fido2_supported": fido2_supported,
        })
    }

    fn list_children(&mut self) -> BTreeMap<String, Value> {
        let mut children = BTreeMap::new();
        let info = self.device.info();
        let transport = self.device.transport();

        let supported = info
            .supported_capabilities
            .get(&transport)
            .copied()
            .unwrap_or(Capability::NONE);

        // "ccid" if a SmartCard connection can be opened
        if self.device.open_smartcard().is_ok() {
            let has_fido2 = supported.contains(Capability::FIDO2);
            children.insert("ccid".to_string(), json!({"fido2": has_fido2}));
        }

        // "ctap" if a FIDO HID connection can be opened
        if supported.contains(Capability::FIDO2) && self.device.open_fido().is_ok() {
            children.insert("ctap".to_string(), json!({"fido2": true}));
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
        _params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "reinsert" => {
                self.device
                    .reinsert(
                        &|status| match status {
                            ReinsertStatus::Remove => {
                                signal("reinsert", json!({"state": "remove"}));
                            }
                            ReinsertStatus::Reinsert => {
                                signal("reinsert", json!({"state": "insert"}));
                            }
                        },
                        &|| cancel.load(Ordering::Relaxed),
                    )
                    .map_err(|e| RpcError::new("device-error", format!("{e}")))?;
                // Invalidate all cached children since connections are stale.
                self.generation += 1;
                Ok(RpcResponse::new(json!({})))
            }
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        let child: Box<dyn RpcNode> = match name {
            "ccid" => {
                let conn = self.device.open_smartcard().map_err(|e| {
                    RpcError::connection_error(&self.device.name(), "ccid", &format!("{e:?}"))
                })?;
                Box::new(ConnectionNode::new_ccid(
                    conn,
                    self.device.clone(),
                    self.scp_params.clone(),
                ))
            }
            "ctap" => {
                let conn = self.device.open_fido().map_err(|e| {
                    RpcError::connection_error(&self.device.name(), "ctap", &format!("{e:?}"))
                })?;
                Box::new(ConnectionNode::new_ctap(conn, self.device.clone()))
            }
            _ => return Err(RpcError::no_such_node(name)),
        };
        self.child_generations
            .insert(name.to_string(), self.generation);
        Ok(child)
    }
}
