use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

use serde_json::{Value, json};

use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::smartcard::ScpKeyParams;

use super::connection::ConnectionNode;
use super::error::{RpcError, RpcResponse};
use super::rpc::{RpcNode, SignalFn};

/// Root RPC node representing a single YubiKey device.
pub struct DeviceNode {
    device: YubiKeyDevice,
    scp_params: Option<ScpKeyParams>,
}

impl DeviceNode {
    pub fn new(device: YubiKeyDevice, scp_params: Option<ScpKeyParams>) -> Self {
        Self { device, scp_params }
    }
}

impl RpcNode for DeviceNode {
    fn get_data(&self) -> Value {
        let info = self.device.info();
        let version = &info.version;
        json!({
            "version": [version.0, version.1, version.2],
            "serial": info.serial,
            "name": self.device.name(),
            "transport": match self.device.transport() {
                Transport::Usb => "usb",
                Transport::Nfc => "nfc",
            },
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

    fn retains_children(&self) -> bool {
        true
    }

    fn call_action(
        &mut self,
        action: &str,
        _params: Value,
        _signal: SignalFn,
        _cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        Err(RpcError::no_such_action(action))
    }

    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        match name {
            "ccid" => {
                let conn = self
                    .device
                    .open_smartcard()
                    .map_err(|_| RpcError::connection_error("ccid"))?;
                Ok(Box::new(ConnectionNode::new_ccid(
                    conn,
                    self.device.clone(),
                    self.scp_params.clone(),
                )))
            }
            "ctap" => {
                let conn = self
                    .device
                    .open_fido()
                    .map_err(|_| RpcError::connection_error("ctap"))?;
                Ok(Box::new(ConnectionNode::new_ctap(
                    conn,
                    self.device.clone(),
                )))
            }
            _ => Err(RpcError::no_such_node(name)),
        }
    }
}
