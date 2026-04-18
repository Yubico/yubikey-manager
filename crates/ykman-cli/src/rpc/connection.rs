use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use yubikit::core::Connection;
use yubikit::device::YubiKeyDevice;
use yubikit::smartcard::ScpKeyParams;
use yubikit::transport::ctaphid::HidFidoConnection;
use yubikit::transport::pcsc::PcscSmartCardConnection;

use super::ctap2::Ctap2Node;
use super::error::{RpcError, RpcResponse};
use super::rpc::{RpcNode, SignalFn};

/// Connection shared between ConnectionNode and its session children.
pub type SharedConn<T> = Arc<Mutex<Option<T>>>;

/// Connection node wrapping either a SmartCard or FIDO HID connection.
pub struct ConnectionNode {
    conn_type: ConnType,
    device: YubiKeyDevice,
    scp_params: Option<ScpKeyParams>,
}

enum ConnType {
    SmartCard(SharedConn<PcscSmartCardConnection>),
    Fido(SharedConn<HidFidoConnection>),
}

impl ConnectionNode {
    pub fn new_ccid(
        conn: PcscSmartCardConnection,
        device: YubiKeyDevice,
        scp_params: Option<ScpKeyParams>,
    ) -> Self {
        Self {
            conn_type: ConnType::SmartCard(Arc::new(Mutex::new(Some(conn)))),
            device,
            scp_params,
        }
    }

    pub fn new_ctap(conn: HidFidoConnection, device: YubiKeyDevice) -> Self {
        Self {
            conn_type: ConnType::Fido(Arc::new(Mutex::new(Some(conn)))),
            device,
            scp_params: None,
        }
    }
}

impl RpcNode for ConnectionNode {
    fn get_data(&self) -> Value {
        let info = self.device.info();
        let version = &info.version;
        json!({
            "version": [version.0, version.1, version.2],
            "serial": info.serial,
            "transport": match &self.conn_type {
                ConnType::SmartCard(_) => "ccid",
                ConnType::Fido(_) => "ctap",
            },
        })
    }

    fn list_children(&mut self) -> BTreeMap<String, Value> {
        let mut children = BTreeMap::new();
        // Both connection types can host a ctap2 child
        children.insert("ctap2".to_string(), json!({}));
        children
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
            "ctap2" => {
                match &self.conn_type {
                    ConnType::Fido(conn) => {
                        let c = conn.lock().unwrap().take().ok_or_else(|| {
                            RpcError::new("connection-error", "Connection in use")
                        })?;
                        Ok(Box::new(Ctap2Node::new_hid(
                            c,
                            conn.clone(),
                            self.device.clone(),
                        )?))
                    }
                    ConnType::SmartCard(conn) => {
                        let c = conn.lock().unwrap().take().ok_or_else(|| {
                            RpcError::new("connection-error", "Connection in use")
                        })?;
                        Ok(Box::new(Ctap2Node::new_smartcard(
                            c,
                            conn.clone(),
                            self.device.clone(),
                            self.scp_params.clone(),
                        )?))
                    }
                }
            }
            _ => Err(RpcError::no_such_node(name)),
        }
    }

    fn close(&mut self) {
        match &self.conn_type {
            ConnType::SmartCard(conn) => {
                let mut guard = conn.lock().unwrap();
                if let Some(mut c) = guard.take() {
                    c.close();
                }
            }
            ConnType::Fido(conn) => {
                let _ = conn.lock().unwrap().take();
            }
        }
    }
}
