//! Root RPC node for the ykman-svc service.
//!
//! Provides:
//! - `logging` action: set log level
//! - `multi_device` action: toggle multi-device mode for the session
//! - `update_children` action: refresh device list

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use serde_json::{Value, json};

use ykman_cli::rpc::error::{RpcError, RpcResponse};
use ykman_cli::rpc::node::{RpcNode, SignalFn};

use crate::device_manager::DeviceManager;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Root node of the service RPC tree.
pub struct ServiceRootNode {
    manager: Arc<DeviceManager>,
    /// Per-session multi_device flag.
    multi_device: bool,
    /// Cached list of device names for list_children.
    cached_children: BTreeMap<String, Value>,
    /// Device names locked by this session (released on drop).
    opened_devices: Vec<String>,
}

impl ServiceRootNode {
    pub fn new(manager: Arc<DeviceManager>) -> Self {
        Self {
            manager,
            multi_device: false,
            cached_children: BTreeMap::new(),
            opened_devices: Vec::new(),
        }
    }
}

impl Drop for ServiceRootNode {
    fn drop(&mut self) {
        for name in &self.opened_devices {
            self.manager.release_device(name);
        }
        if !self.opened_devices.is_empty() {
            log::debug!("Released {} device lock(s) on session end", self.opened_devices.len());
        }
    }
}

impl RpcNode for ServiceRootNode {
    fn get_data(&self) -> Value {
        json!({
            "version": VERSION,
            "multi_device": self.multi_device,
        })
    }

    fn list_actions(&self) -> Vec<&'static str> {
        vec!["logging", "multi_device", "update_children"]
    }

    fn list_children(&mut self) -> BTreeMap<String, Value> {
        self.cached_children.clone()
    }

    fn retains_children(&self) -> bool {
        // In multi_device mode, keep all children alive
        self.multi_device
    }

    fn call_action(
        &mut self,
        action: &str,
        params: Value,
        _signal: SignalFn,
        _cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "logging" => {
                let level = params
                    .get("level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("WARNING");
                let log_level: ykman_cli::logging::LogLevel = level
                    .parse()
                    .unwrap_or(ykman_cli::logging::LogLevel::Warning);
                ykman_cli::logging::set_log_level(log_level);
                Ok(RpcResponse::new(json!({})))
            }
            "multi_device" => {
                let enabled = params
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(!self.multi_device);
                self.multi_device = enabled;
                log::info!("Multi-device mode: {enabled}");
                Ok(RpcResponse::new(json!({"enabled": enabled})))
            }
            "update_children" => {
                let children = self.manager.update_devices();
                self.cached_children = children
                    .iter()
                    .map(|(name, info)| (name.clone(), info.clone()))
                    .collect();
                Ok(RpcResponse::new(json!({
                    "children": self.cached_children,
                })))
            }
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        let node = self.manager.open_device(name)?;
        self.opened_devices.push(name.to_string());
        Ok(node)
    }

    fn is_child_valid(&self, name: &str) -> bool {
        self.manager.is_device_present(name)
    }
}
