use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use yubikit::core::Transport;
use yubikit::device::{LocalYubiKeyDevice, ReinsertStatus};
use yubikit::management::Capability;

use super::connection::ConnectionNode;
use super::error::{RpcError, RpcResponse};
use super::rpc::{RpcNode, SignalFn};

/// Root RPC node representing a single YubiKey device.
pub struct DeviceNode {
    device: LocalYubiKeyDevice,
    /// Incremented after each reinsert to invalidate cached children.
    generation: u64,
    /// Generation at which each child was created.
    child_generations: BTreeMap<String, u64>,
}

impl DeviceNode {
    pub fn new(device: LocalYubiKeyDevice) -> Self {
        Self {
            device,
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
            "version": [version.0, version.1, version.2],
            "serial": info.serial,
            "name": self.device.name(),
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

        // Any SmartCard-based application implies CCID is available
        let has_ccid = transport == Transport::Nfc
            || supported.0
                & (Capability::OATH.0
                    | Capability::PIV.0
                    | Capability::OPENPGP.0
                    | Capability::HSMAUTH.0
                    | Capability::FIDO2.0)
                != 0;

        if has_ccid {
            let has_fido2 = supported.contains(Capability::FIDO2);
            children.insert("ccid".to_string(), json!({"fido2": has_fido2}));
        }

        // CTAP HID is available when FIDO2 is supported over USB
        if transport == Transport::Usb && supported.contains(Capability::FIDO2) {
            children.insert("ctap".to_string(), json!({"fido2": true}));
        }

        // OTP HID is available when OTP is supported over USB
        if transport == Transport::Usb && supported.contains(Capability::OTP) {
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
                Box::new(ConnectionNode::new_ccid(conn, self.device.clone()))
            }
            "ctap" => {
                let conn = self.device.open_fido().map_err(|e| {
                    RpcError::connection_error(&self.device.name(), "ctap", &format!("{e:?}"))
                })?;
                Box::new(ConnectionNode::new_ctap(conn, self.device.clone()))
            }
            "otp" => {
                let conn = self.device.open_otp().map_err(|e| {
                    RpcError::connection_error(&self.device.name(), "otp", &format!("{e:?}"))
                })?;
                Box::new(ConnectionNode::new_otp(conn, self.device.clone()))
            }
            _ => return Err(RpcError::no_such_node(name)),
        };
        self.child_generations
            .insert(name.to_string(), self.generation);
        Ok(child)
    }
}
