//! RPC proxy implementations of `FidoConnection`, `SmartCardConnection`, and `Device`.
//!
//! These allow the client side to use the standard yubikit traits over an RPC
//! connection, transparently proxying raw commands to the server subprocess.

use std::cell::RefCell;
use std::rc::Rc;

use hex::{FromHex, ToHex};
use serde_json::{Value, json};

use yubikit::core::{Connection, Transport};
use yubikit::device::{DeviceError, ReinsertStatus, YubiKeyDevice};
use yubikit::fido::FidoConnection;
use yubikit::management::{Capability, DeviceInfo};
use yubikit::otp::{OtpConnection, OtpError};
use yubikit::smartcard::{SmartCardConnection, SmartCardError};
use yubikit::transport::ctaphid::{CtapHidCapability, FidoError};

use super::client::RpcClient;
use crate::util::CliError;

type SharedClient = Rc<RefCell<RpcClient>>;

// ---------------------------------------------------------------------------
// RpcSmartCardConnection
// ---------------------------------------------------------------------------

/// A `SmartCardConnection` backed by the `send_and_receive` RPC action on a
/// ccid connection node.
pub struct RpcSmartCardConnection {
    client: SharedClient,
    transport: Transport,
}

// SAFETY: RpcSmartCardConnection is only used on the main thread.
// The Send bound is required by the Device trait signature but all RPC proxy
// usage is single-threaded.
unsafe impl Send for RpcSmartCardConnection {}

impl Connection for RpcSmartCardConnection {
    type Error = SmartCardError;
    fn close(&mut self) {}
}

impl SmartCardConnection for RpcSmartCardConnection {
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        let result = self
            .client
            .borrow_mut()
            .call(
                "send_and_receive",
                &["ccid"],
                json!({"apdu": apdu.encode_hex::<String>()}),
                None,
                false,
            )
            .map_err(|e| SmartCardError::Transport(Box::new(RpcTransportError(format!("{e}")))))?;

        let data_hex = result
            .body
            .get("data")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let data = Vec::from_hex(data_hex)
            .map_err(|e| SmartCardError::InvalidData(format!("bad hex from RPC: {e}")))?;
        let sw = result.body.get("sw").and_then(|v| v.as_u64()).unwrap_or(0) as u16;

        Ok((data, sw))
    }

    fn transport(&self) -> Transport {
        self.transport
    }
}

// ---------------------------------------------------------------------------
// RpcFidoConnection
// ---------------------------------------------------------------------------

/// A `FidoConnection` backed by the `call` RPC action on a ctap connection node.
pub struct RpcFidoConnection {
    client: SharedClient,
    device_version: (u8, u8, u8),
    capabilities: CtapHidCapability,
}

// SAFETY: same as RpcSmartCardConnection
unsafe impl Send for RpcFidoConnection {}

impl RpcFidoConnection {
    fn from_client(client: SharedClient) -> Result<Self, CliError> {
        let info = client
            .borrow_mut()
            .get(&["ctap"])
            .map_err(|e| CliError(format!("{e}")))?;
        let data = info.body.get("data").cloned().unwrap_or(json!({}));

        let device_version = if let Some(arr) =
            data.get("device_version").and_then(|v| v.as_array())
            && arr.len() == 3
        {
            (
                arr[0].as_u64().unwrap_or(0) as u8,
                arr[1].as_u64().unwrap_or(0) as u8,
                arr[2].as_u64().unwrap_or(0) as u8,
            )
        } else {
            (0, 0, 0)
        };

        let capabilities = CtapHidCapability::from_raw(
            data.get("capabilities")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u8,
        );

        Ok(Self {
            client,
            device_version,
            capabilities,
        })
    }
}

impl Connection for RpcFidoConnection {
    type Error = FidoError;
    fn close(&mut self) {}
}

impl FidoConnection for RpcFidoConnection {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        _cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        let signal_handler: Option<Box<dyn Fn(&str, &Value) + '_>> =
            on_keepalive.map(|cb| -> Box<dyn Fn(&str, &Value) + '_> {
                let cb = RefCell::new(cb);
                Box::new(move |status: &str, body: &Value| {
                    if status == "keepalive"
                        && let Some(s) = body.get("status").and_then(|v| v.as_u64())
                        && let Ok(mut cb) = cb.try_borrow_mut()
                    {
                        cb(s as u8);
                    }
                })
            });

        let result = self
            .client
            .borrow_mut()
            .call(
                "call",
                &["ctap"],
                json!({"cmd": cmd, "data": data.encode_hex::<String>()}),
                signal_handler
                    .as_ref()
                    .map(|h| h.as_ref() as &dyn Fn(&str, &Value)),
                true, // cancellable
            )
            .map_err(|e| FidoError::Other(format!("{e}")))?;

        let data_hex = result
            .body
            .get("data")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        Vec::from_hex(data_hex).map_err(|e| FidoError::Other(format!("bad hex from RPC: {e}")))
    }

    fn device_version(&self) -> (u8, u8, u8) {
        self.device_version
    }

    fn capabilities(&self) -> CtapHidCapability {
        self.capabilities
    }
}

// ---------------------------------------------------------------------------
// RpcOtpConnection
// ---------------------------------------------------------------------------

/// An `OtpConnection` backed by `otp_send`/`otp_receive` RPC actions on an
/// otp connection node.
pub struct RpcOtpConnection {
    client: SharedClient,
}

// SAFETY: same as RpcSmartCardConnection
unsafe impl Send for RpcOtpConnection {}

impl Connection for RpcOtpConnection {
    type Error = OtpError;
    fn close(&mut self) {}
}

impl OtpConnection for RpcOtpConnection {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError> {
        let result = self
            .client
            .borrow_mut()
            .call("otp_receive", &["otp"], json!({}), None, false)
            .map_err(|e| OtpError::CommandRejected(format!("{e}")))?;

        let data_hex = result
            .body
            .get("data")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        Vec::from_hex(data_hex)
            .map_err(|e| OtpError::CommandRejected(format!("bad hex from RPC: {e}")))
    }

    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        self.client
            .borrow_mut()
            .call(
                "otp_send",
                &["otp"],
                json!({"data": data.encode_hex::<String>()}),
                None,
                false,
            )
            .map_err(|e| OtpError::CommandRejected(format!("{e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RpcDevice
// ---------------------------------------------------------------------------

/// A `Device` backed by an RPC client, proxying all operations to a subprocess.
pub struct RpcDevice {
    client: SharedClient,
    info: DeviceInfo,
    transport: Transport,
    name: String,
    has_ccid: bool,
    has_ctap: bool,
    has_otp: bool,
}

impl RpcDevice {
    /// Create a new RPC device from a spawned RPC client.
    ///
    /// Reads device info and available connections from the root node.
    pub fn new(mut client: RpcClient) -> Result<Self, CliError> {
        let root = client
            .get(&[])
            .map_err(|e| CliError(format!("Failed to get root node: {e}")))?;
        let data = root.body.get("data").cloned().unwrap_or(json!({}));
        let children = root.body.get("children").cloned().unwrap_or(json!({}));

        let transport = match data.get("transport").and_then(|v| v.as_str()) {
            Some("nfc") => Transport::Nfc,
            _ => Transport::Usb,
        };

        let name = data
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("YubiKey")
            .to_string();

        let has_ccid = children.get("ccid").is_some();
        let has_ctap = children.get("ctap").is_some();
        let has_otp = children.get("otp").is_some();

        let info = Self::read_device_info(&data);

        Ok(Self {
            client: Rc::new(RefCell::new(client)),
            info,
            transport,
            name,
            has_ccid,
            has_ctap,
            has_otp,
        })
    }

    fn read_device_info(data: &Value) -> DeviceInfo {
        use std::collections::HashMap;

        let parse_version = |v: &Value| -> yubikit::core::Version {
            if let Some(arr) = v.as_array()
                && arr.len() == 3
            {
                yubikit::core::Version(
                    arr[0].as_u64().unwrap_or(0) as u8,
                    arr[1].as_u64().unwrap_or(0) as u8,
                    arr[2].as_u64().unwrap_or(0) as u8,
                )
            } else {
                yubikit::core::Version(0, 0, 0)
            }
        };

        let version = data
            .get("version")
            .map(parse_version)
            .unwrap_or(yubikit::core::Version(0, 0, 0));

        let serial = data
            .get("serial")
            .and_then(|v| v.as_u64())
            .map(|s| s as u32);

        let parse_cap_map = |key: &str| -> HashMap<Transport, Capability> {
            let mut map = HashMap::new();
            if let Some(obj) = data.get(key).and_then(|v| v.as_object()) {
                for (k, v) in obj {
                    let transport = match k.as_str() {
                        "usb" => Transport::Usb,
                        "nfc" => Transport::Nfc,
                        _ => continue,
                    };
                    let cap = Capability(v.as_u64().unwrap_or(0) as u16);
                    map.insert(transport, cap);
                }
            }
            map
        };

        let parse_cap = |key: &str| -> Capability {
            Capability(data.get(key).and_then(|v| v.as_u64()).unwrap_or(0) as u16)
        };

        let form_factor_raw = data
            .get("form_factor")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        let opt_version = |key: &str| -> Option<yubikit::core::Version> {
            data.get(key).filter(|v| !v.is_null()).map(&parse_version)
        };

        let version_qualifier = if let Some(vq) = data.get("version_qualifier") {
            let vq_version = vq.get("version").map(parse_version).unwrap_or(version);
            let release_type = yubikit::management::ReleaseType::from_value(
                vq.get("release_type").and_then(|v| v.as_u64()).unwrap_or(2) as u8,
            );
            let iteration = vq.get("iteration").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
            yubikit::management::VersionQualifier::new(vq_version, release_type, iteration)
        } else {
            yubikit::management::VersionQualifier::final_release(version)
        };

        DeviceInfo {
            config: yubikit::management::DeviceConfig {
                enabled_capabilities: parse_cap_map("enabled_capabilities"),
                auto_eject_timeout: data
                    .get("auto_eject_timeout")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u16),
                challenge_response_timeout: data
                    .get("challenge_response_timeout")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u8),
                device_flags: data
                    .get("device_flags")
                    .and_then(|v| v.as_u64())
                    .map(|v| yubikit::management::DeviceFlag(v as u8)),
                nfc_restricted: data.get("nfc_restricted").and_then(|v| v.as_bool()),
            },
            serial,
            version,
            form_factor: yubikit::management::FormFactor::from_code(form_factor_raw),
            supported_capabilities: parse_cap_map("supported_capabilities"),
            is_locked: data
                .get("is_locked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            is_fips: data
                .get("is_fips")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            is_sky: data
                .get("is_sky")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            part_number: data
                .get("part_number")
                .and_then(|v| v.as_str())
                .map(String::from),
            fips_capable: parse_cap("fips_capable"),
            fips_approved: parse_cap("fips_approved"),
            pin_complexity: data
                .get("pin_complexity")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            reset_blocked: parse_cap("reset_blocked"),
            fps_version: opt_version("fps_version"),
            stm_version: opt_version("stm_version"),
            version_qualifier,
        }
    }
}

impl YubiKeyDevice for RpcDevice {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn transport(&self) -> Transport {
        self.transport
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn open_smartcard(&self) -> Result<Box<dyn SmartCardConnection + Send>, DeviceError> {
        if !self.has_ccid {
            return Err(DeviceError::NoDeviceFound);
        }
        Ok(Box::new(RpcSmartCardConnection {
            client: self.client.clone(),
            transport: self.transport,
        }))
    }

    fn open_fido(&self) -> Result<Box<dyn FidoConnection + Send>, DeviceError> {
        if !self.has_ctap {
            return Err(DeviceError::NoDeviceFound);
        }
        let conn = RpcFidoConnection::from_client(self.client.clone()).map_err(|e| {
            DeviceError::SmartCard(SmartCardError::Transport(Box::new(RpcTransportError(e.0))))
        })?;
        Ok(Box::new(conn))
    }

    fn open_otp(&self) -> Result<Box<dyn OtpConnection + Send>, DeviceError> {
        if !self.has_otp {
            return Err(DeviceError::NoDeviceFound);
        }
        Ok(Box::new(RpcOtpConnection {
            client: self.client.clone(),
        }))
    }

    fn reinsert(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        let signal_handler = |status: &str, body: &Value| {
            if status == "reinsert" {
                match body.get("state").and_then(|v| v.as_str()) {
                    Some("remove") => status_cb(ReinsertStatus::Remove),
                    Some("insert") => status_cb(ReinsertStatus::Reinsert),
                    _ => {}
                }
            }
        };

        self.client
            .borrow_mut()
            .call("reinsert", &[], json!({}), Some(&signal_handler), true)
            .map_err(|e| {
                DeviceError::SmartCard(SmartCardError::Transport(Box::new(RpcTransportError(
                    format!("{e}"),
                ))))
            })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple error wrapper for RPC transport errors.
#[derive(Debug)]
struct RpcTransportError(String);

impl std::fmt::Display for RpcTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RpcTransportError {}
