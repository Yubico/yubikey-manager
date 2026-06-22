//! RPC proxy implementations of `FidoConnection`, `SmartCardConnection`, and `Device`.
//!
//! These allow the client side to use the standard yubikit traits over an RPC
//! connection, transparently proxying raw commands to the server subprocess.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use hex::{FromHex, ToHex};
use serde_json::{Value, json};

use yubikit::__internal::SecretValue;
use yubikit::core::{Connection, Transport};
use yubikit::device::{DeviceError, ReinsertStatus, YubiKeyDevice};
use yubikit::fido::FidoConnection;
use yubikit::fido::{CtapHidCapability, FidoError};
use yubikit::management::{Capability, DeviceInfo, UsbInterface};
use yubikit::otp::{OtpConnection, OtpError};
use yubikit::smartcard::{SmartCardConnection, SmartCardError};

use super::client::{RpcCallError, RpcClient};

type SharedClient = Arc<Mutex<RpcClient>>;

/// Build a full target path from a device prefix and a sub-path.
fn target(prefix: &[String], path: &[&str]) -> Vec<String> {
    prefix
        .iter()
        .cloned()
        .chain(path.iter().map(|s| s.to_string()))
        .collect()
}

fn required_field<'a>(data: &'a Value, key: &str) -> Result<&'a Value, RpcCallError> {
    data.get(key)
        .ok_or_else(|| RpcCallError::Transport(format!("Malformed RPC response: missing {key}")))
}

fn required_str<'a>(data: &'a Value, key: &str) -> Result<&'a str, RpcCallError> {
    required_field(data, key)?.as_str().ok_or_else(|| {
        RpcCallError::Transport(format!("Malformed RPC response: {key} is not a string"))
    })
}

fn optional_str(data: &Value, key: &str) -> Result<Option<String>, RpcCallError> {
    match data.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(v) => v.as_str().map(|s| Some(s.to_string())).ok_or_else(|| {
            RpcCallError::Transport(format!("Malformed RPC response: {key} is not a string"))
        }),
    }
}

fn required_u64(data: &Value, key: &str) -> Result<u64, RpcCallError> {
    required_field(data, key)?.as_u64().ok_or_else(|| {
        RpcCallError::Transport(format!("Malformed RPC response: {key} is not an integer"))
    })
}

fn optional_u64(data: &Value, key: &str) -> Result<Option<u64>, RpcCallError> {
    match data.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| {
            RpcCallError::Transport(format!("Malformed RPC response: {key} is not an integer"))
        }),
    }
}

fn optional_bool(data: &Value, key: &str) -> Result<Option<bool>, RpcCallError> {
    match data.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(v) => v.as_bool().map(Some).ok_or_else(|| {
            RpcCallError::Transport(format!("Malformed RPC response: {key} is not a boolean"))
        }),
    }
}

fn as_u8(value: u64, key: &str) -> Result<u8, RpcCallError> {
    value
        .try_into()
        .map_err(|_| RpcCallError::Transport(format!("Malformed RPC response: {key} exceeds u8")))
}

fn as_u16(value: u64, key: &str) -> Result<u16, RpcCallError> {
    value
        .try_into()
        .map_err(|_| RpcCallError::Transport(format!("Malformed RPC response: {key} exceeds u16")))
}

fn parse_version_array(v: &Value, key: &str) -> Result<yubikit::core::Version, RpcCallError> {
    let arr = v.as_array().ok_or_else(|| {
        RpcCallError::Transport(format!("Malformed RPC response: {key} is not an array"))
    })?;
    if arr.len() != 3 {
        return Err(RpcCallError::Transport(format!(
            "Malformed RPC response: {key} must contain 3 elements"
        )));
    }
    Ok(yubikit::core::Version(
        as_u8(
            arr[0].as_u64().ok_or_else(|| {
                RpcCallError::Transport(format!(
                    "Malformed RPC response: {key}[0] is not an integer"
                ))
            })?,
            key,
        )?,
        as_u8(
            arr[1].as_u64().ok_or_else(|| {
                RpcCallError::Transport(format!(
                    "Malformed RPC response: {key}[1] is not an integer"
                ))
            })?,
            key,
        )?,
        as_u8(
            arr[2].as_u64().ok_or_else(|| {
                RpcCallError::Transport(format!(
                    "Malformed RPC response: {key}[2] is not an integer"
                ))
            })?,
            key,
        )?,
    ))
}

// ---------------------------------------------------------------------------
// RpcSmartCardConnection
// ---------------------------------------------------------------------------

/// A `SmartCardConnection` backed by the `send_and_receive` RPC action on a
/// ccid connection node.
pub struct RpcSmartCardConnection {
    client: SharedClient,
    transport: Transport,
    device_prefix: Vec<String>,
}

impl Connection for RpcSmartCardConnection {
    type Error = SmartCardError;
    fn close(&mut self) {
        log::debug!("Closing RPC SmartCard connection");
    }
}

impl SmartCardConnection for RpcSmartCardConnection {
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        let apdu_hex = SecretValue::new(apdu.encode_hex::<String>());
        yubikit::log_traffic!(">> {}", apdu_hex.expose_secret());
        let result = self
            .client
            .lock()
            .map_err(|_| {
                SmartCardError::Transport(Box::new(RpcTransportError(
                    "RPC client lock poisoned".into(),
                )))
            })?
            .call(
                "send_and_receive",
                &target(&self.device_prefix, &["ccid"]),
                json!({"apdu": apdu_hex.expose_secret()}),
                None,
                false,
            )
            .map_err(|e| SmartCardError::Transport(Box::new(RpcTransportError(format!("{e}")))))?;

        let data_hex = SecretValue::new(
            required_str(&result.body, "data")
                .map_err(|e| SmartCardError::InvalidData(e.to_string()))?
                .to_string(),
        );
        let data = Vec::from_hex(data_hex.expose_secret())
            .map_err(|e| SmartCardError::InvalidData(format!("bad hex from RPC: {e}")))?;
        let sw = as_u16(
            required_u64(&result.body, "sw")
                .map_err(|e| SmartCardError::InvalidData(e.to_string()))?,
            "sw",
        )
        .map_err(|e| SmartCardError::InvalidData(e.to_string()))?;

        yubikit::log_traffic!("<< {} {:04x}", data_hex.expose_secret(), sw);
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
    device_prefix: Vec<String>,
}

impl RpcFidoConnection {
    fn from_client(client: SharedClient, device_prefix: Vec<String>) -> Result<Self, RpcCallError> {
        let info = client
            .lock()
            .map_err(|_| RpcCallError::Transport("RPC client lock poisoned".into()))?
            .get(&target(&device_prefix, &["ctap"]))
            .map_err(|e| RpcCallError::Transport(format!("{e}")))?;
        let data = required_field(&info.body, "data")?;

        let version =
            parse_version_array(required_field(data, "device_version")?, "device_version")?;
        let device_version = (version.0, version.1, version.2);

        let capabilities = CtapHidCapability::from_raw(as_u8(
            required_u64(data, "capabilities")?,
            "capabilities",
        )?);

        Ok(Self {
            client,
            device_version,
            capabilities,
            device_prefix,
        })
    }
}

impl Connection for RpcFidoConnection {
    type Error = FidoError;
    fn close(&mut self) {
        log::debug!("Closing RPC FIDO connection");
    }
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

        let data_hex = SecretValue::new(data.encode_hex::<String>());
        let result = self
            .client
            .lock()
            .map_err(|_| FidoError::Other("RPC client lock poisoned".into()))?
            .call(
                "call",
                &target(&self.device_prefix, &["ctap"]),
                json!({"cmd": cmd, "data": data_hex.expose_secret()}),
                signal_handler
                    .as_ref()
                    .map(|h| h.as_ref() as &dyn Fn(&str, &Value)),
                true, // cancellable
            )
            .map_err(|e| FidoError::Other(format!("{e}")))?;

        let response_hex = SecretValue::new(
            required_str(&result.body, "data")
                .map_err(|e| FidoError::Other(e.to_string()))?
                .to_string(),
        );
        yubikit::log_traffic!("CTAP cmd={:02x} >> {}", cmd, data_hex.expose_secret());
        yubikit::log_traffic!("CTAP cmd={:02x} << {}", cmd, response_hex.expose_secret());
        Vec::from_hex(response_hex.expose_secret())
            .map_err(|e| FidoError::Other(format!("bad hex from RPC: {e}")))
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
    device_prefix: Vec<String>,
}

impl Connection for RpcOtpConnection {
    type Error = OtpError;
    fn close(&mut self) {
        log::debug!("Closing RPC OTP connection");
    }
}

impl OtpConnection for RpcOtpConnection {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError> {
        let result = self
            .client
            .lock()
            .map_err(|_| OtpError::CommandRejected("RPC client lock poisoned".into()))?
            .call(
                "otp_receive",
                &target(&self.device_prefix, &["otp"]),
                json!({}),
                None,
                false,
            )
            .map_err(|e| OtpError::CommandRejected(format!("{e}")))?;

        let data_hex = SecretValue::new(
            required_str(&result.body, "data")
                .map_err(|e| OtpError::CommandRejected(e.to_string()))?
                .to_string(),
        );
        let data = Vec::from_hex(data_hex.expose_secret())
            .map_err(|e| OtpError::CommandRejected(format!("bad hex from RPC: {e}")))?;
        yubikit::log_traffic!("otp_receive << {}", data_hex.expose_secret());
        Ok(data)
    }

    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        let data_hex = SecretValue::new(data.encode_hex::<String>());
        yubikit::log_traffic!("otp_send >> {}", data_hex.expose_secret());
        self.client
            .lock()
            .map_err(|_| OtpError::CommandRejected("RPC client lock poisoned".into()))?
            .call(
                "otp_send",
                &target(&self.device_prefix, &["otp"]),
                json!({"data": data_hex.expose_secret()}),
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
#[derive(Clone)]
pub struct RpcDevice {
    client: SharedClient,
    prefix: Vec<String>,
    info: DeviceInfo,
    transport: Transport,
    name: String,
    pid: Option<u16>,
    reader_name: Option<String>,
    usb_ifaces: UsbInterface,
    has_ccid: bool,
    has_ctap: bool,
    has_otp: bool,
}

impl RpcDevice {
    /// Create an RPC device from a client owning its connection exclusively,
    /// targeting a specific device by name.
    pub fn from_client_at(client: RpcClient, device_name: &str) -> Result<Self, RpcCallError> {
        let prefix = vec![device_name.to_string()];
        Self::from_shared_inner(Arc::new(Mutex::new(client)), prefix)
    }

    /// Create an RPC device from an already-shared client, targeting a specific
    /// device by name.
    ///
    /// Stores the prefix in the device and passes it to every RPC call,
    /// so concurrent use of the shared client for different devices is safe.
    pub fn from_shared_at(
        client: Arc<Mutex<RpcClient>>,
        device_name: &str,
    ) -> Result<Self, RpcCallError> {
        let prefix = vec![device_name.to_string()];
        Self::from_shared_inner(client, prefix)
    }

    pub fn has_ccid(&self) -> bool {
        self.has_ccid
    }

    pub fn has_ctap(&self) -> bool {
        self.has_ctap
    }

    pub fn has_otp(&self) -> bool {
        self.has_otp
    }

    pub fn pid(&self) -> Option<u16> {
        self.pid
    }

    /// Parse device info from a JSON value (children map entry from the service).
    pub fn parse_device_info(
        data: &serde_json::Value,
    ) -> Result<yubikit::management::DeviceInfo, RpcCallError> {
        Self::read_device_info(data)
    }

    fn from_shared_inner(
        client: Arc<Mutex<RpcClient>>,
        prefix: Vec<String>,
    ) -> Result<Self, RpcCallError> {
        log::debug!("Initializing RPC device");
        let root = client
            .lock()
            .map_err(|_| RpcCallError::Transport("RPC client lock poisoned".into()))?
            .get(&prefix)
            .map_err(|e| RpcCallError::Transport(format!("Failed to get root node: {e}")))?;
        let data = required_field(&root.body, "data")?;
        let children = required_field(&root.body, "children")?;
        let children = children.as_object().ok_or_else(|| {
            RpcCallError::Transport("Malformed RPC response: children is not an object".into())
        })?;

        let transport = match required_str(data, "transport")? {
            "usb" => Transport::Usb,
            "nfc" => Transport::Nfc,
            other => {
                return Err(RpcCallError::Transport(format!(
                    "Malformed RPC response: unknown transport {other}"
                )));
            }
        };

        let name = required_str(data, "name")?.to_string();

        let pid = optional_u64(data, "pid")?
            .map(|p| as_u16(p, "pid"))
            .transpose()?;

        let reader_name = optional_str(data, "reader_name")?;

        let has_ccid = children.get("ccid").is_some();
        let has_ctap = children.get("ctap").is_some();
        let has_otp = children.get("otp").is_some();

        let usb_ifaces = UsbInterface(as_u8(
            required_u64(data, "usb_interfaces")?,
            "usb_interfaces",
        )?);

        let info = Self::read_device_info(data)?;

        log::debug!(
            "RPC device: {name}, transport={transport:?}, ccid={has_ccid}, ctap={has_ctap}, otp={has_otp}"
        );
        Ok(Self {
            client,
            prefix,
            info,
            transport,
            name,
            pid,
            reader_name,
            usb_ifaces,
            has_ccid,
            has_ctap,
            has_otp,
        })
    }

    fn read_device_info(data: &Value) -> Result<DeviceInfo, RpcCallError> {
        use std::collections::HashMap;

        let version = parse_version_array(required_field(data, "version")?, "version")?;

        let serial = optional_u64(data, "serial")?
            .map(|s| {
                s.try_into().map_err(|_| {
                    RpcCallError::Transport("Malformed RPC response: serial exceeds u32".into())
                })
            })
            .transpose()?;

        let parse_cap_map = |key: &str| -> Result<HashMap<Transport, Capability>, RpcCallError> {
            let mut map = HashMap::new();
            let Some(value) = data.get(key) else {
                return Ok(map);
            };
            let obj = value.as_object().ok_or_else(|| {
                RpcCallError::Transport(format!("Malformed RPC response: {key} is not an object"))
            })?;
            for (k, v) in obj {
                let transport = match k.as_str() {
                    "usb" => Transport::Usb,
                    "nfc" => Transport::Nfc,
                    _ => continue,
                };
                let cap = Capability(as_u16(
                    v.as_u64().ok_or_else(|| {
                        RpcCallError::Transport(format!(
                            "Malformed RPC response: {key}.{k} is not an integer"
                        ))
                    })?,
                    key,
                )?);
                map.insert(transport, cap);
            }
            Ok(map)
        };

        let parse_cap = |key: &str| -> Result<Capability, RpcCallError> {
            optional_u64(data, key)?
                .map(|v| as_u16(v, key).map(Capability))
                .transpose()
                .map(|v| v.unwrap_or(Capability(0)))
        };

        let form_factor_raw = as_u8(required_u64(data, "form_factor")?, "form_factor")?;

        let opt_version = |key: &str| -> Result<Option<yubikit::core::Version>, RpcCallError> {
            data.get(key)
                .filter(|v| !v.is_null())
                .map(|v| parse_version_array(v, key))
                .transpose()
        };

        let version_qualifier = if let Some(vq) = data.get("version_qualifier") {
            let vq_version = vq
                .get("version")
                .map(|v| parse_version_array(v, "version_qualifier.version"))
                .transpose()?
                .unwrap_or(version);
            let release_type = yubikit::management::ReleaseType::from_value(
                optional_u64(vq, "release_type")?
                    .map(|v| as_u8(v, "version_qualifier.release_type"))
                    .transpose()?
                    .unwrap_or(2),
            );
            let iteration = optional_u64(vq, "iteration")?
                .map(|v| as_u8(v, "version_qualifier.iteration"))
                .transpose()?
                .unwrap_or(0);
            yubikit::management::VersionQualifier::new(vq_version, release_type, iteration)
        } else {
            yubikit::management::VersionQualifier::final_release(version)
        };

        Ok(DeviceInfo {
            config: yubikit::management::DeviceConfig {
                enabled_capabilities: parse_cap_map("enabled_capabilities")?,
                auto_eject_timeout: optional_u64(data, "auto_eject_timeout")?
                    .map(|v| as_u16(v, "auto_eject_timeout"))
                    .transpose()?,
                challenge_response_timeout: optional_u64(data, "challenge_response_timeout")?
                    .map(|v| as_u8(v, "challenge_response_timeout"))
                    .transpose()?,
                device_flags: optional_u64(data, "device_flags")?
                    .map(|v| as_u8(v, "device_flags").map(yubikit::management::DeviceFlag))
                    .transpose()?,
                nfc_restricted: optional_bool(data, "nfc_restricted")?,
            },
            serial,
            version,
            form_factor: yubikit::management::FormFactor::from_code(form_factor_raw),
            supported_capabilities: parse_cap_map("supported_capabilities")?,
            is_locked: optional_bool(data, "is_locked")?.unwrap_or(false),
            is_fips: optional_bool(data, "is_fips")?.unwrap_or(false),
            is_sky: optional_bool(data, "is_sky")?.unwrap_or(false),
            part_number: optional_str(data, "part_number")?,
            fips_capable: parse_cap("fips_capable")?,
            fips_approved: parse_cap("fips_approved")?,
            pin_complexity: optional_bool(data, "pin_complexity")?.unwrap_or(false),
            reset_blocked: parse_cap("reset_blocked")?,
            fps_version: opt_version("fps_version")?,
            stm_version: opt_version("stm_version")?,
            version_qualifier,
        })
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

    fn pid(&self) -> Option<u16> {
        self.pid
    }

    fn reader_name(&self) -> Option<&str> {
        self.reader_name.as_deref()
    }

    fn usb_interfaces(&self) -> UsbInterface {
        self.usb_ifaces
    }

    fn open_smartcard(&self) -> Result<Box<dyn SmartCardConnection + Send>, DeviceError> {
        if !self.has_ccid {
            return Err(DeviceError::NoDeviceFound);
        }
        log::debug!("Opening RPC SmartCard connection");
        Ok(Box::new(RpcSmartCardConnection {
            client: self.client.clone(),
            transport: self.transport,
            device_prefix: self.prefix.clone(),
        }))
    }

    fn open_fido(&self) -> Result<Box<dyn FidoConnection + Send>, DeviceError> {
        if !self.has_ctap {
            return Err(DeviceError::NoDeviceFound);
        }
        log::debug!("Opening RPC FIDO connection");
        let conn = RpcFidoConnection::from_client(self.client.clone(), self.prefix.clone())
            .map_err(|e| {
                DeviceError::SmartCard(SmartCardError::Transport(Box::new(RpcTransportError(
                    format!("{e}"),
                ))))
            })?;
        Ok(Box::new(conn))
    }

    fn open_otp(&self) -> Result<Box<dyn OtpConnection + Send>, DeviceError> {
        if !self.has_otp {
            return Err(DeviceError::NoDeviceFound);
        }
        log::debug!("Opening RPC OTP connection");
        Ok(Box::new(RpcOtpConnection {
            client: self.client.clone(),
            device_prefix: self.prefix.clone(),
        }))
    }

    fn reinsert(
        &mut self,
        status_cb: &dyn Fn(ReinsertStatus),
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<(), DeviceError> {
        log::debug!("Requesting reinsert via RPC");
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
            .lock()
            .map_err(|_| {
                DeviceError::SmartCard(SmartCardError::Transport(Box::new(RpcTransportError(
                    "RPC client lock poisoned".into(),
                ))))
            })?
            .call(
                "reinsert",
                &self.prefix,
                json!({}),
                Some(&signal_handler),
                true,
            )
            .map_err(|e| {
                DeviceError::SmartCard(SmartCardError::Transport(Box::new(RpcTransportError(
                    format!("{e}"),
                ))))
            })?;

        Ok(())
    }

    fn clone_box(&self) -> Box<dyn YubiKeyDevice> {
        Box::new(self.clone())
    }
}

impl Drop for RpcDevice {
    fn drop(&mut self) {
        log::debug!("RPC device disconnected: {}", self.name);
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
