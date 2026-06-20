use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hex::{self, FromHex, ToHex};
use serde::Deserialize;
use serde_json::{Value, json};

use yubikit::core::Connection;
use yubikit::fido::FidoConnection;
use yubikit::otp::OtpConnection;
use yubikit::platform::device::LocalYubiKeyDevice;
use yubikit::platform::hidapi::{HidFidoConnection, HidOtpConnection};
use yubikit::platform::pcsc::PcscSmartCardConnection;
use yubikit::smartcard::SmartCardConnection;

use ykman::rpc::error::{RpcError, RpcResponse};
use ykman::rpc::node::{RpcNode, SignalFn};

/// Connection shared between ConnectionNode and its session children.
pub(super) type SharedConn<T> = Arc<Mutex<Option<T>>>;

const MAX_APDU_LEN: usize = 8192; // Larger than required by any YubiKey currently.
const MAX_CTAP_DATA_LEN: usize = 8192;
const MAX_OTP_DATA_LEN: usize = 64;

/// Connection node wrapping either a SmartCard or FIDO HID connection.
pub(super) struct ConnectionNode {
    conn_type: ConnType,
    device: LocalYubiKeyDevice,
}

enum ConnType {
    SmartCard(SharedConn<PcscSmartCardConnection>),
    Fido(SharedConn<HidFidoConnection>),
    Otp(SharedConn<HidOtpConnection>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendAndReceiveParams {
    apdu: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CtapCallParams {
    cmd: u8,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OtpSendParams {
    data: String,
}

impl ConnectionNode {
    pub fn new_ccid(conn: PcscSmartCardConnection, device: LocalYubiKeyDevice) -> Self {
        Self {
            conn_type: ConnType::SmartCard(Arc::new(Mutex::new(Some(conn)))),
            device,
        }
    }

    pub fn new_ctap(conn: HidFidoConnection, device: LocalYubiKeyDevice) -> Self {
        Self {
            conn_type: ConnType::Fido(Arc::new(Mutex::new(Some(conn)))),
            device,
        }
    }

    pub fn new_otp(conn: HidOtpConnection, device: LocalYubiKeyDevice) -> Self {
        Self {
            conn_type: ConnType::Otp(Arc::new(Mutex::new(Some(conn)))),
            device,
        }
    }

    fn do_send_and_receive(&self, params: Value) -> Result<RpcResponse, RpcError> {
        let params: SendAndReceiveParams = parse_params(params)?;
        let apdu = decode_hex_param("apdu", &params.apdu, MAX_APDU_LEN)?;

        let ConnType::SmartCard(conn) = &self.conn_type else {
            return Err(RpcError::new(
                "invalid-command",
                "send_and_receive is only available on ccid connections",
            ));
        };
        let mut guard = lock_conn(conn)?;
        let c = guard
            .as_mut()
            .ok_or_else(|| RpcError::new("connection-error", "Connection in use"))?;

        let (data, sw) = c
            .send_and_receive(&apdu)
            .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

        Ok(RpcResponse::new(json!({
            "data": data.encode_hex::<String>(),
            "sw": sw,
        })))
    }

    fn do_call(
        &self,
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        let params: CtapCallParams = parse_params(params)?;
        let data = decode_hex_param(
            "data",
            params.data.as_deref().unwrap_or(""),
            MAX_CTAP_DATA_LEN,
        )?;

        let ConnType::Fido(conn) = &self.conn_type else {
            return Err(RpcError::new(
                "invalid-command",
                "call is only available on ctap connections",
            ));
        };
        let mut guard = lock_conn(conn)?;
        let c = guard
            .as_mut()
            .ok_or_else(|| RpcError::new("connection-error", "Connection in use"))?;

        let is_cancelled = || cancel.load(Ordering::Relaxed);
        let mut on_keepalive = |status: u8| {
            signal("keepalive", json!({"status": status}));
        };

        let response = c
            .call(
                params.cmd,
                &data,
                Some(&mut on_keepalive),
                Some(&is_cancelled),
            )
            .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

        Ok(RpcResponse::new(json!({
            "data": response.encode_hex::<String>(),
        })))
    }

    fn do_otp_receive(&self) -> Result<RpcResponse, RpcError> {
        let ConnType::Otp(conn) = &self.conn_type else {
            return Err(RpcError::new(
                "invalid-command",
                "otp_receive is only available on otp connections",
            ));
        };
        let mut guard = lock_conn(conn)?;
        let c = guard
            .as_mut()
            .ok_or_else(|| RpcError::new("connection-error", "Connection in use"))?;

        let data = c
            .otp_receive()
            .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

        Ok(RpcResponse::new(json!({
            "data": data.encode_hex::<String>(),
        })))
    }

    fn do_otp_send(&self, params: Value) -> Result<RpcResponse, RpcError> {
        let params: OtpSendParams = parse_params(params)?;
        let data = decode_hex_param("data", &params.data, MAX_OTP_DATA_LEN)?;

        let ConnType::Otp(conn) = &self.conn_type else {
            return Err(RpcError::new(
                "invalid-command",
                "otp_send is only available on otp connections",
            ));
        };
        let mut guard = lock_conn(conn)?;
        let c = guard
            .as_mut()
            .ok_or_else(|| RpcError::new("connection-error", "Connection in use"))?;

        c.otp_send(&data)
            .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

        Ok(RpcResponse::new(json!({})))
    }
}

impl RpcNode for ConnectionNode {
    fn get_data(&self) -> Value {
        let info = self.device.info();
        let version = &info.version;
        match &self.conn_type {
            ConnType::SmartCard(_) => {
                json!({
                    "version": [version.0, version.1, version.2],
                    "serial": info.serial,
                    "transport": "ccid",
                })
            }
            ConnType::Fido(conn) => {
                let guard = match lock_conn(conn) {
                    Ok(guard) => guard,
                    Err(e) => {
                        log::error!("{e}");
                        return json!({
                            "version": [version.0, version.1, version.2],
                            "serial": info.serial,
                            "transport": "ctap",
                            "device_version": [version.0, version.1, version.2],
                            "capabilities": 0u8,
                        });
                    }
                };
                let (device_version, capabilities) = if let Some(c) = guard.as_ref() {
                    let v = c.device_version();
                    (json!([v.0, v.1, v.2]), c.capabilities().raw())
                } else {
                    (json!([version.0, version.1, version.2]), 0u8)
                };
                json!({
                    "version": [version.0, version.1, version.2],
                    "serial": info.serial,
                    "transport": "ctap",
                    "device_version": device_version,
                    "capabilities": capabilities,
                })
            }
            ConnType::Otp(_) => {
                json!({
                    "version": [version.0, version.1, version.2],
                    "serial": info.serial,
                    "transport": "otp",
                })
            }
        }
    }

    fn list_actions(&self) -> Vec<&'static str> {
        match &self.conn_type {
            ConnType::SmartCard(_) => vec!["send_and_receive"],
            ConnType::Fido(_) => vec!["call"],
            ConnType::Otp(_) => vec!["otp_send", "otp_receive"],
        }
    }

    fn call_action(
        &mut self,
        action: &str,
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "send_and_receive" => self.do_send_and_receive(params),
            "call" => self.do_call(params, signal, cancel),
            "otp_send" => self.do_otp_send(params),
            "otp_receive" => self.do_otp_receive(),
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn close(&mut self) {
        match &self.conn_type {
            ConnType::SmartCard(conn) => {
                log::debug!("Closing CCID connection");
                let Ok(mut guard) = lock_conn(conn) else {
                    return;
                };
                if let Some(mut c) = guard.take() {
                    c.close();
                }
            }
            ConnType::Fido(conn) => {
                log::debug!("Closing CTAP connection");
                if let Ok(mut guard) = lock_conn(conn) {
                    let _ = guard.take();
                }
            }
            ConnType::Otp(conn) => {
                log::debug!("Closing OTP connection");
                let Ok(mut guard) = lock_conn(conn) else {
                    return;
                };
                if let Some(mut c) = guard.take() {
                    c.close();
                }
            }
        }
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))
}

fn decode_hex_param(name: &str, hex: &str, max_len: usize) -> Result<Vec<u8>, RpcError> {
    if hex.len() % 2 != 0 {
        return Err(RpcError::invalid_params(format!(
            "'{name}' must contain an even number of hex digits"
        )));
    }
    let len = hex.len() / 2;
    if len > max_len {
        return Err(RpcError::invalid_params(format!(
            "'{name}' is too large: {len} > {max_len} bytes"
        )));
    }
    Vec::from_hex(hex).map_err(|e| RpcError::invalid_params(format!("invalid '{name}': {e}")))
}

fn lock_conn<T>(conn: &SharedConn<T>) -> Result<std::sync::MutexGuard<'_, Option<T>>, RpcError> {
    conn.lock()
        .map_err(|_| RpcError::new("connection-error", "Connection lock poisoned"))
}
