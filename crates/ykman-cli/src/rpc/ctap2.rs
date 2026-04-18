use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use yubikit::cbor::Value as CborValue;
use yubikit::core::Connection;
use yubikit::ctap::CtapSession;
use yubikit::ctap2::{
    BioEnrollment, ClientPin, Config, CredentialManagement, Ctap2Error, Ctap2Session, CtapStatus,
    Info, Permissions, PinProtocol, PublicKeyCredentialDescriptor,
};
use yubikit::device::{ReinsertStatus, YubiKeyDevice};
use yubikit::smartcard::ScpKeyParams;
use yubikit::transport::ctaphid::HidFidoConnection;
use yubikit::transport::pcsc::PcscSmartCardConnection;

use super::connection::SharedConn;
use super::error::{RpcError, RpcResponse};
use super::rpc::{RpcNode, SignalFn};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn handle_pin_error<E: std::error::Error + Send + Sync + 'static>(
    e: &Ctap2Error<E>,
    retries: u32,
) -> RpcError {
    if let Ctap2Error::StatusError(status) = e {
        match status {
            CtapStatus::PinInvalid | CtapStatus::PinBlocked | CtapStatus::PinAuthBlocked => {
                return RpcError::with_body(
                    "pin-validation",
                    "Authentication is required",
                    json!({
                        "retries": retries,
                        "auth_blocked": *status == CtapStatus::PinAuthBlocked,
                    }),
                );
            }
            CtapStatus::PinPolicyViolation => return RpcError::pin_complexity(),
            CtapStatus::UserActionTimeout => return RpcError::timeout(),
            CtapStatus::PinAuthInvalid => return RpcError::auth_required(),
            _ => {}
        }
    }
    RpcError::new("device-error", format!("{e}"))
}

fn cbor_to_json(v: &CborValue) -> Value {
    match v {
        CborValue::Int(n) => json!(*n),
        CborValue::Text(s) => json!(s),
        CborValue::Bool(b) => json!(*b),
        CborValue::Bytes(b) => json!(hex::encode(b)),
        CborValue::Array(arr) => Value::Array(arr.iter().map(cbor_to_json).collect()),
        CborValue::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    CborValue::Text(s) => s.clone(),
                    CborValue::Int(n) => n.to_string(),
                    _ => format!("{k:?}"),
                };
                map.insert(key, cbor_to_json(v));
            }
            Value::Object(map)
        }
    }
}

fn info_to_json(info: &Info) -> Value {
    let algorithms: Vec<Value> = info
        .algorithms
        .iter()
        .map(|alg| json!({"type": alg.type_, "alg": alg.alg}))
        .collect();

    let certifications: serde_json::Map<String, Value> = info
        .certifications
        .iter()
        .map(|(k, v)| (k.clone(), cbor_to_json(v)))
        .collect();

    json!({
        "versions": info.versions,
        "extensions": info.extensions,
        "aaguid": hex::encode(info.aaguid.as_bytes()),
        "options": info.options,
        "max_msg_size": info.max_msg_size,
        "pin_uv_protocols": info.pin_uv_protocols,
        "max_creds_in_list": info.max_creds_in_list,
        "max_cred_id_length": info.max_cred_id_length,
        "transports": info.transports,
        "algorithms": algorithms,
        "max_large_blob": info.max_large_blob,
        "force_pin_change": info.force_pin_change,
        "min_pin_length": info.min_pin_length,
        "firmware_version": info.firmware_version,
        "max_cred_blob_length": info.max_cred_blob_length,
        "max_rpids_for_min_pin": info.max_rpids_for_min_pin,
        "preferred_platform_uv_attempts": info.preferred_platform_uv_attempts,
        "uv_modality": info.uv_modality,
        "certifications": certifications,
        "remaining_disc_creds": info.remaining_disc_creds,
        "vendor_prototype_config_commands": info.vendor_prototype_config_commands,
        "attestation_formats": info.attestation_formats,
        "uv_count_since_pin": info.uv_count_since_pin,
        "long_touch_for_reset": info.long_touch_for_reset,
        "transports_for_reset": info.transports_for_reset,
    })
}

// ---------------------------------------------------------------------------
// Transport-generic dispatch macros
// ---------------------------------------------------------------------------

macro_rules! with_ctap2 {
    ($fido_conn:expr, |$session:ident| $body:expr) => {
        match $fido_conn {
            FidoConn::Hid { conn, .. } => match conn.take() {
                None => Err(RpcError::new("connection-error", "Connection in use")),
                Some(c) => match CtapSession::new_fido(c) {
                    Err((e, c)) => {
                        *conn = Some(c);
                        Err(RpcError::new("device-error", format!("{e}")))
                    }
                    Ok(ctap) => match Ctap2Session::new(ctap) {
                        Err((e, _)) => Err(RpcError::new("device-error", format!("{e}"))),
                        Ok($session) => {
                            let (result, returned_c) = { $body };
                            *conn = Some(returned_c);
                            result
                        }
                    },
                },
            },
            FidoConn::SmartCard {
                conn, scp_params, ..
            } => match conn.take() {
                None => Err(RpcError::new("connection-error", "Connection in use")),
                Some(c) => {
                    let ctap_result = if let Some(params) = scp_params {
                        CtapSession::new_with_scp(c, params)
                    } else {
                        CtapSession::new(c)
                    };
                    match ctap_result {
                        Err((e, c)) => {
                            *conn = Some(c);
                            Err(RpcError::new("device-error", format!("{e}")))
                        }
                        Ok(ctap) => match Ctap2Session::new(ctap) {
                            Err((e, _)) => Err(RpcError::new("device-error", format!("{e}"))),
                            Ok($session) => {
                                let (result, returned_c) = { $body };
                                *conn = Some(returned_c);
                                result
                            }
                        },
                    }
                }
            },
        }
    };
}

macro_rules! with_ctap2_dev {
    ($device_type:expr, |$session:ident| $body:expr) => {
        match $device_type {
            FidoDeviceType::Hid { conn, shared } => {
                match conn.take().or_else(|| shared.lock().unwrap().take()) {
                    None => Err(RpcError::new("connection-error", "Connection in use")),
                    Some(c) => match CtapSession::new_fido(c) {
                        Err((e, c)) => {
                            *conn = Some(c);
                            Err(RpcError::new("device-error", format!("{e}")))
                        }
                        Ok(ctap) => match Ctap2Session::new(ctap) {
                            Err((e, _)) => Err(RpcError::new("device-error", format!("{e}"))),
                            Ok($session) => {
                                let (result, returned_c) = { $body };
                                *conn = Some(returned_c);
                                result
                            }
                        },
                    },
                }
            }
            FidoDeviceType::SmartCard {
                conn,
                shared,
                scp_params,
            } => match conn.take().or_else(|| shared.lock().unwrap().take()) {
                None => Err(RpcError::new("connection-error", "Connection in use")),
                Some(c) => {
                    let ctap_result = if let Some(params) = scp_params {
                        CtapSession::new_with_scp(c, params)
                    } else {
                        CtapSession::new(c)
                    };
                    match ctap_result {
                        Err((e, c)) => {
                            *conn = Some(c);
                            Err(RpcError::new("device-error", format!("{e}")))
                        }
                        Ok(ctap) => match Ctap2Session::new(ctap) {
                            Err((e, _)) => Err(RpcError::new("device-error", format!("{e}"))),
                            Ok($session) => {
                                let (result, returned_c) = { $body };
                                *conn = Some(returned_c);
                                result
                            }
                        },
                    }
                }
            },
        }
    };
}

// ---------------------------------------------------------------------------
// Ctap2Node
// ---------------------------------------------------------------------------

pub struct Ctap2Node {
    device_type: FidoDeviceType,
    yk_device: YubiKeyDevice,
    pin_token: Option<Vec<u8>>,
    pin_protocol: Option<PinProtocol>,
    cached_data: Value,
}

enum FidoDeviceType {
    Hid {
        conn: Option<HidFidoConnection>,
        shared: SharedConn<HidFidoConnection>,
    },
    SmartCard {
        conn: Option<PcscSmartCardConnection>,
        shared: SharedConn<PcscSmartCardConnection>,
        scp_params: Option<ScpKeyParams>,
    },
}

impl Ctap2Node {
    pub fn new_hid(
        conn: HidFidoConnection,
        shared: SharedConn<HidFidoConnection>,
        device: YubiKeyDevice,
    ) -> Result<Self, RpcError> {
        let mut node = Self {
            device_type: FidoDeviceType::Hid {
                conn: Some(conn),
                shared,
            },
            yk_device: device,
            pin_token: None,
            pin_protocol: None,
            cached_data: json!({}),
        };
        node.refresh_data();
        Ok(node)
    }

    pub fn new_smartcard(
        conn: PcscSmartCardConnection,
        shared: SharedConn<PcscSmartCardConnection>,
        device: YubiKeyDevice,
        scp_params: Option<ScpKeyParams>,
    ) -> Result<Self, RpcError> {
        let mut node = Self {
            device_type: FidoDeviceType::SmartCard {
                conn: Some(conn),
                shared,
                scp_params,
            },
            yk_device: device,
            pin_token: None,
            pin_protocol: None,
            cached_data: json!({}),
        };
        node.refresh_data();
        Ok(node)
    }

    fn refresh_data(&mut self) {
        let data: Result<Value, RpcError> = with_ctap2_dev!(&mut self.device_type, |ctap2| {
            let info = ctap2.info().clone();
            let mut data = json!({"info": info_to_json(&info)});

            let needs_pin = info.options.get("clientPin") == Some(&true);
            let has_bio = info.options.get("bioEnroll") == Some(&true);

            if needs_pin {
                match ClientPin::new(ctap2) {
                    Err((e, s)) => {
                        let conn = s.into_session().into_connection();
                        (Err(RpcError::new("device-error", format!("{e}"))), conn)
                    }
                    Ok(mut client_pin) => {
                        let (pin_retries, power_cycle) =
                            client_pin.get_pin_retries().unwrap_or((0, None));
                        data["pin_retries"] = json!(pin_retries);
                        data["power_cycle"] = json!(power_cycle);

                        if has_bio {
                            let uv_retries = client_pin.get_uv_retries().unwrap_or(0);
                            data["uv_retries"] = json!(uv_retries);
                        }
                        let conn = client_pin.into_session().into_session().into_connection();
                        (Ok(data), conn)
                    }
                }
            } else {
                let conn = ctap2.into_session().into_connection();
                (Ok(data), conn)
            }
        });
        if let Ok(d) = data {
            self.cached_data = d;
        }
    }

    fn do_reset(&mut self, signal: SignalFn, cancel: &AtomicBool) -> Result<RpcResponse, RpcError> {
        match &mut self.device_type {
            FidoDeviceType::Hid { conn, .. } => {
                let _ = conn.take();

                self.yk_device
                    .reinsert(
                        &|status| match status {
                            ReinsertStatus::Remove => {
                                signal("reset", json!({"state": "remove"}));
                            }
                            ReinsertStatus::Reinsert => {
                                signal("reset", json!({"state": "insert"}));
                            }
                        },
                        &|| cancel.load(Ordering::Relaxed),
                    )
                    .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

                let new_conn = self
                    .yk_device
                    .open_fido()
                    .map_err(|e| RpcError::new("connection-error", format!("{e}")))?;

                let ctap = CtapSession::new_fido(new_conn)
                    .map_err(|(e, _)| RpcError::new("device-error", format!("{e}")))?;
                let mut ctap2 = Ctap2Session::new(ctap)
                    .map_err(|(e, _)| RpcError::new("device-error", format!("{e}")))?;

                signal("reset", json!({"state": "touch"}));
                let is_cancelled = || cancel.load(Ordering::Relaxed);
                let result = ctap2
                    .reset(Some(&mut |_| {}), Some(&is_cancelled))
                    .map_err(|e| {
                        if matches!(&e, Ctap2Error::StatusError(CtapStatus::UserActionTimeout)) {
                            return RpcError::timeout();
                        }
                        RpcError::new("device-error", format!("{e}"))
                    });

                if let FidoDeviceType::Hid { conn, .. } = &mut self.device_type {
                    *conn = Some(ctap2.into_session().into_connection());
                }

                result?;
            }
            FidoDeviceType::SmartCard { conn, .. } => {
                let c = conn
                    .take()
                    .ok_or_else(|| RpcError::new("connection-error", "Connection in use"))?;

                // For SmartCard reset, we just open a session and call reset
                let ctap = CtapSession::new(c)
                    .map_err(|(e, _)| RpcError::new("device-error", format!("{e}")))?;
                let mut ctap2 = Ctap2Session::new(ctap)
                    .map_err(|(e, _)| RpcError::new("device-error", format!("{e}")))?;

                signal("reset", json!({"state": "touch"}));
                let is_cancelled = || cancel.load(Ordering::Relaxed);
                let result = ctap2
                    .reset(Some(&mut |_| {}), Some(&is_cancelled))
                    .map_err(|e| {
                        if matches!(&e, Ctap2Error::StatusError(CtapStatus::UserActionTimeout)) {
                            return RpcError::timeout();
                        }
                        RpcError::new("device-error", format!("{e}"))
                    });

                if let FidoDeviceType::SmartCard { conn, .. } = &mut self.device_type {
                    *conn = Some(ctap2.into_session().into_connection());
                }

                result?;
            }
        }

        self.pin_token = None;
        Ok(RpcResponse::with_flags(
            json!({}),
            vec!["device_info", "device_closed"],
        ))
    }

    fn do_call_action(
        &mut self,
        action: &str,
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "unlock" => {
                let pin = params
                    .get("pin")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RpcError::invalid_params("Missing pin"))?
                    .to_string();

                let result: Result<(Vec<u8>, PinProtocol), RpcError> =
                    with_ctap2_dev!(&mut self.device_type, |ctap2| {
                        let info = ctap2.info().clone();

                        let mut permissions = Permissions::new(0);
                        let options = &info.options;
                        if options.get("credMgmt") == Some(&true)
                            || options.get("credentialMgmtPreview") == Some(&true)
                        {
                            permissions |= Permissions::CREDENTIAL_MGMT;
                        }
                        if options.contains_key("bioEnroll")
                            || options.contains_key("userVerificationMgmtPreview")
                        {
                            permissions |= Permissions::BIO_ENROLL;
                        }
                        if options.get("authnrCfg") == Some(&true) {
                            permissions |= Permissions::AUTHENTICATOR_CFG;
                        }

                        let perms = if permissions.bits() > 0 {
                            Some(permissions)
                        } else {
                            Some(Permissions::GET_ASSERTION)
                        };
                        let rpid = if permissions.bits() == 0 {
                            Some("ykman.example.com")
                        } else {
                            None
                        };

                        match ClientPin::new(ctap2) {
                            Err((e, s)) => {
                                let conn = s.into_session().into_connection();
                                (Err(RpcError::new("device-error", format!("{e}"))), conn)
                            }
                            Ok(mut client_pin) => {
                                match client_pin.get_pin_token(&pin, perms, rpid) {
                                    Ok(token) => {
                                        let protocol = client_pin.protocol();
                                        let conn = client_pin
                                            .into_session()
                                            .into_session()
                                            .into_connection();
                                        (Ok((token, protocol)), conn)
                                    }
                                    Err(e) => {
                                        let retries =
                                            client_pin.get_pin_retries().unwrap_or((0, None)).0;
                                        let conn = client_pin
                                            .into_session()
                                            .into_session()
                                            .into_connection();
                                        (Err(handle_pin_error(&e, retries)), conn)
                                    }
                                }
                            }
                        }
                    });
                result.map(|(token, protocol)| {
                    self.pin_token = Some(token);
                    self.pin_protocol = Some(protocol);
                    RpcResponse::new(json!({}))
                })
            }
            "set_pin" => {
                let new_pin = params
                    .get("new_pin")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RpcError::invalid_params("Missing new_pin"))?
                    .to_string();
                let pin = params
                    .get("pin")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                with_ctap2_dev!(&mut self.device_type, |ctap2| {
                    let has_pin = ctap2.info().options.get("clientPin") == Some(&true);
                    match ClientPin::new(ctap2) {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut client_pin) => {
                            if has_pin && pin.is_none() {
                                let conn =
                                    client_pin.into_session().into_session().into_connection();
                                (Err(RpcError::invalid_params("Missing pin")), conn)
                            } else {
                                let result = if has_pin {
                                    client_pin.change_pin(pin.as_deref().unwrap(), &new_pin)
                                } else {
                                    client_pin.set_pin(&new_pin)
                                };
                                match result {
                                    Ok(()) => {
                                        let conn = client_pin
                                            .into_session()
                                            .into_session()
                                            .into_connection();
                                        (Ok(()), conn)
                                    }
                                    Err(e) => {
                                        let retries =
                                            client_pin.get_pin_retries().unwrap_or((0, None)).0;
                                        let conn = client_pin
                                            .into_session()
                                            .into_session()
                                            .into_connection();
                                        (Err(handle_pin_error(&e, retries)), conn)
                                    }
                                }
                            }
                        }
                    }
                })?;
                self.pin_token = None;
                self.refresh_data();
                Ok(RpcResponse::with_flags(json!({}), vec!["device_info"]))
            }
            "enable_ep_attestation" => {
                self.require_pin_if_needed()?;
                let token = self.pin_token.clone();
                let protocol = self.pin_protocol;
                with_ctap2_dev!(&mut self.device_type, |session| {
                    let config_result = if let (Some(token), Some(protocol)) = (token, protocol) {
                        Config::new(session, protocol, token)
                    } else {
                        Config::new_unauthenticated(session)
                    };
                    match config_result {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut config) => {
                            let result = config
                                .enable_enterprise_attestation()
                                .map_err(|e| RpcError::new("device-error", format!("{e}")));
                            let conn = config.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;
                Ok(RpcResponse::new(json!({})))
            }
            "toggle_always_uv" => {
                self.require_pin_if_needed()?;
                let token = self.pin_token.clone();
                let protocol = self.pin_protocol;
                with_ctap2_dev!(&mut self.device_type, |session| {
                    let config_result = if let (Some(token), Some(protocol)) = (token, protocol) {
                        Config::new(session, protocol, token)
                    } else {
                        Config::new_unauthenticated(session)
                    };
                    match config_result {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut config) => {
                            let result = config
                                .toggle_always_uv()
                                .map_err(|e| RpcError::new("device-error", format!("{e}")));
                            let conn = config.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;
                Ok(RpcResponse::new(json!({})))
            }
            "set_min_pin_length" => {
                let min_length = params
                    .get("min_pin_length")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| RpcError::invalid_params("Missing min_pin_length"))?
                    as u32;
                let rp_ids: Option<Vec<String>> =
                    params.get("rp_ids").and_then(|v| v.as_array()).map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    });
                let force_change = params
                    .get("force_change_pin")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                self.require_pin_if_needed()?;
                let token = self.pin_token.clone();
                let protocol = self.pin_protocol;
                with_ctap2_dev!(&mut self.device_type, |session| {
                    let config_result = if let (Some(token), Some(protocol)) = (token, protocol) {
                        Config::new(session, protocol, token)
                    } else {
                        Config::new_unauthenticated(session)
                    };
                    match config_result {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut config) => {
                            let result = config
                                .set_min_pin_length(
                                    Some(min_length),
                                    rp_ids.as_deref(),
                                    force_change,
                                )
                                .map_err(|e| RpcError::new("device-error", format!("{e}")));
                            let conn = config.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;
                Ok(RpcResponse::new(json!({})))
            }
            "force_pin_change" => {
                self.require_pin_if_needed()?;
                let token = self.pin_token.clone();
                let protocol = self.pin_protocol;
                with_ctap2_dev!(&mut self.device_type, |session| {
                    let config_result = if let (Some(token), Some(protocol)) = (token, protocol) {
                        Config::new(session, protocol, token)
                    } else {
                        Config::new_unauthenticated(session)
                    };
                    match config_result {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut config) => {
                            let result = config
                                .set_min_pin_length(None, None, true)
                                .map_err(|e| RpcError::new("device-error", format!("{e}")));
                            let conn = config.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;
                Ok(RpcResponse::new(json!({})))
            }
            "reset" => self.do_reset(signal, cancel),
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn require_pin_if_needed(&self) -> Result<(), RpcError> {
        let has_pin = self
            .cached_data
            .get("info")
            .and_then(|i| i.get("options"))
            .and_then(|o| o.get("clientPin"))
            == Some(&json!(true));
        if has_pin && self.pin_token.is_none() {
            return Err(RpcError::auth_required());
        }
        Ok(())
    }

    fn do_create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        match name {
            "credentials" => {
                let token = self
                    .pin_token
                    .as_ref()
                    .ok_or_else(RpcError::auth_required)?
                    .clone();
                let protocol = self.pin_protocol.ok_or_else(RpcError::auth_required)?;

                match &mut self.device_type {
                    FidoDeviceType::Hid { conn, shared } => {
                        let c = conn
                            .take()
                            .or_else(|| shared.lock().unwrap().take())
                            .ok_or_else(|| {
                                RpcError::new("connection-error", "Connection in use")
                            })?;
                        Ok(Box::new(CredentialsRpsNode::new_hid(
                            c,
                            shared.clone(),
                            token,
                            protocol,
                        )?))
                    }
                    FidoDeviceType::SmartCard {
                        conn,
                        shared,
                        scp_params,
                    } => {
                        let c = conn
                            .take()
                            .or_else(|| shared.lock().unwrap().take())
                            .ok_or_else(|| {
                                RpcError::new("connection-error", "Connection in use")
                            })?;
                        Ok(Box::new(CredentialsRpsNode::new_smartcard(
                            c,
                            shared.clone(),
                            token,
                            protocol,
                            scp_params.clone(),
                        )?))
                    }
                }
            }
            "fingerprints" => {
                let token = self
                    .pin_token
                    .as_ref()
                    .ok_or_else(RpcError::auth_required)?
                    .clone();
                let protocol = self.pin_protocol.ok_or_else(RpcError::auth_required)?;

                match &mut self.device_type {
                    FidoDeviceType::Hid { conn, shared } => {
                        let c = conn
                            .take()
                            .or_else(|| shared.lock().unwrap().take())
                            .ok_or_else(|| {
                                RpcError::new("connection-error", "Connection in use")
                            })?;
                        Ok(Box::new(FingerprintsNode::new_hid(
                            c,
                            shared.clone(),
                            token,
                            protocol,
                        )?))
                    }
                    FidoDeviceType::SmartCard {
                        conn,
                        shared,
                        scp_params,
                    } => {
                        let c = conn
                            .take()
                            .or_else(|| shared.lock().unwrap().take())
                            .ok_or_else(|| {
                                RpcError::new("connection-error", "Connection in use")
                            })?;
                        Ok(Box::new(FingerprintsNode::new_smartcard(
                            c,
                            shared.clone(),
                            token,
                            protocol,
                            scp_params.clone(),
                        )?))
                    }
                }
            }
            _ => Err(RpcError::no_such_node(name)),
        }
    }
}

impl RpcNode for Ctap2Node {
    fn get_data(&self) -> Value {
        let mut data = self.cached_data.clone();
        data["unlocked"] = json!(self.pin_token.is_some());
        data
    }

    fn list_actions(&self) -> Vec<&'static str> {
        let mut actions = vec!["reset"];
        let options = self.cached_data.get("info").and_then(|i| i.get("options"));
        if options.and_then(|o| o.get("clientPin")) == Some(&json!(true)) {
            actions.push("unlock");
        }
        actions.push("set_pin");
        if options.and_then(|o| o.get("authnrCfg")) == Some(&json!(true)) {
            actions.push("enable_ep_attestation");
            actions.push("toggle_always_uv");
            if options.and_then(|o| o.get("setMinPINLength")) == Some(&json!(true)) {
                actions.push("set_min_pin_length");
                actions.push("force_pin_change");
            }
        }
        actions
    }

    fn list_children(&mut self) -> BTreeMap<String, Value> {
        let mut children = BTreeMap::new();
        let options = self.cached_data.get("info").and_then(|i| i.get("options"));
        let has_cred_mgmt = options
            .and_then(|o| o.get("credMgmt").or_else(|| o.get("credentialMgmtPreview")))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if has_cred_mgmt {
            children.insert("credentials".to_string(), json!({}));
        }
        let has_bio = options
            .map(|o| o.get("bioEnroll").is_some())
            .unwrap_or(false);
        if has_bio {
            children.insert("fingerprints".to_string(), json!({}));
        }
        children
    }

    fn call_action(
        &mut self,
        action: &str,
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        self.do_call_action(action, params, signal, cancel)
    }

    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        self.do_create_child(name)
    }

    fn close(&mut self) {
        match &mut self.device_type {
            FidoDeviceType::Hid { conn, shared } => {
                if let Some(c) = conn.take() {
                    *shared.lock().unwrap() = Some(c);
                }
            }
            FidoDeviceType::SmartCard { conn, shared, .. } => {
                if let Some(c) = conn.take() {
                    *shared.lock().unwrap() = Some(c);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FidoConn — shared connection wrapper for child nodes
// ---------------------------------------------------------------------------

enum FidoConn {
    Hid {
        conn: Option<HidFidoConnection>,
        shared: SharedConn<HidFidoConnection>,
    },
    SmartCard {
        conn: Option<PcscSmartCardConnection>,
        shared: SharedConn<PcscSmartCardConnection>,
        scp_params: Option<ScpKeyParams>,
    },
}

impl FidoConn {
    fn close(&mut self) {
        match self {
            FidoConn::Hid { conn, shared } => {
                if let Some(c) = conn.take() {
                    *shared.lock().unwrap() = Some(c);
                }
            }
            FidoConn::SmartCard { conn, shared, .. } => {
                if let Some(c) = conn.take() {
                    *shared.lock().unwrap() = Some(c);
                }
            }
        }
    }
}

impl Drop for FidoConn {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// CredentialsRpsNode — lists RPs with stored credentials
// ---------------------------------------------------------------------------

struct CredentialsRpsNode {
    fido_conn: FidoConn,
    token: Vec<u8>,
    protocol: PinProtocol,
    rps: BTreeMap<String, Value>,
    rp_hashes: BTreeMap<String, Vec<u8>>,
}

impl CredentialsRpsNode {
    fn new_hid(
        conn: HidFidoConnection,
        shared: SharedConn<HidFidoConnection>,
        token: Vec<u8>,
        protocol: PinProtocol,
    ) -> Result<Self, RpcError> {
        let mut node = Self {
            fido_conn: FidoConn::Hid {
                conn: Some(conn),
                shared,
            },
            token,
            protocol,
            rps: BTreeMap::new(),
            rp_hashes: BTreeMap::new(),
        };
        node.refresh()?;
        Ok(node)
    }

    fn new_smartcard(
        conn: PcscSmartCardConnection,
        shared: SharedConn<PcscSmartCardConnection>,
        token: Vec<u8>,
        protocol: PinProtocol,
        scp_params: Option<ScpKeyParams>,
    ) -> Result<Self, RpcError> {
        let mut node = Self {
            fido_conn: FidoConn::SmartCard {
                conn: Some(conn),
                shared,
                scp_params,
            },
            token,
            protocol,
            rps: BTreeMap::new(),
            rp_hashes: BTreeMap::new(),
        };
        node.refresh()?;
        Ok(node)
    }

    fn refresh(&mut self) -> Result<(), RpcError> {
        self.rps.clear();
        self.rp_hashes.clear();

        let token = self.token.clone();
        let protocol = self.protocol;

        let (rp_map, hash_map): (BTreeMap<String, Value>, BTreeMap<String, Vec<u8>>) =
            with_ctap2!(&mut self.fido_conn, |ctap2| {
                match CredentialManagement::new(ctap2, protocol, token) {
                    Err((e, s)) => {
                        let conn = s.into_session().into_connection();
                        (Err(RpcError::new("device-error", format!("{e}"))), conn)
                    }
                    Ok(mut credman) => {
                        let result = (|| -> Result<_, RpcError> {
                            let (existing, _) = credman
                                .get_metadata()
                                .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

                            if existing == 0 {
                                return Ok((BTreeMap::new(), BTreeMap::new()));
                            }

                            let rps = credman
                                .enumerate_rps()
                                .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

                            let mut rp_map = BTreeMap::new();
                            let mut hash_map = BTreeMap::new();
                            for rp_info in &rps {
                                let rp_id = &rp_info.rp.id;
                                rp_map.insert(rp_id.clone(), json!({"rp_id": rp_id}));
                                hash_map.insert(rp_id.clone(), rp_info.rp_id_hash.clone());
                            }
                            Ok((rp_map, hash_map))
                        })();
                        let conn = credman.into_session().into_session().into_connection();
                        (result, conn)
                    }
                }
            })?;

        self.rps = rp_map;
        self.rp_hashes = hash_map;
        Ok(())
    }
}

impl RpcNode for CredentialsRpsNode {
    fn list_children(&mut self) -> BTreeMap<String, Value> {
        self.rps.clone()
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
        if !self.rps.contains_key(name) {
            return Err(RpcError::no_such_node(name));
        }

        let rp_id_hash = self
            .rp_hashes
            .get(name)
            .ok_or_else(|| RpcError::no_such_node(name))?
            .clone();

        let token = self.token.clone();
        let protocol = self.protocol;

        let creds: BTreeMap<String, Value> = with_ctap2!(&mut self.fido_conn, |ctap2| {
            match CredentialManagement::new(ctap2, protocol, token) {
                Err((e, s)) => {
                    let conn = s.into_session().into_connection();
                    (Err(RpcError::new("device-error", format!("{e}"))), conn)
                }
                Ok(mut credman) => {
                    let result = (|| -> Result<_, RpcError> {
                        let cred_list = credman
                            .enumerate_creds(&rp_id_hash)
                            .map_err(|e| RpcError::new("device-error", format!("{e}")))?;

                        let mut creds = BTreeMap::new();
                        for cred_info in &cred_list {
                            let id_hex = hex::encode(&cred_info.credential_id.id);
                            creds.insert(
                                id_hex.clone(),
                                json!({
                                    "user_name": cred_info.user.name,
                                    "display_name": cred_info.user.display_name,
                                    "user_id": hex::encode(&cred_info.user.id),
                                    "credential_id": {
                                        "id": id_hex,
                                        "type": "public-key",
                                    },
                                }),
                            );
                        }
                        Ok(creds)
                    })();
                    let conn = credman.into_session().into_session().into_connection();
                    (result, conn)
                }
            }
        })?;

        let fido_conn = std::mem::replace(
            &mut self.fido_conn,
            FidoConn::Hid {
                conn: None,
                shared: Arc::new(Mutex::new(None)),
            },
        );

        Ok(Box::new(CredentialsRpNode {
            fido_conn,
            token: self.token.clone(),
            protocol: self.protocol,
            creds,
        }))
    }

    fn close(&mut self) {
        self.fido_conn.close();
    }
}

// ---------------------------------------------------------------------------
// CredentialsRpNode — lists credentials for a single RP
// ---------------------------------------------------------------------------

struct CredentialsRpNode {
    fido_conn: FidoConn,
    token: Vec<u8>,
    protocol: PinProtocol,
    creds: BTreeMap<String, Value>,
}

impl RpcNode for CredentialsRpNode {
    fn list_children(&mut self) -> BTreeMap<String, Value> {
        self.creds.clone()
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
        if !self.creds.contains_key(name) {
            return Err(RpcError::no_such_node(name));
        }

        let cred_data = self.creds.get(name).unwrap().clone();
        let fido_conn = std::mem::replace(
            &mut self.fido_conn,
            FidoConn::Hid {
                conn: None,
                shared: Arc::new(Mutex::new(None)),
            },
        );

        Ok(Box::new(CredentialNode {
            fido_conn,
            token: self.token.clone(),
            protocol: self.protocol,
            cred_id_hex: name.to_string(),
            data: cred_data,
        }))
    }

    fn close(&mut self) {
        self.fido_conn.close();
    }
}

// ---------------------------------------------------------------------------
// CredentialNode — single credential with delete action
// ---------------------------------------------------------------------------

struct CredentialNode {
    fido_conn: FidoConn,
    token: Vec<u8>,
    protocol: PinProtocol,
    cred_id_hex: String,
    data: Value,
}

impl RpcNode for CredentialNode {
    fn get_data(&self) -> Value {
        self.data.clone()
    }

    fn list_actions(&self) -> Vec<&'static str> {
        vec!["delete"]
    }

    fn call_action(
        &mut self,
        action: &str,
        _params: Value,
        _signal: SignalFn,
        _cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "delete" => {
                let cred_id_bytes = hex::decode(&self.cred_id_hex)
                    .map_err(|_| RpcError::invalid_params("Invalid credential ID"))?;
                let token = self.token.clone();
                let protocol = self.protocol;

                with_ctap2!(&mut self.fido_conn, |ctap2| {
                    match CredentialManagement::new(ctap2, protocol, token) {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut credman) => {
                            let cred_id = PublicKeyCredentialDescriptor {
                                type_: yubikit::webauthn::PublicKeyCredentialType::PublicKey,
                                id: cred_id_bytes.clone(),
                                transports: None,
                            };
                            let result = credman
                                .delete_cred(&cred_id)
                                .map_err(|e| RpcError::new("device-error", format!("{e}")));
                            let conn = credman.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;
                Ok(RpcResponse::new(json!({})))
            }
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn close(&mut self) {
        self.fido_conn.close();
    }
}

// ---------------------------------------------------------------------------
// FingerprintsNode — lists bio enrollments
// ---------------------------------------------------------------------------

type SharedTemplates = Arc<Mutex<BTreeMap<String, Option<String>>>>;

struct FingerprintsNode {
    fido_conn: FidoConn,
    token: Vec<u8>,
    protocol: PinProtocol,
    templates: SharedTemplates,
}

impl FingerprintsNode {
    fn new_hid(
        conn: HidFidoConnection,
        shared: SharedConn<HidFidoConnection>,
        token: Vec<u8>,
        protocol: PinProtocol,
    ) -> Result<Self, RpcError> {
        let mut node = Self {
            fido_conn: FidoConn::Hid {
                conn: Some(conn),
                shared,
            },
            token,
            protocol,
            templates: Arc::new(Mutex::new(BTreeMap::new())),
        };
        node.refresh()?;
        Ok(node)
    }

    fn new_smartcard(
        conn: PcscSmartCardConnection,
        shared: SharedConn<PcscSmartCardConnection>,
        token: Vec<u8>,
        protocol: PinProtocol,
        scp_params: Option<ScpKeyParams>,
    ) -> Result<Self, RpcError> {
        let mut node = Self {
            fido_conn: FidoConn::SmartCard {
                conn: Some(conn),
                shared,
                scp_params,
            },
            token,
            protocol,
            templates: Arc::new(Mutex::new(BTreeMap::new())),
        };
        node.refresh()?;
        Ok(node)
    }

    fn refresh(&mut self) -> Result<(), RpcError> {
        self.templates.lock().unwrap().clear();
        let token = self.token.clone();
        let protocol = self.protocol;

        let templates: BTreeMap<String, Option<String>> =
            with_ctap2!(&mut self.fido_conn, |ctap2| {
                match BioEnrollment::new(ctap2, protocol, token) {
                    Err((e, s)) => {
                        let conn = s.into_session().into_connection();
                        (Err(RpcError::new("device-error", format!("{e}"))), conn)
                    }
                    Ok(mut bio) => {
                        let mut templates = BTreeMap::new();
                        let result = match bio.enumerate_enrollments() {
                            Ok(enrollments) => {
                                for fp in &enrollments {
                                    let name = fp
                                        .name
                                        .as_deref()
                                        .filter(|n| !n.is_empty())
                                        .map(String::from);
                                    templates.insert(hex::encode(&fp.id), name);
                                }
                                Ok(templates)
                            }
                            Err(Ctap2Error::StatusError(CtapStatus::InvalidOption)) => {
                                Ok(templates)
                            }
                            Err(e) => Err(RpcError::new("device-error", format!("{e}"))),
                        };
                        let conn = bio.into_session().into_session().into_connection();
                        (result, conn)
                    }
                }
            })?;

        *self.templates.lock().unwrap() = templates;
        Ok(())
    }
}

impl RpcNode for FingerprintsNode {
    fn list_children(&mut self) -> BTreeMap<String, Value> {
        self.templates
            .lock()
            .unwrap()
            .iter()
            .map(|(id, name)| (id.clone(), json!({"name": name})))
            .collect()
    }

    fn list_actions(&self) -> Vec<&'static str> {
        vec!["add"]
    }

    fn call_action(
        &mut self,
        action: &str,
        params: Value,
        signal: SignalFn,
        cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "add" => {
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let token = self.token.clone();
                let protocol = self.protocol;

                let result: (String, Option<String>) = with_ctap2!(&mut self.fido_conn, |ctap2| {
                    match BioEnrollment::new(ctap2, protocol, token) {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut bio) => {
                            let is_cancelled = || cancel.load(Ordering::Relaxed);
                            let result = enroll_fingerprint(&mut bio, &name, signal, &is_cancelled);
                            let conn = bio.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;

                let (template_id_hex, fp_name) = result;
                self.templates
                    .lock()
                    .unwrap()
                    .insert(template_id_hex.clone(), fp_name.clone());

                Ok(RpcResponse::new(json!({
                    "template_id": template_id_hex,
                    "name": fp_name,
                })))
            }
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn create_child(&mut self, name: &str) -> Result<Box<dyn RpcNode>, RpcError> {
        let templates = self.templates.lock().unwrap();
        if !templates.contains_key(name) {
            return Err(RpcError::no_such_node(name));
        }

        let template_id_hex = name.to_string();
        let fp_name = templates.get(name).unwrap().clone();
        drop(templates);

        let fido_conn = std::mem::replace(
            &mut self.fido_conn,
            FidoConn::Hid {
                conn: None,
                shared: Arc::new(Mutex::new(None)),
            },
        );

        Ok(Box::new(FingerprintNode {
            fido_conn,
            token: self.token.clone(),
            protocol: self.protocol,
            template_id_hex,
            name: fp_name,
            parent_templates: self.templates.clone(),
        }))
    }

    fn close(&mut self) {
        self.fido_conn.close();
    }
}

// ---------------------------------------------------------------------------
// FingerprintNode — single fingerprint with rename/delete
// ---------------------------------------------------------------------------

struct FingerprintNode {
    fido_conn: FidoConn,
    token: Vec<u8>,
    protocol: PinProtocol,
    template_id_hex: String,
    name: Option<String>,
    parent_templates: SharedTemplates,
}

impl RpcNode for FingerprintNode {
    fn get_data(&self) -> Value {
        json!({
            "template_id": self.template_id_hex,
            "name": self.name,
        })
    }

    fn list_actions(&self) -> Vec<&'static str> {
        vec!["rename", "delete"]
    }

    fn call_action(
        &mut self,
        action: &str,
        params: Value,
        _signal: SignalFn,
        _cancel: &AtomicBool,
    ) -> Result<RpcResponse, RpcError> {
        match action {
            "rename" => {
                let new_name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RpcError::invalid_params("Missing name"))?
                    .to_string();

                let template_id = hex::decode(&self.template_id_hex)
                    .map_err(|_| RpcError::invalid_params("Invalid template ID"))?;
                let token = self.token.clone();
                let protocol = self.protocol;

                with_ctap2!(&mut self.fido_conn, |ctap2| {
                    match BioEnrollment::new(ctap2, protocol, token) {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut bio) => {
                            let result = bio
                                .set_name(&template_id, &new_name)
                                .map_err(|e| RpcError::new("device-error", format!("{e}")));
                            let conn = bio.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;
                self.name = Some(new_name.clone());
                self.parent_templates
                    .lock()
                    .unwrap()
                    .insert(self.template_id_hex.clone(), Some(new_name));
                Ok(RpcResponse::new(json!({})))
            }
            "delete" => {
                let template_id = hex::decode(&self.template_id_hex)
                    .map_err(|_| RpcError::invalid_params("Invalid template ID"))?;
                let token = self.token.clone();
                let protocol = self.protocol;

                with_ctap2!(&mut self.fido_conn, |ctap2| {
                    match BioEnrollment::new(ctap2, protocol, token) {
                        Err((e, s)) => {
                            let conn = s.into_session().into_connection();
                            (Err(RpcError::new("device-error", format!("{e}"))), conn)
                        }
                        Ok(mut bio) => {
                            let result = bio
                                .remove_enrollment(&template_id)
                                .map_err(|e| RpcError::new("device-error", format!("{e}")));
                            let conn = bio.into_session().into_session().into_connection();
                            (result, conn)
                        }
                    }
                })?;
                self.parent_templates
                    .lock()
                    .unwrap()
                    .remove(&self.template_id_hex);
                Ok(RpcResponse::new(json!({})))
            }
            _ => Err(RpcError::no_such_action(action)),
        }
    }

    fn close(&mut self) {
        self.fido_conn.close();
    }
}

// ---------------------------------------------------------------------------
// Bio enrollment helper
// ---------------------------------------------------------------------------

fn map_ctap_enroll_error<E: std::error::Error + Send + Sync + 'static>(
    e: Ctap2Error<E>,
) -> RpcError {
    if matches!(&e, Ctap2Error::StatusError(CtapStatus::UserActionTimeout)) {
        RpcError::timeout()
    } else {
        RpcError::new("device-error", format!("{e}"))
    }
}

fn enroll_fingerprint<C: Connection + 'static>(
    bio: &mut BioEnrollment<C>,
    name: &Option<String>,
    signal: SignalFn,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(String, Option<String>), RpcError> {
    let resp = bio
        .enroll_begin(None, Some(&mut |_| {}), Some(is_cancelled))
        .map_err(map_ctap_enroll_error)?;

    let template_id = resp.template_id;
    let status = resp.last_sample_status;
    let mut remaining = resp.remaining_samples;

    if status != 0 {
        signal("capture-error", json!({"code": status}));
    } else {
        signal("capture", json!({"remaining": remaining}));
    }

    while remaining > 0 {
        let resp = bio
            .enroll_capture_next(&template_id, None, Some(&mut |_| {}), Some(is_cancelled))
            .map_err(map_ctap_enroll_error)?;

        if resp.last_sample_status != 0 {
            signal("capture-error", json!({"code": resp.last_sample_status}));
        } else {
            signal("capture", json!({"remaining": resp.remaining_samples}));
        }
        remaining = resp.remaining_samples;
    }

    if let Some(n) = name {
        bio.set_name(&template_id, n)
            .map_err(|e| RpcError::new("device-error", format!("{e}")))?;
    }

    Ok((hex::encode(&template_id), name.clone()))
}
