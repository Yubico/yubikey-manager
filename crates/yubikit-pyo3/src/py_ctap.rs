use std::collections::BTreeMap;

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyList};
use yubikit::cbor;
use yubikit::ctap::CtapSession;
use yubikit::ctap2::{
    BioEnrollment, ClientPin, Config, CredentialManagement, Ctap2Error, Ctap2Session, Info,
    LargeBlobs, Permissions, PinProtocol,
};

use crate::py_bridge::{
    BoxedFidoConnection, BoxedSmartCardConnection, extract_fido_connection,
    extract_smartcard_connection, restore_fido_connection, restore_smartcard_connection,
};

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn ctap2_err<E: std::error::Error + Send + Sync + 'static>(e: Ctap2Error<E>) -> PyErr {
    match e {
        Ctap2Error::StatusError(status) => PyOSError::new_err(format!("CTAP2 error: {status}")),
        Ctap2Error::Transport(e) => PyOSError::new_err(e.to_string()),
        Ctap2Error::InvalidResponse(msg) => {
            PyValueError::new_err(format!("Invalid CTAP2 response: {msg}"))
        }
    }
}

fn ctap_err<E: std::error::Error + Send + Sync + 'static>(e: yubikit::ctap::CtapError<E>) -> PyErr {
    PyOSError::new_err(e.to_string())
}

// ---------------------------------------------------------------------------
// Keepalive / cancel helpers
// ---------------------------------------------------------------------------

fn make_keepalive_fn(on_keepalive: &Option<PyObject>) -> impl FnMut(u8) + '_ {
    move |status: u8| {
        if let Some(cb) = on_keepalive {
            Python::with_gil(|py| {
                let _ = cb.call1(py, (status,));
            });
        }
    }
}

fn make_cancel_fn(event: &Option<PyObject>) -> impl Fn() -> bool + '_ {
    move || {
        if let Some(evt) = event {
            Python::with_gil(|py| {
                evt.call_method0(py, "is_set")
                    .and_then(|v| v.extract::<bool>(py))
                    .unwrap_or(false)
            })
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Info → Python dict
// ---------------------------------------------------------------------------

fn info_to_py(py: Python<'_>, info: &Info) -> PyResult<PyObject> {
    let dict = PyDict::new(py);

    dict.set_item("versions", &info.versions)?;
    dict.set_item("extensions", &info.extensions)?;
    dict.set_item("aaguid", PyBytes::new(py, info.aaguid.as_bytes()))?;
    dict.set_item("options", options_to_py(py, &info.options)?)?;
    dict.set_item("max_msg_size", info.max_msg_size)?;
    dict.set_item("pin_uv_protocols", &info.pin_uv_protocols)?;
    dict.set_item("max_creds_in_list", info.max_creds_in_list)?;
    dict.set_item("max_cred_id_length", info.max_cred_id_length)?;
    dict.set_item("transports", &info.transports)?;
    dict.set_item("algorithms", algorithms_to_py(py, info)?)?;
    dict.set_item("max_large_blob", info.max_large_blob)?;
    dict.set_item("force_pin_change", info.force_pin_change)?;
    dict.set_item("min_pin_length", info.min_pin_length)?;
    dict.set_item("firmware_version", info.firmware_version)?;
    dict.set_item("max_cred_blob_length", info.max_cred_blob_length)?;
    dict.set_item("max_rpids_for_min_pin", info.max_rpids_for_min_pin)?;
    dict.set_item(
        "preferred_platform_uv_attempts",
        info.preferred_platform_uv_attempts,
    )?;
    dict.set_item("uv_modality", info.uv_modality)?;
    dict.set_item(
        "certifications",
        certifications_to_py(py, &info.certifications)?,
    )?;
    dict.set_item("remaining_disc_creds", info.remaining_disc_creds)?;
    dict.set_item(
        "vendor_prototype_config_commands",
        &info.vendor_prototype_config_commands,
    )?;
    dict.set_item("attestation_formats", &info.attestation_formats)?;
    dict.set_item("uv_count_since_pin", info.uv_count_since_pin)?;
    dict.set_item("long_touch_for_reset", info.long_touch_for_reset)?;
    dict.set_item(
        "enc_identifier",
        info.enc_identifier
            .as_ref()
            .map(|b| PyBytes::new(py, b).into_any()),
    )?;
    dict.set_item("transports_for_reset", &info.transports_for_reset)?;
    dict.set_item("pin_complexity_policy", info.pin_complexity_policy)?;
    dict.set_item(
        "pin_complexity_policy_url",
        info.pin_complexity_policy_url.as_deref(),
    )?;
    dict.set_item("max_pin_length", info.max_pin_length)?;
    dict.set_item(
        "enc_cred_store_state",
        info.enc_cred_store_state
            .as_ref()
            .map(|b| PyBytes::new(py, b).into_any()),
    )?;
    dict.set_item("config_commands", &info.config_commands)?;

    Ok(dict.into())
}

fn options_to_py(py: Python<'_>, options: &BTreeMap<String, bool>) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    for (k, v) in options {
        dict.set_item(k, *v)?;
    }
    Ok(dict.into())
}

fn algorithms_to_py(py: Python<'_>, info: &Info) -> PyResult<PyObject> {
    let list = PyList::empty(py);
    for alg in &info.algorithms {
        let d = PyDict::new(py);
        d.set_item("type", &alg.credential_type)?;
        d.set_item("alg", alg.alg)?;
        list.append(d)?;
    }
    Ok(list.into())
}

fn certifications_to_py(
    py: Python<'_>,
    certs: &BTreeMap<String, cbor::Value>,
) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    for (k, v) in certs {
        dict.set_item(k, cbor_value_to_py(py, v)?)?;
    }
    Ok(dict.into())
}

fn cbor_value_to_py(py: Python<'_>, value: &cbor::Value) -> PyResult<PyObject> {
    match value {
        cbor::Value::Int(n) => Ok(n.into_pyobject(py)?.into_any().unbind()),
        cbor::Value::Bytes(b) => Ok(PyBytes::new(py, b).into_any().unbind()),
        cbor::Value::Text(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        cbor::Value::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any().unbind()),
        cbor::Value::Array(arr) => {
            let list = PyList::empty(py);
            for v in arr {
                list.append(cbor_value_to_py(py, v)?)?;
            }
            Ok(list.into())
        }
        cbor::Value::Map(entries) => {
            let dict = PyDict::new(py);
            for (k, v) in entries {
                dict.set_item(cbor_value_to_py(py, k)?, cbor_value_to_py(py, v)?)?;
            }
            Ok(dict.into())
        }
    }
}

fn py_to_cbor_value(obj: &Bound<'_, PyAny>) -> PyResult<cbor::Value> {
    if let Ok(val) = obj.extract::<i64>() {
        Ok(cbor::Value::Int(val))
    } else if let Ok(val) = obj.extract::<bool>() {
        Ok(cbor::Value::Bool(val))
    } else if let Ok(val) = obj.extract::<Vec<u8>>() {
        Ok(cbor::Value::Bytes(val))
    } else if let Ok(val) = obj.extract::<String>() {
        Ok(cbor::Value::Text(val))
    } else if let Ok(list) = obj.downcast::<PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(py_to_cbor_value(&item)?);
        }
        Ok(cbor::Value::Array(arr))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut entries = Vec::new();
        for (k, v) in dict.iter() {
            entries.push((py_to_cbor_value(&k)?, py_to_cbor_value(&v)?));
        }
        Ok(cbor::Value::Map(entries))
    } else {
        Err(PyValueError::new_err("Cannot convert to CBOR value"))
    }
}

// ---------------------------------------------------------------------------
// SmartCard-backed Ctap2Session
// ---------------------------------------------------------------------------

#[pyclass(name = "Ctap2Session", unsendable)]
pub struct PyCtap2Session {
    session: Option<Ctap2Session<BoxedSmartCardConnection>>,
    py_connection: PyObject,
}

impl PyCtap2Session {
    fn get_session(&self) -> PyResult<&Ctap2Session<BoxedSmartCardConnection>> {
        self.session
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Session has been consumed by ClientPin"))
    }

    fn get_session_mut(&mut self) -> PyResult<&mut Ctap2Session<BoxedSmartCardConnection>> {
        self.session
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Session has been consumed by ClientPin"))
    }

    pub fn take_session(&mut self) -> PyResult<Ctap2Session<BoxedSmartCardConnection>> {
        self.session
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("Session has been consumed by ClientPin"))
    }

    pub fn restore_session(&mut self, session: Ctap2Session<BoxedSmartCardConnection>) {
        self.session = Some(session);
    }
}

#[pymethods]
impl PyCtap2Session {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        scp_key_params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_smartcard_connection(connection)?;
        let ctap = if let Some(params) = scp_key_params {
            let scp_params = crate::py_bridge::scp_key_params_from_py(params)?;
            CtapSession::new_with_scp(conn, &scp_params).map_err(|(e, _)| ctap_err(e))?
        } else {
            CtapSession::new(conn).map_err(|(e, _)| ctap_err(e))?
        };
        if !ctap.has_ctap2() {
            return Err(PyRuntimeError::new_err("Device does not support CTAP2"));
        }
        Ok(Self {
            session: Some(Ctap2Session::new(ctap).map_err(ctap2_err)?),
            py_connection,
        })
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(session) = self.session.take() {
            let conn = session.into_session().into_connection();
            restore_smartcard_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }

    #[getter]
    fn version(&self) -> PyResult<(u8, u8, u8)> {
        let v = self.get_session()?.version();
        Ok((v.0, v.1, v.2))
    }

    #[pyo3(signature = (event=None, on_keepalive=None))]
    fn selection(
        &mut self,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<()> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        self.get_session_mut()?
            .selection(keepalive_ref, cancel_ref)
            .map_err(ctap2_err)
    }

    fn get_info<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let info = self.get_session_mut()?.get_info().map_err(ctap2_err)?;
        info_to_py(py, &info)
    }

    #[pyo3(signature = (cmd, data=None, event=None, on_keepalive=None))]
    fn send_cbor<'py>(
        &mut self,
        py: Python<'py>,
        cmd: u8,
        data: Option<&[u8]>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let response = self
            .get_session_mut()?
            .send_cbor(cmd, data, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &response))
    }

    #[pyo3(signature = (event=None, on_keepalive=None))]
    fn reset(&mut self, event: Option<PyObject>, on_keepalive: Option<PyObject>) -> PyResult<()> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        self.get_session_mut()?
            .reset(keepalive_ref, cancel_ref)
            .map_err(ctap2_err)
    }
}

#[pyclass(name = "Ctap2FidoSession", unsendable)]
pub struct PyCtap2FidoSession {
    session: Option<Ctap2Session<BoxedFidoConnection>>,
    py_connection: PyObject,
}

impl PyCtap2FidoSession {
    fn get_session(&self) -> PyResult<&Ctap2Session<BoxedFidoConnection>> {
        self.session
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Session has been consumed by ClientPin"))
    }

    fn get_session_mut(&mut self) -> PyResult<&mut Ctap2Session<BoxedFidoConnection>> {
        self.session
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Session has been consumed by ClientPin"))
    }

    pub fn take_session(&mut self) -> PyResult<Ctap2Session<BoxedFidoConnection>> {
        self.session
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("Session has been consumed by ClientPin"))
    }

    pub fn restore_session(&mut self, session: Ctap2Session<BoxedFidoConnection>) {
        self.session = Some(session);
    }
}

#[pymethods]
impl PyCtap2FidoSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_fido_connection(connection)?;
        let ctap = CtapSession::new_fido(conn).map_err(|(e, _)| ctap_err(e))?;
        if !ctap.has_ctap2() {
            return Err(PyRuntimeError::new_err("Device does not support CTAP2"));
        }
        Ok(Self {
            session: Some(Ctap2Session::new(ctap).map_err(ctap2_err)?),
            py_connection,
        })
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(session) = self.session.take() {
            let conn = session.into_session().into_connection();
            restore_fido_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }

    #[getter]
    fn version(&self) -> PyResult<(u8, u8, u8)> {
        let v = self.get_session()?.version();
        Ok((v.0, v.1, v.2))
    }

    #[pyo3(signature = (event=None, on_keepalive=None))]
    fn selection(
        &mut self,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<()> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        self.get_session_mut()?
            .selection(keepalive_ref, cancel_ref)
            .map_err(ctap2_err)
    }

    fn get_info<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let info = self.get_session_mut()?.get_info().map_err(ctap2_err)?;
        info_to_py(py, &info)
    }

    #[pyo3(signature = (cmd, data=None, event=None, on_keepalive=None))]
    fn send_cbor<'py>(
        &mut self,
        py: Python<'py>,
        cmd: u8,
        data: Option<&[u8]>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let response = self
            .get_session_mut()?
            .send_cbor(cmd, data, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &response))
    }

    #[pyo3(signature = (event=None, on_keepalive=None))]
    fn reset(&mut self, event: Option<PyObject>, on_keepalive: Option<PyObject>) -> PyResult<()> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        self.get_session_mut()?
            .reset(keepalive_ref, cancel_ref)
            .map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// PinProtocol PyO3 wrapper
// ---------------------------------------------------------------------------

#[pyclass(name = "PinProtocol", unsendable)]
pub struct PyPinProtocol {
    inner: PinProtocol,
}

#[pymethods]
impl PyPinProtocol {
    #[new]
    fn new(version: u32) -> PyResult<Self> {
        let inner = match version {
            1 => PinProtocol::V1,
            2 => PinProtocol::V2,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "Unsupported PIN protocol version: {version}"
                )));
            }
        };
        Ok(Self { inner })
    }

    #[getter]
    fn version(&self) -> u32 {
        self.inner.version()
    }
}

impl PyPinProtocol {
    pub fn protocol(&self) -> PinProtocol {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// SmartCard-backed ClientPin
// ---------------------------------------------------------------------------

#[pyclass(name = "ClientPin", unsendable)]
pub struct PyClientPin {
    inner: Option<ClientPin<BoxedSmartCardConnection>>,
}

impl PyClientPin {
    fn get(&self) -> PyResult<&ClientPin<BoxedSmartCardConnection>> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("ClientPin has been closed"))
    }

    fn get_mut(&mut self) -> PyResult<&mut ClientPin<BoxedSmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("ClientPin has been closed"))
    }
}

#[pymethods]
impl PyClientPin {
    #[new]
    #[pyo3(signature = (session, protocol=None))]
    fn new(session: &mut PyCtap2Session, protocol: Option<&PyPinProtocol>) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner = if let Some(proto) = protocol {
            ClientPin::new_with_protocol(ctap2, proto.protocol()).map_err(ctap2_err)?
        } else {
            ClientPin::new(ctap2).map_err(ctap2_err)?
        };
        Ok(Self { inner: Some(inner) })
    }

    /// Close this ClientPin and restore the session back to the given
    /// Ctap2Session object, allowing it to be reused.
    fn close(&mut self, session: &mut PyCtap2Session) -> PyResult<()> {
        let pin = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("ClientPin has been closed"))?;
        session.restore_session(pin.into_session());
        Ok(())
    }

    #[getter]
    fn protocol(&self) -> PyResult<PyPinProtocol> {
        Ok(PyPinProtocol {
            inner: self.get()?.protocol(),
        })
    }

    fn get_pin_retries(&mut self) -> PyResult<(u32, Option<u32>)> {
        self.get_mut()?.get_pin_retries().map_err(ctap2_err)
    }

    fn get_uv_retries(&mut self) -> PyResult<u32> {
        self.get_mut()?.get_uv_retries().map_err(ctap2_err)
    }

    fn set_pin(&mut self, pin: &str) -> PyResult<()> {
        self.get_mut()?.set_pin(pin).map_err(ctap2_err)
    }

    fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> PyResult<()> {
        self.get_mut()?
            .change_pin(old_pin, new_pin)
            .map_err(ctap2_err)
    }

    #[pyo3(signature = (pin, permissions=None, permissions_rpid=None))]
    fn get_pin_token<'py>(
        &mut self,
        py: Python<'py>,
        pin: &str,
        permissions: Option<u8>,
        permissions_rpid: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let perms = permissions.map(Permissions::new);
        let token = self
            .get_mut()?
            .get_pin_token(pin, perms, permissions_rpid)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &token))
    }

    #[pyo3(signature = (permissions=None, permissions_rpid=None, event=None, on_keepalive=None))]
    fn get_uv_token<'py>(
        &mut self,
        py: Python<'py>,
        permissions: Option<u8>,
        permissions_rpid: Option<&str>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let perms = permissions.map(Permissions::new);
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let token = self
            .get_mut()?
            .get_uv_token(perms, permissions_rpid, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &token))
    }
}

// ---------------------------------------------------------------------------
// FIDO HID-backed ClientPin
// ---------------------------------------------------------------------------

#[pyclass(name = "ClientPinFido", unsendable)]
pub struct PyClientPinFido {
    inner: Option<ClientPin<BoxedFidoConnection>>,
}

impl PyClientPinFido {
    fn get(&self) -> PyResult<&ClientPin<BoxedFidoConnection>> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("ClientPinFido has been closed"))
    }

    fn get_mut(&mut self) -> PyResult<&mut ClientPin<BoxedFidoConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("ClientPinFido has been closed"))
    }
}

#[pymethods]
impl PyClientPinFido {
    #[new]
    #[pyo3(signature = (session, protocol=None))]
    fn new(session: &mut PyCtap2FidoSession, protocol: Option<&PyPinProtocol>) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner = if let Some(proto) = protocol {
            ClientPin::new_with_protocol(ctap2, proto.protocol()).map_err(ctap2_err)?
        } else {
            ClientPin::new(ctap2).map_err(ctap2_err)?
        };
        Ok(Self { inner: Some(inner) })
    }

    /// Close this ClientPinFido and restore the session back to the given
    /// Ctap2FidoSession object, allowing it to be reused.
    fn close(&mut self, session: &mut PyCtap2FidoSession) -> PyResult<()> {
        let pin = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("ClientPinFido has been closed"))?;
        session.restore_session(pin.into_session());
        Ok(())
    }

    #[getter]
    fn protocol(&self) -> PyResult<PyPinProtocol> {
        Ok(PyPinProtocol {
            inner: self.get()?.protocol(),
        })
    }

    fn get_pin_retries(&mut self) -> PyResult<(u32, Option<u32>)> {
        self.get_mut()?.get_pin_retries().map_err(ctap2_err)
    }

    fn get_uv_retries(&mut self) -> PyResult<u32> {
        self.get_mut()?.get_uv_retries().map_err(ctap2_err)
    }

    fn set_pin(&mut self, pin: &str) -> PyResult<()> {
        self.get_mut()?.set_pin(pin).map_err(ctap2_err)
    }

    fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> PyResult<()> {
        self.get_mut()?
            .change_pin(old_pin, new_pin)
            .map_err(ctap2_err)
    }

    #[pyo3(signature = (pin, permissions=None, permissions_rpid=None))]
    fn get_pin_token<'py>(
        &mut self,
        py: Python<'py>,
        pin: &str,
        permissions: Option<u8>,
        permissions_rpid: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let perms = permissions.map(Permissions::new);
        let token = self
            .get_mut()?
            .get_pin_token(pin, perms, permissions_rpid)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &token))
    }

    #[pyo3(signature = (permissions=None, permissions_rpid=None, event=None, on_keepalive=None))]
    fn get_uv_token<'py>(
        &mut self,
        py: Python<'py>,
        permissions: Option<u8>,
        permissions_rpid: Option<&str>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let perms = permissions.map(Permissions::new);
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let token = self
            .get_mut()?
            .get_uv_token(perms, permissions_rpid, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &token))
    }
}

// ---------------------------------------------------------------------------
// Helper: BTreeMap<u32, Value> → Python dict
// ---------------------------------------------------------------------------

fn cbor_result_to_py(py: Python<'_>, map: &BTreeMap<u32, cbor::Value>) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    for (k, v) in map {
        dict.set_item(k, cbor_value_to_py(py, v)?)?;
    }
    Ok(dict.into())
}

fn cbor_result_list_to_py(
    py: Python<'_>,
    items: &[BTreeMap<u32, cbor::Value>],
) -> PyResult<PyObject> {
    let list = PyList::empty(py);
    for item in items {
        list.append(cbor_result_to_py(py, item)?)?;
    }
    Ok(list.into())
}

// ---------------------------------------------------------------------------
// SmartCard-backed CredentialManagement
// ---------------------------------------------------------------------------

#[pyclass(name = "CredentialManagement", unsendable)]
pub struct PyCredentialManagement {
    inner: Option<CredentialManagement<BoxedSmartCardConnection>>,
}

impl PyCredentialManagement {
    fn get_mut(&mut self) -> PyResult<&mut CredentialManagement<BoxedSmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("CredentialManagement has been closed"))
    }
}

#[pymethods]
impl PyCredentialManagement {
    #[new]
    fn new(
        session: &mut PyCtap2Session,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner = CredentialManagement::new(ctap2, protocol.protocol(), pin_token.to_vec())
            .map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    /// Close this CredentialManagement and restore the session back to the
    /// given Ctap2Session object, allowing it to be reused.
    fn close(&mut self, session: &mut PyCtap2Session) -> PyResult<()> {
        let cm = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("CredentialManagement has been closed"))?;
        session.restore_session(cm.into_session());
        Ok(())
    }

    #[getter]
    fn is_update_supported(&self) -> PyResult<bool> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("CredentialManagement has been closed"))?
            .is_update_supported())
    }

    fn get_metadata(&mut self) -> PyResult<(u32, u32)> {
        self.get_mut()?.get_metadata().map_err(ctap2_err)
    }

    fn enumerate_rps<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let rps = self.get_mut()?.enumerate_rps().map_err(ctap2_err)?;
        cbor_result_list_to_py(py, &rps)
    }

    fn enumerate_creds<'py>(&mut self, py: Python<'py>, rp_id_hash: &[u8]) -> PyResult<PyObject> {
        let creds = self
            .get_mut()?
            .enumerate_creds(rp_id_hash)
            .map_err(ctap2_err)?;
        cbor_result_list_to_py(py, &creds)
    }

    fn delete_cred(&mut self, credential_id: &Bound<'_, PyAny>) -> PyResult<()> {
        let value = py_to_cbor_value(credential_id)?;
        self.get_mut()?.delete_cred(&value).map_err(ctap2_err)
    }

    fn update_user_info(
        &mut self,
        credential_id: &Bound<'_, PyAny>,
        user: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let cred = py_to_cbor_value(credential_id)?;
        let user = py_to_cbor_value(user)?;
        self.get_mut()?
            .update_user_info(&cred, &user)
            .map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// FIDO HID-backed CredentialManagement
// ---------------------------------------------------------------------------

#[pyclass(name = "CredentialManagementFido", unsendable)]
pub struct PyCredentialManagementFido {
    inner: Option<CredentialManagement<BoxedFidoConnection>>,
}

impl PyCredentialManagementFido {
    fn get_mut(&mut self) -> PyResult<&mut CredentialManagement<BoxedFidoConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("CredentialManagementFido has been closed"))
    }
}

#[pymethods]
impl PyCredentialManagementFido {
    #[new]
    fn new(
        session: &mut PyCtap2FidoSession,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner = CredentialManagement::new(ctap2, protocol.protocol(), pin_token.to_vec())
            .map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    /// Close this CredentialManagementFido and restore the session back to the
    /// given Ctap2FidoSession object, allowing it to be reused.
    fn close(&mut self, session: &mut PyCtap2FidoSession) -> PyResult<()> {
        let cm = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("CredentialManagementFido has been closed"))?;
        session.restore_session(cm.into_session());
        Ok(())
    }

    #[getter]
    fn is_update_supported(&self) -> PyResult<bool> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("CredentialManagementFido has been closed"))?
            .is_update_supported())
    }

    fn get_metadata(&mut self) -> PyResult<(u32, u32)> {
        self.get_mut()?.get_metadata().map_err(ctap2_err)
    }

    fn enumerate_rps<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let rps = self.get_mut()?.enumerate_rps().map_err(ctap2_err)?;
        cbor_result_list_to_py(py, &rps)
    }

    fn enumerate_creds<'py>(&mut self, py: Python<'py>, rp_id_hash: &[u8]) -> PyResult<PyObject> {
        let creds = self
            .get_mut()?
            .enumerate_creds(rp_id_hash)
            .map_err(ctap2_err)?;
        cbor_result_list_to_py(py, &creds)
    }

    fn delete_cred(&mut self, credential_id: &Bound<'_, PyAny>) -> PyResult<()> {
        let value = py_to_cbor_value(credential_id)?;
        self.get_mut()?.delete_cred(&value).map_err(ctap2_err)
    }

    fn update_user_info(
        &mut self,
        credential_id: &Bound<'_, PyAny>,
        user: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let cred = py_to_cbor_value(credential_id)?;
        let user = py_to_cbor_value(user)?;
        self.get_mut()?
            .update_user_info(&cred, &user)
            .map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// SmartCard-backed Config
// ---------------------------------------------------------------------------

#[pyclass(name = "Config", unsendable)]
pub struct PyConfig {
    inner: Option<Config<BoxedSmartCardConnection>>,
}

impl PyConfig {
    fn get_mut(&mut self) -> PyResult<&mut Config<BoxedSmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Config has been closed"))
    }
}

#[pymethods]
impl PyConfig {
    #[new]
    fn new(
        session: &mut PyCtap2Session,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner =
            Config::new(ctap2, protocol.protocol(), pin_token.to_vec()).map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn close(&mut self, session: &mut PyCtap2Session) -> PyResult<()> {
        let cfg = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("Config has been closed"))?;
        session.restore_session(cfg.into_session());
        Ok(())
    }

    fn enable_enterprise_attestation(&mut self) -> PyResult<()> {
        self.get_mut()?
            .enable_enterprise_attestation()
            .map_err(ctap2_err)
    }

    fn toggle_always_uv(&mut self) -> PyResult<()> {
        self.get_mut()?.toggle_always_uv().map_err(ctap2_err)
    }

    #[pyo3(signature = (min_pin_length=None, rp_ids=None, force_change_pin=false))]
    fn set_min_pin_length(
        &mut self,
        min_pin_length: Option<u32>,
        rp_ids: Option<Vec<String>>,
        force_change_pin: bool,
    ) -> PyResult<()> {
        self.get_mut()?
            .set_min_pin_length(min_pin_length, rp_ids.as_deref(), force_change_pin)
            .map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// FIDO HID-backed Config
// ---------------------------------------------------------------------------

#[pyclass(name = "ConfigFido", unsendable)]
pub struct PyConfigFido {
    inner: Option<Config<BoxedFidoConnection>>,
}

impl PyConfigFido {
    fn get_mut(&mut self) -> PyResult<&mut Config<BoxedFidoConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("ConfigFido has been closed"))
    }
}

#[pymethods]
impl PyConfigFido {
    #[new]
    fn new(
        session: &mut PyCtap2FidoSession,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner =
            Config::new(ctap2, protocol.protocol(), pin_token.to_vec()).map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn close(&mut self, session: &mut PyCtap2FidoSession) -> PyResult<()> {
        let cfg = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("ConfigFido has been closed"))?;
        session.restore_session(cfg.into_session());
        Ok(())
    }

    fn enable_enterprise_attestation(&mut self) -> PyResult<()> {
        self.get_mut()?
            .enable_enterprise_attestation()
            .map_err(ctap2_err)
    }

    fn toggle_always_uv(&mut self) -> PyResult<()> {
        self.get_mut()?.toggle_always_uv().map_err(ctap2_err)
    }

    #[pyo3(signature = (min_pin_length=None, rp_ids=None, force_change_pin=false))]
    fn set_min_pin_length(
        &mut self,
        min_pin_length: Option<u32>,
        rp_ids: Option<Vec<String>>,
        force_change_pin: bool,
    ) -> PyResult<()> {
        self.get_mut()?
            .set_min_pin_length(min_pin_length, rp_ids.as_deref(), force_change_pin)
            .map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// SmartCard-backed BioEnrollment
// ---------------------------------------------------------------------------

#[pyclass(name = "BioEnrollment", unsendable)]
pub struct PyBioEnrollment {
    inner: Option<BioEnrollment<BoxedSmartCardConnection>>,
}

impl PyBioEnrollment {
    fn get_mut(&mut self) -> PyResult<&mut BioEnrollment<BoxedSmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("BioEnrollment has been closed"))
    }
}

#[pymethods]
impl PyBioEnrollment {
    #[new]
    fn new(
        session: &mut PyCtap2Session,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner = BioEnrollment::new(ctap2, protocol.protocol(), pin_token.to_vec())
            .map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn close(&mut self, session: &mut PyCtap2Session) -> PyResult<()> {
        let bio = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("BioEnrollment has been closed"))?;
        session.restore_session(bio.into_session());
        Ok(())
    }

    fn get_fingerprint_sensor_info<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let info = self
            .get_mut()?
            .get_fingerprint_sensor_info()
            .map_err(ctap2_err)?;
        cbor_result_to_py(py, &info)
    }

    #[pyo3(signature = (timeout=None, event=None, on_keepalive=None))]
    fn enroll_begin<'py>(
        &mut self,
        py: Python<'py>,
        timeout: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let result = self
            .get_mut()?
            .enroll_begin(timeout, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        cbor_result_to_py(py, &result)
    }

    #[pyo3(signature = (template_id, timeout=None, event=None, on_keepalive=None))]
    fn enroll_capture_next<'py>(
        &mut self,
        py: Python<'py>,
        template_id: &[u8],
        timeout: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let result = self
            .get_mut()?
            .enroll_capture_next(template_id, timeout, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        cbor_result_to_py(py, &result)
    }

    fn enroll_cancel(&mut self) -> PyResult<()> {
        self.get_mut()?.enroll_cancel().map_err(ctap2_err)
    }

    fn enumerate_enrollments<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let result = self.get_mut()?.enumerate_enrollments().map_err(ctap2_err)?;
        cbor_result_to_py(py, &result)
    }

    fn set_name(&mut self, template_id: &[u8], name: &str) -> PyResult<()> {
        self.get_mut()?
            .set_name(template_id, name)
            .map_err(ctap2_err)
    }

    fn remove_enrollment(&mut self, template_id: &[u8]) -> PyResult<()> {
        self.get_mut()?
            .remove_enrollment(template_id)
            .map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// FIDO HID-backed BioEnrollment
// ---------------------------------------------------------------------------

#[pyclass(name = "BioEnrollmentFido", unsendable)]
pub struct PyBioEnrollmentFido {
    inner: Option<BioEnrollment<BoxedFidoConnection>>,
}

impl PyBioEnrollmentFido {
    fn get_mut(&mut self) -> PyResult<&mut BioEnrollment<BoxedFidoConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("BioEnrollmentFido has been closed"))
    }
}

#[pymethods]
impl PyBioEnrollmentFido {
    #[new]
    fn new(
        session: &mut PyCtap2FidoSession,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner = BioEnrollment::new(ctap2, protocol.protocol(), pin_token.to_vec())
            .map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn close(&mut self, session: &mut PyCtap2FidoSession) -> PyResult<()> {
        let bio = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("BioEnrollmentFido has been closed"))?;
        session.restore_session(bio.into_session());
        Ok(())
    }

    fn get_fingerprint_sensor_info<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let info = self
            .get_mut()?
            .get_fingerprint_sensor_info()
            .map_err(ctap2_err)?;
        cbor_result_to_py(py, &info)
    }

    #[pyo3(signature = (timeout=None, event=None, on_keepalive=None))]
    fn enroll_begin<'py>(
        &mut self,
        py: Python<'py>,
        timeout: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let result = self
            .get_mut()?
            .enroll_begin(timeout, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        cbor_result_to_py(py, &result)
    }

    #[pyo3(signature = (template_id, timeout=None, event=None, on_keepalive=None))]
    fn enroll_capture_next<'py>(
        &mut self,
        py: Python<'py>,
        template_id: &[u8],
        timeout: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let cancel_fn = make_cancel_fn(&event);
        let mut keepalive_fn = make_keepalive_fn(&on_keepalive);
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_ref: Option<&mut dyn FnMut(u8)> = if on_keepalive.is_some() {
            Some(&mut keepalive_fn)
        } else {
            None
        };
        let result = self
            .get_mut()?
            .enroll_capture_next(template_id, timeout, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        cbor_result_to_py(py, &result)
    }

    fn enroll_cancel(&mut self) -> PyResult<()> {
        self.get_mut()?.enroll_cancel().map_err(ctap2_err)
    }

    fn enumerate_enrollments<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let result = self.get_mut()?.enumerate_enrollments().map_err(ctap2_err)?;
        cbor_result_to_py(py, &result)
    }

    fn set_name(&mut self, template_id: &[u8], name: &str) -> PyResult<()> {
        self.get_mut()?
            .set_name(template_id, name)
            .map_err(ctap2_err)
    }

    fn remove_enrollment(&mut self, template_id: &[u8]) -> PyResult<()> {
        self.get_mut()?
            .remove_enrollment(template_id)
            .map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// SmartCard-backed LargeBlobs
// ---------------------------------------------------------------------------

#[pyclass(name = "LargeBlobs", unsendable)]
pub struct PyLargeBlobs {
    inner: Option<LargeBlobs<BoxedSmartCardConnection>>,
}

impl PyLargeBlobs {
    fn get_mut(&mut self) -> PyResult<&mut LargeBlobs<BoxedSmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("LargeBlobs has been closed"))
    }
}

#[pymethods]
impl PyLargeBlobs {
    #[new]
    fn new(
        session: &mut PyCtap2Session,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner =
            LargeBlobs::new(ctap2, protocol.protocol(), pin_token.to_vec()).map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn close(&mut self, session: &mut PyCtap2Session) -> PyResult<()> {
        let lb = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("LargeBlobs has been closed"))?;
        session.restore_session(lb.into_session());
        Ok(())
    }

    fn read_blob_array<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.get_mut()?.read_blob_array().map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &data))
    }

    fn write_blob_array(&mut self, data: &[u8]) -> PyResult<()> {
        self.get_mut()?.write_blob_array(data).map_err(ctap2_err)
    }
}

// ---------------------------------------------------------------------------
// FIDO HID-backed LargeBlobs
// ---------------------------------------------------------------------------

#[pyclass(name = "LargeBlobsFido", unsendable)]
pub struct PyLargeBlobsFido {
    inner: Option<LargeBlobs<BoxedFidoConnection>>,
}

impl PyLargeBlobsFido {
    fn get_mut(&mut self) -> PyResult<&mut LargeBlobs<BoxedFidoConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("LargeBlobsFido has been closed"))
    }
}

#[pymethods]
impl PyLargeBlobsFido {
    #[new]
    fn new(
        session: &mut PyCtap2FidoSession,
        protocol: &PyPinProtocol,
        pin_token: &[u8],
    ) -> PyResult<Self> {
        let ctap2 = session.take_session()?;
        let inner =
            LargeBlobs::new(ctap2, protocol.protocol(), pin_token.to_vec()).map_err(ctap2_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn close(&mut self, session: &mut PyCtap2FidoSession) -> PyResult<()> {
        let lb = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("LargeBlobsFido has been closed"))?;
        session.restore_session(lb.into_session());
        Ok(())
    }

    fn read_blob_array<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.get_mut()?.read_blob_array().map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &data))
    }

    fn write_blob_array(&mut self, data: &[u8]) -> PyResult<()> {
        self.get_mut()?.write_blob_array(data).map_err(ctap2_err)
    }
}
