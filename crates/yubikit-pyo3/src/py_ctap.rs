use std::collections::BTreeMap;

use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyList};
use yubikit::cbor;
use yubikit::ctap::CtapSession;
use yubikit::ctap2::{Ctap2Error, Ctap2Session, Info};

use crate::py_bridge::{
    BoxedFidoConnection, BoxedSmartCardConnection, extract_fido_connection,
    extract_smartcard_connection,
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

// ---------------------------------------------------------------------------
// SmartCard-backed Ctap2Session
// ---------------------------------------------------------------------------

#[pyclass(name = "Ctap2Session", unsendable)]
pub struct PyCtap2Session {
    session: Ctap2Session<BoxedSmartCardConnection>,
}

#[pymethods]
impl PyCtap2Session {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        scp_key_params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
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
            session: Ctap2Session::new(ctap),
        })
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.session.session().version();
        (v.0, v.1, v.2)
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
        self.session
            .selection(keepalive_ref, cancel_ref)
            .map_err(ctap2_err)
    }

    fn get_info<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let info = self.session.get_info().map_err(ctap2_err)?;
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
            .session
            .send_cbor(cmd, data, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &response))
    }
}

// ---------------------------------------------------------------------------
// FIDO HID-backed Ctap2Session
// ---------------------------------------------------------------------------

#[pyclass(name = "Ctap2FidoSession", unsendable)]
pub struct PyCtap2FidoSession {
    session: Ctap2Session<BoxedFidoConnection>,
}

#[pymethods]
impl PyCtap2FidoSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let conn = extract_fido_connection(connection)?;
        let ctap = CtapSession::new_fido(conn).map_err(|(e, _)| ctap_err(e))?;
        if !ctap.has_ctap2() {
            return Err(PyRuntimeError::new_err("Device does not support CTAP2"));
        }
        Ok(Self {
            session: Ctap2Session::new(ctap),
        })
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.session.session().version();
        (v.0, v.1, v.2)
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
        self.session
            .selection(keepalive_ref, cancel_ref)
            .map_err(ctap2_err)
    }

    fn get_info<'py>(&mut self, py: Python<'py>) -> PyResult<PyObject> {
        let info = self.session.get_info().map_err(ctap2_err)?;
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
            .session
            .send_cbor(cmd, data, keepalive_ref, cancel_ref)
            .map_err(ctap2_err)?;
        Ok(PyBytes::new(py, &response))
    }
}
