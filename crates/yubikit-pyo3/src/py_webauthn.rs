use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use yubikit::ctap2::{Ctap2Session, Permissions};
use yubikit::webauthn::{
    ClientDataCollector, ClientError, CollectedClientData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, UserInteraction, WebAuthnClient,
};

use crate::py_bridge::{
    BoxedFidoConnection, BoxedSmartCardConnection, extract_fido_connection,
    extract_smartcard_connection, restore_fido_connection, restore_smartcard_connection,
};

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn webauthn_err<E: std::error::Error + Send + Sync + 'static>(e: ClientError<E>) -> PyErr {
    match e {
        ClientError::Ctap(e) => PyOSError::new_err(format!("CTAP2 error: {e}")),
        ClientError::ConfigurationUnsupported(msg) => {
            PyOSError::new_err(format!("configuration unsupported: {msg}"))
        }
        ClientError::PinRequired => PyOSError::new_err("PIN required"),
        ClientError::BadRequest(msg) => PyValueError::new_err(format!("bad request: {msg}")),
    }
}

// ---------------------------------------------------------------------------
// Python-backed UserInteraction
// ---------------------------------------------------------------------------

struct PyUserInteraction {
    obj: PyObject,
}

impl UserInteraction for PyUserInteraction {
    fn prompt_up(&self) {
        Python::with_gil(|py| {
            let _ = self.obj.call_method0(py, "prompt_up");
        });
    }

    fn request_pin(&self, permissions: Permissions, rp_id: Option<&str>) -> Option<String> {
        Python::with_gil(|py| {
            self.obj
                .call_method1(py, "request_pin", (permissions.bits(), rp_id))
                .ok()
                .and_then(|v| v.extract::<Option<String>>(py).ok())
                .flatten()
        })
    }

    fn request_uv(&self, permissions: Permissions, rp_id: Option<&str>) -> bool {
        Python::with_gil(|py| {
            self.obj
                .call_method1(py, "request_uv", (permissions.bits(), rp_id))
                .and_then(|v| v.extract::<bool>(py))
                .unwrap_or(true)
        })
    }
}

// ---------------------------------------------------------------------------
// Python-backed ClientDataCollector
// ---------------------------------------------------------------------------

struct PyClientDataCollector {
    obj: PyObject,
}

impl ClientDataCollector for PyClientDataCollector {
    fn collect_create(
        &self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let options_json = options
            .to_json()
            .map_err(|e| format!("failed to serialize options: {e}"))?;
        Python::with_gil(|py| {
            let result = self
                .obj
                .call_method1(py, "collect_create", (options_json,))
                .map_err(|e| format!("collect_create failed: {e}"))?;
            let (client_data_json, rp_id): (Vec<u8>, String) = result
                .extract(py)
                .map_err(|e| format!("collect_create returned invalid type: {e}"))?;
            let cd = CollectedClientData::from_json(client_data_json)?;
            Ok((cd, rp_id))
        })
    }

    fn collect_get(
        &self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let options_json = options
            .to_json()
            .map_err(|e| format!("failed to serialize options: {e}"))?;
        Python::with_gil(|py| {
            let result = self
                .obj
                .call_method1(py, "collect_get", (options_json,))
                .map_err(|e| format!("collect_get failed: {e}"))?;
            let (client_data_json, rp_id): (Vec<u8>, String) = result
                .extract(py)
                .map_err(|e| format!("collect_get returned invalid type: {e}"))?;
            let cd = CollectedClientData::from_json(client_data_json)?;
            Ok((cd, rp_id))
        })
    }
}

// ---------------------------------------------------------------------------
// WebAuthnClient for FIDO HID
// ---------------------------------------------------------------------------

type FidoWebAuthnClientInner =
    WebAuthnClient<BoxedFidoConnection, PyUserInteraction, PyClientDataCollector>;

#[pyclass(name = "WebAuthnClientFido", unsendable)]
pub struct PyWebAuthnClientFido {
    client: Option<FidoWebAuthnClientInner>,
    py_connection: PyObject,
}

#[pymethods]
impl PyWebAuthnClientFido {
    #[new]
    fn new(
        connection: &Bound<'_, PyAny>,
        user_interaction: PyObject,
        client_data_collector: PyObject,
    ) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_fido_connection(connection)?;
        let ctap = yubikit::ctap::CtapSession::new_fido(conn)
            .map_err(|(e, _)| PyOSError::new_err(e.to_string()))?;
        if !ctap.has_ctap2() {
            return Err(PyRuntimeError::new_err("Device does not support CTAP2"));
        }
        let session = Ctap2Session::new(ctap)
            .map_err(|(e, _)| PyOSError::new_err(format!("CTAP2 init failed: {e}")))?;

        let interaction = PyUserInteraction {
            obj: user_interaction,
        };
        let collector = PyClientDataCollector {
            obj: client_data_collector,
        };
        let client = WebAuthnClient::new(session, interaction, collector);

        Ok(Self {
            client: Some(client),
            py_connection,
        })
    }

    fn make_credential(&mut self, options_json: &str) -> PyResult<String> {
        let options = PublicKeyCredentialCreationOptions::from_json(options_json)
            .map_err(|e| PyValueError::new_err(format!("invalid options JSON: {e}")))?;
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("client has been closed"))?;
        let resp = client.make_credential(&options).map_err(webauthn_err)?;
        resp.to_json()
            .map_err(|e| PyRuntimeError::new_err(format!("failed to serialize response: {e}")))
    }

    fn get_assertion(&mut self, options_json: &str) -> PyResult<Vec<String>> {
        let options = PublicKeyCredentialRequestOptions::from_json(options_json)
            .map_err(|e| PyValueError::new_err(format!("invalid options JSON: {e}")))?;
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("client has been closed"))?;
        let responses = client.get_assertion(&options).map_err(webauthn_err)?;
        responses
            .iter()
            .map(|r| {
                r.to_json()
                    .map_err(|e| PyRuntimeError::new_err(format!("failed to serialize: {e}")))
            })
            .collect()
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(client) = self.client.take() {
            let session = client.into_session();
            let conn = session.into_session().into_connection();
            restore_fido_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }
}

type SmartCardWebAuthnClientInner =
    WebAuthnClient<BoxedSmartCardConnection, PyUserInteraction, PyClientDataCollector>;

#[pyclass(name = "WebAuthnClientCcid", unsendable)]
pub struct PyWebAuthnClientCcid {
    client: Option<SmartCardWebAuthnClientInner>,
    py_connection: PyObject,
}

#[pymethods]
impl PyWebAuthnClientCcid {
    #[new]
    #[pyo3(signature = (connection, user_interaction, client_data_collector, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        user_interaction: PyObject,
        client_data_collector: PyObject,
        scp_key_params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_smartcard_connection(connection)?;
        let ctap = if let Some(params) = scp_key_params {
            let scp_params = crate::py_bridge::scp_key_params_from_py(params)?;
            yubikit::ctap::CtapSession::new_with_scp(conn, &scp_params)
                .map_err(|(e, _)| PyOSError::new_err(e.to_string()))?
        } else {
            yubikit::ctap::CtapSession::new(conn)
                .map_err(|(e, _)| PyOSError::new_err(e.to_string()))?
        };
        if !ctap.has_ctap2() {
            return Err(PyRuntimeError::new_err("Device does not support CTAP2"));
        }
        let session = Ctap2Session::new(ctap)
            .map_err(|(e, _)| PyOSError::new_err(format!("CTAP2 init failed: {e}")))?;

        let interaction = PyUserInteraction {
            obj: user_interaction,
        };
        let collector = PyClientDataCollector {
            obj: client_data_collector,
        };
        let client = WebAuthnClient::new(session, interaction, collector);

        Ok(Self {
            client: Some(client),
            py_connection,
        })
    }

    fn make_credential(&mut self, options_json: &str) -> PyResult<String> {
        let options = PublicKeyCredentialCreationOptions::from_json(options_json)
            .map_err(|e| PyValueError::new_err(format!("invalid options JSON: {e}")))?;
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("client has been closed"))?;
        let resp = client.make_credential(&options).map_err(webauthn_err)?;
        resp.to_json()
            .map_err(|e| PyRuntimeError::new_err(format!("failed to serialize response: {e}")))
    }

    fn get_assertion(&mut self, options_json: &str) -> PyResult<Vec<String>> {
        let options = PublicKeyCredentialRequestOptions::from_json(options_json)
            .map_err(|e| PyValueError::new_err(format!("invalid options JSON: {e}")))?;
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("client has been closed"))?;
        let responses = client.get_assertion(&options).map_err(webauthn_err)?;
        responses
            .iter()
            .map(|r| {
                r.to_json()
                    .map_err(|e| PyRuntimeError::new_err(format!("failed to serialize: {e}")))
            })
            .collect()
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(client) = self.client.take() {
            let session = client.into_session();
            let conn = session.into_session().into_connection();
            restore_smartcard_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }
}
