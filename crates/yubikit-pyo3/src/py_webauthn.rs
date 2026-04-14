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
    prompt_up_cb: Option<PyObject>,
    request_pin_cb: Option<PyObject>,
    request_uv_cb: Option<PyObject>,
}

impl UserInteraction for PyUserInteraction {
    fn prompt_up(&self) {
        if let Some(cb) = &self.prompt_up_cb {
            Python::with_gil(|py| {
                let _ = cb.call0(py);
            });
        }
    }

    fn request_pin(&self, _permissions: Permissions, _rp_id: Option<&str>) -> Option<String> {
        let cb = self.request_pin_cb.as_ref()?;
        Python::with_gil(|py| {
            cb.call0(py)
                .ok()
                .and_then(|v| v.extract::<Option<String>>(py).ok())
                .flatten()
        })
    }

    fn request_uv(&self, _permissions: Permissions, _rp_id: Option<&str>) -> bool {
        match &self.request_uv_cb {
            Some(cb) => Python::with_gil(|py| {
                cb.call0(py)
                    .and_then(|v| v.extract::<bool>(py))
                    .unwrap_or(true)
            }),
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Python-backed ClientDataCollector
// ---------------------------------------------------------------------------

struct PyClientDataCollector {
    origin: String,
}

impl ClientDataCollector for PyClientDataCollector {
    fn collect_create(
        &self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let rp_id = options
            .rp
            .id
            .clone()
            .ok_or("RP ID is required for registration")?;
        let cd =
            CollectedClientData::create("webauthn.create", &options.challenge, &self.origin, false);
        Ok((cd, rp_id))
    }

    fn collect_get(
        &self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<(CollectedClientData, String), String> {
        let rp_id = options
            .rp_id
            .clone()
            .ok_or("RP ID is required for authentication")?;
        let cd =
            CollectedClientData::create("webauthn.get", &options.challenge, &self.origin, false);
        Ok((cd, rp_id))
    }
}

// ---------------------------------------------------------------------------
// WebAuthnClient for FIDO HID
// ---------------------------------------------------------------------------

type FidoWebAuthnClient =
    WebAuthnClient<BoxedFidoConnection, PyUserInteraction, PyClientDataCollector>;

#[pyclass(name = "WebAuthnClient", unsendable)]
pub struct PyWebAuthnClient {
    client: Option<FidoWebAuthnClient>,
    py_connection: PyObject,
}

#[pymethods]
impl PyWebAuthnClient {
    /// Create a WebAuthn client from a FIDO HID connection.
    ///
    /// Args:
    ///     connection: A FidoConnection to a FIDO HID device.
    ///     origin: The origin URL (e.g. "https://example.com").
    ///     prompt_up: Optional callback called when user presence is needed.
    ///     request_pin: Optional callback that should return the PIN string, or None to cancel.
    ///     request_uv: Optional callback that returns True to proceed with UV, False for PIN.
    #[new]
    #[pyo3(signature = (connection, origin, prompt_up=None, request_pin=None, request_uv=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        origin: String,
        prompt_up: Option<PyObject>,
        request_pin: Option<PyObject>,
        request_uv: Option<PyObject>,
    ) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_fido_connection(connection)?;
        let ctap = yubikit::ctap::CtapSession::new_fido(conn)
            .map_err(|(e, _)| PyOSError::new_err(e.to_string()))?;
        if !ctap.has_ctap2() {
            return Err(PyRuntimeError::new_err("Device does not support CTAP2"));
        }
        let session = Ctap2Session::new(ctap)
            .map_err(|e| PyOSError::new_err(format!("CTAP2 init failed: {e}")))?;

        let interaction = PyUserInteraction {
            prompt_up_cb: prompt_up,
            request_pin_cb: request_pin,
            request_uv_cb: request_uv,
        };
        let collector = PyClientDataCollector { origin };
        let client = WebAuthnClient::new(session, interaction, collector);

        Ok(Self {
            client: Some(client),
            py_connection,
        })
    }

    /// Perform a WebAuthn registration ceremony.
    ///
    /// Args:
    ///     options_json: JSON string with PublicKeyCredentialCreationOptions.
    ///
    /// Returns:
    ///     JSON string with RegistrationResponse.
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

    /// Perform a WebAuthn authentication ceremony.
    ///
    /// Args:
    ///     options_json: JSON string with PublicKeyCredentialRequestOptions.
    ///
    /// Returns:
    ///     List of JSON strings, one per assertion.
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

    /// Close the client and release the underlying connection.
    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(client) = self.client.take() {
            let session = client.into_session();
            let conn = session.into_session().into_connection();
            restore_fido_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebAuthnClient for SmartCard (CCID)
// ---------------------------------------------------------------------------

type SmartCardWebAuthnClient =
    WebAuthnClient<BoxedSmartCardConnection, PyUserInteraction, PyClientDataCollector>;

#[pyclass(name = "WebAuthnCcidClient", unsendable)]
pub struct PyWebAuthnCcidClient {
    client: Option<SmartCardWebAuthnClient>,
    py_connection: PyObject,
}

#[pymethods]
impl PyWebAuthnCcidClient {
    /// Create a WebAuthn client from a SmartCard (CCID) connection.
    #[new]
    #[pyo3(signature = (connection, origin, prompt_up=None, request_pin=None, request_uv=None, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        origin: String,
        prompt_up: Option<PyObject>,
        request_pin: Option<PyObject>,
        request_uv: Option<PyObject>,
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
            .map_err(|e| PyOSError::new_err(format!("CTAP2 init failed: {e}")))?;

        let interaction = PyUserInteraction {
            prompt_up_cb: prompt_up,
            request_pin_cb: request_pin,
            request_uv_cb: request_uv,
        };
        let collector = PyClientDataCollector { origin };
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
