use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit::yubiotp::{self, ConfigSlot, NdefType, Slot, YubiOtpSession};

use crate::py_bridge::{
    BoxedOtpConnection, BoxedSmartCardConnection, extract_otp_connection,
    extract_smartcard_connection, restore_otp_connection, restore_smartcard_connection,
    scp_key_params_from_py,
};

fn yubiotp_err<E: std::fmt::Debug + std::fmt::Display>(e: yubiotp::YubiOtpError<E>) -> PyErr {
    use pyo3::exceptions::*;
    match e {
        yubiotp::YubiOtpError::NotSupported(msg) => {
            Python::with_gil(|py| match py.import("yubikit.core") {
                Ok(module) => match module.getattr("NotSupportedError") {
                    Ok(cls) => match cls.call1((msg.clone(),)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyValueError::new_err(msg),
                    },
                    Err(_) => PyValueError::new_err(msg),
                },
                Err(_) => PyValueError::new_err(msg),
            })
        }
        yubiotp::YubiOtpError::InvalidData(msg) => PyValueError::new_err(msg),
        yubiotp::YubiOtpError::Connection(e) => PyRuntimeError::new_err(e.to_string()),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

fn parse_slot(slot: u8) -> PyResult<Slot> {
    match slot {
        1 => Ok(Slot::One),
        2 => Ok(Slot::Two),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "Invalid slot (must be 1 or 2)",
        )),
    }
}

fn parse_ndef_type(ndef_type: u8) -> PyResult<NdefType> {
    match ndef_type {
        b'T' => Ok(NdefType::Text),
        b'U' => Ok(NdefType::Uri),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "Invalid NDEF type (must be ord('T') or ord('U'))",
        )),
    }
}

// ---------------------------------------------------------------------------
// SmartCard-backed YubiOTP session
// ---------------------------------------------------------------------------

#[pyclass(name = "YubiOtpSessionCcid", unsendable)]
pub struct PyYubiOtpSessionCcid {
    session: Option<YubiOtpSession<BoxedSmartCardConnection>>,
    py_connection: PyObject,
}

impl PyYubiOtpSessionCcid {
    fn session(&self) -> PyResult<&YubiOtpSession<BoxedSmartCardConnection>> {
        self.session
            .as_ref()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }

    fn session_mut(&mut self) -> PyResult<&mut YubiOtpSession<BoxedSmartCardConnection>> {
        self.session
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }
}

#[pymethods]
impl PyYubiOtpSessionCcid {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        scp_key_params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_smartcard_connection(connection)?;
        if let Some(params) = scp_key_params {
            let scp_params = scp_key_params_from_py(params)?;
            let session =
                YubiOtpSession::new_with_scp(conn, &scp_params).map_err(|(e, _)| yubiotp_err(e))?;
            Ok(Self {
                session: Some(session),
                py_connection,
            })
        } else {
            let session = YubiOtpSession::new(conn).map_err(|(e, _)| yubiotp_err(e))?;
            Ok(Self {
                session: Some(session),
                py_connection,
            })
        }
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(session) = self.session.take() {
            let conn = session.into_connection();
            restore_smartcard_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }

    #[getter]
    fn version(&self) -> PyResult<(u8, u8, u8)> {
        let v = self.session()?.version();
        Ok((v.0, v.1, v.2))
    }

    fn get_serial(&mut self) -> PyResult<u32> {
        self.session_mut()?.get_serial().map_err(yubiotp_err)
    }

    /// Returns (version_tuple, flags).
    fn get_config_state(&self) -> PyResult<((u8, u8, u8), u8)> {
        let state = self.session()?.get_config_state();
        let v = state.version;
        Ok(((v.0, v.1, v.2), state.flags))
    }

    #[pyo3(signature = (slot, config, acc_code=None, cur_acc_code=None))]
    fn put_configuration(
        &mut self,
        slot: u8,
        config: &[u8],
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> PyResult<()> {
        let _ = acc_code; // acc_code already baked into config bytes
        let s = parse_slot(slot)?;
        let config_slot = s.map(ConfigSlot::Config1, ConfigSlot::Config2);
        self.session_mut()?
            .write_config(config_slot, config, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, config, acc_code=None, cur_acc_code=None))]
    fn update_configuration(
        &mut self,
        slot: u8,
        config: &[u8],
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> PyResult<()> {
        let _ = acc_code;
        let s = parse_slot(slot)?;
        let config_slot = s.map(ConfigSlot::Update1, ConfigSlot::Update2);
        self.session_mut()?
            .write_config(config_slot, config, cur_acc_code)
            .map_err(yubiotp_err)
    }

    fn swap_slots(&mut self) -> PyResult<()> {
        self.session_mut()?.swap_slots().map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, cur_acc_code=None))]
    fn delete_slot(&mut self, slot: u8, cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        let s = parse_slot(slot)?;
        self.session_mut()?
            .delete_slot(s, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (scan_map, cur_acc_code=None))]
    fn set_scan_map(&mut self, scan_map: &[u8], cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        self.session_mut()?
            .set_scan_map(scan_map, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, ndef_type, uri=None, cur_acc_code=None))]
    fn set_ndef_configuration(
        &mut self,
        slot: u8,
        ndef_type: u8,
        uri: Option<&str>,
        cur_acc_code: Option<&[u8]>,
    ) -> PyResult<()> {
        let s = parse_slot(slot)?;
        let nt = parse_ndef_type(ndef_type)?;
        self.session_mut()?
            .set_ndef_configuration(s, uri, cur_acc_code, nt)
            .map_err(yubiotp_err)
    }

    fn calculate_hmac_sha1<'py>(
        &mut self,
        py: Python<'py>,
        slot: u8,
        challenge: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let s = parse_slot(slot)?;
        let result = self
            .session_mut()?
            .calculate_hmac_sha1(s, challenge)
            .map_err(yubiotp_err)?;
        Ok(PyBytes::new(py, &result))
    }
}

// ---------------------------------------------------------------------------
// HID/OTP-backed YubiOTP session
// ---------------------------------------------------------------------------

#[pyclass(name = "YubiOtpSessionOtp", unsendable)]
pub struct PyYubiOtpSessionOtp {
    session: Option<YubiOtpSession<BoxedOtpConnection>>,
    py_connection: PyObject,
}

impl PyYubiOtpSessionOtp {
    fn session(&self) -> PyResult<&YubiOtpSession<BoxedOtpConnection>> {
        self.session
            .as_ref()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }

    fn session_mut(&mut self) -> PyResult<&mut YubiOtpSession<BoxedOtpConnection>> {
        self.session
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }
}

#[pymethods]
impl PyYubiOtpSessionOtp {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_otp_connection(connection)?;
        let session = YubiOtpSession::new_otp(conn).map_err(|(e, _)| yubiotp_err(e))?;
        Ok(Self {
            session: Some(session),
            py_connection,
        })
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(session) = self.session.take() {
            let conn = session.into_connection();
            restore_otp_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }

    #[getter]
    fn version(&self) -> PyResult<(u8, u8, u8)> {
        let v = self.session()?.version();
        Ok((v.0, v.1, v.2))
    }

    fn get_serial(&mut self) -> PyResult<u32> {
        self.session_mut()?.get_serial().map_err(yubiotp_err)
    }

    /// Returns (version_tuple, flags).
    fn get_config_state(&self) -> PyResult<((u8, u8, u8), u8)> {
        let state = self.session()?.get_config_state();
        let v = state.version;
        Ok(((v.0, v.1, v.2), state.flags))
    }

    #[pyo3(signature = (slot, config, acc_code=None, cur_acc_code=None))]
    fn put_configuration(
        &mut self,
        slot: u8,
        config: &[u8],
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> PyResult<()> {
        let _ = acc_code;
        let s = parse_slot(slot)?;
        let config_slot = s.map(ConfigSlot::Config1, ConfigSlot::Config2);
        self.session_mut()?
            .write_config(config_slot, config, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, config, acc_code=None, cur_acc_code=None))]
    fn update_configuration(
        &mut self,
        slot: u8,
        config: &[u8],
        acc_code: Option<&[u8]>,
        cur_acc_code: Option<&[u8]>,
    ) -> PyResult<()> {
        let _ = acc_code;
        let s = parse_slot(slot)?;
        let config_slot = s.map(ConfigSlot::Update1, ConfigSlot::Update2);
        self.session_mut()?
            .write_config(config_slot, config, cur_acc_code)
            .map_err(yubiotp_err)
    }

    fn swap_slots(&mut self) -> PyResult<()> {
        self.session_mut()?.swap_slots().map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, cur_acc_code=None))]
    fn delete_slot(&mut self, slot: u8, cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        let s = parse_slot(slot)?;
        self.session_mut()?
            .delete_slot(s, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (scan_map, cur_acc_code=None))]
    fn set_scan_map(&mut self, scan_map: &[u8], cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        self.session_mut()?
            .set_scan_map(scan_map, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, ndef_type, uri=None, cur_acc_code=None))]
    fn set_ndef_configuration(
        &mut self,
        slot: u8,
        ndef_type: u8,
        uri: Option<&str>,
        cur_acc_code: Option<&[u8]>,
    ) -> PyResult<()> {
        let s = parse_slot(slot)?;
        let nt = parse_ndef_type(ndef_type)?;
        self.session_mut()?
            .set_ndef_configuration(s, uri, cur_acc_code, nt)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, challenge, event=None, on_keepalive=None))]
    fn calculate_hmac_sha1<'py>(
        &mut self,
        py: Python<'py>,
        slot: u8,
        challenge: &[u8],
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let s = parse_slot(slot)?;
        let cancel_fn = || {
            Python::with_gil(|py| {
                if let Some(ref evt) = event
                    && let Ok(is_set) = evt.call_method0(py, "is_set")
                    && is_set.extract::<bool>(py).unwrap_or(false)
                {
                    return true;
                }
                false
            })
        };
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };
        let keepalive_fn = |status: u8| {
            if let Some(ref cb) = on_keepalive {
                Python::with_gil(|py| {
                    let _ = cb.call1(py, (status,));
                });
            }
        };
        let keepalive_ref: Option<&dyn Fn(u8)> = if on_keepalive.is_some() {
            Some(&keepalive_fn)
        } else {
            None
        };
        let result = self
            .session_mut()?
            .calculate_hmac_sha1_with_cancel(s, challenge, cancel_ref, keepalive_ref)
            .map_err(yubiotp_err)?;
        Ok(PyBytes::new(py, &result))
    }
}
