use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit::smartcard::Version;
use yubikit::yubiotp::{
    self, ConfigSlot, NdefType, Slot, YubiOtpCcidSession as RustYubiOtpCcidSession,
    YubiOtpOtpSession as RustYubiOtpOtpSession, YubiOtpSession as _,
};

use crate::py_bridge::{PySmartCardConnection, scp_key_params_from_py, smartcard_err};

fn yubiotp_err(e: yubiotp::YubiOtpError) -> PyErr {
    use pyo3::exceptions::*;
    match e {
        yubiotp::YubiOtpError::SmartCard(sc) => smartcard_err(sc),
        yubiotp::YubiOtpError::CommandRejected(msg) => {
            Python::with_gil(|py| match py.import("yubikit.core.otp") {
                Ok(module) => match module.getattr("CommandRejectedError") {
                    Ok(cls) => match cls.call1((msg.clone(),)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyRuntimeError::new_err(msg),
                    },
                    Err(_) => PyRuntimeError::new_err(msg),
                },
                Err(_) => PyRuntimeError::new_err(msg),
            })
        }
        yubiotp::YubiOtpError::BadResponse(msg) => {
            Python::with_gil(|py| match py.import("yubikit.core") {
                Ok(module) => match module.getattr("BadResponseError") {
                    Ok(cls) => match cls.call1((msg.clone(),)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyRuntimeError::new_err(msg),
                    },
                    Err(_) => PyRuntimeError::new_err(msg),
                },
                Err(_) => PyRuntimeError::new_err(msg),
            })
        }
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
        yubiotp::YubiOtpError::Timeout(msg) => PyTimeoutError::new_err(msg),
        yubiotp::YubiOtpError::InvalidParameter(msg) => PyValueError::new_err(msg),
        yubiotp::YubiOtpError::Hid(e) => PyOSError::new_err(e.to_string()),
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

#[pyclass(name = "YubiOtpSession")]
pub struct PyYubiOtpSession {
    session: RustYubiOtpCcidSession<PySmartCardConnection>,
}

#[pymethods]
impl PyYubiOtpSession {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        scp_key_params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        if let Some(params) = scp_key_params {
            let scp_params = scp_key_params_from_py(params)?;
            let session =
                RustYubiOtpCcidSession::new_with_scp(conn, &scp_params).map_err(yubiotp_err)?;
            Ok(Self { session })
        } else {
            let session = RustYubiOtpCcidSession::new(conn).map_err(yubiotp_err)?;
            Ok(Self { session })
        }
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.session.version();
        (v.0, v.1, v.2)
    }

    #[setter]
    fn set_version(&mut self, version: (u8, u8, u8)) {
        self.session
            .set_version(Version(version.0, version.1, version.2));
    }

    fn get_serial(&mut self) -> PyResult<u32> {
        self.session.get_serial().map_err(yubiotp_err)
    }

    /// Returns (version_tuple, flags).
    fn get_config_state(&self) -> ((u8, u8, u8), u8) {
        let state = self.session.get_config_state();
        let v = state.version;
        ((v.0, v.1, v.2), state.flags)
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
        self.session
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
        self.session
            .write_config(config_slot, config, cur_acc_code)
            .map_err(yubiotp_err)
    }

    fn swap_slots(&mut self) -> PyResult<()> {
        self.session.swap_slots().map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, cur_acc_code=None))]
    fn delete_slot(&mut self, slot: u8, cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        let s = parse_slot(slot)?;
        self.session
            .delete_slot(s, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (scan_map, cur_acc_code=None))]
    fn set_scan_map(&mut self, scan_map: &[u8], cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        self.session
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
        self.session
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
            .session
            .calculate_hmac_sha1(s, challenge)
            .map_err(yubiotp_err)?;
        Ok(PyBytes::new(py, &result))
    }
}

// ---------------------------------------------------------------------------
// HID/OTP-backed YubiOTP session
// ---------------------------------------------------------------------------

#[pyclass(name = "YubiOtpOtpSession", unsendable)]
pub struct PyYubiOtpOtpSession {
    session: RustYubiOtpOtpSession,
}

#[pymethods]
impl PyYubiOtpOtpSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut conn_wrapper = connection
            .downcast::<crate::py_hid::OtpConnection>()?
            .borrow_mut();
        let conn = conn_wrapper.take_inner()?;
        let session = RustYubiOtpOtpSession::new(conn).map_err(yubiotp_err)?;
        Ok(Self { session })
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.session.version();
        (v.0, v.1, v.2)
    }

    #[setter]
    fn set_version(&mut self, version: (u8, u8, u8)) {
        self.session
            .set_version(Version(version.0, version.1, version.2));
    }

    fn get_serial(&mut self) -> PyResult<u32> {
        self.session.get_serial().map_err(yubiotp_err)
    }

    /// Returns (version_tuple, flags).
    fn get_config_state(&self) -> ((u8, u8, u8), u8) {
        let state = self.session.get_config_state();
        let v = state.version;
        ((v.0, v.1, v.2), state.flags)
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
        self.session
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
        self.session
            .write_config(config_slot, config, cur_acc_code)
            .map_err(yubiotp_err)
    }

    fn swap_slots(&mut self) -> PyResult<()> {
        self.session.swap_slots().map_err(yubiotp_err)
    }

    #[pyo3(signature = (slot, cur_acc_code=None))]
    fn delete_slot(&mut self, slot: u8, cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        let s = parse_slot(slot)?;
        self.session
            .delete_slot(s, cur_acc_code)
            .map_err(yubiotp_err)
    }

    #[pyo3(signature = (scan_map, cur_acc_code=None))]
    fn set_scan_map(&mut self, scan_map: &[u8], cur_acc_code: Option<&[u8]>) -> PyResult<()> {
        self.session
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
        self.session
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
            .session
            .calculate_hmac_sha1(s, challenge, None, None)
            .map_err(yubiotp_err)?;
        Ok(PyBytes::new(py, &result))
    }
}
