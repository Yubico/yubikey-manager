use pyo3::prelude::*;
use yubikit::management::{DeviceInfo, ManagementSession};
use yubikit::transport::ctaphid::list_fido_devices;

use crate::py_bridge::{
    BoxedFidoConnection, BoxedOtpConnection, BoxedSmartCardConnection, extract_fido_connection,
    extract_otp_connection, extract_smartcard_connection, restore_fido_connection,
    restore_otp_connection, restore_smartcard_connection, scp_key_params_from_py,
};

fn management_err(e: impl std::fmt::Display) -> PyErr {
    pyo3::exceptions::PyOSError::new_err(e.to_string())
}

pub fn device_info_to_dict(py: Python<'_>, info: &DeviceInfo) -> PyResult<PyObject> {
    let dict = pyo3::types::PyDict::new(py);

    dict.set_item("serial", info.serial)?;
    dict.set_item("version", (info.version.0, info.version.1, info.version.2))?;
    dict.set_item("form_factor", info.form_factor as u8)?;
    dict.set_item("is_locked", info.is_locked)?;
    dict.set_item("is_fips", info.is_fips)?;
    dict.set_item("is_sky", info.is_sky)?;
    dict.set_item("part_number", &info.part_number)?;
    dict.set_item("pin_complexity", info.pin_complexity)?;
    dict.set_item("fips_capable", info.fips_capable.0)?;
    dict.set_item("fips_approved", info.fips_approved.0)?;
    dict.set_item("reset_blocked", info.reset_blocked.0)?;

    let supported = pyo3::types::PyDict::new(py);
    // Ensure deterministic order: USB before NFC (matching Python convention)
    let mut supported_entries: Vec<_> = info.supported_capabilities.iter().collect();
    supported_entries.sort_by_key(|(t, _)| **t);
    for (transport, cap) in supported_entries {
        supported.set_item(format!("{:?}", transport), cap.0)?;
    }
    dict.set_item("supported_capabilities", supported)?;

    let enabled = pyo3::types::PyDict::new(py);
    let mut enabled_entries: Vec<_> = info.config.enabled_capabilities.iter().collect();
    enabled_entries.sort_by_key(|(t, _)| **t);
    for (transport, cap) in enabled_entries {
        enabled.set_item(format!("{:?}", transport), cap.0)?;
    }
    dict.set_item("enabled_capabilities", enabled)?;

    dict.set_item("auto_eject_timeout", info.config.auto_eject_timeout)?;
    dict.set_item(
        "challenge_response_timeout",
        info.config.challenge_response_timeout,
    )?;
    dict.set_item("device_flags", info.config.device_flags.map(|f| f.0))?;
    dict.set_item("nfc_restricted", info.config.nfc_restricted)?;

    if let Some(v) = info.fps_version {
        dict.set_item("fps_version", (v.0, v.1, v.2))?;
    }
    if let Some(v) = info.stm_version {
        dict.set_item("stm_version", (v.0, v.1, v.2))?;
    }

    // Version qualifier
    let vq = &info.version_qualifier;
    let vq_dict = pyo3::types::PyDict::new(py);
    vq_dict.set_item("version", (vq.version.0, vq.version.1, vq.version.2))?;
    vq_dict.set_item("release_type", vq.release_type as u8)?;
    vq_dict.set_item("iteration", vq.iteration)?;
    dict.set_item("version_qualifier", vq_dict)?;

    Ok(dict.into())
}

#[pyclass(name = "ManagementSession", unsendable)]
pub struct ManagementCcidSession {
    inner: Option<ManagementSession<BoxedSmartCardConnection>>,
    py_connection: PyObject,
}

impl ManagementCcidSession {
    fn session(&self) -> PyResult<&ManagementSession<BoxedSmartCardConnection>> {
        self.inner
            .as_ref()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }

    fn session_mut(&mut self) -> PyResult<&mut ManagementSession<BoxedSmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }
}

#[pymethods]
impl ManagementCcidSession {
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
            let inner = ManagementSession::new_with_scp(conn, &scp_params)
                .map_err(|(e, _)| management_err(e))?;
            Ok(Self {
                inner: Some(inner),
                py_connection,
            })
        } else {
            let inner = ManagementSession::new(conn).map_err(|(e, _)| management_err(e))?;
            Ok(Self {
                inner: Some(inner),
                py_connection,
            })
        }
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(session) = self.inner.take() {
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

    /// Read device info. Returns a dict with parsed fields.
    fn read_device_info(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .session_mut()?
            .read_device_info()
            .map_err(management_err)?;
        device_info_to_dict(py, &info)
    }

    /// Write device config from individual parameters.
    ///
    /// `enabled_capabilities` is a dict mapping transport name ("Usb"/"Nfc") to capability bitmask.
    #[pyo3(signature = (enabled_capabilities, reboot, cur_lock_code=None, new_lock_code=None, auto_eject_timeout=None, challenge_response_timeout=None, device_flags=None, nfc_restricted=None))]
    fn write_device_config(
        &mut self,
        enabled_capabilities: &Bound<'_, pyo3::types::PyDict>,
        reboot: bool,
        cur_lock_code: Option<&[u8]>,
        new_lock_code: Option<&[u8]>,
        auto_eject_timeout: Option<u16>,
        challenge_response_timeout: Option<u8>,
        device_flags: Option<u8>,
        nfc_restricted: Option<bool>,
    ) -> PyResult<()> {
        use std::collections::HashMap;
        use yubikit::core::Transport;
        use yubikit::management::{Capability, DeviceConfig, DeviceFlag};

        let mut caps = HashMap::new();
        for (key, value) in enabled_capabilities.iter() {
            let transport_name: String = key.extract()?;
            let cap_val: u16 = value.extract()?;
            let transport = match transport_name.as_str() {
                "Usb" => Transport::Usb,
                "Nfc" => Transport::Nfc,
                _ => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "Invalid transport: {}",
                        transport_name
                    )));
                }
            };
            caps.insert(transport, Capability(cap_val));
        }

        let config = DeviceConfig {
            enabled_capabilities: caps,
            auto_eject_timeout,
            challenge_response_timeout,
            device_flags: device_flags.map(DeviceFlag),
            nfc_restricted,
        };

        self.session_mut()?
            .write_device_config(&config, reboot, cur_lock_code, new_lock_code)
            .map_err(management_err)
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> PyResult<()> {
        self.session_mut()?
            .set_mode(mode_code, chalresp_timeout, auto_eject_timeout)
            .map_err(management_err)
    }

    fn device_reset(&mut self) -> PyResult<()> {
        self.session_mut()?.device_reset().map_err(management_err)
    }
}

#[pyclass(name = "ManagementOtpSession", unsendable)]
pub struct ManagementOtpSession {
    inner: Option<ManagementSession<BoxedOtpConnection>>,
    py_connection: PyObject,
}

impl ManagementOtpSession {
    fn session(&self) -> PyResult<&ManagementSession<BoxedOtpConnection>> {
        self.inner
            .as_ref()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }

    fn session_mut(&mut self) -> PyResult<&mut ManagementSession<BoxedOtpConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }
}

#[pymethods]
impl ManagementOtpSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let hid_conn = extract_otp_connection(connection)?;
        let inner = ManagementSession::new_otp(hid_conn).map_err(|(e, _)| management_err(e))?;
        Ok(Self {
            inner: Some(inner),
            py_connection,
        })
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(session) = self.inner.take() {
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

    fn read_device_info(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .session_mut()?
            .read_device_info()
            .map_err(management_err)?;
        device_info_to_dict(py, &info)
    }

    #[pyo3(signature = (enabled_capabilities, reboot, cur_lock_code=None, new_lock_code=None, auto_eject_timeout=None, challenge_response_timeout=None, device_flags=None, nfc_restricted=None))]
    fn write_device_config(
        &mut self,
        enabled_capabilities: &Bound<'_, pyo3::types::PyDict>,
        reboot: bool,
        cur_lock_code: Option<&[u8]>,
        new_lock_code: Option<&[u8]>,
        auto_eject_timeout: Option<u16>,
        challenge_response_timeout: Option<u8>,
        device_flags: Option<u8>,
        nfc_restricted: Option<bool>,
    ) -> PyResult<()> {
        use std::collections::HashMap;
        use yubikit::core::Transport;
        use yubikit::management::{Capability, DeviceConfig, DeviceFlag};

        let mut caps = HashMap::new();
        for (key, value) in enabled_capabilities.iter() {
            let transport_name: String = key.extract()?;
            let cap_val: u16 = value.extract()?;
            let transport = match transport_name.as_str() {
                "Usb" => Transport::Usb,
                "Nfc" => Transport::Nfc,
                _ => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "Invalid transport: {}",
                        transport_name
                    )));
                }
            };
            caps.insert(transport, Capability(cap_val));
        }

        let config = DeviceConfig {
            enabled_capabilities: caps,
            auto_eject_timeout,
            challenge_response_timeout,
            device_flags: device_flags.map(DeviceFlag),
            nfc_restricted,
        };

        self.session_mut()?
            .write_device_config(&config, reboot, cur_lock_code, new_lock_code)
            .map_err(management_err)
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> PyResult<()> {
        self.session_mut()?
            .set_mode(mode_code, chalresp_timeout, auto_eject_timeout)
            .map_err(management_err)
    }
}

#[pyclass(name = "ManagementFidoSession", unsendable)]
pub struct ManagementFidoSession {
    inner: Option<ManagementSession<BoxedFidoConnection>>,
    py_connection: PyObject,
}

impl ManagementFidoSession {
    fn session(&self) -> PyResult<&ManagementSession<BoxedFidoConnection>> {
        self.inner
            .as_ref()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }

    fn session_mut(&mut self) -> PyResult<&mut ManagementSession<BoxedFidoConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }
}

#[pymethods]
impl ManagementFidoSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let py_connection: PyObject = connection.clone().unbind();
        let conn = extract_fido_connection(connection)?;
        let inner = ManagementSession::new_fido(conn).map_err(|(e, _)| management_err(e))?;
        Ok(Self {
            inner: Some(inner),
            py_connection,
        })
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(session) = self.inner.take() {
            let conn = session.into_connection();
            restore_fido_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }

    #[getter]
    fn version(&self) -> PyResult<(u8, u8, u8)> {
        let v = self.session()?.version();
        Ok((v.0, v.1, v.2))
    }

    fn read_device_info(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .session_mut()?
            .read_device_info()
            .map_err(management_err)?;
        device_info_to_dict(py, &info)
    }

    #[pyo3(signature = (enabled_capabilities, reboot, cur_lock_code=None, new_lock_code=None, auto_eject_timeout=None, challenge_response_timeout=None, device_flags=None, nfc_restricted=None))]
    fn write_device_config(
        &mut self,
        enabled_capabilities: &Bound<'_, pyo3::types::PyDict>,
        reboot: bool,
        cur_lock_code: Option<&[u8]>,
        new_lock_code: Option<&[u8]>,
        auto_eject_timeout: Option<u16>,
        challenge_response_timeout: Option<u8>,
        device_flags: Option<u8>,
        nfc_restricted: Option<bool>,
    ) -> PyResult<()> {
        use std::collections::HashMap;
        use yubikit::core::Transport;
        use yubikit::management::{Capability, DeviceConfig, DeviceFlag};

        let mut caps = HashMap::new();
        for (key, value) in enabled_capabilities.iter() {
            let transport_name: String = key.extract()?;
            let cap_val: u16 = value.extract()?;
            let transport = match transport_name.as_str() {
                "Usb" => Transport::Usb,
                "Nfc" => Transport::Nfc,
                _ => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "Invalid transport: {}",
                        transport_name
                    )));
                }
            };
            caps.insert(transport, Capability(cap_val));
        }

        let config = DeviceConfig {
            enabled_capabilities: caps,
            auto_eject_timeout,
            challenge_response_timeout,
            device_flags: device_flags.map(DeviceFlag),
            nfc_restricted,
        };

        self.session_mut()?
            .write_device_config(&config, reboot, cur_lock_code, new_lock_code)
            .map_err(management_err)
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> PyResult<()> {
        self.session_mut()?
            .set_mode(mode_code, chalresp_timeout, auto_eject_timeout)
            .map_err(management_err)
    }
}

/// List FIDO HID devices.
///
/// Returns a list of dicts with 'path' and 'pid' keys.
#[pyfunction]
pub fn py_list_fido_devices(py: Python<'_>) -> PyResult<PyObject> {
    let devices =
        list_fido_devices().map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;
    let list = pyo3::types::PyList::empty(py);
    for dev in devices {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("path", &dev.path)?;
        dict.set_item("pid", dev.pid)?;
        list.append(dict)?;
    }
    Ok(list.into())
}
