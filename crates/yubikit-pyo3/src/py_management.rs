use pyo3::prelude::*;
use yubikit::management::{
    DeviceInfo, ManagementCcidSession as RustManagementCcidSession,
    ManagementFidoSession as RustManagementFidoSession,
    ManagementOtpSession as RustManagementOtpSession, ManagementSession,
};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::transport::otphid::HidOtpConnection;

use crate::py_bridge::{PySmartCardConnection, scp_key_params_from_py, smartcard_err};

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

#[pyclass(name = "ManagementSession")]
pub struct ManagementCcidSession {
    inner: RustManagementCcidSession<PySmartCardConnection>,
}

#[pymethods]
impl ManagementCcidSession {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        scp_key_params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        if let Some(params) = scp_key_params {
            let scp_params = scp_key_params_from_py(params)?;
            let inner = RustManagementCcidSession::new_with_scp(conn, &scp_params)
                .map_err(|(e, _)| smartcard_err(e))?;
            Ok(Self { inner })
        } else {
            let inner = RustManagementCcidSession::new(conn).map_err(|(e, _)| smartcard_err(e))?;
            Ok(Self { inner })
        }
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.inner.version();
        (v.0, v.1, v.2)
    }

    /// Read device info. Returns a dict with parsed fields.
    fn read_device_info(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self.inner.read_device_info().map_err(smartcard_err)?;
        device_info_to_dict(py, &info)
    }

    /// Read device info without version check (for dev device version override).
    fn read_device_info_unchecked(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .inner
            .read_device_info_unchecked()
            .map_err(smartcard_err)?;
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

        self.inner
            .write_device_config(&config, reboot, cur_lock_code, new_lock_code)
            .map_err(smartcard_err)
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> PyResult<()> {
        self.inner
            .set_mode(mode_code, chalresp_timeout, auto_eject_timeout)
            .map_err(smartcard_err)
    }

    fn device_reset(&mut self) -> PyResult<()> {
        self.inner.device_reset().map_err(smartcard_err)
    }
}

fn yubiotp_err(e: yubikit::otp::YubiOtpError) -> PyErr {
    use yubikit::otp::YubiOtpError;
    match e {
        YubiOtpError::CommandRejected(msg) => {
            pyo3::exceptions::PyValueError::new_err(format!("Command rejected: {msg}"))
        }
        YubiOtpError::NotSupported(msg) => {
            pyo3::exceptions::PyValueError::new_err(format!("Not supported: {msg}"))
        }
        other => pyo3::exceptions::PyOSError::new_err(other.to_string()),
    }
}

#[pyclass(name = "ManagementOtpSession", unsendable)]
pub struct ManagementOtpSession {
    inner: RustManagementOtpSession<HidOtpConnection>,
}

#[pymethods]
impl ManagementOtpSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut conn_wrapper = connection
            .downcast::<crate::py_hid::OtpConnection>()?
            .borrow_mut();
        let hid_conn = conn_wrapper.take_inner()?;
        let inner = RustManagementOtpSession::new(hid_conn).map_err(|(e, _)| yubiotp_err(e))?;
        Ok(Self { inner })
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.inner.version();
        (v.0, v.1, v.2)
    }

    fn read_device_info(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self.inner.read_device_info().map_err(smartcard_err)?;
        device_info_to_dict(py, &info)
    }

    fn read_device_info_unchecked(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .inner
            .read_device_info_unchecked()
            .map_err(smartcard_err)?;
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

        self.inner
            .write_device_config(&config, reboot, cur_lock_code, new_lock_code)
            .map_err(smartcard_err)
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> PyResult<()> {
        self.inner
            .set_mode(mode_code, chalresp_timeout, auto_eject_timeout)
            .map_err(smartcard_err)
    }
}

#[pyclass(name = "ManagementFidoSession", unsendable)]
pub struct ManagementFidoSession {
    inner: RustManagementFidoSession<HidFidoConnection>,
}

#[pymethods]
impl ManagementFidoSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut conn_wrapper = connection
            .downcast::<crate::py_hid::FidoConnection>()?
            .borrow_mut();
        let conn = conn_wrapper.take_inner()?;
        let inner = RustManagementFidoSession::new(conn).map_err(|(e, _)| smartcard_err(e))?;
        Ok(Self { inner })
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.inner.version();
        (v.0, v.1, v.2)
    }

    fn read_device_info(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self.inner.read_device_info().map_err(smartcard_err)?;
        device_info_to_dict(py, &info)
    }

    fn read_device_info_unchecked(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .inner
            .read_device_info_unchecked()
            .map_err(smartcard_err)?;
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

        self.inner
            .write_device_config(&config, reboot, cur_lock_code, new_lock_code)
            .map_err(smartcard_err)
    }

    fn set_mode(
        &mut self,
        mode_code: u8,
        chalresp_timeout: u8,
        auto_eject_timeout: u16,
    ) -> PyResult<()> {
        self.inner
            .set_mode(mode_code, chalresp_timeout, auto_eject_timeout)
            .map_err(smartcard_err)
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
