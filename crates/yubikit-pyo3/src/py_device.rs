// Copyright 2026 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::py_bridge::{
    extract_fido_connection, extract_otp_connection, extract_smartcard_connection,
    restore_fido_connection, restore_otp_connection, restore_smartcard_connection,
};
use crate::py_management::device_info_to_dict;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use yubikit::device;
use yubikit::device::YubiKeyDevice;
use yubikit::management;

fn device_err(e: device::DeviceError) -> PyErr {
    PyRuntimeError::new_err(format!("{e}"))
}

/// Read device info from an open connection.
///
/// Accepts a SmartCardConnection, OtpConnection, or FidoConnection.
/// Returns a dict matching the Python DeviceInfo structure.
#[pyfunction]
pub fn read_info(py: Python<'_>, connection: &Bound<'_, PyAny>) -> PyResult<PyObject> {
    // Try OTP connection
    if let Ok(native) = extract_otp_connection(connection) {
        match device::read_info_otp(native) {
            Ok((info, conn)) => {
                restore_otp_connection(connection, conn)?;
                return device_info_to_dict(py, &info);
            }
            Err((e, conn)) => {
                if let Some(conn) = conn {
                    let _ = restore_otp_connection(connection, conn);
                }
                return Err(device_err(e));
            }
        }
    }

    // Try FIDO connection
    if let Ok(native) = extract_fido_connection(connection) {
        match device::read_info_fido(native) {
            Ok((info, conn)) => {
                restore_fido_connection(connection, conn)?;
                return device_info_to_dict(py, &info);
            }
            Err((e, conn)) => {
                if let Some(conn) = conn {
                    let _ = restore_fido_connection(connection, conn);
                }
                return Err(device_err(e));
            }
        }
    }

    // Try SmartCard connection
    let conn = extract_smartcard_connection(connection).map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "Expected a SmartCardConnection, OtpConnection, or FidoConnection",
        )
    })?;
    match device::read_info_ccid(conn) {
        Ok((info, conn)) => {
            restore_smartcard_connection(connection, conn)?;
            device_info_to_dict(py, &info)
        }
        Err(e) => Err(device_err(e)),
    }
}

/// Get the product name for a device given its info dict.
///
/// This is a simplified wrapper — it requires version, form_factor, is_sky,
/// is_fips, pin_complexity, and supported_capabilities from the info.
#[pyfunction]
pub fn get_name(
    py: Python<'_>,
    version: (u8, u8, u8),
    form_factor: u8,
    is_sky: bool,
    is_fips: bool,
    pin_complexity: bool,
    serial: Option<u32>,
    usb_supported: u16,
    has_nfc: bool,
) -> PyResult<String> {
    use std::collections::HashMap;
    use yubikit::core::{Transport, Version};
    use yubikit::management::{Capability, DeviceConfig, DeviceInfo, FormFactor, VersionQualifier};

    let ver = Version(version.0, version.1, version.2);
    let ff = FormFactor::from_code(form_factor);

    let mut supported = HashMap::new();
    supported.insert(Transport::Usb, Capability(usb_supported));
    if has_nfc {
        supported.insert(Transport::Nfc, Capability(usb_supported));
    }

    let info = DeviceInfo {
        config: DeviceConfig {
            enabled_capabilities: HashMap::new(),
            auto_eject_timeout: None,
            challenge_response_timeout: None,
            device_flags: None,
            nfc_restricted: None,
        },
        serial,
        version: ver,
        form_factor: ff,
        supported_capabilities: supported,
        is_locked: false,
        is_fips,
        is_sky,
        part_number: None,
        fips_capable: Capability::NONE,
        fips_approved: Capability::NONE,
        pin_complexity,
        reset_blocked: Capability::NONE,
        fps_version: None,
        stm_version: None,
        version_qualifier: VersionQualifier::final_release(ver),
    };

    let _ = py;
    Ok(device::get_name(&info))
}

/// Scan USB for attached YubiKeys without opening connections.
///
/// Returns (pid_counts, state) where pid_counts maps PID to count
/// and state is a hash that changes when attached devices change.
#[pyfunction]
pub fn scan_devices(py: Python<'_>) -> PyResult<PyObject> {
    let (counts, state) = device::scan_usb_devices();
    let dict = PyDict::new(py);
    for (pid, count) in counts {
        dict.set_item(pid, count)?;
    }
    Ok((dict.into_any(), state).into_pyobject(py)?.into())
}

/// A YubiKey device discovered via native enumeration.
#[pyclass(unsendable)]
pub struct NativeYubiKeyDevice {
    inner: device::LocalYubiKeyDevice,
}

#[pymethods]
impl NativeYubiKeyDevice {
    /// Get the device info as a dict.
    fn info(&self, py: Python<'_>) -> PyResult<PyObject> {
        device_info_to_dict(py, self.inner.info())
    }

    /// Get the USB PID.
    #[getter]
    fn pid(&self) -> Option<u16> {
        self.inner.pid()
    }

    /// Get the transport type ("usb" or "nfc").
    #[getter]
    fn transport(&self) -> &'static str {
        match self.inner.transport() {
            yubikit::core::Transport::Usb => "usb",
            yubikit::core::Transport::Nfc => "nfc",
        }
    }

    /// Get the product name.
    #[getter]
    fn name(&self) -> String {
        self.inner.name()
    }

    /// Get the USB interfaces bitmask.
    #[getter]
    fn usb_interfaces(&self) -> u8 {
        self.inner.usb_interfaces().0
    }

    /// Wait for the user to remove and reinsert this YubiKey.
    ///
    /// `status_cb` is called with "remove" and then "reinsert".
    /// `cancelled_cb` is called periodically; return True to cancel.
    fn reinsert(
        &mut self,
        py: Python<'_>,
        status_cb: PyObject,
        cancelled_cb: PyObject,
    ) -> PyResult<()> {
        self.inner
            .reinsert(
                &|status| {
                    let status_str = match status {
                        device::ReinsertStatus::Remove => "remove",
                        device::ReinsertStatus::Reinsert => "reinsert",
                    };
                    Python::with_gil(|py| {
                        let _ = status_cb.call1(py, (status_str,));
                    });
                },
                &|| {
                    // Release the GIL while sleeping in Rust, but acquire
                    // it briefly to call the Python cancellation check.
                    Python::with_gil(|py| {
                        cancelled_cb
                            .call0(py)
                            .and_then(|r| r.extract::<bool>(py))
                            .unwrap_or(false)
                    })
                },
            )
            .map_err(device_err)?;
        let _ = py;
        Ok(())
    }
}

/// List all connected YubiKeys with device info.
///
/// `transports` is a list of transport names: "ccid", "otp", "fido".
/// Scans the requested transports, merges by PID and identity.
/// Returns a list of NativeYubiKeyDevice.
#[pyfunction]
pub fn list_devices(transports: Vec<String>) -> PyResult<Vec<NativeYubiKeyDevice>> {
    let mut interfaces = management::UsbInterface(0);
    for t in &transports {
        match t.as_str() {
            "ccid" => interfaces = interfaces | management::UsbInterface::CCID,
            "otp" => interfaces = interfaces | management::UsbInterface::OTP,
            "fido" => interfaces = interfaces | management::UsbInterface::FIDO,
            _ => {
                return Err(PyRuntimeError::new_err(format!("Unknown transport: {t}")));
            }
        }
    }
    let devices = device::list_devices(interfaces).map_err(device_err)?;
    Ok(devices
        .into_iter()
        .map(|d| NativeYubiKeyDevice { inner: d })
        .collect())
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "device")?;
    m.add_function(wrap_pyfunction!(read_info, &m)?)?;
    m.add_function(wrap_pyfunction!(get_name, &m)?)?;
    m.add_function(wrap_pyfunction!(scan_devices, &m)?)?;
    m.add_function(wrap_pyfunction!(list_devices, &m)?)?;
    m.add_class::<NativeYubiKeyDevice>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.device", &m)?;

    Ok(())
}
