// Copyright (c) 2026 Yubico AB
// All rights reserved.
//
//   Redistribution and use in source and binary forms, with or
//   without modification, are permitted provided that the following
//   conditions are met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//    2. Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use yubikit_rs::device;
use crate::py_management_session::device_info_to_dict;

fn device_err(e: device::DeviceError) -> PyErr {
    PyRuntimeError::new_err(format!("{e}"))
}

/// Read device info from a PC/SC reader name.
///
/// Returns a dict matching the Python DeviceInfo structure.
#[pyfunction]
pub fn read_info(py: Python<'_>, reader_name: &str) -> PyResult<PyObject> {
    let info = device::read_info(reader_name).map_err(device_err)?;
    device_info_to_dict(py, &info)
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
    use yubikit_rs::iso7816::{Transport, Version};
    use yubikit_rs::management::{
        Capability, DeviceConfig, DeviceInfo, FormFactor, VersionQualifier,
    };

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

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "device")?;
    m.add_function(wrap_pyfunction!(read_info, &m)?)?;
    m.add_function(wrap_pyfunction!(get_name, &m)?)?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.device", &m)?;

    Ok(())
}
