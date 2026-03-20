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

use hidapi::HidApi;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

const YUBICO_VID: u16 = 0x1050;

// OTP HID usage: usage_page=1 (Generic Desktop), usage=6 (Keyboard)
const USAGE_PAGE_OTP: u16 = 0x0001;
const USAGE_OTP: u16 = 0x0006;

fn hid_err(e: hidapi::HidError) -> PyErr {
    PyOSError::new_err(format!("HID error: {e}"))
}

/// Information about an enumerated HID device.
#[pyclass]
#[derive(Clone)]
struct HidDeviceInfo {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    pid: u16,
}

/// List Yubico OTP HID devices, returning (path, pid) info for each.
#[pyfunction]
fn list_otp_devices() -> PyResult<Vec<HidDeviceInfo>> {
    let api = HidApi::new().map_err(hid_err)?;
    let mut devices = Vec::new();
    for dev in api.device_list() {
        if dev.vendor_id() == YUBICO_VID
            && dev.usage_page() == USAGE_PAGE_OTP
            && dev.usage() == USAGE_OTP
        {
            devices.push(HidDeviceInfo {
                path: dev.path().to_string_lossy().into_owned(),
                pid: dev.product_id(),
            });
        }
    }
    Ok(devices)
}

/// List all Yubico HID devices regardless of usage page.
/// Returns (path, pid) for each device. Used for device scanning without opening.
#[pyfunction]
fn list_all_hid_devices() -> PyResult<Vec<HidDeviceInfo>> {
    let api = HidApi::new().map_err(hid_err)?;
    let mut devices = Vec::new();
    for dev in api.device_list() {
        if dev.vendor_id() == YUBICO_VID {
            devices.push(HidDeviceInfo {
                path: dev.path().to_string_lossy().into_owned(),
                pid: dev.product_id(),
            });
        }
    }
    Ok(devices)
}

/// An open connection to an OTP HID device for feature report I/O.
#[pyclass(unsendable)]
struct HidConnection {
    device: Option<hidapi::HidDevice>,
}

#[pymethods]
impl HidConnection {
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        let api = HidApi::new().map_err(hid_err)?;
        let cpath = std::ffi::CString::new(path)
            .map_err(|_| PyOSError::new_err("Invalid device path"))?;
        let device = api.open_path(&cpath).map_err(hid_err)?;
        Ok(Self {
            device: Some(device),
        })
    }

    /// Read an 8-byte feature report from the device.
    fn get_feature_report<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let dev = self.device.as_ref().ok_or_else(|| {
            PyOSError::new_err("Connection is closed")
        })?;
        // Report ID 0 + 8 bytes of data
        let mut buf = [0u8; 9];
        buf[0] = 0; // report ID
        let n = dev.get_feature_report(&mut buf).map_err(hid_err)?;
        // Return only the data portion (skip report ID byte)
        let start = if n > 0 && buf[0] == 0 { 1 } else { 0 };
        let end = n.min(buf.len());
        Ok(PyBytes::new(py, &buf[start..end]))
    }

    /// Write an 8-byte feature report to the device.
    fn set_feature_report(&self, data: &[u8]) -> PyResult<()> {
        let dev = self.device.as_ref().ok_or_else(|| {
            PyOSError::new_err("Connection is closed")
        })?;
        // Prepend report ID 0
        let mut buf = vec![0u8; data.len() + 1];
        buf[0] = 0; // report ID
        buf[1..].copy_from_slice(data);
        dev.send_feature_report(&buf).map_err(hid_err)?;
        Ok(())
    }

    fn close(&mut self) -> PyResult<()> {
        self.device.take();
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.close()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "hid")?;
    sub.add_function(wrap_pyfunction!(list_otp_devices, &sub)?)?;
    sub.add_function(wrap_pyfunction!(list_all_hid_devices, &sub)?)?;
    sub.add_class::<HidDeviceInfo>()?;
    sub.add_class::<HidConnection>()?;
    m.add_submodule(&sub)?;

    // Register in sys.modules so `from _ykman_native.hid import ...` works
    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.hid", &sub)?;

    Ok(())
}
