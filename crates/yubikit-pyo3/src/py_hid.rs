use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit::transport::ctaphid;
use yubikit::transport::otphid as hid;

fn hid_err(e: hid::HidError) -> PyErr {
    PyOSError::new_err(e.to_string())
}

#[pyclass]
#[derive(Clone)]
struct HidDeviceInfo {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    pid: u16,
}

#[pyfunction]
fn list_otp_devices() -> PyResult<Vec<HidDeviceInfo>> {
    hid::list_otp_devices()
        .map(|devs| {
            devs.into_iter()
                .map(|d| HidDeviceInfo {
                    path: d.path,
                    pid: d.pid,
                })
                .collect()
        })
        .map_err(hid_err)
}

#[pyfunction]
fn list_all_hid_devices() -> PyResult<Vec<HidDeviceInfo>> {
    hid::list_all_hid_devices()
        .map(|devs| {
            devs.into_iter()
                .map(|d| HidDeviceInfo {
                    path: d.path,
                    pid: d.pid,
                })
                .collect()
        })
        .map_err(hid_err)
}

#[pyclass(unsendable)]
pub struct OtpConnection {
    inner: Option<hid::HidOtpConnection>,
}

impl OtpConnection {
    /// Take the inner native connection, leaving None behind.
    pub fn take_inner(&mut self) -> PyResult<hid::HidOtpConnection> {
        self.inner
            .take()
            .ok_or_else(|| PyOSError::new_err("OTP connection already consumed or closed"))
    }

    /// Restore a previously taken inner connection.
    pub fn restore_inner(&mut self, conn: hid::HidOtpConnection) {
        self.inner = Some(conn);
    }

    /// Create from an already-open native connection.
    pub fn from_native(conn: hid::HidOtpConnection) -> Self {
        Self { inner: Some(conn) }
    }
}

#[pymethods]
impl OtpConnection {
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: Some(hid::HidOtpConnection::new(path).map_err(hid_err)?),
        })
    }

    fn get_feature_report<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let conn = self
            .inner
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        let data = conn.get_feature_report().map_err(hid_err)?;
        Ok(PyBytes::new(py, &data))
    }

    fn set_feature_report(&self, data: &[u8]) -> PyResult<()> {
        let conn = self
            .inner
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        conn.set_feature_report(data).map_err(hid_err)
    }

    fn close(&mut self) -> PyResult<()> {
        if let Some(mut conn) = self.inner.take() {
            conn.close();
        }
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

// ---------------------------------------------------------------------------
// FIDO HID (CTAP)
// ---------------------------------------------------------------------------

fn ctap_err(e: ctaphid::CtapHidTransportError) -> PyErr {
    PyOSError::new_err(e.to_string())
}

#[pyclass]
#[derive(Clone)]
pub struct FidoDeviceInfo {
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub pid: u16,
}

#[pyfunction]
fn list_fido_devices() -> PyResult<Vec<FidoDeviceInfo>> {
    ctaphid::list_fido_devices()
        .map(|devs| {
            devs.into_iter()
                .map(|d| FidoDeviceInfo {
                    path: d.path,
                    pid: d.pid,
                })
                .collect()
        })
        .map_err(ctap_err)
}

/// Native FIDO HID connection wrapping the Rust CTAP HID transport.
#[pyclass(unsendable)]
pub struct FidoConnection {
    inner: Option<ctaphid::HidFidoConnection>,
    path: String,
    device_version: (u8, u8, u8),
    capabilities: u8,
}

impl FidoConnection {
    /// Take the inner native connection, leaving None behind.
    pub fn take_inner(&mut self) -> PyResult<ctaphid::HidFidoConnection> {
        self.inner
            .take()
            .ok_or_else(|| PyOSError::new_err("FIDO connection already consumed or closed"))
    }

    /// Restore a previously taken inner connection.
    pub fn restore_inner(&mut self, conn: ctaphid::HidFidoConnection) {
        self.inner = Some(conn);
    }

    /// Create from an already-open native connection.
    pub fn from_native(conn: ctaphid::HidFidoConnection) -> Self {
        let device_version = conn.device_version();
        let capabilities = conn.capabilities().raw();
        Self {
            inner: Some(conn),
            path: String::new(),
            device_version,
            capabilities,
        }
    }
}

#[pymethods]
impl FidoConnection {
    #[new]
    fn new(path: &str, pid: u16) -> PyResult<Self> {
        let info = ctaphid::FidoDeviceInfo {
            path: path.to_string(),
            pid,
            report_size_in: 64,
            report_size_out: 64,
        };
        let conn = ctaphid::HidFidoConnection::open(&info).map_err(ctap_err)?;
        let device_version = conn.device_version();
        let capabilities = conn.capabilities().raw();
        Ok(Self {
            inner: Some(conn),
            path: path.to_string(),
            device_version,
            capabilities,
        })
    }

    /// Send a CTAP HID command and receive the response.
    fn call<'py>(&self, py: Python<'py>, cmd: u8, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let conn = self
            .inner
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        let response = conn.call(cmd, data).map_err(ctap_err)?;
        Ok(PyBytes::new(py, &response))
    }

    #[getter]
    fn device_version(&self) -> (u8, u8, u8) {
        self.device_version
    }

    #[getter]
    fn capabilities(&self) -> u8 {
        self.capabilities
    }

    #[getter]
    fn path(&self) -> &str {
        &self.path
    }

    fn close(&mut self) -> PyResult<()> {
        if let Some(mut conn) = self.inner.take() {
            conn.close();
        }
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
    sub.add_function(wrap_pyfunction!(list_fido_devices, &sub)?)?;
    sub.add_class::<HidDeviceInfo>()?;
    sub.add_class::<OtpConnection>()?;
    sub.add_class::<FidoDeviceInfo>()?;
    sub.add_class::<FidoConnection>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.hid", &sub)?;

    Ok(())
}
