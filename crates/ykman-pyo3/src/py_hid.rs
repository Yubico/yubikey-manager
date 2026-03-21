use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit_rs::transport::hid;

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
struct HidConnection {
    inner: hid::HidConnection,
}

#[pymethods]
impl HidConnection {
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: hid::HidConnection::new(path).map_err(hid_err)?,
        })
    }

    fn get_feature_report<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.inner.get_feature_report().map_err(hid_err)?;
        Ok(PyBytes::new(py, &data))
    }

    fn set_feature_report(&self, data: &[u8]) -> PyResult<()> {
        self.inner.set_feature_report(data).map_err(hid_err)
    }

    fn close(&mut self) -> PyResult<()> {
        self.inner.close();
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

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.hid", &sub)?;

    Ok(())
}
