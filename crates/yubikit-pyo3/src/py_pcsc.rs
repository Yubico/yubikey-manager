use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit::transport::pcsc;

fn pcsc_err(e: pcsc::PcscError) -> PyErr {
    PyOSError::new_err(e.to_string())
}

#[pyfunction]
fn list_readers() -> PyResult<Vec<String>> {
    pcsc::list_readers().map_err(pcsc_err)
}

#[pyclass]
struct PcscConnection {
    inner: pcsc::PcscConnection,
}

#[pymethods]
impl PcscConnection {
    #[new]
    #[pyo3(signature = (reader_name, exclusive=true))]
    fn new(reader_name: &str, exclusive: bool) -> PyResult<Self> {
        Ok(Self {
            inner: pcsc::PcscConnection::new(reader_name, exclusive).map_err(pcsc_err)?,
        })
    }

    fn get_atr<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let atr = self.inner.get_atr().map_err(pcsc_err)?;
        Ok(PyBytes::new(py, &atr))
    }

    fn transmit<'py>(&self, py: Python<'py>, apdu: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let resp = self.inner.transmit(apdu).map_err(pcsc_err)?;
        Ok(PyBytes::new(py, &resp))
    }

    fn disconnect(&mut self) -> PyResult<()> {
        self.inner.disconnect().map_err(pcsc_err)
    }

    #[pyo3(signature = (exclusive=false))]
    fn connect(&mut self, exclusive: bool) -> PyResult<()> {
        self.inner.connect(exclusive).map_err(pcsc_err)
    }

    #[pyo3(signature = (exclusive=true))]
    fn reconnect(&mut self, exclusive: bool) -> PyResult<()> {
        self.inner.reconnect(exclusive).map_err(pcsc_err)
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
        self.disconnect()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "pcsc")?;
    sub.add_function(wrap_pyfunction!(list_readers, &sub)?)?;
    sub.add_class::<PcscConnection>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.pcsc", &sub)?;

    Ok(())
}
