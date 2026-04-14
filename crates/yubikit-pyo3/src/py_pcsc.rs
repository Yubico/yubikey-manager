use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit::smartcard::SmartCardConnection;
use yubikit::transport::pcsc;

fn pcsc_err(e: pcsc::PcscError) -> PyErr {
    PyOSError::new_err(e.to_string())
}

#[pyfunction]
fn list_readers() -> PyResult<Vec<String>> {
    pcsc::list_readers().map_err(pcsc_err)
}

#[pyclass]
pub struct PcscConnection {
    inner: Option<pcsc::PcscSmartCardConnection>,
}

impl PcscConnection {
    /// Take the inner native connection, leaving None behind.
    pub fn take_inner(&mut self) -> PyResult<pcsc::PcscSmartCardConnection> {
        self.inner
            .take()
            .ok_or_else(|| PyOSError::new_err("PCSC connection already consumed or closed"))
    }

    /// Restore a previously taken inner connection.
    pub fn restore_inner(&mut self, conn: pcsc::PcscSmartCardConnection) {
        self.inner = Some(conn);
    }
}

#[pymethods]
impl PcscConnection {
    #[new]
    #[pyo3(signature = (reader_name, exclusive=true))]
    fn new(reader_name: &str, exclusive: bool) -> PyResult<Self> {
        Ok(Self {
            inner: Some(
                pcsc::PcscSmartCardConnection::new(reader_name, exclusive).map_err(pcsc_err)?,
            ),
        })
    }

    /// Open a connection with automatic exclusive→shared fallback and
    /// scdaemon/yubikey-agent kill-retry logic.
    #[staticmethod]
    fn open(reader_name: &str) -> PyResult<Self> {
        Ok(Self {
            inner: Some(pcsc::PcscSmartCardConnection::open(reader_name).map_err(pcsc_err)?),
        })
    }

    fn get_atr<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let conn = self
            .inner
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        let atr = conn.get_atr().map_err(pcsc_err)?;
        Ok(PyBytes::new(py, &atr))
    }

    fn transmit<'py>(&self, py: Python<'py>, apdu: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let conn = self
            .inner
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        let resp = conn.transmit(apdu).map_err(pcsc_err)?;
        Ok(PyBytes::new(py, &resp))
    }

    fn disconnect(&mut self) -> PyResult<()> {
        let conn = self
            .inner
            .as_mut()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        conn.disconnect().map_err(pcsc_err)
    }

    #[pyo3(signature = (exclusive=false))]
    fn connect(&mut self, exclusive: bool) -> PyResult<()> {
        let conn = self
            .inner
            .as_mut()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        conn.connect(exclusive).map_err(pcsc_err)
    }

    #[pyo3(signature = (exclusive=true))]
    fn reconnect(&mut self, exclusive: bool) -> PyResult<()> {
        let conn = self
            .inner
            .as_mut()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        conn.reconnect(exclusive).map_err(pcsc_err)
    }

    /// Get the detected transport type ("usb" or "nfc").
    #[getter]
    fn transport(&self) -> PyResult<&'static str> {
        let conn = self
            .inner
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        Ok(match conn.transport() {
            yubikit::core::Transport::Usb => "usb",
            yubikit::core::Transport::Nfc => "nfc",
        })
    }

    fn close(&mut self) {
        self.inner.take();
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
        self.close();
        Ok(())
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
