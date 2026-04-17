use pyo3::prelude::*;
use yubikit::scp;

#[pyclass]
struct ScpState {
    inner: scp::ScpState,
}

#[pymethods]
impl ScpState {
    #[new]
    #[pyo3(signature = (key_senc, key_smac, key_srmac, mac_chain=None, enc_counter=1))]
    fn new(
        key_senc: Vec<u8>,
        key_smac: Vec<u8>,
        key_srmac: Vec<u8>,
        mac_chain: Option<Vec<u8>>,
        enc_counter: Option<u32>,
    ) -> PyResult<Self> {
        let key_senc: [u8; 16] = key_senc
            .as_slice()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_senc must be 16 bytes"))?;
        let key_smac: [u8; 16] = key_smac
            .as_slice()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_smac must be 16 bytes"))?;
        let key_srmac: [u8; 16] = key_srmac
            .as_slice()
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_srmac must be 16 bytes"))?;
        Ok(ScpState {
            inner: scp::ScpState::new(key_senc, key_smac, key_srmac, mac_chain, enc_counter),
        })
    }

    fn encrypt(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .encrypt(data)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    fn mac(&mut self, data: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .mac(data)
            .map(|m| m.to_vec())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    fn unmac(&self, data: &[u8], sw: u16) -> PyResult<Vec<u8>> {
        self.inner
            .unmac(data, sw)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn decrypt(&self, encrypted: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .decrypt(encrypted)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "scp")?;
    m.add_class::<ScpState>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.scp", &m)?;

    Ok(())
}
