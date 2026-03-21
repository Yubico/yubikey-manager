use pyo3::prelude::*;
use yubikit_rs::scp;

#[pyfunction]
#[pyo3(signature = (key, t, context, l=0x80))]
fn scp_derive(key: &[u8], t: u8, context: &[u8], l: u16) -> PyResult<Vec<u8>> {
    scp::scp03_derive(key, t, context, l)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn scp_calculate_mac(key: &[u8], chain: &[u8], message: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let (new_chain, mac) = scp::scp03_calculate_mac(key, chain, message)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok((new_chain.to_vec(), mac.to_vec()))
}

#[pyfunction]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    scp::constant_time_eq(a, b)
}

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
    ) -> Self {
        ScpState {
            inner: scp::ScpState::new(key_senc, key_smac, key_srmac, mac_chain, enc_counter),
        }
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
    m.add_function(wrap_pyfunction!(scp_derive, &m)?)?;
    m.add_function(wrap_pyfunction!(scp_calculate_mac, &m)?)?;
    m.add_function(wrap_pyfunction!(constant_time_eq, &m)?)?;
    m.add_class::<ScpState>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.scp", &m)?;

    Ok(())
}
