use pyo3::prelude::*;
use yubikit::oath;

#[pyfunction]
fn format_cred_id(
    issuer: Option<&str>,
    name: &str,
    oath_type: u8,
    period: u32,
) -> PyResult<Vec<u8>> {
    let ot = oath::OathType::from_u8(oath_type)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid OATH type"))?;
    Ok(oath::format_cred_id(issuer, name, ot, period))
}

#[pyfunction]
fn parse_cred_id(cred_id: &[u8], oath_type: u8) -> PyResult<(Option<String>, String, u32)> {
    let ot = oath::OathType::from_u8(oath_type)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid OATH type"))?;
    Ok(oath::parse_cred_id(cred_id, ot))
}

#[pyfunction]
fn get_device_id(salt: &[u8]) -> String {
    oath::get_device_id(salt)
}

#[pyfunction]
fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    oath::hmac_sha1(key, message)
}

#[pyfunction]
fn hmac_verify(key: &[u8], message: &[u8], expected: &[u8]) -> bool {
    oath::hmac_verify(key, message, expected)
}

#[pyfunction]
fn derive_key(salt: &[u8], passphrase: &str) -> Vec<u8> {
    oath::derive_key(salt, passphrase)
}

#[pyfunction]
fn hmac_shorten_key(key: &[u8], algo: u8) -> PyResult<Vec<u8>> {
    let ha = oath::HashAlgorithm::from_u8(algo)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid hash algorithm"))?;
    Ok(oath::hmac_shorten_key(key, ha))
}

#[pyfunction]
fn get_challenge(timestamp: u64, period: u32) -> [u8; 8] {
    oath::get_challenge(timestamp, period)
}

#[pyfunction]
fn format_code(
    oath_type: u8,
    period: u32,
    timestamp: u64,
    truncated: &[u8],
) -> PyResult<(String, u64, u64)> {
    let ot = oath::OathType::from_u8(oath_type)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid OATH type"))?;
    Ok(oath::format_code(ot, period, timestamp, truncated))
}

#[pyfunction]
fn build_put_data(
    cred_id: &[u8],
    oath_type: u8,
    hash_algorithm: u8,
    digits: u8,
    secret: &[u8],
    touch_required: bool,
    counter: u32,
) -> PyResult<Vec<u8>> {
    let ot = oath::OathType::from_u8(oath_type)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid OATH type"))?;
    let ha = oath::HashAlgorithm::from_u8(hash_algorithm)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid hash algorithm"))?;
    Ok(oath::build_put_data(
        cred_id, ot, ha, digits, secret, touch_required, counter,
    ))
}

#[pyfunction]
fn build_set_key_data(key: &[u8], challenge: &[u8]) -> Vec<u8> {
    oath::build_set_key_data(key, challenge)
}

#[pyfunction]
fn build_validate_data(key: &[u8], device_challenge: &[u8], host_challenge: &[u8]) -> Vec<u8> {
    oath::build_validate_data(key, device_challenge, host_challenge)
}

#[pyfunction]
fn parse_list_entry(data: &[u8]) -> PyResult<(u8, Vec<u8>)> {
    let (oath_type, cred_id) = oath::parse_list_entry(data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok((oath_type as u8, cred_id))
}

#[pyfunction]
fn parse_b32_key(key: &str) -> PyResult<Vec<u8>> {
    oath::parse_b32_key(key)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "oath")?;
    m.add_function(wrap_pyfunction!(format_cred_id, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_cred_id, &m)?)?;
    m.add_function(wrap_pyfunction!(get_device_id, &m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha1, &m)?)?;
    m.add_function(wrap_pyfunction!(hmac_verify, &m)?)?;
    m.add_function(wrap_pyfunction!(derive_key, &m)?)?;
    m.add_function(wrap_pyfunction!(hmac_shorten_key, &m)?)?;
    m.add_function(wrap_pyfunction!(get_challenge, &m)?)?;
    m.add_function(wrap_pyfunction!(format_code, &m)?)?;
    m.add_function(wrap_pyfunction!(build_put_data, &m)?)?;
    m.add_function(wrap_pyfunction!(build_set_key_data, &m)?)?;
    m.add_function(wrap_pyfunction!(build_validate_data, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_list_entry, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_b32_key, &m)?)?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.oath", &m)?;

    Ok(())
}
