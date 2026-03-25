use pyo3::prelude::*;
use yubikit::{core_types, smartcard, otp, tlv};

#[pyfunction]
fn calculate_crc(data: &[u8]) -> u16 {
    otp::calculate_crc(data)
}

#[pyfunction]
fn check_crc(data: &[u8]) -> bool {
    otp::check_crc(data)
}

#[pyfunction]
fn modhex_encode(data: &[u8]) -> String {
    otp::modhex_encode(data)
}

#[pyfunction]
fn modhex_decode(string: &str) -> PyResult<Vec<u8>> {
    otp::modhex_decode(string).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (data, offset=None))]
fn tlv_parse(data: &[u8], offset: Option<usize>) -> PyResult<(u32, usize, usize, usize)> {
    tlv::tlv_parse(data, offset.unwrap_or(0))
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn tlv_encode(tag: u32, value: &[u8]) -> Vec<u8> {
    tlv::tlv_encode(tag, value)
}

#[pyfunction]
#[pyo3(signature = (value, min_len=1))]
fn int2bytes<'py>(value: &Bound<'py, PyAny>, min_len: usize) -> PyResult<Bound<'py, PyAny>> {
    let bit_length: usize = value.call_method0("bit_length")?.extract()?;
    let byte_len = std::cmp::max(min_len, (bit_length + 7) / 8);
    value.call_method1("to_bytes", (byte_len, "big"))
}

#[pyfunction]
fn bytes2int<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let int_type = py.get_type::<pyo3::types::PyInt>();
    int_type.call_method1("from_bytes", (data, "big"))
}

#[pyfunction]
fn oid_to_string(data: &[u8]) -> PyResult<String> {
    tlv::oid_to_string(data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn oid_from_string(data: &str) -> PyResult<Vec<u8>> {
    tlv::oid_from_string(data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn format_short_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u8) -> PyResult<Vec<u8>> {
    smartcard::format_short_apdu(cla, ins, p1, p2, data, le)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn format_extended_apdu(
    cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u16, max_apdu_size: usize,
) -> PyResult<Vec<u8>> {
    smartcard::format_extended_apdu(cla, ins, p1, p2, data, le, max_apdu_size)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn set_override_version(major: u8, minor: u8, patch: u8) {
    core_types::set_override_version(core_types::Version(major, minor, patch));
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "core")?;
    m.add_function(wrap_pyfunction!(calculate_crc, &m)?)?;
    m.add_function(wrap_pyfunction!(check_crc, &m)?)?;
    m.add_function(wrap_pyfunction!(modhex_encode, &m)?)?;
    m.add_function(wrap_pyfunction!(modhex_decode, &m)?)?;
    m.add_function(wrap_pyfunction!(tlv_parse, &m)?)?;
    m.add_function(wrap_pyfunction!(tlv_encode, &m)?)?;
    m.add_function(wrap_pyfunction!(int2bytes, &m)?)?;
    m.add_function(wrap_pyfunction!(bytes2int, &m)?)?;
    m.add_function(wrap_pyfunction!(oid_to_string, &m)?)?;
    m.add_function(wrap_pyfunction!(oid_from_string, &m)?)?;
    m.add_function(wrap_pyfunction!(format_short_apdu, &m)?)?;
    m.add_function(wrap_pyfunction!(format_extended_apdu, &m)?)?;
    m.add_function(wrap_pyfunction!(set_override_version, &m)?)?;
    m.add_class::<crate::py_smartcard_protocol::SmartCardProtocol>()?;
    m.add_class::<crate::py_otp_protocol::OtpProtocol>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.core", &m)?;

    Ok(())
}
