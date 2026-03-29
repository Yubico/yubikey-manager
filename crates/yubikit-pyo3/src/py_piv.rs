use pyo3::prelude::*;
use yubikit::piv::{
    self, KeyType, ManagementKeyType, PinPolicy, PivSession as RustPivSession, Slot, TouchPolicy,
};

use crate::py_bridge::{PySmartCardConnection, scp_key_params_from_py, smartcard_err};

fn piv_err(e: piv::PivError) -> PyErr {
    use pyo3::exceptions::*;
    match e {
        piv::PivError::SmartCard(sc) => smartcard_err(sc),
        piv::PivError::InvalidPin(retries) => {
            Python::with_gil(|py| match py.import("yubikit.core") {
                Ok(module) => match module.getattr("InvalidPinError") {
                    Ok(cls) => match cls.call1((retries,)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyValueError::new_err(format!(
                            "Invalid PIN, {} attempts remaining",
                            retries
                        )),
                    },
                    Err(_) => PyValueError::new_err(format!(
                        "Invalid PIN, {} attempts remaining",
                        retries
                    )),
                },
                Err(_) => {
                    PyValueError::new_err(format!("Invalid PIN, {} attempts remaining", retries))
                }
            })
        }
        piv::PivError::NotSupported(msg) => {
            Python::with_gil(|py| match py.import("yubikit.core") {
                Ok(module) => match module.getattr("NotSupportedError") {
                    Ok(cls) => match cls.call1((msg.clone(),)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyRuntimeError::new_err(msg),
                    },
                    Err(_) => PyRuntimeError::new_err(msg),
                },
                Err(_) => PyRuntimeError::new_err(msg),
            })
        }
        piv::PivError::BadResponse(msg) => Python::with_gil(|py| match py.import("yubikit.core") {
            Ok(module) => match module.getattr("BadResponseError") {
                Ok(cls) => match cls.call1((msg.clone(),)) {
                    Ok(exc) => PyErr::from_value(exc),
                    Err(_) => PyRuntimeError::new_err(msg),
                },
                Err(_) => PyRuntimeError::new_err(msg),
            },
            Err(_) => PyRuntimeError::new_err(msg),
        }),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

fn parse_slot(v: u8) -> PyResult<Slot> {
    Slot::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid slot: 0x{:02X}", v))
    })
}

fn parse_key_type(v: u8) -> PyResult<KeyType> {
    KeyType::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid key type: 0x{:02X}", v))
    })
}

fn parse_mgmt_key_type(v: u8) -> PyResult<ManagementKeyType> {
    ManagementKeyType::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid management key type: 0x{:02X}", v))
    })
}

fn parse_pin_policy(v: u8) -> PyResult<PinPolicy> {
    PinPolicy::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid pin policy: 0x{:02X}", v))
    })
}

fn parse_touch_policy(v: u8) -> PyResult<TouchPolicy> {
    TouchPolicy::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid touch policy: 0x{:02X}", v))
    })
}

#[pyclass]
pub struct PivSession {
    inner: RustPivSession<PySmartCardConnection>,
}

#[pymethods]
impl PivSession {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(
        connection: &Bound<'_, PyAny>,
        scp_key_params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        if let Some(params) = scp_key_params {
            let scp_params = scp_key_params_from_py(params)?;
            let inner =
                RustPivSession::new_with_scp(conn, &scp_params).map_err(|(e, _)| piv_err(e))?;
            Ok(Self { inner })
        } else {
            let inner = RustPivSession::new(conn).map_err(|(e, _)| piv_err(e))?;
            Ok(Self { inner })
        }
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.inner.version();
        (v.0, v.1, v.2)
    }

    #[getter]
    fn management_key_type(&self) -> u8 {
        self.inner.management_key_type() as u8
    }

    fn reset(&mut self) -> PyResult<()> {
        self.inner.reset().map_err(piv_err)
    }

    fn get_serial(&mut self) -> PyResult<u32> {
        self.inner.get_serial().map_err(piv_err)
    }

    fn authenticate(&mut self, management_key: &[u8]) -> PyResult<()> {
        self.inner.authenticate(management_key).map_err(piv_err)
    }

    fn set_management_key(
        &mut self,
        key_type: u8,
        management_key: &[u8],
        require_touch: bool,
    ) -> PyResult<()> {
        let kt = parse_mgmt_key_type(key_type)?;
        self.inner
            .set_management_key(kt, management_key, require_touch)
            .map_err(piv_err)
    }

    fn verify_pin(&mut self, pin: &str) -> PyResult<()> {
        self.inner.verify_pin(pin).map_err(piv_err)
    }

    #[pyo3(signature = (temporary_pin=false, check_only=false))]
    fn verify_uv(&mut self, temporary_pin: bool, check_only: bool) -> PyResult<Option<Vec<u8>>> {
        self.inner
            .verify_uv(temporary_pin, check_only)
            .map_err(piv_err)
    }

    fn verify_temporary_pin(&mut self, pin: &[u8]) -> PyResult<()> {
        self.inner.verify_temporary_pin(pin).map_err(piv_err)
    }

    fn get_pin_attempts(&mut self) -> PyResult<u32> {
        self.inner.get_pin_attempts().map_err(piv_err)
    }

    fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> PyResult<()> {
        self.inner.change_pin(old_pin, new_pin).map_err(piv_err)
    }

    fn change_puk(&mut self, old_puk: &str, new_puk: &str) -> PyResult<()> {
        self.inner.change_puk(old_puk, new_puk).map_err(piv_err)
    }

    fn unblock_pin(&mut self, puk: &str, new_pin: &str) -> PyResult<()> {
        self.inner.unblock_pin(puk, new_pin).map_err(piv_err)
    }

    fn set_pin_attempts(&mut self, pin_attempts: u8, puk_attempts: u8) -> PyResult<()> {
        self.inner
            .set_pin_attempts(pin_attempts, puk_attempts)
            .map_err(piv_err)
    }

    /// Returns (default_value, total_attempts, attempts_remaining).
    fn get_pin_metadata(&mut self) -> PyResult<(bool, u32, u32)> {
        let m = self.inner.get_pin_metadata().map_err(piv_err)?;
        Ok((m.default_value, m.total_attempts, m.attempts_remaining))
    }

    /// Returns (default_value, total_attempts, attempts_remaining).
    fn get_puk_metadata(&mut self) -> PyResult<(bool, u32, u32)> {
        let m = self.inner.get_puk_metadata().map_err(piv_err)?;
        Ok((m.default_value, m.total_attempts, m.attempts_remaining))
    }

    /// Returns (key_type, default_value, touch_policy).
    fn get_management_key_metadata(&mut self) -> PyResult<(u8, bool, u8)> {
        let m = self.inner.get_management_key_metadata().map_err(piv_err)?;
        Ok((m.key_type as u8, m.default_value, m.touch_policy as u8))
    }

    /// Returns (key_type, pin_policy, touch_policy, generated, public_key_der).
    fn get_slot_metadata(&mut self, slot: u8) -> PyResult<(u8, u8, u8, bool, Vec<u8>)> {
        let s = parse_slot(slot)?;
        let m = self.inner.get_slot_metadata(s).map_err(piv_err)?;
        Ok((
            m.key_type as u8,
            m.pin_policy as u8,
            m.touch_policy as u8,
            m.generated,
            m.public_key_der,
        ))
    }

    /// Returns (configured, attempts_remaining, temporary_pin).
    fn get_bio_metadata(&mut self) -> PyResult<(bool, u32, bool)> {
        let m = self.inner.get_bio_metadata().map_err(piv_err)?;
        Ok((m.configured, m.attempts_remaining, m.temporary_pin))
    }

    /// Sign pre-processed data. Returns raw signature bytes.
    fn sign(&mut self, slot: u8, key_type: u8, message: &[u8]) -> PyResult<Vec<u8>> {
        let s = parse_slot(slot)?;
        let kt = parse_key_type(key_type)?;
        self.inner.sign(s, kt, message).map_err(piv_err)
    }

    fn decrypt(&mut self, slot: u8, cipher_text: &[u8]) -> PyResult<Vec<u8>> {
        let s = parse_slot(slot)?;
        self.inner.decrypt(s, cipher_text).map_err(piv_err)
    }

    fn calculate_secret(
        &mut self,
        slot: u8,
        key_type: u8,
        peer_public_key: &[u8],
    ) -> PyResult<Vec<u8>> {
        let s = parse_slot(slot)?;
        let kt = parse_key_type(key_type)?;
        self.inner
            .calculate_secret(s, kt, peer_public_key)
            .map_err(piv_err)
    }

    fn get_object(&mut self, object_id: u32) -> PyResult<Vec<u8>> {
        self.inner.get_object_raw(object_id).map_err(piv_err)
    }

    /// Put an object. Pass `None` to delete.
    fn put_object(&mut self, object_id: u32, data: Option<&[u8]>) -> PyResult<()> {
        self.inner.put_object_raw(object_id, data).map_err(piv_err)
    }

    /// Get certificate as DER bytes.
    fn get_certificate(&mut self, slot: u8) -> PyResult<Vec<u8>> {
        let s = parse_slot(slot)?;
        self.inner.get_certificate(s).map_err(piv_err)
    }

    fn put_certificate(&mut self, slot: u8, cert_der: &[u8], compress: bool) -> PyResult<()> {
        let s = parse_slot(slot)?;
        self.inner
            .put_certificate(s, cert_der, compress)
            .map_err(piv_err)
    }

    fn delete_certificate(&mut self, slot: u8) -> PyResult<()> {
        let s = parse_slot(slot)?;
        self.inner.delete_certificate(s).map_err(piv_err)
    }

    /// Import a private key. `key_der` is the raw key material.
    fn put_key(
        &mut self,
        slot: u8,
        key_type: u8,
        key_der: &[u8],
        pin_policy: u8,
        touch_policy: u8,
    ) -> PyResult<()> {
        let s = parse_slot(slot)?;
        let kt = parse_key_type(key_type)?;
        let pp = parse_pin_policy(pin_policy)?;
        let tp = parse_touch_policy(touch_policy)?;
        self.inner.put_key(s, kt, key_der, pp, tp).map_err(piv_err)
    }

    /// Generate a key pair. Returns public key bytes.
    fn generate_key(
        &mut self,
        slot: u8,
        key_type: u8,
        pin_policy: u8,
        touch_policy: u8,
    ) -> PyResult<Vec<u8>> {
        let s = parse_slot(slot)?;
        let kt = parse_key_type(key_type)?;
        let pp = parse_pin_policy(pin_policy)?;
        let tp = parse_touch_policy(touch_policy)?;
        self.inner.generate_key(s, kt, pp, tp).map_err(piv_err)
    }

    /// Attest a key in a slot. Returns DER certificate.
    fn attest_key(&mut self, slot: u8) -> PyResult<Vec<u8>> {
        let s = parse_slot(slot)?;
        self.inner.attest_key(s).map_err(piv_err)
    }

    fn move_key(&mut self, from_slot: u8, to_slot: u8) -> PyResult<()> {
        let f = parse_slot(from_slot)?;
        let t = parse_slot(to_slot)?;
        self.inner.move_key(f, t).map_err(piv_err)
    }

    fn delete_key(&mut self, slot: u8) -> PyResult<()> {
        let s = parse_slot(slot)?;
        self.inner.delete_key(s).map_err(piv_err)
    }

    fn check_key_support(
        &mut self,
        key_type: u8,
        pin_policy: u8,
        touch_policy: u8,
        generate: bool,
        fips_restrictions: bool,
    ) -> PyResult<()> {
        let kt = parse_key_type(key_type)?;
        let pp = parse_pin_policy(pin_policy)?;
        let tp = parse_touch_policy(touch_policy)?;
        self.inner
            .check_key_support(kt, pp, tp, generate, fips_restrictions)
            .map_err(piv_err)
    }
}
