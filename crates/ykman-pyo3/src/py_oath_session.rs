use pyo3::prelude::*;
use yubikey_mgmt::oath::{self, OathSession as RustOathSession};

use crate::py_bridge::{PySmartCardConnection, smartcard_err};

#[pyclass]
pub struct OathSession {
    inner: RustOathSession<PySmartCardConnection>,
}

#[pymethods]
impl OathSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        let inner = RustOathSession::new(conn).map_err(smartcard_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.inner.version();
        (v.0, v.1, v.2)
    }

    #[setter]
    fn set_version(&mut self, version: (u8, u8, u8)) {
        self.inner
            .set_version(yubikey_mgmt::iso7816::Version(version.0, version.1, version.2));
    }

    #[getter]
    fn device_id(&self) -> &str {
        self.inner.device_id()
    }

    #[getter]
    fn has_key(&self) -> bool {
        self.inner.has_key()
    }

    #[getter]
    fn locked(&self) -> bool {
        self.inner.locked()
    }

    fn reset(&mut self) -> PyResult<()> {
        self.inner.reset().map_err(smartcard_err)
    }

    fn derive_key(&self, password: &str) -> Vec<u8> {
        self.inner.derive_key(password)
    }

    fn validate(&mut self, key: &[u8]) -> PyResult<()> {
        self.inner.validate(key).map_err(smartcard_err)
    }

    fn set_key(&mut self, key: &[u8]) -> PyResult<()> {
        self.inner.set_key(key).map_err(smartcard_err)
    }

    fn unset_key(&mut self) -> PyResult<()> {
        self.inner.unset_key().map_err(smartcard_err)
    }

    /// Put a credential on the device.
    ///
    /// Returns (device_id, id, issuer, name, oath_type, period, touch_required).
    #[pyo3(signature = (name, oath_type, hash_algorithm, secret, digits, period, counter, issuer=None, touch_required=false))]
    fn put_credential(
        &mut self,
        name: &str,
        oath_type: u8,
        hash_algorithm: u8,
        secret: &[u8],
        digits: u8,
        period: u32,
        counter: u32,
        issuer: Option<&str>,
        touch_required: bool,
    ) -> PyResult<(String, Vec<u8>, Option<String>, String, u8, u32, Option<bool>)> {
        let ot = oath::OathType::from_u8(oath_type)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid OATH type"))?;
        let ha = oath::HashAlgorithm::from_u8(hash_algorithm)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid hash algorithm"))?;

        let cred_data = oath::CredentialData {
            name: name.to_string(),
            oath_type: ot,
            hash_algorithm: ha,
            secret: secret.to_vec(),
            digits,
            period,
            counter,
            issuer: issuer.map(|s| s.to_string()),
        };

        let cred = self
            .inner
            .put_credential(&cred_data, touch_required)
            .map_err(smartcard_err)?;

        Ok((
            cred.device_id,
            cred.id,
            cred.issuer,
            cred.name,
            cred.oath_type as u8,
            cred.period,
            cred.touch_required,
        ))
    }

    /// Rename a credential. Returns the new credential ID.
    fn rename_credential(
        &mut self,
        credential_id: &[u8],
        name: &str,
        issuer: Option<&str>,
    ) -> PyResult<Vec<u8>> {
        self.inner
            .rename_credential(credential_id, name, issuer)
            .map_err(smartcard_err)
    }

    /// List credentials.
    ///
    /// Returns list of (device_id, id, issuer, name, oath_type, period, touch_required).
    fn list_credentials(
        &mut self,
    ) -> PyResult<Vec<(String, Vec<u8>, Option<String>, String, u8, u32, Option<bool>)>> {
        let creds = self.inner.list_credentials().map_err(smartcard_err)?;
        Ok(creds
            .into_iter()
            .map(|c| {
                (
                    c.device_id,
                    c.id,
                    c.issuer,
                    c.name,
                    c.oath_type as u8,
                    c.period,
                    c.touch_required,
                )
            })
            .collect())
    }

    fn calculate(&mut self, credential_id: &[u8], challenge: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .calculate(credential_id, challenge)
            .map_err(smartcard_err)
    }

    fn delete_credential(&mut self, credential_id: &[u8]) -> PyResult<()> {
        self.inner
            .delete_credential(credential_id)
            .map_err(smartcard_err)
    }

    /// Calculate all credentials.
    ///
    /// Returns list of (device_id, id, issuer, name, oath_type, period, touch_required,
    ///   code_value, code_valid_from, code_valid_to) for credentials with codes,
    /// or (device_id, id, issuer, name, oath_type, period, touch_required,
    ///   None, None, None) for those without.
    fn calculate_all(
        &mut self,
        timestamp: u64,
    ) -> PyResult<
        Vec<(
            String,
            Vec<u8>,
            Option<String>,
            String,
            u8,
            u32,
            Option<bool>,
            Option<String>,
            Option<u64>,
            Option<u64>,
        )>,
    > {
        let results = self.inner.calculate_all(timestamp).map_err(smartcard_err)?;
        Ok(results
            .into_iter()
            .map(|(cred, code)| {
                let (value, valid_from, valid_to) = match code {
                    Some(c) => (Some(c.value), Some(c.valid_from), Some(c.valid_to)),
                    None => (None, None, None),
                };
                (
                    cred.device_id,
                    cred.id,
                    cred.issuer,
                    cred.name,
                    cred.oath_type as u8,
                    cred.period,
                    cred.touch_required,
                    value,
                    valid_from,
                    valid_to,
                )
            })
            .collect())
    }

    /// Calculate a code for a single credential.
    ///
    /// Returns (value, valid_from, valid_to).
    fn calculate_code(
        &mut self,
        device_id: &str,
        cred_id: &[u8],
        issuer: Option<&str>,
        name: &str,
        oath_type: u8,
        period: u32,
        touch_required: Option<bool>,
        timestamp: u64,
    ) -> PyResult<(String, u64, u64)> {
        let ot = oath::OathType::from_u8(oath_type)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid OATH type"))?;
        let credential = oath::Credential {
            device_id: device_id.to_string(),
            id: cred_id.to_vec(),
            issuer: issuer.map(|s| s.to_string()),
            name: name.to_string(),
            oath_type: ot,
            period,
            touch_required,
        };
        let code = self
            .inner
            .calculate_code(&credential, timestamp)
            .map_err(smartcard_err)?;
        Ok((code.value, code.valid_from, code.valid_to))
    }
}
