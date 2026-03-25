use pyo3::prelude::*;
use yubikit::hsmauth::{self, HsmAuthSession as RustHsmAuthSession};

use crate::py_bridge::{scp_key_params_from_py, PySmartCardConnection, smartcard_err};

fn hsmauth_err(e: hsmauth::HsmAuthError) -> PyErr {
    use pyo3::exceptions::*;
    match e {
        hsmauth::HsmAuthError::SmartCard(sc) => smartcard_err(sc),
        hsmauth::HsmAuthError::InvalidPin(retries) => Python::with_gil(|py| {
            match py.import("yubikit.core") {
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
                Err(_) => PyValueError::new_err(format!(
                    "Invalid PIN, {} attempts remaining",
                    retries
                )),
            }
        }),
        hsmauth::HsmAuthError::NotSupported(msg) => PyRuntimeError::new_err(msg),
        hsmauth::HsmAuthError::InvalidParameter(msg) => PyValueError::new_err(msg),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

/// Convert (label, algorithm, counter, touch_required) tuple from Credential.
fn cred_to_tuple(c: hsmauth::Credential) -> (String, u8, u32, bool) {
    (c.label, c.algorithm as u8, c.counter, c.touch_required)
}

#[pyclass]
pub struct HsmAuthSession {
    inner: RustHsmAuthSession<PySmartCardConnection>,
}

#[pymethods]
impl HsmAuthSession {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(connection: &Bound<'_, PyAny>, scp_key_params: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        if let Some(params) = scp_key_params {
            let scp_params = scp_key_params_from_py(params)?;
            let inner = RustHsmAuthSession::new_with_scp(conn, &scp_params).map_err(hsmauth_err)?;
            Ok(Self { inner })
        } else {
            let inner = RustHsmAuthSession::new(conn).map_err(hsmauth_err)?;
            Ok(Self { inner })
        }
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.inner.version();
        (v.0, v.1, v.2)
    }

    #[setter]
    fn set_version(&mut self, version: (u8, u8, u8)) {
        self.inner.set_version(yubikit::smartcard::Version(
            version.0, version.1, version.2,
        ));
    }

    fn reset(&mut self) -> PyResult<()> {
        self.inner.reset().map_err(hsmauth_err)
    }

    /// List credentials. Returns list of (label, algorithm, counter, touch_required).
    fn list_credentials(&mut self) -> PyResult<Vec<(String, u8, u32, bool)>> {
        let creds = self.inner.list_credentials().map_err(hsmauth_err)?;
        Ok(creds.into_iter().map(cred_to_tuple).collect())
    }

    /// Store a symmetric (AES) credential. Returns (label, algorithm, counter, touch_required).
    fn put_credential_symmetric(
        &mut self,
        management_key: &[u8],
        label: &str,
        key_enc: &[u8],
        key_mac: &[u8],
        credential_password: &[u8],
        touch_required: bool,
    ) -> PyResult<(String, u8, u32, bool)> {
        let cred = self
            .inner
            .put_credential_symmetric(
                management_key,
                label,
                key_enc,
                key_mac,
                credential_password,
                touch_required,
            )
            .map_err(hsmauth_err)?;
        Ok(cred_to_tuple(cred))
    }

    /// Store a derived symmetric credential. Returns (label, algorithm, counter, touch_required).
    fn put_credential_derived(
        &mut self,
        management_key: &[u8],
        label: &str,
        derivation_password: &str,
        credential_password: &[u8],
        touch_required: bool,
    ) -> PyResult<(String, u8, u32, bool)> {
        let cred = self
            .inner
            .put_credential_derived(
                management_key,
                label,
                derivation_password,
                credential_password,
                touch_required,
            )
            .map_err(hsmauth_err)?;
        Ok(cred_to_tuple(cred))
    }

    /// Store an asymmetric (EC P-256) credential.
    ///
    /// `private_key` is the raw 32-byte scalar.
    /// Returns (label, algorithm, counter, touch_required).
    fn put_credential_asymmetric(
        &mut self,
        management_key: &[u8],
        label: &str,
        private_key: &[u8],
        credential_password: &[u8],
        touch_required: bool,
    ) -> PyResult<(String, u8, u32, bool)> {
        use elliptic_curve::SecretKey;
        let sk = SecretKey::<p256::NistP256>::from_slice(private_key)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let cred = self
            .inner
            .put_credential_asymmetric(
                management_key,
                label,
                &sk,
                credential_password,
                touch_required,
            )
            .map_err(hsmauth_err)?;
        Ok(cred_to_tuple(cred))
    }

    /// Generate an asymmetric credential on-device.
    /// Returns (label, algorithm, counter, touch_required).
    fn generate_credential_asymmetric(
        &mut self,
        management_key: &[u8],
        label: &str,
        credential_password: &[u8],
        touch_required: bool,
    ) -> PyResult<(String, u8, u32, bool)> {
        let cred = self
            .inner
            .generate_credential_asymmetric(
                management_key,
                label,
                credential_password,
                touch_required,
            )
            .map_err(hsmauth_err)?;
        Ok(cred_to_tuple(cred))
    }

    /// Get the public key for an asymmetric credential.
    /// Returns SEC1 uncompressed point bytes (65 bytes: 0x04 || x || y).
    fn get_public_key(&mut self, label: &str) -> PyResult<Vec<u8>> {
        use elliptic_curve::sec1::ToEncodedPoint;
        let pk = self.inner.get_public_key(label).map_err(hsmauth_err)?;
        let encoded = pk.to_encoded_point(false);
        Ok(encoded.as_bytes().to_vec())
    }

    fn delete_credential(&mut self, management_key: &[u8], label: &str) -> PyResult<()> {
        self.inner
            .delete_credential(management_key, label)
            .map_err(hsmauth_err)
    }

    fn change_credential_password(
        &mut self,
        label: &str,
        credential_password: &[u8],
        new_credential_password: &[u8],
    ) -> PyResult<()> {
        self.inner
            .change_credential_password(label, credential_password, new_credential_password)
            .map_err(hsmauth_err)
    }

    fn change_credential_password_admin(
        &mut self,
        management_key: &[u8],
        label: &str,
        new_credential_password: &[u8],
    ) -> PyResult<()> {
        self.inner
            .change_credential_password_admin(management_key, label, new_credential_password)
            .map_err(hsmauth_err)
    }

    fn put_management_key(
        &mut self,
        management_key: &[u8],
        new_management_key: &[u8],
    ) -> PyResult<()> {
        self.inner
            .put_management_key(management_key, new_management_key)
            .map_err(hsmauth_err)
    }

    fn get_management_key_retries(&mut self) -> PyResult<u32> {
        self.inner
            .get_management_key_retries()
            .map_err(hsmauth_err)
    }

    /// Calculate symmetric session keys.
    /// Returns (key_senc, key_smac, key_srmac).
    fn calculate_session_keys_symmetric(
        &mut self,
        label: &str,
        context: &[u8],
        credential_password: &[u8],
        card_crypto: Option<&[u8]>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let keys = self
            .inner
            .calculate_session_keys_symmetric(label, context, credential_password, card_crypto)
            .map_err(hsmauth_err)?;
        Ok((keys.key_senc, keys.key_smac, keys.key_srmac))
    }

    /// Calculate asymmetric session keys.
    ///
    /// `peer_public_key` is the SEC1 uncompressed point (65 bytes: 0x04 || x || y).
    /// Returns (key_senc, key_smac, key_srmac).
    fn calculate_session_keys_asymmetric(
        &mut self,
        label: &str,
        context: &[u8],
        peer_public_key: &[u8],
        credential_password: &[u8],
        card_crypto: &[u8],
    ) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        use elliptic_curve::sec1::FromEncodedPoint;
        let point = p256::EncodedPoint::from_bytes(peer_public_key)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let pk = Option::from(p256::PublicKey::from_encoded_point(&point)).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("Invalid P-256 public key")
        })?;
        let keys = self
            .inner
            .calculate_session_keys_asymmetric(
                label,
                context,
                &pk,
                credential_password,
                card_crypto,
            )
            .map_err(hsmauth_err)?;
        Ok((keys.key_senc, keys.key_smac, keys.key_srmac))
    }

    /// Get challenge for a credential.
    fn get_challenge(
        &mut self,
        label: &str,
        credential_password: Option<&[u8]>,
    ) -> PyResult<Vec<u8>> {
        self.inner
            .get_challenge(label, credential_password)
            .map_err(hsmauth_err)
    }
}
