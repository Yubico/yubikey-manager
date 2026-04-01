use pyo3::prelude::*;
use yubikit::securitydomain::{
    Curve, KeyRef, SecurityDomainSession as RustSecurityDomainSession, StaticKeys,
};

use crate::py_bridge::{PySmartCardConnection, scp_key_params_from_py, smartcard_err};

fn parse_curve(v: u8) -> PyResult<Curve> {
    Curve::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid curve: 0x{:02X}", v))
    })
}

#[pyclass]
pub struct SecurityDomainSession {
    inner: Option<RustSecurityDomainSession<PySmartCardConnection>>,
}

impl SecurityDomainSession {
    fn session(&self) -> PyResult<&RustSecurityDomainSession<PySmartCardConnection>> {
        self.inner
            .as_ref()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }

    fn session_mut(&mut self) -> PyResult<&mut RustSecurityDomainSession<PySmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))
    }
}

#[pymethods]
impl SecurityDomainSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        let inner = RustSecurityDomainSession::new(conn).map_err(|(e, _)| smartcard_err(e))?;
        Ok(Self { inner: Some(inner) })
    }

    /// Take the connection from the current session, re-open with SCP.
    fn authenticate(&mut self, key_params: &Bound<'_, PyAny>) -> PyResult<()> {
        let params = scp_key_params_from_py(key_params)?;
        let old = self
            .inner
            .take()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("Session is closed"))?;
        let conn = old.into_connection();
        match RustSecurityDomainSession::new_with_scp(conn, &params) {
            Ok(new_session) => {
                self.inner = Some(new_session);
                Ok(())
            }
            Err((e, conn)) => {
                // SCP failed — try to re-open a plain session so the object stays usable.
                match RustSecurityDomainSession::new(conn) {
                    Ok(session) => self.inner = Some(session),
                    Err((recovery_err, _)) => {
                        log::warn!(
                            "Failed to recover SD session after auth failure: {recovery_err}"
                        );
                    }
                }
                Err(smartcard_err(e))
            }
        }
    }

    #[getter]
    fn version(&self) -> PyResult<(u8, u8, u8)> {
        let v = self.session()?.version();
        Ok((v.0, v.1, v.2))
    }

    fn get_data(&mut self, tag: u32, data: &[u8]) -> PyResult<Vec<u8>> {
        self.session_mut()?
            .get_data(tag, data)
            .map_err(smartcard_err)
    }

    /// Returns dict mapping (kid, kvn) tuples to dict of {component_id: version}.
    fn get_key_information(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .session_mut()?
            .get_key_information()
            .map_err(smartcard_err)?;
        let dict = pyo3::types::PyDict::new(py);
        for (key_ref, components) in &info {
            let inner_dict = pyo3::types::PyDict::new(py);
            for (component_id, version) in components {
                inner_dict.set_item(*component_id, *version)?;
            }
            dict.set_item((key_ref.kid, key_ref.kvn), inner_dict)?;
        }
        Ok(dict.into())
    }

    fn get_card_recognition_data(&mut self) -> PyResult<Vec<u8>> {
        self.session_mut()?
            .get_card_recognition_data()
            .map_err(smartcard_err)
    }

    /// Returns dict mapping (kid, kvn) tuples to identifier bytes.
    fn get_supported_ca_identifiers(
        &mut self,
        kloc: bool,
        klcc: bool,
        py: Python<'_>,
    ) -> PyResult<PyObject> {
        let ids = self
            .session_mut()?
            .get_supported_ca_identifiers(kloc, klcc)
            .map_err(smartcard_err)?;
        let dict = pyo3::types::PyDict::new(py);
        for (key_ref, data) in &ids {
            dict.set_item((key_ref.kid, key_ref.kvn), data.clone())?;
        }
        Ok(dict.into())
    }

    /// Returns list of DER-encoded certificates.
    fn get_certificate_bundle(&mut self, kid: u8, kvn: u8) -> PyResult<Vec<Vec<u8>>> {
        let key = KeyRef::new(kid, kvn);
        self.session_mut()?
            .get_certificate_bundle(key)
            .map_err(smartcard_err)
    }

    fn reset(&mut self) -> PyResult<()> {
        self.session_mut()?.reset().map_err(smartcard_err)
    }

    fn store_data(&mut self, data: &[u8]) -> PyResult<()> {
        self.session_mut()?.store_data(data).map_err(smartcard_err)
    }

    /// Store a certificate bundle. `certificates` is a list of DER-encoded certs.
    fn store_certificate_bundle(
        &mut self,
        kid: u8,
        kvn: u8,
        certificates: Vec<Vec<u8>>,
    ) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        let cert_refs: Vec<&[u8]> = certificates.iter().map(|c| c.as_slice()).collect();
        self.session_mut()?
            .store_certificate_bundle(key, &cert_refs)
            .map_err(smartcard_err)
    }

    fn store_allowlist(&mut self, kid: u8, kvn: u8, serials: Vec<Vec<u8>>) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        self.session_mut()?
            .store_allowlist(key, &serials)
            .map_err(smartcard_err)
    }

    fn store_ca_issuer(&mut self, kid: u8, kvn: u8, ski: &[u8]) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        self.session_mut()?
            .store_ca_issuer(key, ski)
            .map_err(smartcard_err)
    }

    fn delete_key(&mut self, kid: u8, kvn: u8, delete_last: bool) -> PyResult<()> {
        self.session_mut()?
            .delete_key(kid, kvn, delete_last)
            .map_err(smartcard_err)
    }

    /// Generate an EC key pair. Returns the public key bytes.
    fn generate_ec_key(
        &mut self,
        kid: u8,
        kvn: u8,
        curve: u8,
        replace_kvn: u8,
    ) -> PyResult<Vec<u8>> {
        let key = KeyRef::new(kid, kvn);
        let c = parse_curve(curve)?;
        self.session_mut()?
            .generate_ec_key(key, c, replace_kvn)
            .map_err(smartcard_err)
    }

    /// Import SCP03 static keys.
    fn put_key_static(
        &mut self,
        kid: u8,
        kvn: u8,
        key_enc: &[u8],
        key_mac: &[u8],
        key_dek: Option<Vec<u8>>,
        replace_kvn: u8,
    ) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        let key_enc_arr: [u8; 16] = key_enc
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_enc must be 16 bytes"))?;
        let key_mac_arr: [u8; 16] = key_mac
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_mac must be 16 bytes"))?;
        let key_dek_arr: Option<[u8; 16]> = key_dek
            .map(|v| {
                v.as_slice().try_into().map_err(|_| {
                    pyo3::exceptions::PyValueError::new_err("key_dek must be 16 bytes")
                })
            })
            .transpose()?;
        let static_keys = StaticKeys::new(key_enc_arr, key_mac_arr, key_dek_arr);
        self.session_mut()?
            .put_key_static(key, &static_keys, replace_kvn)
            .map_err(smartcard_err)
    }

    /// Import an EC private key. `private_key` is the raw scalar bytes.
    fn put_key_ec_private(
        &mut self,
        kid: u8,
        kvn: u8,
        private_key: &[u8],
        curve: u8,
        replace_kvn: u8,
    ) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        let c = parse_curve(curve)?;
        self.session_mut()?
            .put_key_ec_private(key, private_key, c, replace_kvn)
            .map_err(smartcard_err)
    }

    /// Import an EC public key. `public_key` is the SEC1 uncompressed point.
    fn put_key_ec_public(
        &mut self,
        kid: u8,
        kvn: u8,
        public_key: &[u8],
        curve: u8,
        replace_kvn: u8,
    ) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        let c = parse_curve(curve)?;
        self.session_mut()?
            .put_key_ec_public(key, public_key, c, replace_kvn)
            .map_err(smartcard_err)
    }
}
