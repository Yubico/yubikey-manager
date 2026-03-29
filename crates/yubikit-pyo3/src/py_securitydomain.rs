use pyo3::prelude::*;
use yubikit::securitydomain::{
    Curve, KeyRef, SecurityDomainSession as RustSecurityDomainSession, StaticKeys,
};

use crate::py_bridge::{PySmartCardConnection, init_scp_from_py, smartcard_err};

fn parse_curve(v: u8) -> PyResult<Curve> {
    Curve::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid curve: 0x{:02X}", v))
    })
}

#[pyclass]
pub struct SecurityDomainSession {
    inner: RustSecurityDomainSession<PySmartCardConnection>,
}

#[pymethods]
impl SecurityDomainSession {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        let inner = RustSecurityDomainSession::new(conn).map_err(smartcard_err)?;
        Ok(Self { inner })
    }

    /// Initialize SCP and authenticate the session.
    fn authenticate(&mut self, key_params: &Bound<'_, PyAny>) -> PyResult<()> {
        init_scp_from_py(self.inner.protocol_mut(), key_params)
    }

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        let v = self.inner.version();
        (v.0, v.1, v.2)
    }

    #[setter]
    fn set_version(&mut self, version: (u8, u8, u8)) {
        self.inner
            .set_version(yubikit::smartcard::Version(version.0, version.1, version.2));
    }

    fn get_data(&mut self, tag: u32, data: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.get_data(tag, data).map_err(smartcard_err)
    }

    /// Returns dict mapping (kid, kvn) tuples to dict of {component_id: version}.
    fn get_key_information(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self.inner.get_key_information().map_err(smartcard_err)?;
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
        self.inner
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
            .inner
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
        self.inner
            .get_certificate_bundle(key)
            .map_err(smartcard_err)
    }

    fn reset(&mut self) -> PyResult<()> {
        self.inner.reset().map_err(smartcard_err)
    }

    fn store_data(&mut self, data: &[u8]) -> PyResult<()> {
        self.inner.store_data(data).map_err(smartcard_err)
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
        self.inner
            .store_certificate_bundle(key, &cert_refs)
            .map_err(smartcard_err)
    }

    fn store_allowlist(&mut self, kid: u8, kvn: u8, serials: Vec<Vec<u8>>) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        self.inner
            .store_allowlist(key, &serials)
            .map_err(smartcard_err)
    }

    fn store_ca_issuer(&mut self, kid: u8, kvn: u8, ski: &[u8]) -> PyResult<()> {
        let key = KeyRef::new(kid, kvn);
        self.inner.store_ca_issuer(key, ski).map_err(smartcard_err)
    }

    fn delete_key(&mut self, kid: u8, kvn: u8, delete_last: bool) -> PyResult<()> {
        self.inner
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
        self.inner
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
        let static_keys = StaticKeys::new(key_enc.to_vec(), key_mac.to_vec(), key_dek);
        self.inner
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
        self.inner
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
        self.inner
            .put_key_ec_public(key, public_key, c, replace_kvn)
            .map_err(smartcard_err)
    }
}
