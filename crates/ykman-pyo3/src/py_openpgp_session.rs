use pyo3::prelude::*;
use yubikit_rs::openpgp::{
    self, Do, KeyRef, OpenPgpSession as RustOpenPgpSession, Pw, RsaSize, SignHashAlgorithm, Uif,
};

use crate::py_bridge::{scp_key_params_from_py, PySmartCardConnection, smartcard_err};

fn openpgp_err(e: openpgp::OpenPgpError) -> PyErr {
    use pyo3::exceptions::*;
    match e {
        openpgp::OpenPgpError::SmartCard(sc) => smartcard_err(sc),
        openpgp::OpenPgpError::InvalidPin(retries) => Python::with_gil(|py| {
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
        openpgp::OpenPgpError::PinBlocked => Python::with_gil(|py| {
            match py.import("yubikit.core") {
                Ok(module) => match module.getattr("InvalidPinError") {
                    Ok(cls) => match cls.call1((0i32, "PIN blocked")) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyRuntimeError::new_err("PIN blocked"),
                    },
                    Err(_) => PyRuntimeError::new_err("PIN blocked"),
                },
                Err(_) => PyRuntimeError::new_err("PIN blocked"),
            }
        }),
        openpgp::OpenPgpError::NotSupported(msg) => Python::with_gil(|py| {
            match py.import("yubikit.core") {
                Ok(module) => match module.getattr("NotSupportedError") {
                    Ok(cls) => match cls.call1((msg.clone(),)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyRuntimeError::new_err(msg.clone()),
                    },
                    Err(_) => PyRuntimeError::new_err(msg.clone()),
                },
                Err(_) => PyRuntimeError::new_err(msg.clone()),
            }
        }),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

fn parse_key_ref(v: u8) -> PyResult<KeyRef> {
    KeyRef::from_u8(v).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid key ref: 0x{:02X}", v))
    })
}

fn parse_do(v: u16) -> PyResult<Do> {
    match v {
        0x0101 => Ok(Do::PrivateUse1),
        0x0102 => Ok(Do::PrivateUse2),
        0x0103 => Ok(Do::PrivateUse3),
        0x0104 => Ok(Do::PrivateUse4),
        0x4F => Ok(Do::Aid),
        0x5B => Ok(Do::Name),
        0x5E => Ok(Do::LoginData),
        0xEF2D => Ok(Do::Language),
        0x5F35 => Ok(Do::Sex),
        0x5F50 => Ok(Do::Url),
        0x5F52 => Ok(Do::HistoricalBytes),
        0x7F66 => Ok(Do::ExtendedLengthInfo),
        0x7F74 => Ok(Do::GeneralFeatureManagement),
        0x65 => Ok(Do::CardholderRelatedData),
        0x6E => Ok(Do::ApplicationRelatedData),
        0xC1 => Ok(Do::AlgorithmAttributesSig),
        0xC2 => Ok(Do::AlgorithmAttributesDec),
        0xC3 => Ok(Do::AlgorithmAttributesAut),
        0xDA => Ok(Do::AlgorithmAttributesAtt),
        0xC4 => Ok(Do::PwStatusBytes),
        0xC7 => Ok(Do::FingerprintSig),
        0xC8 => Ok(Do::FingerprintDec),
        0xC9 => Ok(Do::FingerprintAut),
        0xDB => Ok(Do::FingerprintAtt),
        0xCA => Ok(Do::CaFingerprint1),
        0xCB => Ok(Do::CaFingerprint2),
        0xCC => Ok(Do::CaFingerprint3),
        0xDC => Ok(Do::CaFingerprint4),
        0xCE => Ok(Do::GenerationTimeSig),
        0xCF => Ok(Do::GenerationTimeDec),
        0xD0 => Ok(Do::GenerationTimeAut),
        0xDD => Ok(Do::GenerationTimeAtt),
        0xD3 => Ok(Do::ResettingCode),
        0xD6 => Ok(Do::UifSig),
        0xD7 => Ok(Do::UifDec),
        0xD8 => Ok(Do::UifAut),
        0xD9 => Ok(Do::UifAtt),
        0x7A => Ok(Do::SecuritySupportTemplate),
        0x7F21 => Ok(Do::CardholderCertificate),
        0xF9 => Ok(Do::Kdf),
        0xFA => Ok(Do::AlgorithmInformation),
        0xFC => Ok(Do::AttCertificate),
        0xDE => Ok(Do::KeyInformation),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid data object: 0x{:04X}",
            v
        ))),
    }
}

fn parse_rsa_size(v: u16) -> PyResult<RsaSize> {
    match v {
        2048 => Ok(RsaSize::Rsa2048),
        3072 => Ok(RsaSize::Rsa3072),
        4096 => Ok(RsaSize::Rsa4096),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid RSA size: {}",
            v
        ))),
    }
}

fn parse_hash_algorithm(v: u8) -> PyResult<SignHashAlgorithm> {
    match v {
        0 => Ok(SignHashAlgorithm::None),
        1 => Ok(SignHashAlgorithm::Sha1),
        2 => Ok(SignHashAlgorithm::Sha256),
        3 => Ok(SignHashAlgorithm::Sha384),
        4 => Ok(SignHashAlgorithm::Sha512),
        5 => Ok(SignHashAlgorithm::Prehashed),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid hash algorithm: {}",
            v
        ))),
    }
}

fn parse_pw(v: u8) -> PyResult<Pw> {
    match v {
        0x81 => Ok(Pw::User),
        0x82 => Ok(Pw::Reset),
        0x83 => Ok(Pw::Admin),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid PW ref: 0x{:02X}",
            v
        ))),
    }
}

#[pyclass]
pub struct OpenPgpSession {
    inner: RustOpenPgpSession<PySmartCardConnection>,
}

#[pymethods]
impl OpenPgpSession {
    #[new]
    #[pyo3(signature = (connection, scp_key_params=None))]
    fn new(connection: &Bound<'_, PyAny>, scp_key_params: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let conn = PySmartCardConnection::from_py(connection)?;
        if let Some(params) = scp_key_params {
            let scp_params = scp_key_params_from_py(params)?;
            let inner = RustOpenPgpSession::new_with_scp(conn, &scp_params).map_err(openpgp_err)?;
            Ok(Self { inner })
        } else {
            let inner = RustOpenPgpSession::new(conn).map_err(openpgp_err)?;
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
        self.inner
            .set_version(yubikit_rs::smartcard::Version(version.0, version.1, version.2));
    }

    #[getter]
    fn aid(&self) -> Vec<u8> {
        self.inner.aid().raw.clone()
    }

    fn reset(&mut self) -> PyResult<()> {
        self.inner.reset().map_err(openpgp_err)
    }

    fn get_data(&mut self, data_object: u16) -> PyResult<Vec<u8>> {
        let do_ = parse_do(data_object)?;
        self.inner.get_data(do_).map_err(openpgp_err)
    }

    fn put_data(&mut self, data_object: u16, data: &[u8]) -> PyResult<()> {
        let do_ = parse_do(data_object)?;
        self.inner.put_data(do_, data).map_err(openpgp_err)
    }

    /// Returns raw encoded application related data bytes.
    fn get_application_related_data(&mut self) -> PyResult<Vec<u8>> {
        // Return the raw DO data so Python can parse it
        self.inner
            .get_data(Do::ApplicationRelatedData)
            .map_err(openpgp_err)
    }

    /// Returns (pin_policy_user, max_len_user, max_len_reset, max_len_admin,
    ///          attempts_user, attempts_reset, attempts_admin).
    fn get_pin_status(&mut self) -> PyResult<(u8, u8, u8, u8, u8, u8, u8)> {
        let s = self.inner.get_pin_status().map_err(openpgp_err)?;
        Ok((
            s.pin_policy_user as u8,
            s.max_len_user,
            s.max_len_reset,
            s.max_len_admin,
            s.attempts_user,
            s.attempts_reset,
            s.attempts_admin,
        ))
    }

    fn get_signature_counter(&mut self) -> PyResult<u32> {
        self.inner.get_signature_counter().map_err(openpgp_err)
    }

    /// Returns dict mapping key_ref (u8) to key_status (u8).
    fn get_key_information(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self.inner.get_key_information().map_err(openpgp_err)?;
        let dict = pyo3::types::PyDict::new(py);
        for (key_ref, status) in &info {
            dict.set_item(*key_ref as u8, *status as u8)?;
        }
        Ok(dict.into())
    }

    /// Returns dict mapping key_ref (u8) to generation timestamp (u32).
    fn get_generation_times(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let times = self.inner.get_generation_times().map_err(openpgp_err)?;
        let dict = pyo3::types::PyDict::new(py);
        for (key_ref, ts) in &times {
            dict.set_item(*key_ref as u8, *ts)?;
        }
        Ok(dict.into())
    }

    /// Returns dict mapping key_ref (u8) to fingerprint bytes.
    fn get_fingerprints(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let fps = self.inner.get_fingerprints().map_err(openpgp_err)?;
        let dict = pyo3::types::PyDict::new(py);
        for (key_ref, fp) in &fps {
            dict.set_item(*key_ref as u8, fp.clone())?;
        }
        Ok(dict.into())
    }

    fn verify_pin(&mut self, pin: &str, extended: bool) -> PyResult<()> {
        self.inner.verify_pin(pin, extended).map_err(openpgp_err)
    }

    fn verify_admin(&mut self, admin_pin: &str) -> PyResult<()> {
        self.inner.verify_admin(admin_pin).map_err(openpgp_err)
    }

    fn unverify_pin(&mut self, pw: u8) -> PyResult<()> {
        let p = parse_pw(pw)?;
        self.inner.unverify_pin(p).map_err(openpgp_err)
    }

    fn change_pin(&mut self, pin: &str, new_pin: &str) -> PyResult<()> {
        self.inner.change_pin(pin, new_pin).map_err(openpgp_err)
    }

    fn change_admin(&mut self, admin_pin: &str, new_admin_pin: &str) -> PyResult<()> {
        self.inner
            .change_admin(admin_pin, new_admin_pin)
            .map_err(openpgp_err)
    }

    fn set_reset_code(&mut self, reset_code: &str) -> PyResult<()> {
        self.inner.set_reset_code(reset_code).map_err(openpgp_err)
    }

    fn reset_pin(&mut self, new_pin: &str, reset_code: Option<&str>) -> PyResult<()> {
        self.inner
            .reset_pin(new_pin, reset_code)
            .map_err(openpgp_err)
    }

    fn set_signature_pin_policy(&mut self, pin_policy: u8) -> PyResult<()> {
        let pp = openpgp::PinPolicy::from_u8(pin_policy);
        self.inner
            .set_signature_pin_policy(pp)
            .map_err(openpgp_err)
    }

    fn set_pin_attempts(
        &mut self,
        user_attempts: u8,
        reset_attempts: u8,
        admin_attempts: u8,
    ) -> PyResult<()> {
        self.inner
            .set_pin_attempts(user_attempts, reset_attempts, admin_attempts)
            .map_err(openpgp_err)
    }

    /// Get KDF as raw encoded bytes.
    fn get_kdf(&mut self) -> PyResult<Vec<u8>> {
        let kdf = self.inner.get_kdf().map_err(openpgp_err)?;
        Ok(kdf.to_bytes())
    }

    /// Set KDF from raw encoded bytes.
    fn set_kdf(&mut self, kdf_data: &[u8]) -> PyResult<()> {
        let kdf = openpgp::Kdf::parse(kdf_data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        self.inner.set_kdf(&kdf).map_err(openpgp_err)
    }

    /// Get algorithm attributes as raw encoded bytes.
    fn get_algorithm_attributes(&mut self, key_ref: u8) -> PyResult<Vec<u8>> {
        let kr = parse_key_ref(key_ref)?;
        let attrs = self
            .inner
            .get_algorithm_attributes(kr)
            .map_err(openpgp_err)?;
        Ok(attrs.to_bytes())
    }

    /// Get supported algorithm information.
    ///
    /// Returns dict mapping key_ref (u8) to list of encoded algorithm attribute bytes.
    fn get_algorithm_information(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self
            .inner
            .get_algorithm_information()
            .map_err(openpgp_err)?;
        let dict = pyo3::types::PyDict::new(py);
        for (key_ref, attrs_list) in &info {
            let encoded: Vec<Vec<u8>> = attrs_list.iter().map(|a| a.to_bytes()).collect();
            dict.set_item(*key_ref as u8, encoded)?;
        }
        Ok(dict.into())
    }

    /// Set algorithm attributes from raw encoded bytes.
    fn set_algorithm_attributes(&mut self, key_ref: u8, attributes: &[u8]) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        let attrs = openpgp::AlgorithmAttributes::parse(attributes)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        self.inner
            .set_algorithm_attributes(kr, &attrs)
            .map_err(openpgp_err)
    }

    fn get_uif(&mut self, key_ref: u8) -> PyResult<u8> {
        let kr = parse_key_ref(key_ref)?;
        let uif = self.inner.get_uif(kr).map_err(openpgp_err)?;
        Ok(uif as u8)
    }

    fn set_uif(&mut self, key_ref: u8, uif: u8) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        let u = Uif::from_u8(uif).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid UIF value: {}", uif))
        })?;
        self.inner.set_uif(kr, u).map_err(openpgp_err)
    }

    fn set_generation_time(&mut self, key_ref: u8, timestamp: u32) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        self.inner
            .set_generation_time(kr, timestamp)
            .map_err(openpgp_err)
    }

    fn set_fingerprint(&mut self, key_ref: u8, fingerprint: &[u8]) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        self.inner
            .set_fingerprint(kr, fingerprint)
            .map_err(openpgp_err)
    }

    /// Generate an RSA key. Returns public key bytes.
    fn generate_rsa_key(&mut self, key_ref: u8, key_size: u16) -> PyResult<Vec<u8>> {
        let kr = parse_key_ref(key_ref)?;
        let rs = parse_rsa_size(key_size)?;
        self.inner.generate_rsa_key(kr, rs).map_err(openpgp_err)
    }

    /// Generate an EC key. `curve_oid` is the OID as a dotted string (e.g. "1.2.840.10045.3.1.7").
    /// Returns public key bytes.
    fn generate_ec_key(&mut self, key_ref: u8, curve_oid: &str) -> PyResult<Vec<u8>> {
        let kr = parse_key_ref(key_ref)?;
        self.inner
            .generate_ec_key(kr, curve_oid)
            .map_err(openpgp_err)
    }

    fn get_public_key(&mut self, key_ref: u8) -> PyResult<Vec<u8>> {
        let kr = parse_key_ref(key_ref)?;
        self.inner.get_public_key(kr).map_err(openpgp_err)
    }

    /// Import a private key.
    ///
    /// `key_type` selects the variant:
    ///   0 = RSA (e, p, q)
    ///   1 = RSA-CRT (e, p, q, iqmp, dmp1, dmq1, n)
    ///   2 = EC (scalar, optional public_key)
    ///
    /// For RSA: `components` is [e, p, q].
    /// For RSA-CRT: `components` is [e, p, q, iqmp, dmp1, dmq1, n].
    /// For EC: `components` is [scalar] or [scalar, public_key].
    fn put_key(&mut self, key_ref: u8, key_type: u8, components: Vec<Vec<u8>>) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        let private_key = match key_type {
            0 => {
                if components.len() != 3 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "RSA key requires [e, p, q]",
                    ));
                }
                openpgp::OpenPgpPrivateKey::Rsa {
                    e: components[0].clone(),
                    p: components[1].clone(),
                    q: components[2].clone(),
                }
            }
            1 => {
                if components.len() != 7 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "RSA-CRT key requires [e, p, q, iqmp, dmp1, dmq1, n]",
                    ));
                }
                openpgp::OpenPgpPrivateKey::RsaCrt {
                    e: components[0].clone(),
                    p: components[1].clone(),
                    q: components[2].clone(),
                    iqmp: components[3].clone(),
                    dmp1: components[4].clone(),
                    dmq1: components[5].clone(),
                    n: components[6].clone(),
                }
            }
            2 => {
                if components.is_empty() || components.len() > 2 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "EC key requires [scalar] or [scalar, public_key]",
                    ));
                }
                openpgp::OpenPgpPrivateKey::Ec {
                    scalar: components[0].clone(),
                    public_key: components.get(1).cloned(),
                }
            }
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Invalid key type: {} (expected 0=RSA, 1=RSA-CRT, 2=EC)",
                    key_type
                )));
            }
        };
        self.inner.put_key(kr, &private_key).map_err(openpgp_err)
    }

    fn delete_key(&mut self, key_ref: u8) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        self.inner.delete_key(kr).map_err(openpgp_err)
    }

    fn sign(&mut self, message: &[u8], hash_algorithm: u8) -> PyResult<Vec<u8>> {
        let ha = parse_hash_algorithm(hash_algorithm)?;
        self.inner.sign(message, ha).map_err(openpgp_err)
    }

    fn decrypt(&mut self, value: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.decrypt(value).map_err(openpgp_err)
    }

    fn authenticate(&mut self, message: &[u8], hash_algorithm: u8) -> PyResult<Vec<u8>> {
        let ha = parse_hash_algorithm(hash_algorithm)?;
        self.inner
            .authenticate(message, ha)
            .map_err(openpgp_err)
    }

    /// Get certificate as DER bytes.
    fn get_certificate(&mut self, key_ref: u8) -> PyResult<Vec<u8>> {
        let kr = parse_key_ref(key_ref)?;
        self.inner.get_certificate(kr).map_err(openpgp_err)
    }

    fn put_certificate(&mut self, key_ref: u8, cert_der: &[u8]) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        self.inner
            .put_certificate(kr, cert_der)
            .map_err(openpgp_err)
    }

    fn delete_certificate(&mut self, key_ref: u8) -> PyResult<()> {
        let kr = parse_key_ref(key_ref)?;
        self.inner.delete_certificate(kr).map_err(openpgp_err)
    }

    /// Attest a key. Returns DER certificate.
    fn attest_key(&mut self, key_ref: u8) -> PyResult<Vec<u8>> {
        let kr = parse_key_ref(key_ref)?;
        self.inner.attest_key(kr).map_err(openpgp_err)
    }

    fn get_challenge(&mut self, length: u16) -> PyResult<Vec<u8>> {
        self.inner.get_challenge(length).map_err(openpgp_err)
    }
}
