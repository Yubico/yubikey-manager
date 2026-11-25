//! Helpers for reading private keys and certificates from files.
//!
//! Supports PEM (including encrypted PKCS#8), DER and PKCS#12 data. Functions
//! never prompt for passwords; when one is needed but not given,
//! [`PkiError::PasswordRequired`] is returned so the caller can ask for it and
//! try again.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use yubikit::keys::PublicKey;

/// The kind of password protection that was encountered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordProtection {
    /// An encrypted PKCS#8 private key.
    EncryptedKey,
    /// A PKCS#12 file.
    Pkcs12,
}

/// Errors from reading keys and certificates.
#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("A password is required")]
    PasswordRequired(PasswordProtection),
    #[error("Wrong password")]
    WrongPassword,
    #[error("Invalid PEM data: {0}")]
    InvalidPem(String),
    #[error("Invalid encrypted private key: {0}")]
    InvalidEncryptedKey(String),
    #[error("Failed to parse PKCS#12 file: {0}")]
    Pkcs12(String),
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("No private key found")]
    NoPrivateKey,
    #[error("No certificate found")]
    NoCertificate,
}

/// A decoded PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The label, e.g. `CERTIFICATE` or `PRIVATE KEY`.
    pub label: String,
    /// The decoded contents.
    pub der: Vec<u8>,
}

/// Returns true if the data looks like PEM text.
pub fn is_pem(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok_and(|text| text.contains("-----BEGIN "))
}

/// Decode all PEM blocks in the text, ignoring any text between blocks.
pub fn pem_decode_all(text: &str) -> Result<Vec<PemBlock>, PkiError> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            current = Some((label.to_string(), String::new()));
        } else if let Some(label) = line
            .strip_prefix("-----END ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            let Some((begin, b64)) = current.take() else {
                return Err(PkiError::InvalidPem(format!("Unexpected END {label}")));
            };
            if begin != label {
                return Err(PkiError::InvalidPem(format!(
                    "BEGIN {begin} does not match END {label}"
                )));
            }
            let der = BASE64
                .decode(&b64)
                .map_err(|e| PkiError::InvalidPem(e.to_string()))?;
            blocks.push(PemBlock { label: begin, der });
        } else if let Some((label, b64)) = current.as_mut() {
            if line.contains(':') {
                // RFC 1421 headers are only used by legacy encrypted keys
                if line.starts_with("Proc-Type:") && line.contains("ENCRYPTED") {
                    return Err(PkiError::InvalidEncryptedKey(format!(
                        "Legacy PEM encryption of {label} is not supported, use PKCS#8"
                    )));
                }
            } else {
                b64.push_str(line);
            }
        }
    }
    if let Some((label, _)) = current {
        return Err(PkiError::InvalidPem(format!("Missing END {label}")));
    }
    if blocks.is_empty() {
        return Err(PkiError::InvalidPem("No PEM data found".into()));
    }
    Ok(blocks)
}

/// Decode the first PEM block in the text.
pub fn pem_decode(text: &str) -> Result<Vec<u8>, PkiError> {
    Ok(pem_decode_all(text)?.swap_remove(0).der)
}

/// Encode DER data as a PEM block with the given label.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = BASE64.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // Base64 output is always ASCII
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Return the contents of the first PEM block if the data is PEM, otherwise
/// the data itself, which is assumed to be DER.
pub fn pem_or_der(data: &[u8]) -> Result<Vec<u8>, PkiError> {
    match std::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN ") => pem_decode(text),
        _ => Ok(data.to_vec()),
    }
}

/// Returns true if the data looks like a PKCS#12 file: a DER SEQUENCE whose
/// first element is the INTEGER 3.
pub fn is_pkcs12(data: &[u8]) -> bool {
    if data.len() < 10 || data[0] != 0x30 {
        return false;
    }
    let len_byte = data[1];
    let offset = if len_byte & 0x80 == 0 {
        2
    } else {
        2 + (len_byte & 0x7f) as usize
    };
    offset + 3 <= data.len()
        && data[offset] == 0x02
        && data[offset + 1] == 0x01
        && data[offset + 2] == 0x03
}

/// Decrypt a DER-encoded PKCS#8 `EncryptedPrivateKeyInfo`, returning the
/// DER-encoded PKCS#8 `PrivateKeyInfo`.
pub fn decrypt_private_key(encrypted_der: &[u8], password: &str) -> Result<Vec<u8>, PkiError> {
    let enc_key = pkcs8::EncryptedPrivateKeyInfo::try_from(encrypted_der)
        .map_err(|e| PkiError::InvalidEncryptedKey(e.to_string()))?;
    let key = enc_key
        .decrypt(password)
        .map_err(|_| PkiError::WrongPassword)?;
    Ok(key.as_bytes().to_vec())
}

/// The contents of a key or certificate file.
#[derive(Debug, Default)]
pub struct KeyFile {
    /// The first private key in the file, DER-encoded. This is PKCS#8, unless
    /// the file used a legacy PEM label such as `EC PRIVATE KEY` or
    /// `RSA PRIVATE KEY`, in which case the inner structure is returned as-is.
    pub private_key: Option<Vec<u8>>,
    /// All certificates in the file, DER-encoded, in file order.
    pub certificates: Vec<Vec<u8>>,
}

/// Parse a file containing a private key and/or certificates.
///
/// Accepts PEM (with any number of keys and certificates, encrypted PKCS#8
/// keys are decrypted using the password), PKCS#12, or a single DER-encoded
/// certificate or private key.
pub fn parse_key_file(data: &[u8], password: Option<&str>) -> Result<KeyFile, PkiError> {
    parse(data, password, true)
}

/// Parse a file containing a private key, returning it DER-encoded.
///
/// See [`parse_key_file`] for supported formats.
pub fn load_private_key(data: &[u8], password: Option<&str>) -> Result<Vec<u8>, PkiError> {
    parse(data, password, true)?
        .private_key
        .ok_or(PkiError::NoPrivateKey)
}

/// Parse a file containing certificates, returning them DER-encoded.
///
/// Private keys in PEM files are ignored, so no password is needed unless the
/// file is PKCS#12.
pub fn load_certificates(data: &[u8], password: Option<&str>) -> Result<Vec<Vec<u8>>, PkiError> {
    let certs = parse(data, password, false)?.certificates;
    if certs.is_empty() {
        return Err(PkiError::NoCertificate);
    }
    Ok(certs)
}

/// Parse a file containing a certificate, returning the first one.
pub fn load_certificate(data: &[u8], password: Option<&str>) -> Result<Vec<u8>, PkiError> {
    Ok(load_certificates(data, password)?.swap_remove(0))
}

fn parse(data: &[u8], password: Option<&str>, want_key: bool) -> Result<KeyFile, PkiError> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN ")
    {
        return parse_pem(text, password, want_key);
    }
    if is_pkcs12(data) {
        return parse_pkcs12(data, password);
    }
    if Certificate::from_der(data).is_ok() {
        Ok(KeyFile {
            private_key: None,
            certificates: vec![data.to_vec()],
        })
    } else {
        Ok(KeyFile {
            private_key: Some(data.to_vec()),
            certificates: Vec::new(),
        })
    }
}

fn parse_pem(text: &str, password: Option<&str>, want_key: bool) -> Result<KeyFile, PkiError> {
    let mut file = KeyFile::default();
    for block in pem_decode_all(text)? {
        match block.label.as_str() {
            "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
                file.certificates.push(block.der)
            }
            "ENCRYPTED PRIVATE KEY" if want_key && file.private_key.is_none() => {
                let password =
                    password.ok_or(PkiError::PasswordRequired(PasswordProtection::EncryptedKey))?;
                file.private_key = Some(decrypt_private_key(&block.der, password)?);
            }
            label
                if want_key
                    && file.private_key.is_none()
                    && label.ends_with("PRIVATE KEY")
                    && !label.starts_with("ENCRYPTED") =>
            {
                file.private_key = Some(block.der)
            }
            _ => {}
        }
    }
    Ok(file)
}

fn parse_pkcs12(data: &[u8], password: Option<&str>) -> Result<KeyFile, PkiError> {
    use p12_keystore::error::Error;
    use p12_keystore::{KeyStore, KeyStoreEntry};

    let ks = KeyStore::from_pkcs12(data, password.unwrap_or("")).map_err(|e| match e {
        Error::MacError(_) if password.is_none() => {
            PkiError::PasswordRequired(PasswordProtection::Pkcs12)
        }
        Error::MacError(_) => PkiError::WrongPassword,
        e => PkiError::Pkcs12(e.to_string()),
    })?;

    let mut file = KeyFile::default();
    if let Some((_, chain)) = ks.private_key_chain() {
        file.private_key = Some(chain.key().to_vec());
        file.certificates
            .extend(chain.chain().iter().map(|c| c.as_der().to_vec()));
    }
    for (_, entry) in ks.entries() {
        if let KeyStoreEntry::Certificate(cert) = entry {
            let der = cert.as_der().to_vec();
            if !file.certificates.contains(&der) {
                file.certificates.push(der);
            }
        }
    }
    Ok(file)
}

/// Information about an X.509 certificate.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Subject distinguished name, in RFC 4514 form.
    pub subject: String,
    /// Issuer distinguished name, in RFC 4514 form.
    pub issuer: String,
    /// Serial number bytes.
    pub serial: Vec<u8>,
    /// SHA-256 fingerprint of the DER-encoded certificate.
    pub fingerprint: [u8; 32],
    /// Start of the validity period.
    pub not_before: String,
    /// End of the validity period.
    pub not_after: String,
    /// The subject public key, if it is of a supported type.
    pub public_key: Option<PublicKey>,
}

/// Parse a DER-encoded X.509 certificate.
pub fn certificate_info(cert_der: &[u8]) -> Result<CertificateInfo, PkiError> {
    let cert =
        Certificate::from_der(cert_der).map_err(|e| PkiError::InvalidCertificate(e.to_string()))?;
    let tbs = &cert.tbs_certificate;
    let public_key = tbs
        .subject_public_key_info
        .to_der()
        .ok()
        .and_then(|spki| PublicKey::from_spki(&spki).ok());
    Ok(CertificateInfo {
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        serial: tbs.serial_number.as_bytes().to_vec(),
        fingerprint: Sha256::digest(cert_der).into(),
        not_before: tbs.validity.not_before.to_string(),
        not_after: tbs.validity.not_after.to_string(),
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../ykman-cli/tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    #[test]
    fn test_pem_round_trip() {
        let der = fixture("ec_p256_cert.der");
        let pem = pem_encode("CERTIFICATE", &der);
        // The fixture may be checked out with CRLF line endings on Windows
        let expected = String::from_utf8(fixture("ec_p256_cert.pem"))
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(pem, expected);
        assert_eq!(pem_decode(&pem).unwrap(), der);
    }

    #[test]
    fn test_pem_decode_multiple_blocks() {
        let text = String::from_utf8(fixture("ec_p256_key.pem")).unwrap()
            + &String::from_utf8(fixture("ec_p256_cert.pem")).unwrap();
        let file = parse_key_file(text.as_bytes(), None).unwrap();
        assert_eq!(file.private_key.unwrap(), fixture("ec_p256_key.der"));
        assert_eq!(file.certificates, vec![fixture("ec_p256_cert.der")]);
    }

    #[test]
    fn test_der_key_and_cert() {
        assert_eq!(
            load_private_key(&fixture("ec_p256_key.der"), None).unwrap(),
            fixture("ec_p256_key.der")
        );
        assert_eq!(
            load_certificate(&fixture("ec_p256_cert.der"), None).unwrap(),
            fixture("ec_p256_cert.der")
        );
    }

    #[test]
    fn test_encrypted_pem_key() {
        let data = fixture("ec_p256_key_enc.pem");
        assert!(matches!(
            load_private_key(&data, None),
            Err(PkiError::PasswordRequired(PasswordProtection::EncryptedKey))
        ));
        assert!(matches!(
            load_private_key(&data, Some("wrong")),
            Err(PkiError::WrongPassword)
        ));
        assert_eq!(
            load_private_key(&data, Some("test123")).unwrap(),
            fixture("ec_p256_key.der")
        );
    }

    #[test]
    fn test_pkcs12() {
        let data = fixture("ec_p256_enc.p12");
        assert!(is_pkcs12(&data));
        assert!(matches!(
            parse_key_file(&data, None),
            Err(PkiError::PasswordRequired(PasswordProtection::Pkcs12))
        ));
        assert!(matches!(
            parse_key_file(&data, Some("wrong")),
            Err(PkiError::WrongPassword)
        ));
        let file = parse_key_file(&data, Some("test123")).unwrap();
        assert!(file.private_key.is_some());
        assert_eq!(file.certificates, vec![fixture("ec_p256_cert.der")]);
    }

    #[test]
    fn test_certificate_info() {
        let der = fixture("ec_p256_cert.der");
        let info = certificate_info(&der).unwrap();
        assert_eq!(info.subject, "CN=Test EC P256");
        assert_eq!(info.issuer, "CN=Test EC P256");
        assert_eq!(info.fingerprint.to_vec(), Sha256::digest(&der).to_vec());
        assert!(matches!(info.public_key, Some(PublicKey::Ec(_))));
    }
}
