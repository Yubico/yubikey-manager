//! Reading and writing OATH credentials in PSKC (RFC 6030) files.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pbkdf2::hmac::{Hmac, Mac};
use quick_xml::XmlVersion;
use quick_xml::escape::{escape, unescape};
use quick_xml::events::{BytesStart, Event};
use subtle::ConstantTimeEq;
use yubikit::oath::{CredentialData, HashAlgorithm, OathType};
use zeroize::Zeroizing;

const ALG_PREFIX: &str = "urn:ietf:params:xml:ns:keyprov:pskc:";
const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const HMAC_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
const PBKDF2: &str = "http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2";
const PBKDF2_ITERATIONS: u32 = 100_000;
const DECRYPT_FAILED: &str = "Failed to decrypt PSKC file. Wrong passphrase or pre-shared key?";

/// How the secrets in a PSKC file are protected.
#[derive(Debug, PartialEq, Eq)]
pub enum PskcProtection {
    None,
    Passphrase,
    PresharedKey,
}

/// Key used to encrypt a PSKC file being written.
pub enum PskcEncryption {
    Passphrase(Zeroizing<String>),
    PresharedKey(Zeroizing<Vec<u8>>),
}

/// An OATH credential read from a PSKC file.
pub struct PskcCredential {
    pub issuer: Option<String>,
    pub name: String,
    pub oath_type: OathType,
    pub hash_algorithm: HashAlgorithm,
    pub secret: Zeroizing<Vec<u8>>,
    pub digits: u8,
    pub period: u32,
    pub counter: u32,
}

#[derive(Default)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Element>,
    text: String,
}

impl Element {
    fn from_start(e: &BytesStart) -> Result<Self> {
        let mut attrs = Vec::new();
        for attr in e.attributes() {
            let attr = attr.map_err(|e| anyhow!("Failed to parse PSKC XML: {e}"))?;
            let value = attr
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|e| anyhow!("Failed to parse PSKC XML: {e}"))?;
            attrs.push((
                attr.key.local_name().as_ref().to_string(),
                value.into_owned(),
            ));
        }
        Ok(Self {
            name: e.local_name().as_ref().to_string(),
            attrs,
            ..Default::default()
        })
    }

    fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    fn find(&self, path: &[&str]) -> Option<&Element> {
        path.iter().try_fold(self, |el, name| el.child(name))
    }

    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn text(&self) -> &str {
        self.text.trim()
    }

    fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(Element::text)
    }
}

fn parse_tree(xml: &str) -> Result<Element> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack = vec![Element::default()];
    loop {
        let event = reader
            .read_event()
            .map_err(|e| anyhow!("Failed to parse PSKC XML: {e}"))?;
        let current = stack.last_mut().expect("stack is never empty");
        match event {
            Event::Start(e) => stack.push(Element::from_start(&e)?),
            Event::Empty(e) => current.children.push(Element::from_start(&e)?),
            Event::End(_) => {
                let element = stack.pop().expect("stack is never empty");
                stack
                    .last_mut()
                    .ok_or_else(|| anyhow!("Failed to parse PSKC XML: unbalanced tags"))?
                    .children
                    .push(element);
            }
            Event::Text(e) => current
                .text
                .push_str(&e.xml_content(XmlVersion::Implicit1_0)),
            Event::CData(e) => current.text.push_str(&e),
            Event::GeneralRef(e) => {
                let reference = format!("&{};", e.xml_content(XmlVersion::Implicit1_0));
                let resolved =
                    unescape(&reference).map_err(|e| anyhow!("Failed to parse PSKC XML: {e}"))?;
                current.text.push_str(&resolved);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let mut document = stack
        .pop()
        .filter(|_| stack.is_empty())
        .ok_or_else(|| anyhow!("Failed to parse PSKC XML: unexpected end of file"))?;
    document
        .children
        .pop()
        .filter(|root| root.name == "KeyContainer")
        .ok_or_else(|| anyhow!("Not a PSKC file."))
}

fn algorithm_name(uri: &str) -> &str {
    uri.rsplit_once('#').map_or(uri, |(_, name)| name)
}

fn hmac(algorithm: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    macro_rules! compute {
        ($digest:ty) => {{
            let mut mac =
                <Hmac<$digest> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    Ok(match algorithm_name(algorithm) {
        "hmac-sha1" => compute!(sha1::Sha1),
        "hmac-sha224" => compute!(sha2_legacy::Sha224),
        "hmac-sha256" => compute!(sha2_legacy::Sha256),
        "hmac-sha384" => compute!(sha2_legacy::Sha384),
        "hmac-sha512" => compute!(sha2_legacy::Sha512),
        _ => bail!("Unsupported PSKC MAC algorithm: {algorithm}"),
    })
}

fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut data = vec![0u8; 16];
    getrandom::fill(&mut data).map_err(|e| anyhow!("Failed to generate random: {e}"))?;
    let encryptor = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &data)
        .map_err(|_| anyhow!("Invalid PSKC encryption key length."))?;
    data.extend(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext));
    Ok(data)
}

fn decrypt(algorithm: &str, key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    macro_rules! cbc_decrypt {
        ($cipher:ty) => {{
            let (iv, ciphertext) = data.split_at(16);
            cbc::Decryptor::<$cipher>::new_from_slices(key, iv)
                .map_err(|_| anyhow!(DECRYPT_FAILED))?
                .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .map_err(|_| anyhow!(DECRYPT_FAILED))?
        }};
    }
    if data.len() < 32 || !data.len().is_multiple_of(16) {
        bail!(DECRYPT_FAILED);
    }
    Ok(Zeroizing::new(match algorithm_name(algorithm) {
        "aes128-cbc" => cbc_decrypt!(aes::Aes128),
        "aes192-cbc" => cbc_decrypt!(aes::Aes192),
        "aes256-cbc" => cbc_decrypt!(aes::Aes256),
        _ => bail!("Unsupported PSKC encryption algorithm: {algorithm}"),
    }))
}

fn derive_key(
    prf: &str,
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = Zeroizing::new(vec![0u8; key_length]);
    let passphrase = passphrase.as_bytes();
    match algorithm_name(prf) {
        "hmac-sha1" => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, salt, iterations, &mut key),
        "hmac-sha224" => {
            pbkdf2::pbkdf2_hmac::<sha2_legacy::Sha224>(passphrase, salt, iterations, &mut key)
        }
        "hmac-sha256" => {
            pbkdf2::pbkdf2_hmac::<sha2_legacy::Sha256>(passphrase, salt, iterations, &mut key)
        }
        "hmac-sha384" => {
            pbkdf2::pbkdf2_hmac::<sha2_legacy::Sha384>(passphrase, salt, iterations, &mut key)
        }
        "hmac-sha512" => {
            pbkdf2::pbkdf2_hmac::<sha2_legacy::Sha512>(passphrase, salt, iterations, &mut key)
        }
        _ => bail!("Unsupported PSKC key derivation PRF: {prf}"),
    }
    Ok(key)
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    let value: String = value.split_ascii_whitespace().collect();
    B64.decode(value)
        .map_err(|_| anyhow!("Invalid Base64 data in PSKC file."))
}

/// A parsed PSKC file.
pub struct PskcFile {
    root: Element,
}

impl PskcFile {
    pub fn parse(xml: &str) -> Result<Self> {
        Ok(Self {
            root: parse_tree(xml)?,
        })
    }

    pub fn protection(&self) -> PskcProtection {
        fn has_encrypted_value(el: &Element) -> bool {
            el.name == "EncryptedValue" || el.children.iter().any(has_encrypted_value)
        }
        match self.root.child("EncryptionKey") {
            Some(key) if key.child("DerivedKey").is_some() => PskcProtection::Passphrase,
            Some(_) => PskcProtection::PresharedKey,
            None if has_encrypted_value(&self.root) => PskcProtection::PresharedKey,
            None => PskcProtection::None,
        }
    }

    /// Derive the decryption key from a passphrase.
    pub fn derive_key(&self, passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
        let method = self
            .root
            .find(&["EncryptionKey", "DerivedKey", "KeyDerivationMethod"])
            .ok_or_else(|| anyhow!("PSKC file has no key derivation method."))?;
        let algorithm = method.attr("Algorithm").unwrap_or_default();
        if algorithm != PBKDF2 {
            bail!("Unsupported PSKC key derivation algorithm: {algorithm}");
        }
        let params = method
            .child("PBKDF2-params")
            .ok_or_else(|| anyhow!("PSKC file has no PBKDF2 parameters."))?;
        let salt = params
            .find(&["Salt", "Specified"])
            .map(|s| decode_b64(s.text()))
            .transpose()?
            .ok_or_else(|| anyhow!("PSKC file has no PBKDF2 salt."))?;
        let iterations = params
            .child_text("IterationCount")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("PSKC file has no valid PBKDF2 iteration count."))?;
        let key_length = match params.child_text("KeyLength") {
            Some(s) => s
                .parse()
                .ok()
                .filter(|n| (1..=64).contains(n))
                .ok_or_else(|| anyhow!("PSKC file has an invalid PBKDF2 key length."))?,
            None => 16,
        };
        let prf = params
            .child("PRF")
            .and_then(|p| p.attr("Algorithm"))
            .unwrap_or(HMAC_SHA1);
        derive_key(prf, passphrase, &salt, iterations, key_length)
    }

    /// Extract the OATH credentials, decrypting them with `key` if the file is
    /// encrypted.
    pub fn credentials(&self, key: Option<&[u8]>) -> Result<Vec<PskcCredential>> {
        let decryptor = key.map(|key| Decryptor::new(&self.root, key)).transpose()?;
        let mut credentials = Vec::new();
        for package in self.root.children("KeyPackage") {
            let Some(key) = package.child("Key") else {
                continue;
            };
            if let Some(credential) = parse_credential(key, decryptor.as_ref())? {
                credentials.push(credential);
            }
        }
        Ok(credentials)
    }
}

struct Decryptor<'a> {
    key: &'a [u8],
    mac_algorithm: String,
    mac_key: Zeroizing<Vec<u8>>,
}

impl<'a> Decryptor<'a> {
    fn new(root: &Element, key: &'a [u8]) -> Result<Self> {
        let mac_method = root.child("MACMethod");
        let mac_algorithm = mac_method
            .and_then(|m| m.attr("Algorithm"))
            .unwrap_or(HMAC_SHA1)
            .to_string();
        // Files without a MAC key use the encryption key for the MAC.
        let mac_key = match mac_method.and_then(|m| m.child("MACKey")) {
            Some(mac_key) => decrypt_element(mac_key, key)?,
            None => Zeroizing::new(key.to_vec()),
        };
        Ok(Self {
            key,
            mac_algorithm,
            mac_key,
        })
    }
}

fn decrypt_element(el: &Element, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let algorithm = el
        .child("EncryptionMethod")
        .and_then(|m| m.attr("Algorithm"))
        .ok_or_else(|| anyhow!("PSKC file has an encrypted value without algorithm."))?;
    let data = el
        .find(&["CipherData", "CipherValue"])
        .map(|v| decode_b64(v.text()))
        .transpose()?
        .ok_or_else(|| anyhow!("PSKC file has an encrypted value without data."))?;
    decrypt(algorithm, key, &data)
}

/// Read a data field such as `Secret` or `Counter`, decrypting it if needed.
fn read_value(
    field: &Element,
    decryptor: Option<&Decryptor>,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if let Some(plain) = field.child("PlainValue") {
        return Ok(Some(Zeroizing::new(plain.text().as_bytes().to_vec())));
    }
    let Some(encrypted) = field.child("EncryptedValue") else {
        return Ok(None);
    };
    let decryptor = decryptor.ok_or_else(|| anyhow!(DECRYPT_FAILED))?;
    let value = decrypt_element(encrypted, decryptor.key)?;
    if let Some(mac) = field.child("ValueMAC") {
        let expected = decode_b64(mac.text())?;
        let data = encrypted
            .find(&["CipherData", "CipherValue"])
            .map(|v| decode_b64(v.text()))
            .transpose()?
            .unwrap_or_default();
        let actual = hmac(&decryptor.mac_algorithm, &decryptor.mac_key, &data)?;
        if !bool::from(actual.ct_eq(&expected)) {
            bail!(DECRYPT_FAILED);
        }
    }
    Ok(Some(value))
}

fn read_secret(
    data: &Element,
    decryptor: Option<&Decryptor>,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(secret) = data.child("Secret") else {
        return Ok(None);
    };
    if let Some(plain) = secret.child("PlainValue") {
        return decode_b64(plain.text()).map(|s| Some(Zeroizing::new(s)));
    }
    read_value(secret, decryptor)
}

fn read_int(data: &Element, name: &str, decryptor: Option<&Decryptor>) -> Result<Option<u32>> {
    let Some(field) = data.child(name) else {
        return Ok(None);
    };
    if field.child("EncryptedValue").is_some() {
        let value = read_value(field, decryptor)?.unwrap_or_default();
        if value.len() > 4 && value[..value.len() - 4].iter().any(|&b| b != 0) {
            bail!("PSKC {name} value is out of range.");
        }
        return Ok(Some(
            value.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)),
        ));
    }
    let text = field.child("PlainValue").unwrap_or(field).text();
    text.parse()
        .map(Some)
        .map_err(|_| anyhow!("Invalid PSKC {name} value: {text}"))
}

fn parse_credential(
    key: &Element,
    decryptor: Option<&Decryptor>,
) -> Result<Option<PskcCredential>> {
    let oath_type = match key
        .attr("Algorithm")
        .and_then(|a| a.strip_prefix(ALG_PREFIX))
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("hotp") => OathType::Hotp,
        Some("totp") => OathType::Totp,
        other => {
            log::debug!("Skipping PSKC key with unsupported algorithm: {other:?}");
            return Ok(None);
        }
    };
    let Some(id) = key.attr("Id") else {
        log::debug!("Skipping PSKC key without Id");
        return Ok(None);
    };
    let data = key.child("Data");
    let Some(secret) = data
        .map(|d| read_secret(d, decryptor))
        .transpose()?
        .flatten()
    else {
        log::debug!("Skipping PSKC key without secret");
        return Ok(None);
    };
    let read = |name| {
        data.map(|d| read_int(d, name, decryptor))
            .transpose()
            .map(Option::flatten)
    };
    let period = read("TimeInterval")?.unwrap_or(30);
    let counter = read("Counter")?.unwrap_or(0);

    let params = key.child("AlgorithmParameters");
    let hash_algorithm = match params
        .and_then(|p| p.child_text("Suite"))
        .map(str::to_ascii_uppercase)
    {
        Some(s) if s.contains("SHA256") => HashAlgorithm::Sha256,
        Some(s) if s.contains("SHA512") => HashAlgorithm::Sha512,
        _ => HashAlgorithm::Sha1,
    };
    let digits = params
        .and_then(|p| p.child("ResponseFormat"))
        .and_then(|f| f.attr("Length"))
        .and_then(|l| l.parse().ok())
        .unwrap_or(6);

    let mut issuer = None;
    let mut name = id.to_string();
    // If nothing more specific is available, use the friendly name if it contains ':'
    if let Some((i, n)) = key
        .child_text("FriendlyName")
        .and_then(|f| f.split_once(':'))
    {
        issuer = Some(i.to_string());
        name = n.to_string();
    }
    if let Some(i) = key.child_text("Issuer") {
        issuer = Some(i.to_string());
    }
    if let Some(user_id) = key
        .child_text("UserId")
        .or_else(|| key.child_text("KeyUserId"))
    {
        // Use the CN field if the user ID is a DN
        name = match user_id.split("CN=").nth(1) {
            Some(cn) => cn.split(',').next().unwrap_or(cn).to_string(),
            None => user_id.to_string(),
        };
    }

    Ok(Some(PskcCredential {
        issuer,
        name,
        oath_type,
        hash_algorithm,
        secret,
        digits,
        period,
        counter,
    }))
}

/// Serialize a credential as a PSKC file, optionally encrypting the secret.
pub fn write_pskc(
    cred: &CredentialData,
    serial: u32,
    encryption: Option<&PskcEncryption>,
) -> Result<String> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let encryption = match encryption {
        None => {
            xml.push_str(
                "<pskc:KeyContainer xmlns:pskc=\"urn:ietf:params:xml:ns:keyprov:pskc\" \
                 Version=\"1.0\">\n",
            );
            None
        }
        Some(PskcEncryption::Passphrase(passphrase)) => {
            let mut salt = [0u8; 16];
            getrandom::fill(&mut salt).map_err(|e| anyhow!("Failed to generate random: {e}"))?;
            let key = derive_key(HMAC_SHA1, passphrase, &salt, PBKDF2_ITERATIONS, 16)?;
            xml.push_str(&format!(
                "<pskc:KeyContainer xmlns:pskc=\"urn:ietf:params:xml:ns:keyprov:pskc\" \
                 xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" \
                 xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Version=\"1.0\">\n \
                 <pskc:EncryptionKey>\n  \
                 <xenc11:DerivedKey>\n   \
                 <xenc11:KeyDerivationMethod Algorithm=\"{PBKDF2}\">\n    \
                 <xenc11:PBKDF2-params>\n     \
                 <Salt>\n      \
                 <Specified>{salt}</Specified>\n     \
                 </Salt>\n     \
                 <IterationCount>{PBKDF2_ITERATIONS}</IterationCount>\n     \
                 <KeyLength>16</KeyLength>\n    \
                 </xenc11:PBKDF2-params>\n   \
                 </xenc11:KeyDerivationMethod>\n  \
                 </xenc11:DerivedKey>\n \
                 </pskc:EncryptionKey>\n",
                salt = B64.encode(salt),
            ));
            Some(key)
        }
        Some(PskcEncryption::PresharedKey(key)) => {
            xml.push_str(
                "<pskc:KeyContainer xmlns:pskc=\"urn:ietf:params:xml:ns:keyprov:pskc\" \
                 xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Version=\"1.0\">\n \
                 <pskc:EncryptionKey/>\n",
            );
            Some(key.clone())
        }
    };

    let secret = match &encryption {
        None => format!(
            "     <pskc:PlainValue>{}</pskc:PlainValue>\n",
            B64.encode(&cred.secret)
        ),
        Some(key) => {
            let mut mac_key = Zeroizing::new(vec![0u8; 20]);
            getrandom::fill(&mut mac_key).map_err(|e| anyhow!("Failed to generate random: {e}"))?;
            let encrypted_mac_key = encrypt(key, &mac_key)?;
            let encrypted_secret = encrypt(key, &cred.secret)?;
            let value_mac = hmac(HMAC_SHA1, &mac_key, &encrypted_secret)?;
            xml.push_str(&format!(
                " <pskc:MACMethod Algorithm=\"{HMAC_SHA1}\">\n  \
                 <pskc:MACKey>\n   \
                 <xenc:EncryptionMethod Algorithm=\"{AES128_CBC}\"/>\n   \
                 <xenc:CipherData>\n    \
                 <xenc:CipherValue>{}</xenc:CipherValue>\n   \
                 </xenc:CipherData>\n  \
                 </pskc:MACKey>\n \
                 </pskc:MACMethod>\n",
                B64.encode(encrypted_mac_key)
            ));
            format!(
                "     <pskc:EncryptedValue>\n      \
                 <xenc:EncryptionMethod Algorithm=\"{AES128_CBC}\"/>\n      \
                 <xenc:CipherData>\n       \
                 <xenc:CipherValue>{}</xenc:CipherValue>\n      \
                 </xenc:CipherData>\n     \
                 </pskc:EncryptedValue>\n     \
                 <pskc:ValueMAC>{}</pskc:ValueMAC>\n",
                B64.encode(encrypted_secret),
                B64.encode(value_mac)
            )
        }
    };

    let oath_type = match cred.oath_type {
        OathType::Hotp => "hotp",
        OathType::Totp => "totp",
    };
    let suite = match cred.hash_algorithm {
        HashAlgorithm::Sha1 => "SHA1",
        HashAlgorithm::Sha256 => "SHA256",
        HashAlgorithm::Sha512 => "SHA512",
        _ => bail!("Unsupported hash algorithm for PSKC."),
    };
    let friendly_name = match &cred.issuer {
        Some(issuer) => format!("{issuer}:{}", cred.name),
        None => cred.name.clone(),
    };
    let issuer = cred
        .issuer
        .as_deref()
        .map(|i| format!("   <pskc:Issuer>{}</pskc:Issuer>\n", escape(i)))
        .unwrap_or_default();
    let (field, value) = match cred.oath_type {
        OathType::Totp => ("TimeInterval", cred.period),
        OathType::Hotp => ("Counter", cred.counter),
    };

    xml.push_str(&format!(
        " <pskc:KeyPackage>\n  \
         <pskc:DeviceInfo>\n   \
         <pskc:Manufacturer>Yubico</pskc:Manufacturer>\n   \
         <pskc:SerialNo>{serial}</pskc:SerialNo>\n  \
         </pskc:DeviceInfo>\n  \
         <pskc:Key Algorithm=\"{ALG_PREFIX}{oath_type}\" Id=\"{serial}\">\n\
         {issuer}   \
         <pskc:AlgorithmParameters>\n    \
         <pskc:Suite>{suite}</pskc:Suite>\n    \
         <pskc:ResponseFormat Encoding=\"DECIMAL\" Length=\"{digits}\"/>\n   \
         </pskc:AlgorithmParameters>\n   \
         <pskc:FriendlyName>{friendly_name}</pskc:FriendlyName>\n   \
         <pskc:Data>\n    \
         <pskc:Secret>\n\
         {secret}    \
         </pskc:Secret>\n    \
         <pskc:{field}>\n     \
         <pskc:PlainValue>{value}</pskc:PlainValue>\n    \
         </pskc:{field}>\n   \
         </pskc:Data>\n   \
         <pskc:UserId>CN={user_id}</pskc:UserId>\n  \
         </pskc:Key>\n \
         </pskc:KeyPackage>\n\
         </pskc:KeyContainer>\n",
        digits = cred.digits,
        friendly_name = escape(friendly_name.as_str()),
        user_id = escape(cred.name.as_str()),
    ));
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(oath_type: OathType) -> CredentialData {
        CredentialData {
            name: "user, <name>".into(),
            oath_type,
            hash_algorithm: HashAlgorithm::Sha256,
            secret: b"12345678901234567890".to_vec(),
            digits: 8,
            period: 60,
            counter: 42,
            issuer: Some("Issuer & Co".into()),
        }
    }

    fn round_trip(oath_type: OathType, encryption: Option<PskcEncryption>, key: Option<&str>) {
        let cred = credential(oath_type);
        let xml = write_pskc(&cred, 1234567, encryption.as_ref()).unwrap();
        let pskc = PskcFile::parse(&xml).unwrap();
        let key = match (pskc.protection(), key) {
            (PskcProtection::None, None) => None,
            (PskcProtection::Passphrase, Some(p)) => Some(pskc.derive_key(p).unwrap()),
            (PskcProtection::PresharedKey, Some(k)) => {
                Some(Zeroizing::new(hex::decode(k).unwrap()))
            }
            (protection, _) => panic!("unexpected protection: {protection:?}"),
        };
        let creds = pskc
            .credentials(key.as_ref().map(|k| k.as_slice()))
            .unwrap();
        assert_eq!(creds.len(), 1);
        let c = &creds[0];
        assert_eq!(c.issuer.as_deref(), Some("Issuer & Co"));
        // The CN is cut at the first ',', as in 5.x
        assert_eq!(c.name, "user");
        assert_eq!(c.oath_type, oath_type);
        assert_eq!(c.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(c.secret.as_slice(), cred.secret.as_slice());
        assert_eq!(c.digits, 8);
        match oath_type {
            OathType::Totp => assert_eq!((c.period, c.counter), (60, 0)),
            OathType::Hotp => assert_eq!((c.period, c.counter), (30, 42)),
        }
    }

    #[test]
    fn test_round_trip_plain() {
        round_trip(OathType::Totp, None, None);
        round_trip(OathType::Hotp, None, None);
    }

    #[test]
    fn test_round_trip_passphrase() {
        let encryption = PskcEncryption::Passphrase(Zeroizing::new("passphrase123".into()));
        round_trip(OathType::Totp, Some(encryption), Some("passphrase123"));
    }

    #[test]
    fn test_round_trip_preshared_key() {
        let key = "12345678901234567890123456789012";
        let encryption = PskcEncryption::PresharedKey(Zeroizing::new(hex::decode(key).unwrap()));
        round_trip(OathType::Hotp, Some(encryption), Some(key));
    }

    #[test]
    fn test_wrong_passphrase() {
        let encryption = PskcEncryption::Passphrase(Zeroizing::new("passphrase123".into()));
        let xml = write_pskc(&credential(OathType::Totp), 1, Some(&encryption)).unwrap();
        let pskc = PskcFile::parse(&xml).unwrap();
        let key = pskc.derive_key("wrong passphrase").unwrap();
        let err = pskc.credentials(Some(&key)).err().unwrap();
        assert_eq!(err.to_string(), DECRYPT_FAILED);
    }

    // Generated by python-pskc, as used by ykman 5.x.
    const PYTHON_PSKC_PASSPHRASE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<pskc:KeyContainer xmlns:pskc="urn:ietf:params:xml:ns:keyprov:pskc" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Version="1.0">
 <pskc:EncryptionKey>
  <xenc11:DerivedKey>
   <xenc11:KeyDerivationMethod Algorithm="http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2">
    <xenc11:PBKDF2-params>
     <Salt>
      <Specified>DnRDvw3K5pIr0DqyGs7zoA==</Specified>
     </Salt>
     <IterationCount>100000</IterationCount>
     <KeyLength>16</KeyLength>
    </xenc11:PBKDF2-params>
   </xenc11:KeyDerivationMethod>
  </xenc11:DerivedKey>
 </pskc:EncryptionKey>
 <pskc:MACMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
  <pskc:MACKey>
   <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
   <xenc:CipherData>
    <xenc:CipherValue>Ks0fvhden25wXueRdw1ASwziH9J/NYGrbDxoFa1ugXlZeEd4AUlYEeNaa/wFkd2M</xenc:CipherValue>
   </xenc:CipherData>
  </pskc:MACKey>
 </pskc:MACMethod>
 <pskc:KeyPackage>
  <pskc:DeviceInfo>
   <pskc:Manufacturer>Yubico</pskc:Manufacturer>
   <pskc:SerialNo>1234567</pskc:SerialNo>
  </pskc:DeviceInfo>
  <pskc:Key Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp" Id="1234567">
   <pskc:Issuer>Iss &amp; &lt;co&gt;</pskc:Issuer>
   <pskc:AlgorithmParameters>
    <pskc:Suite>SHA1</pskc:Suite>
    <pskc:ResponseFormat Encoding="DECIMAL" Length="6"/>
   </pskc:AlgorithmParameters>
   <pskc:FriendlyName>Iss &amp; &lt;co&gt;:user</pskc:FriendlyName>
   <pskc:Data>
    <pskc:Secret>
     <pskc:EncryptedValue>
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <xenc:CipherData>
       <xenc:CipherValue>XiP1sA0unu1EgwcCy0qAysESdZBxMNJTGYRTkQ8u6kYQzlB30OZwke8GJ3INMF7a</xenc:CipherValue>
      </xenc:CipherData>
     </pskc:EncryptedValue>
     <pskc:ValueMAC>so6voIVg0CErQ+qOFhaLxtR0Vus=</pskc:ValueMAC>
    </pskc:Secret>
    <pskc:TimeInterval>
     <pskc:PlainValue>45</pskc:PlainValue>
    </pskc:TimeInterval>
   </pskc:Data>
   <pskc:UserId>CN=user</pskc:UserId>
  </pskc:Key>
 </pskc:KeyPackage>
</pskc:KeyContainer>
"#;

    #[test]
    fn test_read_python_pskc_passphrase() {
        let pskc = PskcFile::parse(PYTHON_PSKC_PASSPHRASE).unwrap();
        assert_eq!(pskc.protection(), PskcProtection::Passphrase);
        let key = pskc.derive_key("passphrase123").unwrap();
        let creds = pskc.credentials(Some(&key)).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].issuer.as_deref(), Some("Iss & <co>"));
        assert_eq!(creds[0].name, "user");
        assert_eq!(creds[0].secret.as_slice(), b"12345678901234567890");
        assert_eq!(creds[0].period, 45);
    }
}
