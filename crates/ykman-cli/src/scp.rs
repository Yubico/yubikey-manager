//! SCP (Secure Channel Protocol) utilities for automatic SCP11b negotiation
//! and explicit SCP from CLI flags.

use anyhow::{Result, anyhow};
use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::securitydomain::{KeyRef, SecurityDomainSession};
use yubikit::smartcard::{ScpKeyParams, SmartCardConnection, SmartCardProtocol};

use crate::util::{
    format_session_error, format_smartcard_connection_error, parse_hex_u8, read_file_or_stdin,
};

/// Parsed SCP parameters from CLI flags (before device interaction).
#[derive(Clone, Default)]
pub struct ScpParams {
    /// SCP03 keys: (K-ENC, K-MAC, K-DEK?)
    pub scp03_keys: Option<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)>,
    /// SCP11 private key (raw 32-byte scalar)
    pub scp11_private_key: Option<Vec<u8>>,
    /// SCP11 certificate chain (DER)
    pub scp11_certificates: Vec<Vec<u8>>,
    /// Card key reference (kid, kvn)
    pub sd_ref: Option<(u8, u8)>,
    /// OCE key reference (kid, kvn)
    pub oce_ref: Option<(u8, u8)>,
    /// CA certificate for SCP11 verification (DER)
    pub ca_cert: Option<Vec<u8>>,
}

impl ScpParams {
    /// Returns true if the user specified any SCP flags.
    pub fn is_explicit(&self) -> bool {
        self.scp03_keys.is_some() || self.scp11_private_key.is_some() || self.sd_ref.is_some()
    }
}

pub struct ScpInputs<'a> {
    pub scp_cred: &'a [String],
    pub scp_ca: Option<&'a str>,
    pub scp_sd: Option<&'a [String]>,
    pub scp_oce: Option<&'a [String]>,
    pub scp_password: Option<&'a str>,
}

pub fn parse_scp_params(input: ScpInputs<'_>) -> Result<ScpParams> {
    let mut params = ScpParams::default();

    if let Some(sd) = input.scp_sd {
        let kid = parse_hex_u8(&sd[0])?;
        let kvn = parse_hex_u8(&sd[1])?;
        params.sd_ref = Some((kid, kvn));
    }

    if let Some(oce) = input.scp_oce {
        let kid = parse_hex_u8(&oce[0])?;
        let kvn = parse_hex_u8(&oce[1])?;
        params.oce_ref = Some((kid, kvn));
    }

    if let Some(ca_path) = input.scp_ca {
        let data = read_file_or_stdin(ca_path)?;
        params.ca_cert = Some(der_or_first_pem(&data)?);
    }

    if input.scp_cred.is_empty() {
        return Ok(params);
    }

    let first = &input.scp_cred[0];
    let parts: Vec<&str> = first.split(':').collect();
    if (parts.len() == 2 || parts.len() == 3)
        && parts
            .iter()
            .all(|p| p.len() == 32 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        let key_enc = hex::decode(parts[0]).map_err(|_| anyhow!("Invalid SCP03 K-ENC hex."))?;
        let key_mac = hex::decode(parts[1]).map_err(|_| anyhow!("Invalid SCP03 K-MAC hex."))?;
        let key_dek = if parts.len() == 3 {
            Some(hex::decode(parts[2]).map_err(|_| anyhow!("Invalid SCP03 K-DEK hex."))?)
        } else {
            None
        };
        params.scp03_keys = Some((key_enc, key_mac, key_dek));
        return Ok(params);
    }

    for path in input.scp_cred {
        let data = read_file_or_stdin(path)?;
        let pem_text = std::str::from_utf8(&data).ok();

        if let Some(text) = pem_text {
            if text.contains("-----BEGIN") {
                if text.contains("PRIVATE KEY") {
                    let der = decrypt_private_key_data(text, input.scp_password)?;
                    params.scp11_private_key = Some(extract_ec_private_key(&der)?);
                }
                params
                    .scp11_certificates
                    .extend(pem_decode_all_certs(text)?);
            } else {
                params.scp11_certificates.push(data);
            }
        } else {
            params.scp11_certificates.push(data);
        }
    }

    Ok(params)
}

/// Check if a device is connected over NFC (external reader).
pub fn is_nfc(dev: &dyn YubiKeyDevice) -> bool {
    dev.transport() == Transport::Nfc
}

/// Check if automatic SCP11b should be used for a given capability.
pub fn needs_scp11b(dev: &dyn YubiKeyDevice, capability: Capability) -> bool {
    is_nfc(dev) && dev.info().fips_capable.contains(capability)
}

/// Resolve SCP configuration for a command.
///
/// If the user explicitly specified SCP flags, those take priority.
/// Otherwise, if the device is NFC + FIPS-capable for the given capability,
/// auto-negotiate SCP11b.
pub fn resolve_scp(
    dev: &dyn YubiKeyDevice,
    params: &ScpParams,
    capability: Capability,
) -> Result<Option<ScpKeyParams>> {
    // 1. Explicit SCP03
    if let Some((ref key_enc, ref key_mac, ref key_dek)) = params.scp03_keys {
        let kvn = params.sd_ref.map(|(_, kvn)| kvn).unwrap_or(0);
        return Ok(Some(ScpKeyParams::Scp03 {
            kvn,
            key_enc: key_enc
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("SCP03 K-ENC must be 16 bytes."))?,
            key_mac: key_mac
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("SCP03 K-MAC must be 16 bytes."))?,
            key_dek: key_dek
                .as_deref()
                .map(<[u8; 16]>::try_from)
                .transpose()
                .map_err(|_| anyhow!("SCP03 K-DEK must be 16 bytes."))?,
        }));
    }

    // 2. Explicit SCP11a/c (has private key + certs)
    if let Some(ref sk) = params.scp11_private_key {
        let (kid, kvn) = params.sd_ref.unwrap_or((0x11, 0));
        let pk = find_scp11_pk(dev, kid, kvn, params.ca_cert.as_deref())?;
        return Ok(Some(ScpKeyParams::Scp11ac {
            kid,
            kvn,
            pk_sd_ecka: pk,
            sk_oce_ecka: sk
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("SCP11 OCE private key must be 32 bytes."))?,
            certificates: params.scp11_certificates.clone(),
            oce_ref: params.oce_ref,
        }));
    }

    // 3. Explicit --scp-sd without --scp (SCP11b with explicit ref)
    if let Some((kid, kvn)) = params.sd_ref {
        let pk = find_scp11_pk(dev, kid, kvn, params.ca_cert.as_deref())?;
        return Ok(Some(ScpKeyParams::Scp11b {
            kid,
            kvn,
            pk_sd_ecka: pk,
        }));
    }

    // 4. Auto SCP11b for NFC + FIPS
    if needs_scp11b(dev, capability) {
        let (kid, kvn, pk) = find_scp11b_params(dev)?;
        return Ok(Some(ScpKeyParams::Scp11b {
            kid,
            kvn,
            pk_sd_ecka: pk,
        }));
    }

    Ok(None)
}

pub fn resolve_scp_for_app(
    dev: &dyn YubiKeyDevice,
    params: &ScpParams,
    capability: Capability,
    app_name: &str,
) -> Result<Option<ScpKeyParams>> {
    match resolve_scp(dev, params, capability) {
        Ok(config) => Ok(config),
        Err(_) if !params.is_explicit() && needs_scp11b(dev, capability) => {
            Err(anyhow!("Unable to manage {app_name} over NFC without SCP"))
        }
        Err(e) => Err(e),
    }
}

/// Apply SCP configuration to a SmartCardProtocol.
/// The AID must already be selected before calling this.
pub fn apply_scp<C: SmartCardConnection>(
    protocol: &mut SmartCardProtocol<C>,
    params: &ScpKeyParams,
) -> Result<()> {
    protocol
        .init_scp(params)
        .map_err(|e| anyhow!("SCP initialization failed: {e}"))?;
    Ok(())
}

/// Find SCP11b key parameters from the Security Domain on a separate connection.
/// Returns (kid, kvn, pk_sd_ecka_bytes).
pub fn find_scp11b_params(dev: &dyn YubiKeyDevice) -> Result<(u8, u8, Vec<u8>)> {
    find_scp11_pk_with_kid(dev, 0x13).map(|(kvn, pk)| (0x13, kvn, pk))
}

/// Find public key for a given SCP11 kid/kvn from the Security Domain.
fn find_scp11_pk(
    dev: &dyn YubiKeyDevice,
    kid: u8,
    kvn: u8,
    _ca_cert: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| format_smartcard_connection_error("Security Domain", e))?;
    let mut sd = SecurityDomainSession::new(conn)
        .map_err(|(e, _)| format_session_error("Security Domain", e))?;

    let key_ref = KeyRef::new(kid, kvn);
    let certs = sd
        .get_certificate_bundle(key_ref)
        .map_err(|e| anyhow!("Failed to get certificate bundle: {e}"))?;

    if certs.is_empty() {
        return Err(anyhow!(
            "No certificate chain stored for SCP key (KID=0x{kid:02X}, KVN=0x{kvn:02X})"
        ));
    }

    let leaf_cert = &certs[certs.len() - 1];
    extract_ec_pubkey_from_cert(leaf_cert)
}

fn find_scp11_pk_with_kid(dev: &dyn YubiKeyDevice, kid: u8) -> Result<(u8, Vec<u8>)> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| format_smartcard_connection_error("Security Domain", e))?;
    let mut sd = SecurityDomainSession::new(conn)
        .map_err(|(e, _)| format_session_error("Security Domain", e))?;

    let keys = sd
        .get_key_information()
        .map_err(|e| anyhow!("Failed to get key info: {e}"))?;

    let mut kvn = None;
    for key_ref in keys.keys() {
        if key_ref.kid == kid {
            kvn = Some(key_ref.kvn);
            break;
        }
    }
    let kvn = kvn.ok_or_else(|| anyhow!("No SCP key (KID=0x{kid:02X}) found on device"))?;

    let key_ref = KeyRef::new(kid, kvn);
    let certs = sd
        .get_certificate_bundle(key_ref)
        .map_err(|e| anyhow!("Failed to get certificate bundle: {e}"))?;

    if certs.is_empty() {
        return Err(anyhow!(
            "No certificate chain stored for SCP key (KVN=0x{kvn:02X})"
        ));
    }

    let leaf_cert = &certs[certs.len() - 1];
    let pk_bytes = extract_ec_pubkey_from_cert(leaf_cert)?;

    Ok((kvn, pk_bytes))
}

/// Extract the uncompressed EC public key bytes from a DER-encoded X.509 cert.
fn extract_ec_pubkey_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;

    // Outer SEQUENCE
    let (_, content_start, _) = parse_der_tag(cert_der, &mut pos, 0x30)?;

    // TBSCertificate SEQUENCE
    pos = content_start;
    let (_, tbs_start, tbs_end) = parse_der_tag(cert_der, &mut pos, 0x30)?;
    pos = tbs_start;

    // version [0] EXPLICIT (optional)
    if pos < tbs_end && cert_der[pos] == 0xA0 {
        let (_, _, end) = parse_der_tag(cert_der, &mut pos, 0xA0)?;
        pos = end;
    }

    // serialNumber, signature, issuer, validity, subject (skip 5 elements)
    for _ in 0..5 {
        skip_der_element(cert_der, &mut pos)?;
    }

    // subjectPublicKeyInfo SEQUENCE
    let (_, spki_start, _) = parse_der_tag(cert_der, &mut pos, 0x30)?;
    pos = spki_start;

    // algorithm SEQUENCE (skip)
    skip_der_element(cert_der, &mut pos)?;

    // BIT STRING containing the public key
    let (_, bs_start, bs_end) = parse_der_tag(cert_der, &mut pos, 0x03)?;

    if bs_start >= bs_end {
        return Err(anyhow!("Empty BIT STRING in certificate"));
    }
    if cert_der[bs_start] != 0 {
        return Err(anyhow!("Unexpected unused bits in BIT STRING"));
    }

    let pk_bytes = &cert_der[bs_start + 1..bs_end];

    if (pk_bytes.len() == 65 && pk_bytes[0] == 0x04)
        || (pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03))
    {
        Ok(pk_bytes.to_vec())
    } else {
        Err(anyhow!(
            "Unexpected public key format ({} bytes)",
            pk_bytes.len()
        ))
    }
}

fn parse_der_tag(data: &[u8], pos: &mut usize, expected_tag: u8) -> Result<(u8, usize, usize)> {
    if *pos >= data.len() {
        return Err(anyhow!("DER parse: unexpected end"));
    }
    let tag = data[*pos];
    if tag != expected_tag {
        return Err(anyhow!(
            "DER parse: expected 0x{expected_tag:02X}, got 0x{tag:02X}"
        ));
    }
    *pos += 1;
    let (len, content_start) = parse_der_length(data, *pos)?;
    let content_end = content_start + len;
    if content_end > data.len() {
        return Err(anyhow!("DER parse: content extends beyond data"));
    }
    *pos = content_end;
    Ok((tag, content_start, content_end))
}

fn skip_der_element(data: &[u8], pos: &mut usize) -> Result<()> {
    if *pos >= data.len() {
        return Err(anyhow!("DER parse: unexpected end"));
    }
    *pos += 1;
    let (len, content_start) = parse_der_length(data, *pos)?;
    *pos = content_start + len;
    if *pos > data.len() {
        return Err(anyhow!("DER parse: element extends beyond data"));
    }
    Ok(())
}

fn parse_der_length(data: &[u8], pos: usize) -> Result<(usize, usize)> {
    if pos >= data.len() {
        return Err(anyhow!("DER parse: unexpected end of length"));
    }
    let first = data[pos];
    if first < 0x80 {
        Ok((first as usize, pos + 1))
    } else if first == 0x81 {
        if pos + 1 >= data.len() {
            return Err(anyhow!("DER parse: truncated length"));
        }
        Ok((data[pos + 1] as usize, pos + 2))
    } else if first == 0x82 {
        if pos + 2 >= data.len() {
            return Err(anyhow!("DER parse: truncated length"));
        }
        let len = ((data[pos + 1] as usize) << 8) | data[pos + 2] as usize;
        Ok((len, pos + 3))
    } else {
        Err(anyhow!(
            "DER parse: unsupported length encoding 0x{first:02X}"
        ))
    }
}

fn der_or_first_pem(data: &[u8]) -> Result<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
    {
        return pem_decode_first(text);
    }
    Ok(data.to_vec())
}

fn decrypt_private_key_data(text: &str, password: Option<&str>) -> Result<Vec<u8>> {
    if text.contains("ENCRYPTED") {
        let password = match password {
            Some(password) => password.to_string(),
            None => crate::util::prompt_secret("Enter password to decrypt SCP key")?,
        };
        decrypt_pem_private_key(text, &password)
    } else {
        pem_decode_first(text)
    }
}

fn decrypt_pem_private_key(pem_text: &str, password: &str) -> Result<Vec<u8>> {
    use pkcs8::EncryptedPrivateKeyInfo;

    let der = pem_decode_first(pem_text)?;
    let enc_key = EncryptedPrivateKeyInfo::try_from(der.as_slice())
        .map_err(|e| anyhow!("Failed to parse encrypted SCP key: {e}"))?;
    let dec_key = enc_key
        .decrypt(password)
        .map_err(|_| anyhow!("Wrong password for encrypted SCP key."))?;
    Ok(dec_key.as_bytes().to_vec())
}

fn pem_decode_first(text: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let mut in_block = false;
    let mut b64 = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| anyhow!("Invalid PEM data: {e}"))
}

fn pem_decode_all_certs(text: &str) -> Result<Vec<Vec<u8>>> {
    use base64::Engine;
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            in_cert = true;
            b64.clear();
            continue;
        }
        if line.starts_with("-----END CERTIFICATE") {
            in_cert = false;
            let der = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| anyhow!("Invalid PEM cert: {e}"))?;
            certs.push(der);
            continue;
        }
        if in_cert {
            b64.push_str(line.trim());
        }
    }
    Ok(certs)
}

fn extract_ec_private_key(der: &[u8]) -> Result<Vec<u8>> {
    use elliptic_curve::SecretKey;
    use elliptic_curve::pkcs8::DecodePrivateKey;

    if let Ok(sk) = SecretKey::<p256::NistP256>::from_pkcs8_der(der) {
        return Ok(sk.to_bytes().as_slice().to_vec());
    }
    if let Ok(sk) = SecretKey::<p256::NistP256>::from_sec1_der(der) {
        return Ok(sk.to_bytes().as_slice().to_vec());
    }

    for i in 0..der.len().saturating_sub(33) {
        if der[i] == 0x04 && der[i + 1] == 0x20 {
            return Ok(der[i + 2..i + 34].to_vec());
        }
    }
    Err(anyhow!("Could not extract EC private key from DER."))
}
