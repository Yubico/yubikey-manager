//! SCP (Secure Channel Protocol) utilities for automatic SCP11b negotiation
//! and explicit SCP from CLI flags.

use yubikit::device::YubiKeyDevice;
use yubikit::smartcard::{SmartCardConnection, SmartCardProtocol};
use yubikit::management::Capability;
use yubikit::securitydomain::{KeyRef, SecurityDomainSession};

use crate::util::CliError;

const YK_READER_PREFIX: &str = "yubico yubikey";

/// SCP configuration resolved from CLI flags and device state.
#[derive(Clone)]
pub enum ScpConfig {
    /// No SCP — plain connection.
    None,
    /// SCP03 with static keys.
    Scp03 {
        kvn: u8,
        key_enc: Vec<u8>,
        key_mac: Vec<u8>,
        key_dek: Option<Vec<u8>>,
    },
    /// SCP11b — only needs card key reference + public key from SD.
    Scp11b {
        kid: u8,
        kvn: u8,
        pk_sd_ecka: Vec<u8>,
    },
    /// SCP11a or SCP11c — needs OCE private key + cert chain.
    Scp11ac {
        kid: u8,
        kvn: u8,
        pk_sd_ecka: Vec<u8>,
        sk_oce_ecka: Vec<u8>,
        certificates: Vec<Vec<u8>>,
        oce_ref: Option<(u8, u8)>,
    },
}

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
        self.scp03_keys.is_some()
            || self.scp11_private_key.is_some()
            || self.sd_ref.is_some()
    }
}

/// Check if a device is connected over NFC (external reader).
pub fn is_nfc(dev: &YubiKeyDevice) -> bool {
    match dev.reader_name() {
        Some(name) => !name.to_ascii_lowercase().contains(YK_READER_PREFIX),
        None => false,
    }
}

/// Check if automatic SCP11b should be used for a given capability.
pub fn needs_scp11b(dev: &YubiKeyDevice, capability: Capability) -> bool {
    is_nfc(dev) && dev.info().fips_capable.contains(capability)
}

/// Resolve SCP configuration for a command.
///
/// If the user explicitly specified SCP flags, those take priority.
/// Otherwise, if the device is NFC + FIPS-capable for the given capability,
/// auto-negotiate SCP11b.
pub fn resolve_scp(
    dev: &YubiKeyDevice,
    params: &ScpParams,
    capability: Capability,
) -> Result<ScpConfig, CliError> {
    // 1. Explicit SCP03
    if let Some((ref key_enc, ref key_mac, ref key_dek)) = params.scp03_keys {
        let kvn = params.sd_ref.map(|(_, kvn)| kvn).unwrap_or(0);
        return Ok(ScpConfig::Scp03 {
            kvn,
            key_enc: key_enc.clone(),
            key_mac: key_mac.clone(),
            key_dek: key_dek.clone(),
        });
    }

    // 2. Explicit SCP11a/c (has private key + certs)
    if let Some(ref sk) = params.scp11_private_key {
        let (kid, kvn) = params.sd_ref.unwrap_or((0x11, 0));
        let pk = find_scp11_pk(dev, kid, kvn, params.ca_cert.as_deref())?;
        return Ok(ScpConfig::Scp11ac {
            kid,
            kvn,
            pk_sd_ecka: pk,
            sk_oce_ecka: sk.clone(),
            certificates: params.scp11_certificates.clone(),
            oce_ref: params.oce_ref,
        });
    }

    // 3. Explicit --scp-sd without --scp (SCP11b with explicit ref)
    if let Some((kid, kvn)) = params.sd_ref {
        let pk = find_scp11_pk(dev, kid, kvn, params.ca_cert.as_deref())?;
        return Ok(ScpConfig::Scp11b {
            kid,
            kvn,
            pk_sd_ecka: pk,
        });
    }

    // 4. Auto SCP11b for NFC + FIPS
    if needs_scp11b(dev, capability) {
        let (kid, kvn, pk) = find_scp11b_params(dev)?;
        return Ok(ScpConfig::Scp11b {
            kid,
            kvn,
            pk_sd_ecka: pk,
        });
    }

    Ok(ScpConfig::None)
}

/// Apply SCP configuration to a SmartCardProtocol.
/// The AID must already be selected before calling this.
/// Convert an `ScpConfig` into `ScpKeyParams`, returning `None` for
/// `ScpConfig::None`.
pub fn to_scp_key_params(config: &ScpConfig) -> Option<yubikit::scp::ScpKeyParams> {
    match config {
        ScpConfig::None => None,
        ScpConfig::Scp03 {
            kvn,
            key_enc,
            key_mac,
            key_dek,
        } => Some(yubikit::scp::ScpKeyParams::Scp03 {
            kvn: *kvn,
            key_enc: key_enc.clone(),
            key_mac: key_mac.clone(),
            key_dek: key_dek.clone(),
        }),
        ScpConfig::Scp11b {
            kid,
            kvn,
            pk_sd_ecka,
        } => Some(yubikit::scp::ScpKeyParams::Scp11b {
            kid: *kid,
            kvn: *kvn,
            pk_sd_ecka: pk_sd_ecka.clone(),
        }),
        ScpConfig::Scp11ac {
            kid,
            kvn,
            pk_sd_ecka,
            sk_oce_ecka,
            certificates,
            oce_ref,
        } => Some(yubikit::scp::ScpKeyParams::Scp11ac {
            kid: *kid,
            kvn: *kvn,
            pk_sd_ecka: pk_sd_ecka.clone(),
            sk_oce_ecka: sk_oce_ecka.clone(),
            certificates: certificates.clone(),
            oce_ref: *oce_ref,
        }),
    }
}

pub fn apply_scp<C: SmartCardConnection>(
    protocol: &mut SmartCardProtocol<C>,
    config: &ScpConfig,
) -> Result<(), CliError> {
    if let Some(params) = to_scp_key_params(config) {
        protocol
            .init_scp(&params)
            .map_err(|e| CliError(format!("SCP initialization failed: {e}")))?;
    }
    Ok(())
}

/// Find SCP11b key parameters from the Security Domain on a separate connection.
/// Returns (kid, kvn, pk_sd_ecka_bytes).
pub fn find_scp11b_params(dev: &YubiKeyDevice) -> Result<(u8, u8, Vec<u8>), CliError> {
    find_scp11_pk_with_kid(dev, 0x13)
        .map(|(kvn, pk)| (0x13, kvn, pk))
}

/// Find public key for a given SCP11 kid/kvn from the Security Domain.
fn find_scp11_pk(
    dev: &YubiKeyDevice,
    kid: u8,
    kvn: u8,
    _ca_cert: Option<&[u8]>,
) -> Result<Vec<u8>, CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection for SCP: {e}")))?;
    let mut sd = SecurityDomainSession::new(conn)
        .map_err(|e| CliError(format!("Failed to open Security Domain: {e}")))?;

    let key_ref = KeyRef::new(kid, kvn);
    let certs = sd
        .get_certificate_bundle(key_ref)
        .map_err(|e| CliError(format!("Failed to get certificate bundle: {e}")))?;

    if certs.is_empty() {
        return Err(CliError(format!(
            "No certificate chain stored for SCP key (KID=0x{kid:02X}, KVN=0x{kvn:02X})"
        )));
    }

    let leaf_cert = &certs[certs.len() - 1];
    extract_ec_pubkey_from_cert(leaf_cert)
}

fn find_scp11_pk_with_kid(dev: &YubiKeyDevice, kid: u8) -> Result<(u8, Vec<u8>), CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection for SCP: {e}")))?;
    let mut sd = SecurityDomainSession::new(conn)
        .map_err(|e| CliError(format!("Failed to open Security Domain: {e}")))?;

    let keys = sd
        .get_key_information()
        .map_err(|e| CliError(format!("Failed to get key info: {e}")))?;

    let mut kvn = None;
    for (key_ref, _) in &keys {
        if key_ref.kid == kid {
            kvn = Some(key_ref.kvn);
            break;
        }
    }
    let kvn = kvn.ok_or_else(|| {
        CliError(format!("No SCP key (KID=0x{kid:02X}) found on device"))
    })?;

    let key_ref = KeyRef::new(kid, kvn);
    let certs = sd
        .get_certificate_bundle(key_ref)
        .map_err(|e| CliError(format!("Failed to get certificate bundle: {e}")))?;

    if certs.is_empty() {
        return Err(CliError(format!(
            "No certificate chain stored for SCP key (KVN=0x{kvn:02X})"
        )));
    }

    let leaf_cert = &certs[certs.len() - 1];
    let pk_bytes = extract_ec_pubkey_from_cert(leaf_cert)?;

    Ok((kvn, pk_bytes))
}

/// Extract the uncompressed EC public key bytes from a DER-encoded X.509 cert.
fn extract_ec_pubkey_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, CliError> {
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
        return Err(CliError("Empty BIT STRING in certificate".into()));
    }
    if cert_der[bs_start] != 0 {
        return Err(CliError("Unexpected unused bits in BIT STRING".into()));
    }

    let pk_bytes = &cert_der[bs_start + 1..bs_end];

    if (pk_bytes.len() == 65 && pk_bytes[0] == 0x04)
        || (pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03))
    {
        Ok(pk_bytes.to_vec())
    } else {
        Err(CliError(format!(
            "Unexpected public key format ({} bytes)",
            pk_bytes.len()
        )))
    }
}

fn parse_der_tag(
    data: &[u8],
    pos: &mut usize,
    expected_tag: u8,
) -> Result<(u8, usize, usize), CliError> {
    if *pos >= data.len() {
        return Err(CliError("DER parse: unexpected end".into()));
    }
    let tag = data[*pos];
    if tag != expected_tag {
        return Err(CliError(format!(
            "DER parse: expected 0x{expected_tag:02X}, got 0x{tag:02X}"
        )));
    }
    *pos += 1;
    let (len, content_start) = parse_der_length(data, *pos)?;
    let content_end = content_start + len;
    if content_end > data.len() {
        return Err(CliError("DER parse: content extends beyond data".into()));
    }
    *pos = content_end;
    Ok((tag, content_start, content_end))
}

fn skip_der_element(data: &[u8], pos: &mut usize) -> Result<(), CliError> {
    if *pos >= data.len() {
        return Err(CliError("DER parse: unexpected end".into()));
    }
    *pos += 1;
    let (len, content_start) = parse_der_length(data, *pos)?;
    *pos = content_start + len;
    if *pos > data.len() {
        return Err(CliError("DER parse: element extends beyond data".into()));
    }
    Ok(())
}

fn parse_der_length(data: &[u8], pos: usize) -> Result<(usize, usize), CliError> {
    if pos >= data.len() {
        return Err(CliError("DER parse: unexpected end of length".into()));
    }
    let first = data[pos];
    if first < 0x80 {
        Ok((first as usize, pos + 1))
    } else if first == 0x81 {
        if pos + 1 >= data.len() {
            return Err(CliError("DER parse: truncated length".into()));
        }
        Ok((data[pos + 1] as usize, pos + 2))
    } else if first == 0x82 {
        if pos + 2 >= data.len() {
            return Err(CliError("DER parse: truncated length".into()));
        }
        let len = ((data[pos + 1] as usize) << 8) | data[pos + 2] as usize;
        Ok((len, pos + 3))
    } else {
        Err(CliError(format!(
            "DER parse: unsupported length encoding 0x{first:02X}"
        )))
    }
}
