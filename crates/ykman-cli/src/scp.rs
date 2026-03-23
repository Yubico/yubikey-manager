//! SCP (Secure Channel Protocol) utilities for automatic SCP11b negotiation.

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::management::Capability;
use yubikit_rs::securitydomain::{KeyRef, SecurityDomainSession};

use crate::util::CliError;

const YK_READER_PREFIX: &str = "yubico yubikey";

/// Check if a device is connected over NFC (external reader, not the YubiKey's
/// own CCID interface).
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

/// Find SCP11b key parameters from the Security Domain on a separate connection.
/// Returns (kid, kvn, pk_sd_ecka_bytes).
pub fn find_scp11b_params(dev: &YubiKeyDevice) -> Result<(u8, u8, Vec<u8>), CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection for SCP: {e}")))?;
    let mut sd = SecurityDomainSession::new(conn)
        .map_err(|e| CliError(format!("Failed to open Security Domain: {e}")))?;

    // Find SCP11b key (KID=0x13)
    let keys = sd
        .get_key_information()
        .map_err(|e| CliError(format!("Failed to get key info: {e}")))?;

    let mut kvn = None;
    for (key_ref, _) in &keys {
        if key_ref.kid == 0x13 {
            kvn = Some(key_ref.kvn);
            break;
        }
    }
    let kvn = kvn.ok_or_else(|| {
        CliError("No SCP11b key (KID=0x13) found on device".into())
    })?;

    // Get certificate bundle
    let key_ref = KeyRef::new(0x13, kvn);
    let certs = sd
        .get_certificate_bundle(key_ref)
        .map_err(|e| CliError(format!("Failed to get certificate bundle: {e}")))?;

    if certs.is_empty() {
        return Err(CliError(format!(
            "No certificate chain stored for SCP11b key (KVN=0x{kvn:02X})"
        )));
    }

    // Extract public key from leaf certificate (last in chain)
    let leaf_cert = &certs[certs.len() - 1];
    let pk_bytes = extract_ec_pubkey_from_cert(leaf_cert)?;

    Ok((0x13, kvn, pk_bytes))
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
