// Copyright (c) 2026 Yubico AB
// All rights reserved.
//
//   Redistribution and use in source and binary forms, with or
//   without modification, are permitted provided that the following
//   conditions are met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//    2. Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use std::collections::HashMap;
use std::fmt;

use aes::Aes128;
use cbc::Encryptor as CbcEncryptor;
use cipher::{BlockEncryptMut, KeyIvInit};

use crate::core::patch_version;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol, Sw, Version};
use crate::tlv::{parse_tlv_list, tlv_encode, tlv_parse, tlv_unpack};

// ---------------------------------------------------------------------------
// APDU instruction constants
// ---------------------------------------------------------------------------

const INS_GET_DATA: u8 = 0xCA;
const INS_PUT_KEY: u8 = 0xD8;
const INS_STORE_DATA: u8 = 0xE2;
const INS_DELETE: u8 = 0xE4;
const INS_GENERATE_KEY: u8 = 0xF1;

// SCP INS constants used by reset()
const INS_INITIALIZE_UPDATE: u8 = 0x50;
const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_PERFORM_SECURITY_OPERATION: u8 = 0x2A;

// ---------------------------------------------------------------------------
// Tag constants
// ---------------------------------------------------------------------------

const TAG_KEY_INFORMATION: u32 = 0xE0;
const TAG_CARD_RECOGNITION_DATA: u32 = 0x66;
const TAG_CA_KLOC_IDENTIFIERS: u32 = 0xFF33;
const TAG_CA_KLCC_IDENTIFIERS: u32 = 0xFF34;
const TAG_CERTIFICATE_STORE: u32 = 0xBF21;

// ---------------------------------------------------------------------------
// Default KCV IV for AES key check values
// ---------------------------------------------------------------------------

const DEFAULT_KCV_IV: [u8; 16] = [0x01; 16];

// ---------------------------------------------------------------------------
// KeyType
// ---------------------------------------------------------------------------

/// SCP key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyType {
    Aes = 0x88,
    EccPublicKey = 0xB0,
    EccPrivateKey = 0xB1,
    EccKeyParams = 0xF0,
}

impl KeyType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x88 => Some(Self::Aes),
            0xB0 => Some(Self::EccPublicKey),
            0xB1 => Some(Self::EccPrivateKey),
            0xF0 => Some(Self::EccKeyParams),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Curve
// ---------------------------------------------------------------------------

/// Elliptic curve identifiers for SCP11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Curve {
    Secp256r1 = 0x00,
    Secp384r1 = 0x01,
    Secp521r1 = 0x02,
    BrainpoolP256r1 = 0x03,
    BrainpoolP384r1 = 0x05,
    BrainpoolP512r1 = 0x07,
}

impl Curve {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Secp256r1),
            0x01 => Some(Self::Secp384r1),
            0x02 => Some(Self::Secp521r1),
            0x03 => Some(Self::BrainpoolP256r1),
            0x05 => Some(Self::BrainpoolP384r1),
            0x07 => Some(Self::BrainpoolP512r1),
            _ => None,
        }
    }

    /// OID for this curve (DER-encoded OID value bytes, without the 0x06 tag).
    pub fn oid(&self) -> &'static [u8] {
        match self {
            // 1.2.840.10045.3.1.7
            Self::Secp256r1 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
            // 1.3.132.0.34
            Self::Secp384r1 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
            // 1.3.132.0.35
            Self::Secp521r1 => &[0x2B, 0x81, 0x04, 0x00, 0x23],
            // 1.3.36.3.3.2.8.1.1.7
            Self::BrainpoolP256r1 => &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
            // 1.3.36.3.3.2.8.1.1.11
            Self::BrainpoolP384r1 => &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
            // 1.3.36.3.3.2.8.1.1.13
            Self::BrainpoolP512r1 => &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
        }
    }

    /// Detect curve from an uncompressed SEC1 public key (0x04 || x || y).
    /// Uses the byte length to determine the curve.
    pub fn from_public_key_bytes(data: &[u8]) -> Option<Self> {
        if data.first() != Some(&0x04) {
            return None;
        }
        let coord_len = (data.len() - 1) / 2;
        match coord_len {
            32 => Some(Self::Secp256r1), // Could also be BrainpoolP256r1
            48 => Some(Self::Secp384r1), // Could also be BrainpoolP384r1
            64 => Some(Self::BrainpoolP512r1),
            66 => Some(Self::Secp521r1),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ScpKid
// ---------------------------------------------------------------------------

/// SCP Key ID values identifying the SCP variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScpKid {
    Scp03 = 0x01,
    Scp11a = 0x11,
    Scp11b = 0x13,
    Scp11c = 0x15,
}

impl ScpKid {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Scp03),
            0x11 => Some(Self::Scp11a),
            0x13 => Some(Self::Scp11b),
            0x15 => Some(Self::Scp11c),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// KeyRef
// ---------------------------------------------------------------------------

/// Reference to an SCP key: key ID (kid) and key version number (kvn).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyRef {
    pub kid: u8,
    pub kvn: u8,
}

impl KeyRef {
    pub fn new(kid: u8, kvn: u8) -> Self {
        Self { kid, kvn }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() >= 2 {
            Some(Self {
                kid: data[0],
                kvn: data[1],
            })
        } else {
            None
        }
    }

    pub fn to_bytes(self) -> [u8; 2] {
        [self.kid, self.kvn]
    }
}

impl fmt::Debug for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyRef(kid=0x{:02x}, kvn=0x{:02x})", self.kid, self.kvn)
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyRef(kid=0x{:02x}, kvn=0x{:02x})", self.kid, self.kvn)
    }
}

// ---------------------------------------------------------------------------
// StaticKeys (SCP03)
// ---------------------------------------------------------------------------

/// SCP03 static key set.
#[derive(Debug, Clone)]
pub struct StaticKeys {
    pub key_enc: Vec<u8>,
    pub key_mac: Vec<u8>,
    pub key_dek: Option<Vec<u8>>,
}

impl StaticKeys {
    pub fn new(key_enc: Vec<u8>, key_mac: Vec<u8>, key_dek: Option<Vec<u8>>) -> Self {
        Self {
            key_enc,
            key_mac,
            key_dek,
        }
    }

    /// Default SCP03 static keys (all 0x40..0x4f repeated).
    pub fn default_keys() -> Self {
        let key: Vec<u8> = (0x40..=0x4F).collect();
        Self {
            key_enc: key.clone(),
            key_mac: key.clone(),
            key_dek: Some(key),
        }
    }

    /// Iterate over the three keys (enc, mac, dek) in order.
    /// Panics if key_dek is None.
    pub fn keys(&self) -> [&[u8]; 3] {
        [
            &self.key_enc,
            &self.key_mac,
            self.key_dek.as_deref().expect("key_dek must be set"),
        ]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode an integer as an ASN.1 INTEGER in TLV(0x93).
fn int2asn1(value: &[u8]) -> Vec<u8> {
    let mut bs = value.to_vec();
    // Remove leading zeros
    while bs.len() > 1 && bs[0] == 0 {
        bs.remove(0);
    }
    if bs[0] & 0x80 != 0 {
        bs.insert(0, 0x00);
    }
    tlv_encode(0x93, &bs)
}

/// AES-CBC encrypt with a given IV (no padding).
fn encrypt_cbc(key: &[u8], data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
    let encryptor =
        CbcEncryptor::<Aes128>::new_from_slices(key, iv).expect("AES-CBC key/iv size mismatch");
    encryptor.encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
}

/// AES-CBC encrypt with zero IV.
fn encrypt_cbc_zero_iv(key: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt_cbc(key, data, &[0u8; 16])
}

// ---------------------------------------------------------------------------
// SecurityDomainSession
// ---------------------------------------------------------------------------

/// A session for managing SCP keys on the YubiKey Security Domain.
pub struct SecurityDomainSession<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
    /// The static DEK from the SCP03 key set used for authentication.
    /// Required for `put_key_static` and `put_key_ec_private` operations.
    dek: Option<Vec<u8>>,
}

impl<C: SmartCardConnection> SecurityDomainSession<C> {
    /// Open a new Security Domain session by selecting the Secure Domain AID.
    pub fn new(connection: C) -> Result<Self, SmartCardError> {
        let mut protocol = SmartCardProtocol::new(connection);
        protocol.select(Aid::SECURE_DOMAIN)?;
        let version = patch_version(Version(5, 3, 0));
        protocol.configure(version);
        Ok(Self {
            protocol,
            version,
            dek: None,
        })
    }

    /// Open a Security Domain session with SCP (Secure Channel Protocol).
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, SmartCardError> {
        let mut protocol = SmartCardProtocol::new(connection);
        protocol.select(Aid::SECURE_DOMAIN)?;
        protocol.init_scp(scp_key_params)?;
        let version = patch_version(Version(5, 3, 0));
        protocol.configure(version);
        // Store DEK from SCP03 key params for key management operations
        let dek = match scp_key_params {
            crate::scp::ScpKeyParams::Scp03 { key_dek, .. } => key_dek.clone(),
            _ => None,
        };
        Ok(Self {
            protocol,
            version,
            dek,
        })
    }

    /// The Security Domain version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The static DEK from the SCP03 key set, if authenticated with SCP03.
    /// Needed as the `dek` parameter for `put_key_static` and `put_key_ec_private`.
    pub fn dek(&self) -> Option<&[u8]> {
        self.dek.as_deref()
    }

    /// Override the version (for development devices).
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
        self.protocol.configure(version);
    }

    /// Get a reference to the underlying protocol.
    pub fn protocol(&self) -> &SmartCardProtocol<C> {
        &self.protocol
    }

    /// Get a mutable reference to the underlying protocol.
    pub fn protocol_mut(&mut self) -> &mut SmartCardProtocol<C> {
        &mut self.protocol
    }

    /// Read data from the security domain.
    pub fn get_data(&mut self, tag: u32, data: &[u8]) -> Result<Vec<u8>, SmartCardError> {
        self.protocol
            .send_apdu(0, INS_GET_DATA, (tag >> 8) as u8, (tag & 0xFF) as u8, data)
    }

    /// Get information about the currently loaded keys.
    ///
    /// Returns a map from `KeyRef` to a map of key-component-type to length.
    pub fn get_key_information(
        &mut self,
    ) -> Result<HashMap<KeyRef, HashMap<u8, u8>>, SmartCardError> {
        let resp = self.get_data(TAG_KEY_INFORMATION, &[])?;
        let entries = parse_tlv_list(&resp)?;

        let mut keys = HashMap::new();
        for (tag, entry_data) in entries {
            if tag != 0xC0 {
                return Err(SmartCardError::BadResponse(format!(
                    "Expected tag 0xC0, got 0x{tag:02X}"
                )));
            }
            let inner = &entry_data;
            if inner.len() < 2 {
                return Err(SmartCardError::BadResponse(
                    "Key info entry too short".into(),
                ));
            }
            let key_ref = KeyRef::from_bytes(&inner[..2]).expect("inner has at least 2 bytes");
            let mut components = HashMap::new();
            let pairs = &inner[2..];
            for chunk in pairs.chunks_exact(2) {
                components.insert(chunk[0], chunk[1]);
            }
            keys.insert(key_ref, components);
        }
        Ok(keys)
    }

    /// Get card recognition data.
    pub fn get_card_recognition_data(&mut self) -> Result<Vec<u8>, SmartCardError> {
        let resp = self.get_data(TAG_CARD_RECOGNITION_DATA, &[])?;
        Ok(tlv_unpack(0x73, &resp)?)
    }

    /// Get supported CA identifiers (Subject Key Identifiers).
    ///
    /// Setting one of `kloc` or `klcc` to `true` returns only those CAs.
    /// If both are `false`, both kinds are returned.
    pub fn get_supported_ca_identifiers(
        &mut self,
        kloc: bool,
        klcc: bool,
    ) -> Result<HashMap<KeyRef, Vec<u8>>, SmartCardError> {
        let (kloc, klcc) = if !kloc && !klcc {
            (true, true)
        } else {
            (kloc, klcc)
        };

        let mut data = Vec::new();
        for (fetch, tag) in [
            (kloc, TAG_CA_KLOC_IDENTIFIERS),
            (klcc, TAG_CA_KLCC_IDENTIFIERS),
        ] {
            if fetch {
                match self.get_data(tag, &[]) {
                    Ok(resp) => data.extend_from_slice(&resp),
                    Err(SmartCardError::Apdu { sw, .. })
                        if Sw::from_u16(sw) == Some(Sw::ReferenceDataNotFound) =>
                    {
                        // No data for this tag, skip
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        let tlvs = parse_tlv_list(&data)?;

        let mut result = HashMap::new();
        // Entries come in pairs: (tag, ski_value), (tag, key_ref_value)
        for pair in tlvs.chunks(2) {
            if pair.len() == 2
                && let Some(key_ref) = KeyRef::from_bytes(&pair[1].1)
            {
                result.insert(key_ref, pair[0].1.clone());
            }
        }
        Ok(result)
    }

    /// Get the certificate bundle associated with an SCP11 key.
    ///
    /// Returns DER-encoded certificates, leaf-last.
    pub fn get_certificate_bundle(&mut self, key: KeyRef) -> Result<Vec<Vec<u8>>, SmartCardError> {
        let key_tlv = tlv_encode(0xA6, &tlv_encode(0x83, &key.to_bytes()));

        match self.get_data(TAG_CERTIFICATE_STORE, &key_tlv) {
            Ok(resp) => {
                // Each certificate is a full DER-encoded TLV (SEQUENCE).
                // Return each entry as raw bytes including tag + length.
                let mut certs = Vec::new();
                let mut offset = 0;
                while offset < resp.len() {
                    let (_, _, _, end) = tlv_parse(&resp, offset).map_err(|e| {
                        SmartCardError::BadResponse(format!("TLV parse error: {e}"))
                    })?;
                    certs.push(resp[offset..end].to_vec());
                    offset = end;
                }
                Ok(certs)
            }
            Err(SmartCardError::Apdu { sw, .. })
                if Sw::from_u16(sw) == Some(Sw::ReferenceDataNotFound) =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Perform a factory reset of the Security Domain.
    ///
    /// Removes all keys and associated data by blocking each key with
    /// repeated failed authentication attempts.
    pub fn reset(&mut self) -> Result<(), SmartCardError> {
        let keys: Vec<KeyRef> = self.get_key_information()?.into_keys().collect();
        let data = [0u8; 8];

        for key in keys {
            let (ins, key_ref) = if key.kid == 0x01 {
                // SCP03: use KID=0, KVN=0 to allow deleting default keys (KVN=0xFF)
                (INS_INITIALIZE_UPDATE, KeyRef::new(0, 0))
            } else if key.kid == 0x02 || key.kid == 0x03 {
                continue; // Deleted along with KID=0x01
            } else if key.kid == 0x11 || key.kid == 0x15 {
                (INS_EXTERNAL_AUTHENTICATE, key)
            } else if key.kid == 0x13 {
                (INS_INTERNAL_AUTHENTICATE, key)
            } else {
                // 0x10, 0x20-0x2F
                (INS_PERFORM_SECURITY_OPERATION, key)
            };

            for _ in 0..65 {
                match self
                    .protocol
                    .send_apdu(0x80, ins, key_ref.kvn, key_ref.kid, &data)
                {
                    Err(SmartCardError::Apdu { sw, .. })
                        if Sw::from_u16(sw) == Some(Sw::AuthMethodBlocked)
                            || Sw::from_u16(sw) == Some(Sw::SecurityConditionNotSatisfied) =>
                    {
                        break;
                    }
                    Err(SmartCardError::Apdu { sw, .. })
                        if Sw::from_u16(sw) == Some(Sw::IncorrectParameters) =>
                    {
                        continue;
                    }
                    Err(e) => return Err(e),
                    Ok(_) => continue,
                }
            }
        }

        Ok(())
    }

    /// Store data in the security domain.
    ///
    /// Requires OCE verification (SCP authentication).
    pub fn store_data(&mut self, data: &[u8]) -> Result<(), SmartCardError> {
        self.protocol.send_apdu(0, INS_STORE_DATA, 0x90, 0, data)?;
        Ok(())
    }

    /// Store the certificate chain for the given key.
    ///
    /// Requires OCE verification. Certificates are DER-encoded, leaf-last.
    pub fn store_certificate_bundle(
        &mut self,
        key: KeyRef,
        certificates: &[&[u8]],
    ) -> Result<(), SmartCardError> {
        let key_tlv = tlv_encode(0xA6, &tlv_encode(0x83, &key.to_bytes()));
        let certs_concat: Vec<u8> = certificates
            .iter()
            .flat_map(|c| c.iter().copied())
            .collect();
        let cert_store_tlv = tlv_encode(TAG_CERTIFICATE_STORE, &certs_concat);

        let mut data = key_tlv;
        data.extend_from_slice(&cert_store_tlv);
        self.store_data(&data)
    }

    /// Store which certificate serial numbers can be used for a given key.
    ///
    /// Requires OCE verification. If no allowlist is stored, any certificate
    /// signed by the CA can be used.
    pub fn store_allowlist(
        &mut self,
        key: KeyRef,
        serials: &[Vec<u8>],
    ) -> Result<(), SmartCardError> {
        let key_tlv = tlv_encode(0xA6, &tlv_encode(0x83, &key.to_bytes()));
        let serials_data: Vec<u8> = serials.iter().flat_map(|s| int2asn1(s)).collect();
        let allowlist_tlv = tlv_encode(0x70, &serials_data);

        let mut data = key_tlv;
        data.extend_from_slice(&allowlist_tlv);
        self.store_data(&data)
    }

    /// Store the SKI (Subject Key Identifier) for the CA of a given key.
    ///
    /// Requires OCE verification.
    pub fn store_ca_issuer(&mut self, key: KeyRef, ski: &[u8]) -> Result<(), SmartCardError> {
        let klcc = matches!(
            key.kid,
            x if x == ScpKid::Scp11a as u8
                || x == ScpKid::Scp11b as u8
                || x == ScpKid::Scp11c as u8
        );
        let flag = if klcc { b"\x01" } else { b"\x00" };

        let inner = [
            tlv_encode(0x80, flag),
            tlv_encode(0x42, ski),
            tlv_encode(0x83, &key.to_bytes()),
        ]
        .concat();
        let data = tlv_encode(0xA6, &inner);
        self.store_data(&data)
    }

    /// Delete one or more keys matching the given KID and/or KVN.
    ///
    /// Requires OCE verification. To delete the final key, set `delete_last`
    /// to `true`.
    pub fn delete_key(
        &mut self,
        kid: u8,
        kvn: u8,
        delete_last: bool,
    ) -> Result<(), SmartCardError> {
        if kid == 0 && kvn == 0 {
            return Err(SmartCardError::BadResponse(
                "Must specify at least one of kid, kvn".into(),
            ));
        }

        let kid = if (1..=3).contains(&kid) {
            // SCP03 keys can only be deleted by KVN
            if kvn != 0 {
                0
            } else {
                return Err(SmartCardError::BadResponse(
                    "SCP03 keys can only be deleted by KVN".into(),
                ));
            }
        } else {
            kid
        };

        let mut data = Vec::new();
        if kid != 0 {
            data.extend_from_slice(&tlv_encode(0xD0, &[kid]));
        }
        if kvn != 0 {
            data.extend_from_slice(&tlv_encode(0xD2, &[kvn]));
        }

        self.protocol
            .send_apdu(0x80, INS_DELETE, 0, if delete_last { 1 } else { 0 }, &data)?;
        Ok(())
    }

    /// Generate a new SCP11 EC key pair.
    ///
    /// Requires OCE verification. Use `replace_kvn` to replace an existing key.
    /// Returns the public key as SEC1 uncompressed point bytes.
    pub fn generate_ec_key(
        &mut self,
        key: KeyRef,
        curve: Curve,
        replace_kvn: u8,
    ) -> Result<Vec<u8>, SmartCardError> {
        let mut data = vec![key.kvn];
        data.extend_from_slice(&tlv_encode(KeyType::EccKeyParams as u32, &[curve as u8]));

        let resp = self
            .protocol
            .send_apdu(0x80, INS_GENERATE_KEY, replace_kvn, key.kid, &data)?;

        Ok(tlv_unpack(KeyType::EccPublicKey as u32, &resp)?)
    }

    /// Import an SCP03 static key set.
    ///
    /// Requires OCE verification and an active SCP session with a DEK key.
    /// Use `replace_kvn` to replace an existing key.
    pub fn put_key_static(
        &mut self,
        key: KeyRef,
        static_keys: &StaticKeys,
        dek: &[u8],
        replace_kvn: u8,
    ) -> Result<(), SmartCardError> {
        let keys_dek = static_keys
            .key_dek
            .as_ref()
            .ok_or_else(|| SmartCardError::BadResponse("New DEK must be set".into()))?;

        let mut data = vec![key.kvn];
        let mut expected = vec![key.kvn];

        for k in [&static_keys.key_enc, &static_keys.key_mac, keys_dek] {
            let kcv = &encrypt_cbc_zero_iv(k, &DEFAULT_KCV_IV)[..3];
            let encrypted = encrypt_cbc_zero_iv(dek, k);
            data.extend_from_slice(&tlv_encode(KeyType::Aes as u32, &encrypted));
            data.push(kcv.len() as u8);
            data.extend_from_slice(kcv);
            expected.extend_from_slice(kcv);
        }

        let p2 = key.kid | 0x80;
        let resp = self
            .protocol
            .send_apdu(0x80, INS_PUT_KEY, replace_kvn, p2, &data)?;

        if resp != expected {
            return Err(SmartCardError::BadResponse(
                "Incorrect key check value".into(),
            ));
        }
        Ok(())
    }

    /// Import an EC private key.
    ///
    /// Requires OCE verification and an active SCP session with a DEK key.
    /// `private_key` is the raw scalar bytes (big-endian).
    /// Use `replace_kvn` to replace an existing key.
    pub fn put_key_ec_private(
        &mut self,
        key: KeyRef,
        private_key: &[u8],
        curve: Curve,
        dek: &[u8],
        replace_kvn: u8,
    ) -> Result<(), SmartCardError> {
        let encrypted = encrypt_cbc_zero_iv(dek, private_key);
        let mut data = vec![key.kvn];
        data.extend_from_slice(&tlv_encode(KeyType::EccPrivateKey as u32, &encrypted));
        data.extend_from_slice(&tlv_encode(KeyType::EccKeyParams as u32, &[curve as u8]));
        data.push(0x00); // No KCV for EC keys

        let resp = self
            .protocol
            .send_apdu(0x80, INS_PUT_KEY, replace_kvn, key.kid, &data)?;

        let expected = vec![key.kvn];
        if resp != expected {
            return Err(SmartCardError::BadResponse(
                "Incorrect key check value".into(),
            ));
        }
        Ok(())
    }

    /// Import an EC public key.
    ///
    /// Requires OCE verification.
    /// `public_key` is the SEC1 uncompressed point bytes (0x04 || x || y).
    /// Use `replace_kvn` to replace an existing key.
    pub fn put_key_ec_public(
        &mut self,
        key: KeyRef,
        public_key: &[u8],
        curve: Curve,
        replace_kvn: u8,
    ) -> Result<(), SmartCardError> {
        let mut data = vec![key.kvn];
        data.extend_from_slice(&tlv_encode(KeyType::EccPublicKey as u32, public_key));
        data.extend_from_slice(&tlv_encode(KeyType::EccKeyParams as u32, &[curve as u8]));
        data.push(0x00); // No KCV for EC keys

        let resp = self
            .protocol
            .send_apdu(0x80, INS_PUT_KEY, replace_kvn, key.kid, &data)?;

        let expected = vec![key.kvn];
        if resp != expected {
            return Err(SmartCardError::BadResponse(
                "Incorrect key check value".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_ref_creation() {
        let kr = KeyRef::new(0x13, 0x01);
        assert_eq!(kr.kid, 0x13);
        assert_eq!(kr.kvn, 0x01);
        assert_eq!(kr.to_bytes(), [0x13, 0x01]);
    }

    #[test]
    fn test_key_ref_from_bytes() {
        let kr = KeyRef::from_bytes(&[0x01, 0xFF]).unwrap();
        assert_eq!(kr.kid, 0x01);
        assert_eq!(kr.kvn, 0xFF);
        assert!(KeyRef::from_bytes(&[0x01]).is_none());
    }

    #[test]
    fn test_key_ref_display() {
        let kr = KeyRef::new(0x13, 0x01);
        assert_eq!(format!("{kr}"), "KeyRef(kid=0x13, kvn=0x01)");
    }

    #[test]
    fn test_key_ref_equality() {
        let a = KeyRef::new(0x13, 0x01);
        let b = KeyRef::new(0x13, 0x01);
        let c = KeyRef::new(0x13, 0x02);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_key_ref_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(KeyRef::new(0x01, 0x01));
        set.insert(KeyRef::new(0x01, 0x01));
        set.insert(KeyRef::new(0x13, 0x01));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_curve_from_u8() {
        assert_eq!(Curve::from_u8(0x00), Some(Curve::Secp256r1));
        assert_eq!(Curve::from_u8(0x01), Some(Curve::Secp384r1));
        assert_eq!(Curve::from_u8(0x02), Some(Curve::Secp521r1));
        assert_eq!(Curve::from_u8(0x03), Some(Curve::BrainpoolP256r1));
        assert_eq!(Curve::from_u8(0x05), Some(Curve::BrainpoolP384r1));
        assert_eq!(Curve::from_u8(0x07), Some(Curve::BrainpoolP512r1));
        assert_eq!(Curve::from_u8(0xFF), None);
    }

    #[test]
    fn test_curve_oid() {
        // secp256r1 OID: 1.2.840.10045.3.1.7
        let oid = Curve::Secp256r1.oid();
        assert_eq!(oid, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
    }

    #[test]
    fn test_curve_from_public_key_bytes() {
        // 65 bytes = 0x04 + 32 + 32 -> Secp256r1
        let mut key = vec![0x04];
        key.extend_from_slice(&[0u8; 64]);
        assert_eq!(Curve::from_public_key_bytes(&key), Some(Curve::Secp256r1));

        // 97 bytes = 0x04 + 48 + 48 -> Secp384r1
        let mut key = vec![0x04];
        key.extend_from_slice(&[0u8; 96]);
        assert_eq!(Curve::from_public_key_bytes(&key), Some(Curve::Secp384r1));

        // Missing 0x04 prefix
        assert_eq!(Curve::from_public_key_bytes(&[0x00; 65]), None);
    }

    #[test]
    fn test_key_type_values() {
        assert_eq!(KeyType::Aes as u8, 0x88);
        assert_eq!(KeyType::EccPublicKey as u8, 0xB0);
        assert_eq!(KeyType::EccPrivateKey as u8, 0xB1);
        assert_eq!(KeyType::EccKeyParams as u8, 0xF0);
    }

    #[test]
    fn test_key_type_from_u8() {
        assert_eq!(KeyType::from_u8(0x88), Some(KeyType::Aes));
        assert_eq!(KeyType::from_u8(0xB0), Some(KeyType::EccPublicKey));
        assert_eq!(KeyType::from_u8(0xB1), Some(KeyType::EccPrivateKey));
        assert_eq!(KeyType::from_u8(0xF0), Some(KeyType::EccKeyParams));
        assert_eq!(KeyType::from_u8(0x00), None);
    }

    #[test]
    fn test_scp_kid_values() {
        assert_eq!(ScpKid::Scp03 as u8, 0x01);
        assert_eq!(ScpKid::Scp11a as u8, 0x11);
        assert_eq!(ScpKid::Scp11b as u8, 0x13);
        assert_eq!(ScpKid::Scp11c as u8, 0x15);
    }

    #[test]
    fn test_scp_kid_from_u8() {
        assert_eq!(ScpKid::from_u8(0x01), Some(ScpKid::Scp03));
        assert_eq!(ScpKid::from_u8(0x11), Some(ScpKid::Scp11a));
        assert_eq!(ScpKid::from_u8(0x13), Some(ScpKid::Scp11b));
        assert_eq!(ScpKid::from_u8(0x15), Some(ScpKid::Scp11c));
        assert_eq!(ScpKid::from_u8(0x00), None);
    }

    #[test]
    fn test_static_keys_default() {
        let keys = StaticKeys::default_keys();
        let expected: Vec<u8> = (0x40..=0x4F).collect();
        assert_eq!(keys.key_enc, expected);
        assert_eq!(keys.key_mac, expected);
        assert_eq!(keys.key_dek.as_ref().unwrap(), &expected);
    }

    #[test]
    fn test_static_keys_iteration() {
        let keys = StaticKeys::default_keys();
        let all = keys.keys();
        assert_eq!(all.len(), 3);
        let expected: Vec<u8> = (0x40..=0x4F).collect();
        for k in all {
            assert_eq!(k, expected.as_slice());
        }
    }

    #[test]
    fn test_int2asn1() {
        // Small positive value (no leading zero needed)
        let result = int2asn1(&[0x2A]);
        // Should be TLV(0x93, [0x2A])
        assert_eq!(result, tlv_encode(0x93, &[0x2A]));

        // Value with high bit set (needs leading zero)
        let result = int2asn1(&[0x80]);
        assert_eq!(result, tlv_encode(0x93, &[0x00, 0x80]));
    }

    #[test]
    fn test_encrypt_cbc_zero_iv() {
        // Verify basic AES-CBC encryption works with 16-byte input
        let key = [0x40u8; 16];
        let data = [0x00u8; 16];
        let result = encrypt_cbc_zero_iv(&key, &data);
        assert_eq!(result.len(), 16);
        // Result should be deterministic
        let result2 = encrypt_cbc_zero_iv(&key, &data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_encrypt_cbc_kcv() {
        // Key check value: encrypt DEFAULT_KCV_IV with the key itself
        let key = [0x40u8; 16];
        let kcv = &encrypt_cbc(&key, &DEFAULT_KCV_IV, &DEFAULT_KCV_IV)[..3];
        assert_eq!(kcv.len(), 3);
    }
}
