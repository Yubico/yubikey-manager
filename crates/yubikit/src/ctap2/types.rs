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

//! CTAP2 data types.
//!
//! Typed representations of CTAP2 CBOR structures, replacing raw
//! `Value` in public APIs. Each type provides CBOR serialization
//! and deserialization via `to_value()` / `from_value()`.

use std::collections::BTreeMap;

use crate::cbor::Value;

use super::pin_protocol::CoseKey;

// ---------------------------------------------------------------------------
// WebAuthn / CTAP2 entity types
// ---------------------------------------------------------------------------

/// Relying Party entity (§5.4.2 of WebAuthn / §6.1 param 2 of CTAP2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: Option<String>,
}

impl PublicKeyCredentialRpEntity {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut entries = vec![(Value::Text("id".into()), Value::Text(self.id.clone()))];
        if let Some(name) = &self.name {
            entries.push((Value::Text("name".into()), Value::Text(name.clone())));
        }
        Value::Map(entries)
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        let id = value.map_get_text("id")?.as_text()?.to_string();
        let name = value
            .map_get_text("name")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());
        Some(Self { id, name })
    }
}

/// User entity (§5.4.3 of WebAuthn / §6.1 param 3 of CTAP2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    pub name: Option<String>,
    pub display_name: Option<String>,
}

impl PublicKeyCredentialUserEntity {
    pub fn new(id: Vec<u8>) -> Self {
        Self {
            id,
            name: None,
            display_name: None,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut entries = vec![(Value::Text("id".into()), Value::Bytes(self.id.clone()))];
        if let Some(name) = &self.name {
            entries.push((Value::Text("name".into()), Value::Text(name.clone())));
        }
        if let Some(dn) = &self.display_name {
            entries.push((Value::Text("displayName".into()), Value::Text(dn.clone())));
        }
        Value::Map(entries)
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        let id = value
            .map_get_text("id")
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())?;
        let name = value
            .map_get_text("name")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());
        let display_name = value
            .map_get_text("displayName")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());
        Some(Self {
            id,
            name,
            display_name,
        })
    }
}

/// Credential descriptor (§5.8.3 of WebAuthn / §6.1 param 5 entries of CTAP2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialDescriptor {
    pub type_: String,
    pub id: Vec<u8>,
    pub transports: Option<Vec<String>>,
}

impl PublicKeyCredentialDescriptor {
    pub fn new(id: Vec<u8>) -> Self {
        Self {
            type_: "public-key".into(),
            id,
            transports: None,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            (Value::Text("type".into()), Value::Text(self.type_.clone())),
            (Value::Text("id".into()), Value::Bytes(self.id.clone())),
        ];
        if let Some(transports) = &self.transports {
            entries.push((
                Value::Text("transports".into()),
                Value::Array(transports.iter().map(|t| Value::Text(t.clone())).collect()),
            ));
        }
        Value::Map(entries)
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        let type_ = value
            .map_get_text("type")
            .and_then(|v| v.as_text())
            .unwrap_or("public-key")
            .to_string();
        let id = value
            .map_get_text("id")
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())?;
        let transports = value
            .map_get_text("transports")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_text().map(|s| s.to_string()))
                    .collect()
            });
        Some(Self {
            type_,
            id,
            transports,
        })
    }
}

/// Algorithm parameter for credential creation (§5.8.2 of WebAuthn).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialParameters {
    pub type_: String,
    pub alg: i64,
}

impl PublicKeyCredentialParameters {
    pub fn new(alg: i64) -> Self {
        Self {
            type_: "public-key".into(),
            alg,
        }
    }

    /// ES256 (-7) algorithm parameter.
    pub fn es256() -> Self {
        Self::new(-7)
    }

    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Text("type".into()), Value::Text(self.type_.clone())),
            (Value::Text("alg".into()), Value::Int(self.alg)),
        ])
    }

    pub fn from_value(value: &Value) -> Option<Self> {
        let type_ = value
            .map_get_text("type")
            .and_then(|v| v.as_text())
            .unwrap_or("public-key")
            .to_string();
        let alg = value.map_get_text("alg").and_then(|v| v.as_int())?;
        Some(Self { type_, alg })
    }
}

// ---------------------------------------------------------------------------
// makeCredential / getAssertion options
// ---------------------------------------------------------------------------

/// Options for makeCredential and getAssertion commands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticatorOptions {
    /// Request resident key / discoverable credential.
    pub rk: Option<bool>,
    /// Request user verification.
    pub uv: Option<bool>,
    /// Request user presence (getAssertion only; defaults to true).
    pub up: Option<bool>,
}

impl AuthenticatorOptions {
    pub fn to_value(&self) -> Option<Value> {
        let mut entries = Vec::new();
        if let Some(rk) = self.rk {
            entries.push((Value::Text("rk".into()), Value::Bool(rk)));
        }
        if let Some(uv) = self.uv {
            entries.push((Value::Text("uv".into()), Value::Bool(uv)));
        }
        if let Some(up) = self.up {
            entries.push((Value::Text("up".into()), Value::Bool(up)));
        }
        if entries.is_empty() {
            None
        } else {
            Some(Value::Map(entries))
        }
    }
}

// ---------------------------------------------------------------------------
// makeCredential response (§6.1)
// ---------------------------------------------------------------------------

/// Response from authenticatorMakeCredential (§6.1).
#[derive(Debug, Clone)]
pub struct AttestationResponse {
    /// Attestation statement format identifier.
    pub fmt: String,
    /// Authenticator data (raw bytes, includes flags, counter, attested
    /// credential data, and optional extensions).
    pub auth_data: Vec<u8>,
    /// Attestation statement (format-dependent, kept as raw CBOR).
    pub att_stmt: Value,
    /// Enterprise attestation returned.
    pub ep_att: Option<bool>,
    /// Large blob key for the credential.
    pub large_blob_key: Option<Vec<u8>>,
    /// Unsigned extension outputs (open-ended).
    pub unsigned_extension_outputs: Option<Value>,
}

impl AttestationResponse {
    pub(crate) fn from_int_map(map: BTreeMap<u32, Value>) -> Result<Self, String> {
        let fmt = map
            .get(&0x01)
            .and_then(|v| v.as_text())
            .ok_or("missing fmt (0x01)")?
            .to_string();
        let auth_data = map
            .get(&0x02)
            .and_then(|v| v.as_bytes())
            .ok_or("missing authData (0x02)")?
            .to_vec();
        let att_stmt = map.get(&0x03).cloned().unwrap_or(Value::Map(Vec::new()));
        let ep_att = map.get(&0x04).and_then(|v| v.as_bool());
        let large_blob_key = map
            .get(&0x05)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        let unsigned_extension_outputs = map.get(&0x06).cloned();
        Ok(Self {
            fmt,
            auth_data,
            att_stmt,
            ep_att,
            large_blob_key,
            unsigned_extension_outputs,
        })
    }
}

// ---------------------------------------------------------------------------
// getAssertion response (§6.2)
// ---------------------------------------------------------------------------

/// Response from authenticatorGetAssertion / getNextAssertion (§6.2).
#[derive(Debug, Clone)]
pub struct AssertionResponse {
    /// The credential used (may be absent if allowList had exactly one entry).
    pub credential: Option<PublicKeyCredentialDescriptor>,
    /// Authenticator data (raw bytes).
    pub auth_data: Vec<u8>,
    /// The assertion signature.
    pub signature: Vec<u8>,
    /// User entity associated with the credential.
    pub user: Option<PublicKeyCredentialUserEntity>,
    /// Total number of matching credentials (only in first response).
    pub number_of_credentials: Option<u32>,
    /// Whether the user selected this credential via authenticator UI.
    pub user_selected: Option<bool>,
    /// Large blob key for the credential.
    pub large_blob_key: Option<Vec<u8>>,
}

impl AssertionResponse {
    pub(crate) fn from_int_map(map: BTreeMap<u32, Value>) -> Result<Self, String> {
        let credential = map
            .get(&0x01)
            .and_then(PublicKeyCredentialDescriptor::from_value);
        let auth_data = map
            .get(&0x02)
            .and_then(|v| v.as_bytes())
            .ok_or("missing authData (0x02)")?
            .to_vec();
        let signature = map
            .get(&0x03)
            .and_then(|v| v.as_bytes())
            .ok_or("missing signature (0x03)")?
            .to_vec();
        let user = map
            .get(&0x04)
            .and_then(PublicKeyCredentialUserEntity::from_value);
        let number_of_credentials = map.get(&0x05).and_then(|v| v.as_int()).map(|n| n as u32);
        let user_selected = map.get(&0x06).and_then(|v| v.as_bool());
        let large_blob_key = map
            .get(&0x07)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        Ok(Self {
            credential,
            auth_data,
            signature,
            user,
            number_of_credentials,
            user_selected,
            large_blob_key,
        })
    }
}

// ---------------------------------------------------------------------------
// Credential Management types (§6.8)
// ---------------------------------------------------------------------------

/// RP entry returned by credential management enumeration.
#[derive(Debug, Clone)]
pub struct RpInfo {
    /// The RP entity.
    pub rp: PublicKeyCredentialRpEntity,
    /// SHA-256 hash of the RP ID.
    pub rp_id_hash: Vec<u8>,
}

impl RpInfo {
    pub(crate) fn from_int_map(map: &BTreeMap<u32, Value>) -> Option<Self> {
        let rp = map
            .get(&0x03)
            .and_then(PublicKeyCredentialRpEntity::from_value)?;
        let rp_id_hash = map
            .get(&0x04)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())?;
        Some(Self { rp, rp_id_hash })
    }
}

/// Credential entry returned by credential management enumeration.
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    /// The user entity.
    pub user: PublicKeyCredentialUserEntity,
    /// The credential descriptor (contains ID).
    pub credential_id: PublicKeyCredentialDescriptor,
    /// The credential public key (COSE_Key).
    pub public_key: CoseKey,
    /// Credential protection level (credProtect extension).
    pub cred_protect: Option<u32>,
    /// Large blob key for this credential.
    pub large_blob_key: Option<Vec<u8>>,
    /// Whether the credential supports third-party payment.
    pub third_party_payment: Option<bool>,
}

impl CredentialInfo {
    pub(crate) fn from_int_map(map: &BTreeMap<u32, Value>) -> Option<Self> {
        let user = map
            .get(&0x06)
            .and_then(PublicKeyCredentialUserEntity::from_value)?;
        let credential_id = map
            .get(&0x07)
            .and_then(PublicKeyCredentialDescriptor::from_value)?;
        let public_key = map.get(&0x08)?.clone();
        let cred_protect = map.get(&0x0A).and_then(|v| v.as_int()).map(|n| n as u32);
        let large_blob_key = map
            .get(&0x0B)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        let third_party_payment = map.get(&0x0C).and_then(|v| v.as_bool());
        Some(Self {
            user,
            credential_id,
            public_key,
            cred_protect,
            large_blob_key,
            third_party_payment,
        })
    }
}

// ---------------------------------------------------------------------------
// Bio Enrollment types (§6.7)
// ---------------------------------------------------------------------------

/// Fingerprint sensor information.
#[derive(Debug, Clone)]
pub struct FingerprintSensorInfo {
    /// Fingerprint sensor modality (0x01 = touch, 0x02 = swipe).
    pub fingerprint_kind: u32,
    /// Maximum number of good samples required for enrollment.
    pub max_capture_samples_required_for_enroll: u32,
}

impl FingerprintSensorInfo {
    pub(crate) fn from_int_map(map: &BTreeMap<u32, Value>) -> Option<Self> {
        let fingerprint_kind = map.get(&0x02).and_then(|v| v.as_int())? as u32;
        let max_capture_samples_required_for_enroll =
            map.get(&0x03).and_then(|v| v.as_int())? as u32;
        Some(Self {
            fingerprint_kind,
            max_capture_samples_required_for_enroll,
        })
    }
}

/// Result from a fingerprint enrollment step (begin or capture next).
#[derive(Debug, Clone)]
pub struct EnrollSampleResult {
    /// Template identifier for the enrollment in progress.
    pub template_id: Vec<u8>,
    /// Status of the last sample (0 = good).
    pub last_sample_status: u32,
    /// Number of samples remaining.
    pub remaining_samples: u32,
}

impl EnrollSampleResult {
    pub(crate) fn from_int_map(map: &BTreeMap<u32, Value>) -> Option<Self> {
        let template_id = map
            .get(&0x04)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())?;
        let last_sample_status = map.get(&0x05).and_then(|v| v.as_int())? as u32;
        let remaining_samples = map.get(&0x06).and_then(|v| v.as_int())? as u32;
        Some(Self {
            template_id,
            last_sample_status,
            remaining_samples,
        })
    }
}

/// An enrolled fingerprint template entry.
#[derive(Debug, Clone)]
pub struct FingerprintTemplate {
    /// Template identifier.
    pub id: Vec<u8>,
    /// Friendly name (may be empty).
    pub name: Option<String>,
}

impl FingerprintTemplate {
    pub(crate) fn from_template_info(value: &Value) -> Option<Self> {
        let id = value
            .map_get_int(0x01)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())?;
        let name = value
            .map_get_int(0x02)
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());
        Some(Self { id, name })
    }
}

// ---------------------------------------------------------------------------
// Helper: encode lists for CTAP2 parameters
// ---------------------------------------------------------------------------

/// Encode a list of credential descriptors as a CBOR array.
pub fn encode_allow_exclude_list(list: &[PublicKeyCredentialDescriptor]) -> Value {
    Value::Array(list.iter().map(|d| d.to_value()).collect())
}

/// Encode a list of credential parameters as a CBOR array.
pub fn encode_pub_key_cred_params(params: &[PublicKeyCredentialParameters]) -> Value {
    Value::Array(params.iter().map(|p| p.to_value()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rp_entity_roundtrip() {
        let rp = PublicKeyCredentialRpEntity {
            id: "example.com".into(),
            name: Some("Example".into()),
        };
        let val = rp.to_value();
        let rp2 = PublicKeyCredentialRpEntity::from_value(&val).unwrap();
        assert_eq!(rp, rp2);
    }

    #[test]
    fn test_user_entity_roundtrip() {
        let user = PublicKeyCredentialUserEntity {
            id: vec![1, 2, 3, 4],
            name: Some("alice".into()),
            display_name: Some("Alice".into()),
        };
        let val = user.to_value();
        let user2 = PublicKeyCredentialUserEntity::from_value(&val).unwrap();
        assert_eq!(user, user2);
    }

    #[test]
    fn test_credential_descriptor_roundtrip() {
        let desc = PublicKeyCredentialDescriptor {
            type_: "public-key".into(),
            id: vec![0xAA, 0xBB, 0xCC],
            transports: Some(vec!["usb".into(), "nfc".into()]),
        };
        let val = desc.to_value();
        let desc2 = PublicKeyCredentialDescriptor::from_value(&val).unwrap();
        assert_eq!(desc, desc2);
    }

    #[test]
    fn test_credential_params_roundtrip() {
        let params = PublicKeyCredentialParameters::es256();
        let val = params.to_value();
        let params2 = PublicKeyCredentialParameters::from_value(&val).unwrap();
        assert_eq!(params, params2);
    }

    #[test]
    fn test_options_empty() {
        let opts = AuthenticatorOptions::default();
        assert!(opts.to_value().is_none());
    }

    #[test]
    fn test_options_rk() {
        let opts = AuthenticatorOptions {
            rk: Some(true),
            ..Default::default()
        };
        let val = opts.to_value().unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_attestation_response_parse() {
        let mut map = BTreeMap::new();
        map.insert(0x01, Value::Text("none".into()));
        map.insert(0x02, Value::Bytes(vec![0x00; 37]));
        map.insert(0x03, Value::Map(vec![]));
        let resp = AttestationResponse::from_int_map(map).unwrap();
        assert_eq!(resp.fmt, "none");
        assert_eq!(resp.auth_data.len(), 37);
        assert!(resp.ep_att.is_none());
    }

    #[test]
    fn test_assertion_response_parse() {
        let mut map = BTreeMap::new();
        map.insert(0x02, Value::Bytes(vec![0x00; 37]));
        map.insert(0x03, Value::Bytes(vec![0xAA; 64]));
        map.insert(0x05, Value::Int(3));
        let resp = AssertionResponse::from_int_map(map).unwrap();
        assert!(resp.credential.is_none());
        assert_eq!(resp.auth_data.len(), 37);
        assert_eq!(resp.signature.len(), 64);
        assert_eq!(resp.number_of_credentials, Some(3));
    }

    #[test]
    fn test_fingerprint_sensor_info_parse() {
        let mut map = BTreeMap::new();
        map.insert(0x02, Value::Int(1));
        map.insert(0x03, Value::Int(4));
        let info = FingerprintSensorInfo::from_int_map(&map).unwrap();
        assert_eq!(info.fingerprint_kind, 1);
        assert_eq!(info.max_capture_samples_required_for_enroll, 4);
    }

    #[test]
    fn test_enroll_sample_result_parse() {
        let mut map = BTreeMap::new();
        map.insert(0x04, Value::Bytes(vec![0x01, 0x02]));
        map.insert(0x05, Value::Int(0));
        map.insert(0x06, Value::Int(3));
        let result = EnrollSampleResult::from_int_map(&map).unwrap();
        assert_eq!(result.template_id, vec![0x01, 0x02]);
        assert_eq!(result.last_sample_status, 0);
        assert_eq!(result.remaining_samples, 3);
    }

    #[test]
    fn test_fingerprint_template_parse() {
        let infos = Value::Array(vec![
            Value::Map(vec![
                (Value::Int(0x01), Value::Bytes(vec![0x01])),
                (Value::Int(0x02), Value::Text("index finger".into())),
            ]),
            Value::Map(vec![(Value::Int(0x01), Value::Bytes(vec![0x02]))]),
        ]);
        let templates: Vec<_> = infos
            .as_array()
            .unwrap()
            .iter()
            .filter_map(FingerprintTemplate::from_template_info)
            .collect();
        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0].id, vec![0x01]);
        assert_eq!(templates[0].name, Some("index finger".into()));
        assert_eq!(templates[1].id, vec![0x02]);
        assert!(templates[1].name.is_none());
    }

    #[test]
    fn test_rp_info_parse() {
        let mut map = BTreeMap::new();
        map.insert(
            0x03,
            Value::Map(vec![(
                Value::Text("id".into()),
                Value::Text("example.com".into()),
            )]),
        );
        map.insert(0x04, Value::Bytes(vec![0xAA; 32]));
        let info = RpInfo::from_int_map(&map).unwrap();
        assert_eq!(info.rp.id, "example.com");
        assert_eq!(info.rp_id_hash.len(), 32);
    }

    #[test]
    fn test_credential_info_parse() {
        let mut map = BTreeMap::new();
        map.insert(
            0x06,
            Value::Map(vec![(
                Value::Text("id".into()),
                Value::Bytes(vec![0x01, 0x02]),
            )]),
        );
        map.insert(
            0x07,
            Value::Map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("id".into()), Value::Bytes(vec![0xCC, 0xDD])),
            ]),
        );
        map.insert(0x08, Value::Map(vec![])); // empty COSE key for test
        map.insert(0x0A, Value::Int(2));
        let info = CredentialInfo::from_int_map(&map).unwrap();
        assert_eq!(info.user.id, vec![0x01, 0x02]);
        assert_eq!(info.credential_id.id, vec![0xCC, 0xDD]);
        assert_eq!(info.cred_protect, Some(2));
    }
}
