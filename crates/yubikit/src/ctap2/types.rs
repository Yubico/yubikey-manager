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
//! and deserialization via `to_cbor()` / `from_cbor()`.

use crate::cbor::Value;
use crate::webauthn::types::{PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity};

use super::pin_protocol::CoseKey;

// ---------------------------------------------------------------------------
// WebAuthn / CTAP2 entity types
// ---------------------------------------------------------------------------

/// Relying Party entity (§5.4.2 of WebAuthn / §6.1 param 2 of CTAP2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialRpEntity {
    /// The relying party identifier (usually a domain name).
    pub id: String,
    /// Optional human-readable name for the relying party.
    pub name: Option<String>,
}

impl PublicKeyCredentialRpEntity {
    pub(crate) fn to_cbor(&self) -> Value {
        let mut entries = vec![(Value::Text("id".into()), Value::Text(self.id.clone()))];
        if let Some(name) = &self.name {
            entries.push((Value::Text("name".into()), Value::Text(name.clone())));
        }
        Value::Map(entries)
    }

    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
        let id = value.map_get_text("id")?.as_text()?.to_string();
        let name = value
            .map_get_text("name")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());
        Some(Self { id, name })
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
    pub(crate) fn to_cbor(&self) -> Option<Value> {
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
    pub(crate) fn from_cbor(value: &Value) -> Result<Self, String> {
        let fmt = value
            .map_get_int(0x01)
            .and_then(|v| v.as_text())
            .ok_or("missing fmt (0x01)")?
            .to_string();
        let auth_data = value
            .map_get_int(0x02)
            .and_then(|v| v.as_bytes())
            .ok_or("missing authData (0x02)")?
            .to_vec();
        let att_stmt = value
            .map_get_int(0x03)
            .cloned()
            .unwrap_or(Value::Map(Vec::new()));
        let ep_att = value.map_get_int(0x04).and_then(|v| v.as_bool());
        let large_blob_key = value
            .map_get_int(0x05)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        let unsigned_extension_outputs = value.map_get_int(0x06).cloned();
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
    pub(crate) fn from_cbor(value: &Value) -> Result<Self, String> {
        let credential = value
            .map_get_int(0x01)
            .and_then(PublicKeyCredentialDescriptor::from_cbor);
        let auth_data = value
            .map_get_int(0x02)
            .and_then(|v| v.as_bytes())
            .ok_or("missing authData (0x02)")?
            .to_vec();
        let signature = value
            .map_get_int(0x03)
            .and_then(|v| v.as_bytes())
            .ok_or("missing signature (0x03)")?
            .to_vec();
        let user = value
            .map_get_int(0x04)
            .and_then(PublicKeyCredentialUserEntity::from_cbor);
        let number_of_credentials = value
            .map_get_int(0x05)
            .and_then(|v| v.as_int())
            .map(|n| n as u32);
        let user_selected = value.map_get_int(0x06).and_then(|v| v.as_bool());
        let large_blob_key = value
            .map_get_int(0x07)
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
    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
        let rp = value
            .map_get_int(0x03)
            .and_then(PublicKeyCredentialRpEntity::from_cbor)?;
        let rp_id_hash = value
            .map_get_int(0x04)
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
    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
        let user = value
            .map_get_int(0x06)
            .and_then(PublicKeyCredentialUserEntity::from_cbor)?;
        let credential_id = value
            .map_get_int(0x07)
            .and_then(PublicKeyCredentialDescriptor::from_cbor)?;
        let public_key = value.map_get_int(0x08)?.clone();
        let cred_protect = value
            .map_get_int(0x0A)
            .and_then(|v| v.as_int())
            .map(|n| n as u32);
        let large_blob_key = value
            .map_get_int(0x0B)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        let third_party_payment = value.map_get_int(0x0C).and_then(|v| v.as_bool());
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
    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
        let fingerprint_kind = value.map_get_int(0x02).and_then(|v| v.as_int())? as u32;
        let max_capture_samples_required_for_enroll =
            value.map_get_int(0x03).and_then(|v| v.as_int())? as u32;
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
    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
        let template_id = value
            .map_get_int(0x04)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())?;
        let last_sample_status = value.map_get_int(0x05).and_then(|v| v.as_int())? as u32;
        let remaining_samples = value.map_get_int(0x06).and_then(|v| v.as_int())? as u32;
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
    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rp_entity_roundtrip() {
        let rp = PublicKeyCredentialRpEntity {
            id: "example.com".into(),
            name: Some("Example".into()),
        };
        let val = rp.to_cbor();
        let rp2 = PublicKeyCredentialRpEntity::from_cbor(&val).unwrap();
        assert_eq!(rp, rp2);
    }

    #[test]
    fn test_options_empty() {
        let opts = AuthenticatorOptions::default();
        assert!(opts.to_cbor().is_none());
    }

    #[test]
    fn test_options_rk() {
        let opts = AuthenticatorOptions {
            rk: Some(true),
            ..Default::default()
        };
        let val = opts.to_cbor().unwrap();
        let map = val.as_map().unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_attestation_response_parse() {
        let value = Value::Map(vec![
            (Value::Int(0x01), Value::Text("none".into())),
            (Value::Int(0x02), Value::Bytes(vec![0x00; 37])),
            (Value::Int(0x03), Value::Map(vec![])),
        ]);
        let resp = AttestationResponse::from_cbor(&value).unwrap();
        assert_eq!(resp.fmt, "none");
        assert_eq!(resp.auth_data.len(), 37);
        assert!(resp.ep_att.is_none());
    }

    #[test]
    fn test_assertion_response_parse() {
        let value = Value::Map(vec![
            (Value::Int(0x02), Value::Bytes(vec![0x00; 37])),
            (Value::Int(0x03), Value::Bytes(vec![0xAA; 64])),
            (Value::Int(0x05), Value::Int(3)),
        ]);
        let resp = AssertionResponse::from_cbor(&value).unwrap();
        assert!(resp.credential.is_none());
        assert_eq!(resp.auth_data.len(), 37);
        assert_eq!(resp.signature.len(), 64);
        assert_eq!(resp.number_of_credentials, Some(3));
    }

    #[test]
    fn test_fingerprint_sensor_info_parse() {
        let value = Value::Map(vec![
            (Value::Int(0x02), Value::Int(1)),
            (Value::Int(0x03), Value::Int(4)),
        ]);
        let info = FingerprintSensorInfo::from_cbor(&value).unwrap();
        assert_eq!(info.fingerprint_kind, 1);
        assert_eq!(info.max_capture_samples_required_for_enroll, 4);
    }

    #[test]
    fn test_enroll_sample_result_parse() {
        let value = Value::Map(vec![
            (Value::Int(0x04), Value::Bytes(vec![0x01, 0x02])),
            (Value::Int(0x05), Value::Int(0)),
            (Value::Int(0x06), Value::Int(3)),
        ]);
        let result = EnrollSampleResult::from_cbor(&value).unwrap();
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
            .filter_map(FingerprintTemplate::from_cbor)
            .collect();
        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0].id, vec![0x01]);
        assert_eq!(templates[0].name, Some("index finger".into()));
        assert_eq!(templates[1].id, vec![0x02]);
        assert!(templates[1].name.is_none());
    }

    #[test]
    fn test_rp_info_parse() {
        let value = Value::Map(vec![
            (
                Value::Int(0x03),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Text("example.com".into()),
                )]),
            ),
            (Value::Int(0x04), Value::Bytes(vec![0xAA; 32])),
        ]);
        let info = RpInfo::from_cbor(&value).unwrap();
        assert_eq!(info.rp.id, "example.com");
        assert_eq!(info.rp_id_hash.len(), 32);
    }

    #[test]
    fn test_credential_info_parse() {
        let value = Value::Map(vec![
            (
                Value::Int(0x06),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Bytes(vec![0x01, 0x02]),
                )]),
            ),
            (
                Value::Int(0x07),
                Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("id".into()), Value::Bytes(vec![0xCC, 0xDD])),
                ]),
            ),
            (Value::Int(0x08), Value::Map(vec![])), // empty COSE key for test
            (Value::Int(0x0A), Value::Int(2)),
        ]);
        let info = CredentialInfo::from_cbor(&value).unwrap();
        assert_eq!(info.user.id, vec![0x01, 0x02]);
        assert_eq!(info.credential_id.id, vec![0xCC, 0xDD]);
        assert_eq!(info.cred_protect, Some(2));
    }
}
