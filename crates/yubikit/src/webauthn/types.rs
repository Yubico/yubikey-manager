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

//! WebAuthn types for credential creation and assertion ceremonies.
//!
//! These types correspond to the WebAuthn Level 3 specification and are used
//! as the public API for [`super::WebAuthnClient`]. They are also used by
//! [`crate::ctap2`] for CBOR serialization to/from the authenticator.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cbor::Value;

// ---------------------------------------------------------------------------
// Base64url serde helpers
// ---------------------------------------------------------------------------

mod base64url {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        BASE64_URL_SAFE_NO_PAD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        BASE64_URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

mod base64url_opt {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => BASE64_URL_SAFE_NO_PAD.encode(b).serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => BASE64_URL_SAFE_NO_PAD
                .decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// String enums
// ---------------------------------------------------------------------------

/// The type of a public key credential (§5.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

impl PublicKeyCredentialType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicKey => "public-key",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "public-key" => Some(Self::PublicKey),
            _ => None,
        }
    }
}

impl std::fmt::Display for PublicKeyCredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Attestation conveyance preference (§5.4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    /// The RP is not interested in attestation.
    #[default]
    None,
    /// The RP prefers an attestation conveyance yielding verifiable
    /// attestation statements, but allows the client to decide.
    Indirect,
    /// The RP wants to receive the attestation statement as generated
    /// by the authenticator.
    Direct,
    /// The RP wants to receive an attestation statement that may
    /// identify the authenticator uniquely.
    Enterprise,
}

impl AttestationConveyancePreference {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Indirect => "indirect",
            Self::Direct => "direct",
            Self::Enterprise => "enterprise",
        }
    }
}

/// User verification requirement (§5.8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    Required,
    #[default]
    Preferred,
    Discouraged,
}

impl UserVerificationRequirement {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::Discouraged => "discouraged",
        }
    }
}

/// Resident key requirement (§5.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    Required,
    #[default]
    Preferred,
    Discouraged,
}

impl ResidentKeyRequirement {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::Discouraged => "discouraged",
        }
    }
}

/// Authenticator attachment modality (§5.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatorAttachment {
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

impl AuthenticatorAttachment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::CrossPlatform => "cross-platform",
        }
    }
}

/// Transport hint for authenticator communication (§5.8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Hybrid,
    Internal,
}

impl AuthenticatorTransport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Nfc => "nfc",
            Self::Ble => "ble",
            Self::Hybrid => "hybrid",
            Self::Internal => "internal",
        }
    }

    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "usb" => Some(Self::Usb),
            "nfc" => Some(Self::Nfc),
            "ble" => Some(Self::Ble),
            "hybrid" => Some(Self::Hybrid),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Hint to the client about preferred authenticator type (§5.8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKeyCredentialHint {
    #[serde(rename = "security-key")]
    SecurityKey,
    #[serde(rename = "client-device")]
    ClientDevice,
    #[serde(rename = "hybrid")]
    Hybrid,
}

impl PublicKeyCredentialHint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SecurityKey => "security-key",
            Self::ClientDevice => "client-device",
            Self::Hybrid => "hybrid",
        }
    }
}

// ---------------------------------------------------------------------------
// Entity types
// ---------------------------------------------------------------------------

/// Relying Party entity (§5.4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl PublicKeyCredentialRpEntity {
    /// SHA-256 hash of the RP ID, if set.
    pub fn id_hash(&self) -> Option<[u8; 32]> {
        self.id.as_ref().map(|id| {
            let mut hasher = Sha256::new();
            hasher.update(id.as_bytes());
            hasher.finalize().into()
        })
    }
}

/// User entity (§5.4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialUserEntity {
    #[serde(with = "base64url")]
    pub id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl PublicKeyCredentialUserEntity {
    pub(crate) fn to_cbor(&self) -> Value {
        let mut entries = vec![(Value::Text("id".into()), Value::Bytes(self.id.clone()))];
        if let Some(name) = &self.name {
            entries.push((Value::Text("name".into()), Value::Text(name.clone())));
        }
        if let Some(dn) = &self.display_name {
            entries.push((Value::Text("displayName".into()), Value::Text(dn.clone())));
        }
        Value::Map(entries)
    }

    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
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

/// Algorithm parameter for credential creation (§5.8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub type_: PublicKeyCredentialType,
    pub alg: i64,
}

impl PublicKeyCredentialParameters {
    pub(crate) fn to_cbor(&self) -> Value {
        Value::Map(vec![
            (
                Value::Text("type".into()),
                Value::Text(self.type_.as_str().to_string()),
            ),
            (Value::Text("alg".into()), Value::Int(self.alg)),
        ])
    }

    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
        let type_ = value
            .map_get_text("type")
            .and_then(|v| v.as_text())
            .and_then(PublicKeyCredentialType::from_str)
            .unwrap_or(PublicKeyCredentialType::PublicKey);
        let alg = value.map_get_text("alg").and_then(|v| v.as_int())?;
        Some(Self { type_, alg })
    }
}

/// Credential descriptor (§5.8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: PublicKeyCredentialType,
    #[serde(with = "base64url")]
    pub id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

impl PublicKeyCredentialDescriptor {
    pub(crate) fn to_cbor(&self) -> Value {
        let mut entries = vec![
            (
                Value::Text("type".into()),
                Value::Text(self.type_.as_str().to_string()),
            ),
            (Value::Text("id".into()), Value::Bytes(self.id.clone())),
        ];
        if let Some(transports) = &self.transports {
            entries.push((
                Value::Text("transports".into()),
                Value::Array(
                    transports
                        .iter()
                        .map(|t| Value::Text(t.as_str().to_string()))
                        .collect(),
                ),
            ));
        }
        Value::Map(entries)
    }

    pub(crate) fn from_cbor(value: &Value) -> Option<Self> {
        let type_ = value
            .map_get_text("type")
            .and_then(|v| v.as_text())
            .and_then(PublicKeyCredentialType::from_str)
            .unwrap_or(PublicKeyCredentialType::PublicKey);
        let id = value
            .map_get_text("id")
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())?;
        let transports = value
            .map_get_text("transports")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_text().and_then(AuthenticatorTransport::from_str))
                    .collect()
            });
        Some(Self {
            type_,
            id,
            transports,
        })
    }
}

// ---------------------------------------------------------------------------
// Selection criteria
// ---------------------------------------------------------------------------

/// Criteria for authenticator selection during registration (§5.4.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for `navigator.credentials.create()` (§5.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    #[serde(with = "base64url")]
    pub challenge: Vec<u8>,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<PublicKeyCredentialHint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl PublicKeyCredentialCreationOptions {
    /// Deserialize from the WebAuthn JSON format.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to the WebAuthn JSON format.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Options for `navigator.credentials.get()` (§5.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    #[serde(with = "base64url")]
    pub challenge: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<PublicKeyCredentialHint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl PublicKeyCredentialRequestOptions {
    /// Deserialize from the WebAuthn JSON format.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to the WebAuthn JSON format.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// ---------------------------------------------------------------------------
// Collected client data
// ---------------------------------------------------------------------------

/// Client data collected during a WebAuthn ceremony (§5.8.1).
///
/// Holds the raw JSON-serialized bytes as well as the parsed fields.
#[derive(Debug, Clone)]
pub struct CollectedClientData {
    json: Vec<u8>,
    pub type_: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    pub cross_origin: bool,
}

impl CollectedClientData {
    /// Create collected client data for a ceremony.
    ///
    /// `type_` is `"webauthn.create"` or `"webauthn.get"`.
    pub fn create(type_: &str, challenge: &[u8], origin: &str, cross_origin: bool) -> Self {
        use base64::prelude::*;
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(challenge);
        let json = format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":{}}}"#,
            type_, challenge_b64, origin, cross_origin
        );
        Self {
            json: json.into_bytes(),
            type_: type_.to_string(),
            challenge: challenge.to_vec(),
            origin: origin.to_string(),
            cross_origin,
        }
    }

    /// Create from raw JSON bytes (as provided by a client data collector).
    pub fn from_json(json: Vec<u8>) -> Result<Self, String> {
        use base64::prelude::*;
        let parsed: serde_json::Value =
            serde_json::from_slice(&json).map_err(|e| format!("invalid client data JSON: {e}"))?;
        let obj = parsed
            .as_object()
            .ok_or("client data JSON must be an object")?;
        let type_ = obj
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or("missing 'type' in client data")?
            .to_string();
        let challenge_b64 = obj
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or("missing 'challenge' in client data")?;
        let challenge = BASE64_URL_SAFE_NO_PAD
            .decode(challenge_b64)
            .map_err(|e| format!("invalid challenge base64: {e}"))?;
        let origin = obj
            .get("origin")
            .and_then(|v| v.as_str())
            .ok_or("missing 'origin' in client data")?
            .to_string();
        let cross_origin = obj
            .get("crossOrigin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(Self {
            json,
            type_,
            challenge,
            origin,
            cross_origin,
        })
    }

    /// The raw JSON-serialized client data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.json
    }

    /// SHA-256 hash of the JSON-serialized client data.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.json);
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response from a registration ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON", with = "base64url")]
    pub client_data_json: Vec<u8>,
    #[serde(with = "base64url")]
    pub attestation_object: Vec<u8>,
}

/// Response from an authentication ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON", with = "base64url")]
    pub client_data_json: Vec<u8>,
    #[serde(with = "base64url")]
    pub authenticator_data: Vec<u8>,
    #[serde(with = "base64url")]
    pub signature: Vec<u8>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "base64url_opt",
        default
    )]
    pub user_handle: Option<Vec<u8>>,
}

/// Result of a successful registration ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponse {
    #[serde(with = "base64url")]
    pub id: Vec<u8>,
    pub response: AuthenticatorAttestationResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(rename = "type")]
    pub type_: PublicKeyCredentialType,
}

impl RegistrationResponse {
    /// Serialize to the WebAuthn JSON format.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Result of a successful authentication ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponse {
    #[serde(with = "base64url")]
    pub id: Vec<u8>,
    pub response: AuthenticatorAssertionResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(rename = "type")]
    pub type_: PublicKeyCredentialType,
}

impl AuthenticationResponse {
    /// Serialize to the WebAuthn JSON format.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// ---------------------------------------------------------------------------
// Conversions to CTAP2 types
// ---------------------------------------------------------------------------

impl PublicKeyCredentialRpEntity {
    /// Convert to the CTAP2 RP entity used by `Ctap2Session::make_credential`.
    pub(crate) fn to_ctap2(
        &self,
        effective_rp_id: &str,
    ) -> crate::ctap2::types::PublicKeyCredentialRpEntity {
        crate::ctap2::types::PublicKeyCredentialRpEntity {
            id: effective_rp_id.to_string(),
            name: Some(self.name.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: encode lists for CTAP2 parameters
// ---------------------------------------------------------------------------

/// Encode a list of credential descriptors as a CBOR array.
pub(crate) fn encode_allow_exclude_list(list: &[PublicKeyCredentialDescriptor]) -> Value {
    Value::Array(list.iter().map(|d| d.to_cbor()).collect())
}

/// Encode a list of credential parameters as a CBOR array.
pub(crate) fn encode_pub_key_cred_params(params: &[PublicKeyCredentialParameters]) -> Value {
    Value::Array(params.iter().map(|p| p.to_cbor()).collect())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collected_client_data_create() {
        let challenge = b"test-challenge";
        let cd =
            CollectedClientData::create("webauthn.create", challenge, "https://example.com", false);

        assert_eq!(cd.type_, "webauthn.create");
        assert_eq!(cd.challenge, challenge);
        assert_eq!(cd.origin, "https://example.com");
        assert!(!cd.cross_origin);

        let json_str = std::str::from_utf8(cd.as_bytes()).unwrap();
        assert!(json_str.contains(r#""type":"webauthn.create""#));
        assert!(json_str.contains(r#""origin":"https://example.com""#));
        assert!(json_str.contains(r#""crossOrigin":false"#));
    }

    #[test]
    fn test_collected_client_data_hash() {
        let cd = CollectedClientData::create("webauthn.get", b"ch", "https://example.com", false);
        let hash = cd.hash();
        assert_eq!(hash.len(), 32);
        // Hash should be deterministic
        assert_eq!(hash, cd.hash());
    }

    #[test]
    fn test_rp_entity_id_hash() {
        let mut rp = PublicKeyCredentialRpEntity {
            name: "Example".to_string(),
            id: None,
        };
        assert!(rp.id_hash().is_none());

        rp.id = Some("example.com".to_string());
        let hash = rp.id_hash().unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_credential_descriptor() {
        let desc = PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: vec![1, 2, 3],
            transports: None,
        };
        assert_eq!(desc.type_, PublicKeyCredentialType::PublicKey);
        assert_eq!(desc.id, vec![1, 2, 3]);
        assert!(desc.transports.is_none());
    }

    #[test]
    fn test_credential_parameters() {
        let params = PublicKeyCredentialParameters {
            type_: PublicKeyCredentialType::PublicKey,
            alg: -7,
        };
        assert_eq!(params.type_, PublicKeyCredentialType::PublicKey);
        assert_eq!(params.alg, -7);
    }

    #[test]
    fn test_enum_str_values() {
        assert_eq!(PublicKeyCredentialType::PublicKey.as_str(), "public-key");
        assert_eq!(AttestationConveyancePreference::None.as_str(), "none");
        assert_eq!(AttestationConveyancePreference::Direct.as_str(), "direct");
        assert_eq!(UserVerificationRequirement::Required.as_str(), "required");
        assert_eq!(UserVerificationRequirement::Preferred.as_str(), "preferred");
        assert_eq!(
            UserVerificationRequirement::Discouraged.as_str(),
            "discouraged"
        );
        assert_eq!(ResidentKeyRequirement::Required.as_str(), "required");
        assert_eq!(AuthenticatorAttachment::Platform.as_str(), "platform");
        assert_eq!(
            AuthenticatorAttachment::CrossPlatform.as_str(),
            "cross-platform"
        );
        assert_eq!(AuthenticatorTransport::Usb.as_str(), "usb");
        assert_eq!(
            PublicKeyCredentialHint::SecurityKey.as_str(),
            "security-key"
        );
    }

    #[test]
    fn test_to_ctap2_rp() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example RP".to_string(),
            id: Some("example.com".to_string()),
        };
        let ctap2_rp = rp.to_ctap2("example.com");
        assert_eq!(ctap2_rp.id, "example.com");
        assert_eq!(ctap2_rp.name.as_deref(), Some("Example RP"));
    }

    #[test]
    fn test_user_entity_cbor_roundtrip() {
        let user = PublicKeyCredentialUserEntity {
            id: vec![1, 2, 3],
            name: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
        };
        let cbor = user.to_cbor();
        let user2 = PublicKeyCredentialUserEntity::from_cbor(&cbor).unwrap();
        assert_eq!(user, user2);
    }

    #[test]
    fn test_credential_params_cbor_roundtrip() {
        let params = PublicKeyCredentialParameters {
            type_: PublicKeyCredentialType::PublicKey,
            alg: -7,
        };
        let cbor = params.to_cbor();
        let params2 = PublicKeyCredentialParameters::from_cbor(&cbor).unwrap();
        assert_eq!(params, params2);
    }

    #[test]
    fn test_credential_descriptor_cbor_roundtrip() {
        let desc = PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: vec![0xAA, 0xBB],
            transports: Some(vec![
                AuthenticatorTransport::Usb,
                AuthenticatorTransport::Nfc,
            ]),
        };
        let cbor = desc.to_cbor();
        let desc2 = PublicKeyCredentialDescriptor::from_cbor(&cbor).unwrap();
        assert_eq!(desc, desc2);
    }

    #[test]
    fn test_creation_options_from_json() {
        let json = r#"{
            "rp": {"name": "Example", "id": "example.com"},
            "user": {"id": "dXNlci0x", "name": "alice", "displayName": "Alice"},
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "authenticatorSelection": {
                "userVerification": "preferred",
                "residentKey": "required"
            }
        }"#;
        let opts = PublicKeyCredentialCreationOptions::from_json(json).unwrap();
        assert_eq!(opts.rp.name, "Example");
        assert_eq!(opts.rp.id.as_deref(), Some("example.com"));
        assert_eq!(opts.user.name.as_deref(), Some("alice"));
        assert_eq!(opts.challenge, b"challenge");
        assert_eq!(opts.pub_key_cred_params.len(), 1);
        assert_eq!(opts.pub_key_cred_params[0].alg, -7);
        assert_eq!(opts.timeout, Some(60000));
        let sel = opts.authenticator_selection.unwrap();
        assert_eq!(
            sel.user_verification,
            Some(UserVerificationRequirement::Preferred)
        );
        assert_eq!(sel.resident_key, Some(ResidentKeyRequirement::Required));
    }

    #[test]
    fn test_request_options_from_json() {
        let json = r#"{
            "challenge": "Y2hhbGxlbmdl",
            "rpId": "example.com",
            "allowCredentials": [{"type": "public-key", "id": "AABB"}],
            "userVerification": "discouraged"
        }"#;
        let opts = PublicKeyCredentialRequestOptions::from_json(json).unwrap();
        assert_eq!(opts.challenge, b"challenge");
        assert_eq!(opts.rp_id.as_deref(), Some("example.com"));
        assert_eq!(opts.allow_credentials.as_ref().unwrap().len(), 1);
        assert_eq!(
            opts.user_verification,
            Some(UserVerificationRequirement::Discouraged)
        );
    }

    #[test]
    fn test_registration_response_to_json() {
        let resp = RegistrationResponse {
            id: vec![0xAA, 0xBB],
            response: AuthenticatorAttestationResponse {
                client_data_json: b"{}".to_vec(),
                attestation_object: vec![0x01, 0x02],
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            type_: PublicKeyCredentialType::PublicKey,
        };
        let json = resp.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "qrs");
        assert_eq!(parsed["type"], "public-key");
        assert_eq!(parsed["authenticatorAttachment"], "cross-platform");
        assert!(parsed["response"]["clientDataJSON"].is_string());
        assert!(parsed["response"]["attestationObject"].is_string());
    }

    #[test]
    fn test_authentication_response_to_json() {
        let resp = AuthenticationResponse {
            id: vec![0xCC],
            response: AuthenticatorAssertionResponse {
                client_data_json: b"{}".to_vec(),
                authenticator_data: vec![0x01],
                signature: vec![0x02, 0x03],
                user_handle: Some(b"user".to_vec()),
            },
            authenticator_attachment: None,
            type_: PublicKeyCredentialType::PublicKey,
        };
        let json = resp.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "zA");
        assert_eq!(parsed["type"], "public-key");
        assert!(parsed["response"]["signature"].is_string());
        assert!(parsed["response"]["userHandle"].is_string());
    }
}
