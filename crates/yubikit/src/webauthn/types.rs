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
//! as the public API for [`super::WebAuthnClient`]. Lower-level CTAP2 types
//! remain in [`crate::ctap2::types`].

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// String enums
// ---------------------------------------------------------------------------

/// The type of a public key credential (§5.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCredentialType {
    PublicKey,
}

impl PublicKeyCredentialType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicKey => "public-key",
        }
    }
}

impl std::fmt::Display for PublicKeyCredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Attestation conveyance preference (§5.4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorAttachment {
    Platform,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// Hint to the client about preferred authenticator type (§5.8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCredentialHint {
    SecurityKey,
    ClientDevice,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: Option<String>,
}

impl PublicKeyCredentialRpEntity {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            id: None,
        }
    }

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
}

/// Algorithm parameter for credential creation (§5.8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialParameters {
    pub type_: PublicKeyCredentialType,
    pub alg: i64,
}

impl PublicKeyCredentialParameters {
    pub fn new(alg: i64) -> Self {
        Self {
            type_: PublicKeyCredentialType::PublicKey,
            alg,
        }
    }

    /// ES256 (-7) algorithm parameter.
    pub fn es256() -> Self {
        Self::new(-7)
    }
}

/// Credential descriptor (§5.8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialDescriptor {
    pub type_: PublicKeyCredentialType,
    pub id: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

impl PublicKeyCredentialDescriptor {
    pub fn new(id: Vec<u8>) -> Self {
        Self {
            type_: PublicKeyCredentialType::PublicKey,
            id,
            transports: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Selection criteria
// ---------------------------------------------------------------------------

/// Criteria for authenticator selection during registration (§5.4.4).
#[derive(Debug, Clone, Default)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub resident_key: Option<ResidentKeyRequirement>,
    pub user_verification: Option<UserVerificationRequirement>,
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for `navigator.credentials.create()` (§5.4).
#[derive(Debug, Clone)]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Vec<u8>,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub hints: Option<Vec<PublicKeyCredentialHint>>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub attestation_formats: Option<Vec<String>>,
    pub extensions: Option<std::collections::HashMap<String, Vec<u8>>>,
}

/// Options for `navigator.credentials.get()` (§5.5).
#[derive(Debug, Clone)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Vec<u8>,
    pub timeout: Option<u64>,
    pub rp_id: Option<String>,
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub user_verification: Option<UserVerificationRequirement>,
    pub hints: Option<Vec<PublicKeyCredentialHint>>,
    pub extensions: Option<std::collections::HashMap<String, Vec<u8>>>,
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
#[derive(Debug, Clone)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// Response from an authentication ceremony.
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// Result of a successful registration ceremony.
#[derive(Debug, Clone)]
pub struct RegistrationResponse {
    pub id: Vec<u8>,
    pub response: AuthenticatorAttestationResponse,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub type_: PublicKeyCredentialType,
}

/// Result of a successful authentication ceremony.
#[derive(Debug, Clone)]
pub struct AuthenticationResponse {
    pub id: Vec<u8>,
    pub response: AuthenticatorAssertionResponse,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub type_: PublicKeyCredentialType,
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
        let mut rp = crate::ctap2::types::PublicKeyCredentialRpEntity::new(effective_rp_id);
        rp.name = Some(self.name.clone());
        rp
    }
}

impl PublicKeyCredentialUserEntity {
    /// Convert to the CTAP2 user entity.
    pub(crate) fn to_ctap2(&self) -> crate::ctap2::types::PublicKeyCredentialUserEntity {
        let mut user = crate::ctap2::types::PublicKeyCredentialUserEntity::new(self.id.clone());
        user.name = self.name.clone();
        user.display_name = self.display_name.clone();
        user
    }
}

impl PublicKeyCredentialParameters {
    /// Convert to the CTAP2 credential parameters.
    pub(crate) fn to_ctap2(&self) -> crate::ctap2::types::PublicKeyCredentialParameters {
        crate::ctap2::types::PublicKeyCredentialParameters::new(self.alg)
    }
}

impl PublicKeyCredentialDescriptor {
    /// Convert to the CTAP2 credential descriptor.
    pub(crate) fn to_ctap2(&self) -> crate::ctap2::types::PublicKeyCredentialDescriptor {
        let mut desc = crate::ctap2::types::PublicKeyCredentialDescriptor::new(self.id.clone());
        desc.transports = self
            .transports
            .as_ref()
            .map(|ts| ts.iter().map(|t| t.as_str().to_string()).collect());
        desc
    }
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
        let mut rp = PublicKeyCredentialRpEntity::new("Example");
        assert!(rp.id_hash().is_none());

        rp.id = Some("example.com".to_string());
        let hash = rp.id_hash().unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_credential_descriptor() {
        let desc = PublicKeyCredentialDescriptor::new(vec![1, 2, 3]);
        assert_eq!(desc.type_, PublicKeyCredentialType::PublicKey);
        assert_eq!(desc.id, vec![1, 2, 3]);
        assert!(desc.transports.is_none());
    }

    #[test]
    fn test_credential_parameters() {
        let params = PublicKeyCredentialParameters::es256();
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
    fn test_to_ctap2_user() {
        let user = PublicKeyCredentialUserEntity {
            id: vec![1, 2, 3],
            name: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
        };
        let ctap2_user = user.to_ctap2();
        assert_eq!(ctap2_user.id, vec![1, 2, 3]);
        assert_eq!(ctap2_user.name.as_deref(), Some("alice"));
        assert_eq!(ctap2_user.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_to_ctap2_descriptor() {
        let desc = PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: vec![0xAA, 0xBB],
            transports: Some(vec![
                AuthenticatorTransport::Usb,
                AuthenticatorTransport::Nfc,
            ]),
        };
        let ctap2_desc = desc.to_ctap2();
        assert_eq!(ctap2_desc.type_, "public-key");
        assert_eq!(ctap2_desc.id, vec![0xAA, 0xBB]);
        assert_eq!(
            ctap2_desc.transports.as_deref(),
            Some(&["usb".to_string(), "nfc".to_string()][..])
        );
    }
}
