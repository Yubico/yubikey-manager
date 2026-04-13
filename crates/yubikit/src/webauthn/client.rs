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

//! WebAuthn client for performing registration and authentication ceremonies.

use crate::cbor;
use crate::core::Connection;
use crate::ctap2::types::AuthenticatorOptions;
use crate::ctap2::{ClientPin, Ctap2Error, Ctap2Session, Info, Permissions};

use super::types::{
    AuthenticationResponse, AuthenticatorAssertionResponse, AuthenticatorAttachment,
    AuthenticatorAttestationResponse, CollectedClientData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialType, RegistrationResponse,
    ResidentKeyRequirement, UserVerificationRequirement,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during WebAuthn operations.
#[derive(Debug)]
pub enum ClientError<E: std::error::Error + Send + Sync + 'static> {
    /// A CTAP2-level error from the authenticator.
    Ctap(Ctap2Error<E>),
    /// User verification is required but not configured on the authenticator.
    ConfigurationUnsupported(String),
    /// The user's PIN is required but was not provided.
    PinRequired,
    /// A request parameter was invalid.
    BadRequest(String),
}

impl<E: std::error::Error + Send + Sync + 'static> From<Ctap2Error<E>> for ClientError<E> {
    fn from(e: Ctap2Error<E>) -> Self {
        Self::Ctap(e)
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::fmt::Display for ClientError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ctap(e) => write!(f, "CTAP error: {e}"),
            Self::ConfigurationUnsupported(msg) => write!(f, "configuration unsupported: {msg}"),
            Self::PinRequired => write!(f, "PIN required"),
            Self::BadRequest(msg) => write!(f, "bad request: {msg}"),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error for ClientError<E> {}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// User interaction callbacks for PIN/UV prompts.
pub trait UserInteraction {
    /// Called when the authenticator is waiting for user presence (touch).
    fn prompt_up(&self);

    /// Called when a PIN is needed. Return the PIN, or `None` to cancel.
    fn request_pin(&self, permissions: Permissions, rp_id: Option<&str>) -> Option<String>;

    /// Called when built-in user verification (e.g. biometrics) is available.
    /// Return `true` to proceed with UV, or `false` to fall back to PIN.
    fn request_uv(&self, permissions: Permissions, rp_id: Option<&str>) -> bool;
}

/// Collects client data and determines the effective RP ID for a ceremony.
pub trait ClientDataCollector {
    /// Collect client data for a registration or authentication request.
    ///
    /// Returns the [`CollectedClientData`] (containing the JSON-serialized
    /// client data) and the effective RP ID string.
    fn collect_create(
        &self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<(CollectedClientData, String), String>;

    /// Collect client data for an authentication request.
    fn collect_get(
        &self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<(CollectedClientData, String), String>;
}

// ---------------------------------------------------------------------------
// WebAuthn client
// ---------------------------------------------------------------------------

/// WebAuthn client that wraps a [`Ctap2Session`] and performs registration
/// and authentication ceremonies.
pub struct WebAuthnClient<C: Connection + 'static, U: UserInteraction, D: ClientDataCollector> {
    session: Option<Ctap2Session<C>>,
    user_interaction: U,
    client_data_collector: D,
}

impl<C: Connection + 'static, U: UserInteraction, D: ClientDataCollector> WebAuthnClient<C, U, D> {
    /// Create a new WebAuthn client.
    pub fn new(session: Ctap2Session<C>, user_interaction: U, client_data_collector: D) -> Self {
        Self {
            session: Some(session),
            user_interaction,
            client_data_collector,
        }
    }

    /// Consume the client and return the underlying session.
    pub fn into_session(self) -> Ctap2Session<C> {
        self.session.expect("session already taken")
    }

    /// Reference to the cached authenticator info.
    pub fn info(&self) -> &Info {
        self.session().info()
    }

    fn session(&self) -> &Ctap2Session<C> {
        self.session.as_ref().expect("session already taken")
    }

    fn take_session(&mut self) -> Ctap2Session<C> {
        self.session.take().expect("session already taken")
    }

    fn restore_session(&mut self, session: Ctap2Session<C>) {
        self.session = Some(session);
    }

    // -----------------------------------------------------------------------
    // Registration (makeCredential)
    // -----------------------------------------------------------------------

    /// Perform a WebAuthn registration ceremony.
    pub fn make_credential(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<RegistrationResponse, ClientError<C::Error>> {
        let (client_data, rp_id) = self
            .client_data_collector
            .collect_create(options)
            .map_err(ClientError::BadRequest)?;
        let client_data_hash = client_data.hash();

        // Determine resident key and UV requirements
        let selection = options.authenticator_selection.as_ref();
        let uv_requirement = selection
            .and_then(|s| s.user_verification)
            .unwrap_or_default();
        let rk_requirement = selection.and_then(|s| s.resident_key).unwrap_or_default();

        let rk = matches!(
            rk_requirement,
            ResidentKeyRequirement::Required | ResidentKeyRequirement::Preferred
        );

        // Get PIN/UV auth parameters
        let permissions = Permissions::MAKE_CREDENTIAL;
        let (pin_uv_param, pin_uv_protocol, internal_uv) =
            self.get_auth_params(uv_requirement, permissions, Some(&rp_id), &client_data_hash)?;

        let authenticator_options = AuthenticatorOptions {
            rk: Some(rk),
            uv: if internal_uv { Some(true) } else { None },
            up: None,
        };

        // Convert WebAuthn types to CTAP2 types
        let ctap2_rp = options.rp.to_ctap2(&rp_id);
        let ctap2_user = options.user.to_ctap2();
        let ctap2_params: Vec<_> = options
            .pub_key_cred_params
            .iter()
            .map(|p| p.to_ctap2())
            .collect();
        let ctap2_exclude: Option<Vec<_>> = options
            .exclude_credentials
            .as_ref()
            .map(|creds| creds.iter().map(|c| c.to_ctap2()).collect());

        let enterprise_attestation = match options.attestation {
            Some(super::types::AttestationConveyancePreference::Enterprise) => Some(1u32),
            _ => None,
        };

        let mut session = self.take_session();
        let interaction = &self.user_interaction;
        let mut on_keepalive = |status: u8| {
            if status == 0x02 {
                // KEEPALIVE_STATUS_UPNEEDED
                interaction.prompt_up();
            }
        };

        let att_resp = match session.make_credential(
            &client_data_hash,
            &ctap2_rp,
            &ctap2_user,
            &ctap2_params,
            ctap2_exclude.as_deref(),
            None, // extensions (TODO)
            Some(&authenticator_options),
            pin_uv_param.as_deref(),
            pin_uv_protocol,
            enterprise_attestation,
            Some(&mut on_keepalive),
            None,
        ) {
            Ok(resp) => {
                self.restore_session(session);
                resp
            }
            Err(e) => {
                self.restore_session(session);
                return Err(e.into());
            }
        };

        // Build the attestation object CBOR (fmt, authData, attStmt)
        let att_obj_cbor = cbor::encode(&cbor::Value::Map(vec![
            (
                cbor::Value::Text("fmt".into()),
                cbor::Value::Text(att_resp.fmt),
            ),
            (
                cbor::Value::Text("authData".into()),
                cbor::Value::Bytes(att_resp.auth_data.clone()),
            ),
            (cbor::Value::Text("attStmt".into()), att_resp.att_stmt),
        ]));

        // Extract credential ID from auth_data
        // authData layout: rpIdHash(32) + flags(1) + counter(4) + [attestedCredData]
        // attestedCredData: aaguid(16) + credIdLen(2) + credId(credIdLen) + ...
        let credential_id = extract_credential_id(&att_resp.auth_data)
            .ok_or_else(|| ClientError::BadRequest("no credential data in auth_data".into()))?;

        Ok(RegistrationResponse {
            id: credential_id,
            response: AuthenticatorAttestationResponse {
                client_data_json: client_data.as_bytes().to_vec(),
                attestation_object: att_obj_cbor,
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            type_: PublicKeyCredentialType::PublicKey,
        })
    }

    // -----------------------------------------------------------------------
    // Authentication (getAssertion)
    // -----------------------------------------------------------------------

    /// Perform a WebAuthn authentication ceremony.
    ///
    /// Returns a list of authentication responses (one per matching credential;
    /// typically one unless the authenticator has multiple discoverable
    /// credentials for the RP).
    pub fn get_assertion(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<Vec<AuthenticationResponse>, ClientError<C::Error>> {
        let (client_data, rp_id) = self
            .client_data_collector
            .collect_get(options)
            .map_err(ClientError::BadRequest)?;
        let client_data_hash = client_data.hash();

        let uv_requirement = options.user_verification.unwrap_or_default();

        let permissions = Permissions::GET_ASSERTION;
        let (pin_uv_param, pin_uv_protocol, internal_uv) =
            self.get_auth_params(uv_requirement, permissions, Some(&rp_id), &client_data_hash)?;

        let authenticator_options = AuthenticatorOptions {
            rk: None,
            uv: if internal_uv { Some(true) } else { None },
            up: None,
        };

        let ctap2_allow: Option<Vec<_>> = options
            .allow_credentials
            .as_ref()
            .map(|creds| creds.iter().map(|c| c.to_ctap2()).collect());

        let mut session = self.take_session();
        let interaction = &self.user_interaction;
        let mut on_keepalive = |status: u8| {
            if status == 0x02 {
                interaction.prompt_up();
            }
        };

        let first = match session.get_assertion(
            &rp_id,
            &client_data_hash,
            ctap2_allow.as_deref(),
            None, // extensions (TODO)
            Some(&authenticator_options),
            pin_uv_param.as_deref(),
            pin_uv_protocol,
            Some(&mut on_keepalive),
            None,
        ) {
            Ok(resp) => resp,
            Err(e) => {
                self.restore_session(session);
                return Err(e.into());
            }
        };

        let total = first.number_of_credentials.unwrap_or(1) as usize;
        let client_data_json = client_data.as_bytes().to_vec();

        let mut responses = Vec::with_capacity(total);

        // First assertion
        let credential_id = first
            .credential
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_default();
        responses.push(AuthenticationResponse {
            id: credential_id,
            response: AuthenticatorAssertionResponse {
                client_data_json: client_data_json.clone(),
                authenticator_data: first.auth_data,
                signature: first.signature,
                user_handle: first.user.map(|u| u.id),
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            type_: PublicKeyCredentialType::PublicKey,
        });

        // Additional assertions (getNextAssertion)
        for _ in 1..total {
            let next = match session.get_next_assertion() {
                Ok(resp) => resp,
                Err(e) => {
                    self.restore_session(session);
                    return Err(e.into());
                }
            };
            let credential_id = next
                .credential
                .as_ref()
                .map(|c| c.id.clone())
                .unwrap_or_default();
            responses.push(AuthenticationResponse {
                id: credential_id,
                response: AuthenticatorAssertionResponse {
                    client_data_json: client_data_json.clone(),
                    authenticator_data: next.auth_data,
                    signature: next.signature,
                    user_handle: next.user.map(|u| u.id),
                },
                authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
                type_: PublicKeyCredentialType::PublicKey,
            });
        }

        self.restore_session(session);
        Ok(responses)
    }

    // -----------------------------------------------------------------------
    // PIN / UV helpers
    // -----------------------------------------------------------------------

    /// Determine whether UV should be used, and if so, obtain a PIN/UV token.
    ///
    /// Returns `(pin_uv_param, pin_uv_protocol_version, internal_uv)`.
    fn get_auth_params(
        &mut self,
        uv_requirement: UserVerificationRequirement,
        permissions: Permissions,
        rp_id: Option<&str>,
        client_data_hash: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<u32>, bool), ClientError<C::Error>> {
        if !self.should_use_uv(uv_requirement, permissions)? {
            return Ok((None, None, false));
        }

        let session = self.take_session();
        match self.obtain_token(session, permissions, rp_id) {
            Ok((session, token, protocol, internal_uv)) => {
                self.restore_session(session);
                let (pin_uv_param, protocol_version) = if let Some(token) = token {
                    let param = protocol.authenticate(&token, client_data_hash);
                    (Some(param), Some(protocol.version()))
                } else {
                    (None, Some(protocol.version()))
                };
                Ok((pin_uv_param, protocol_version, internal_uv))
            }
            Err((session, e)) => {
                self.restore_session(session);
                Err(e)
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn obtain_token(
        &self,
        session: Ctap2Session<C>,
        permissions: Permissions,
        rp_id: Option<&str>,
    ) -> Result<
        (
            Ctap2Session<C>,
            Option<Vec<u8>>,
            crate::ctap2::PinProtocol,
            bool,
        ),
        (Ctap2Session<C>, ClientError<C::Error>),
    > {
        let info = session.info().clone();

        // Select protocol before creating ClientPin so we keep the session on failure
        let protocol = if info.pin_uv_protocols.contains(&2) {
            crate::ctap2::PinProtocol::V2
        } else if info.pin_uv_protocols.contains(&1) {
            crate::ctap2::PinProtocol::V1
        } else {
            return Err((
                session,
                ClientError::ConfigurationUnsupported("no supported PIN/UV protocol".into()),
            ));
        };

        // new_with_protocol is infallible in practice
        let mut client_pin = ClientPin::new_with_protocol(session, protocol)
            .expect("ClientPin::new_with_protocol should not fail");

        let protocol = client_pin.protocol();

        // Try UV first if supported
        if info.options.get("uv").copied().unwrap_or(false)
            && info.options.get("pinUvAuthToken").copied().unwrap_or(false)
        {
            if self.user_interaction.request_uv(permissions, rp_id) {
                match client_pin.get_uv_token(Some(permissions), rp_id, None, None) {
                    Ok(token) => {
                        let session = client_pin.into_session();
                        return Ok((session, Some(token), protocol, false));
                    }
                    Err(_) => {
                        // UV failed, fall through to PIN
                    }
                }
            }
        } else if info.options.get("uv").copied().unwrap_or(false) {
            // Device has internal UV but no pinUvAuthToken — use internal UV
            if self.user_interaction.request_uv(permissions, rp_id) {
                let session = client_pin.into_session();
                return Ok((session, None, protocol, true));
            }
        }

        // Fall back to PIN
        if info.options.get("clientPin").copied().unwrap_or(false) {
            if let Some(pin) = self.user_interaction.request_pin(permissions, rp_id) {
                match client_pin.get_pin_token(&pin, Some(permissions), rp_id) {
                    Ok(token) => {
                        let session = client_pin.into_session();
                        return Ok((session, Some(token), protocol, false));
                    }
                    Err(e) => {
                        let session = client_pin.into_session();
                        return Err((session, ClientError::Ctap(e)));
                    }
                }
            } else {
                let session = client_pin.into_session();
                return Err((session, ClientError::PinRequired));
            }
        }

        let session = client_pin.into_session();
        Err((
            session,
            ClientError::ConfigurationUnsupported("user verification not configured".into()),
        ))
    }

    /// Determine whether user verification should be performed.
    fn should_use_uv(
        &self,
        uv_requirement: UserVerificationRequirement,
        permissions: Permissions,
    ) -> Result<bool, ClientError<C::Error>> {
        let info = self.session().info();

        let uv_configured = info.options.get("uv").copied().unwrap_or(false)
            || info.options.get("clientPin").copied().unwrap_or(false)
            || info.options.get("bioEnroll").copied().unwrap_or(false);

        let uv_supported = info.options.contains_key("uv")
            || info.options.contains_key("clientPin")
            || info.options.contains_key("bioEnroll");

        match uv_requirement {
            UserVerificationRequirement::Required => {
                if !uv_configured {
                    return Err(ClientError::ConfigurationUnsupported(
                        "user verification required but not configured".into(),
                    ));
                }
                Ok(true)
            }
            UserVerificationRequirement::Preferred => {
                if uv_supported && uv_configured {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            UserVerificationRequirement::Discouraged => {
                // Even if discouraged, UV may still be needed:
                // - alwaysUv option
                // - makeCredential when makeCredUvNotRqd is not set
                if info.options.get("alwaysUv").copied().unwrap_or(false) && uv_configured {
                    return Ok(true);
                }

                let mc = permissions.bits() & Permissions::MAKE_CREDENTIAL.bits() != 0;
                let make_cred_uv_not_rqd = info
                    .options
                    .get("makeCredUvNotRqd")
                    .copied()
                    .unwrap_or(false);

                if mc && !make_cred_uv_not_rqd && uv_configured {
                    return Ok(true);
                }

                // Additional permissions beyond MC/GA always need UV
                let additional = permissions.bits()
                    & !(Permissions::MAKE_CREDENTIAL.bits() | Permissions::GET_ASSERTION.bits());
                if additional != 0 && uv_configured {
                    return Ok(true);
                }

                Ok(false)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the credential ID from authenticator data containing attested
/// credential data.
///
/// Layout: rpIdHash(32) + flags(1) + counter(4) + aaguid(16) + credIdLen(2) + credId
fn extract_credential_id(auth_data: &[u8]) -> Option<Vec<u8>> {
    // Minimum: 32 + 1 + 4 + 16 + 2 = 55 bytes
    if auth_data.len() < 55 {
        return None;
    }

    let flags = auth_data[32];
    // AT flag (bit 6) must be set
    if flags & 0x40 == 0 {
        return None;
    }

    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_id_start = 55;
    let cred_id_end = cred_id_start + cred_id_len;

    if auth_data.len() < cred_id_end {
        return None;
    }

    Some(auth_data[cred_id_start..cred_id_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_credential_id() {
        // Build a minimal auth_data with AT flag and credential data
        let mut auth_data = vec![0u8; 55 + 4]; // 55 header + 4 byte cred ID
        auth_data[32] = 0x41; // UP + AT flags
        // counter at [33..37] = 0
        // aaguid at [37..53] = 0
        auth_data[53] = 0x00; // credIdLen high byte
        auth_data[54] = 0x04; // credIdLen low byte = 4
        auth_data[55] = 0xAA;
        auth_data[56] = 0xBB;
        auth_data[57] = 0xCC;
        auth_data[58] = 0xDD;

        let id = extract_credential_id(&auth_data).unwrap();
        assert_eq!(id, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_extract_credential_id_no_at_flag() {
        let mut auth_data = vec![0u8; 59];
        auth_data[32] = 0x01; // UP only, no AT
        assert!(extract_credential_id(&auth_data).is_none());
    }

    #[test]
    fn test_extract_credential_id_too_short() {
        let auth_data = vec![0u8; 40];
        assert!(extract_credential_id(&auth_data).is_none());
    }
}
