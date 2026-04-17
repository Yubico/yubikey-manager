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
use crate::ctap2::{ClientPin, Ctap2Error, Ctap2Session, CtapStatus, Permissions, PinProtocol};

use super::extensions::{self, prf};
use super::types::{
    AuthenticationResponse, AuthenticatorAssertionResponse, AuthenticatorAttachment,
    AuthenticatorAttestationResponse, CollectedClientData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions, PublicKeyCredentialType,
    RegistrationResponse, ResidentKeyRequirement, UserVerificationRequirement,
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

/// WebAuthn client that wraps a [`Ctap2Session`](crate::ctap2::Ctap2Session) and performs registration
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

        // Need GET_ASSERTION permission if we have an exclude list to filter
        let mut permissions = Permissions::MAKE_CREDENTIAL;
        if options.exclude_credentials.is_some() {
            permissions |= Permissions::GET_ASSERTION;
        }

        // Get PIN/UV token
        let (token, protocol, internal_uv) =
            self.get_token(uv_requirement, permissions, Some(&rp_id))?;

        // Pre-flight filtering of exclude list
        let exclude_cred = if let Some(ref exclude_list) = options.exclude_credentials {
            self.filter_creds(&rp_id, exclude_list, protocol, token.as_deref())?
        } else {
            None
        };

        // Compute pin_uv_param for the actual request
        let (pin_uv_param, pin_uv_protocol) =
            compute_pin_uv_param(token.as_deref(), protocol, &client_data_hash);

        let authenticator_options = AuthenticatorOptions {
            rk: Some(rk),
            uv: if internal_uv { Some(true) } else { None },
            up: None,
        };

        // Convert WebAuthn RP to CTAP2 (different field requirements)
        let ctap2_rp = options.rp.to_ctap2(&rp_id);

        let enterprise_attestation = match options.attestation {
            Some(super::types::AttestationConveyancePreference::Enterprise) => Some(1u32),
            _ => None,
        };

        // Build the filtered exclude list (single matching cred, or None)
        let filtered_exclude: Option<Vec<PublicKeyCredentialDescriptor>>;
        let exclude_slice = if let Some(cred) = exclude_cred {
            filtered_exclude = Some(vec![cred]);
            filtered_exclude.as_deref()
        } else {
            None
        };

        // Build extension inputs
        let (ext_cbor, hmac_state) = self.build_make_credential_extensions(options, protocol)?;

        let mut session = self.take_session();
        let interaction = &self.user_interaction;
        let mut on_keepalive = |status: u8| {
            if status == 0x02 {
                interaction.prompt_up();
            }
        };

        let att_resp = match session.make_credential(
            &client_data_hash,
            &ctap2_rp,
            &options.user,
            &options.pub_key_cred_params,
            exclude_slice,
            ext_cbor,
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
        let credential_id = extract_credential_id(&att_resp.auth_data)
            .ok_or_else(|| ClientError::BadRequest("no credential data in auth_data".into()))?;

        // Parse extension outputs
        let ext_outputs = self.parse_registration_extensions(
            options,
            &att_resp.auth_data,
            hmac_state.as_ref(),
            att_resp.large_blob_key.is_some(),
            rk,
        );

        Ok(RegistrationResponse {
            id: credential_id,
            response: AuthenticatorAttestationResponse {
                client_data_json: client_data.as_bytes().to_vec(),
                attestation_object: att_obj_cbor,
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            type_: PublicKeyCredentialType::PublicKey,
            client_extension_results: ext_outputs,
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

        let mut permissions = Permissions::GET_ASSERTION;

        // Large blob write requires an additional permission
        if let Some(ref ext) = options.extensions
            && let Some(ref lb) = ext.large_blob
            && lb.write.is_some()
        {
            permissions |= Permissions::LARGE_BLOB_WRITE;
        }

        let (token, protocol, internal_uv) =
            self.get_token(uv_requirement, permissions, Some(&rp_id))?;

        // Pre-flight filtering of allow list
        let selected_cred_id: Option<Vec<u8>>;
        let filtered_allow: Option<Vec<PublicKeyCredentialDescriptor>>;
        let allow_slice = if let Some(ref allow_list) = options.allow_credentials {
            let selected = self.filter_creds(&rp_id, allow_list, protocol, token.as_deref())?;
            if let Some(cred) = selected {
                selected_cred_id = Some(cred.id.clone());
                filtered_allow = Some(vec![cred]);
                filtered_allow.as_deref()
            } else if !allow_list.is_empty() {
                selected_cred_id = None;
                filtered_allow = Some(vec![PublicKeyCredentialDescriptor {
                    type_: allow_list[0].type_,
                    id: vec![0],
                    transports: None,
                }]);
                filtered_allow.as_deref()
            } else {
                selected_cred_id = None;
                None
            }
        } else {
            selected_cred_id = None;
            None
        };

        // Compute pin_uv_param for the actual request
        let (pin_uv_param, pin_uv_protocol) =
            compute_pin_uv_param(token.as_deref(), protocol, &client_data_hash);

        let authenticator_options = AuthenticatorOptions {
            rk: None,
            uv: if internal_uv { Some(true) } else { None },
            up: None,
        };

        // Build extension inputs
        let (ext_cbor, hmac_state) =
            self.build_get_assertion_extensions(options, protocol, selected_cred_id.as_deref())?;

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
            allow_slice,
            ext_cbor,
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

        // Parse extension outputs for the first assertion
        let first_cred_id = first
            .credential
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_default();

        let ext_outputs =
            self.parse_authentication_extensions(options, &first.auth_data, hmac_state.as_ref());

        // Handle large blob read/write if requested
        let large_blob_output = if let Some(ref ext) = options.extensions {
            if let Some(ref lb_input) = ext.large_blob {
                let (s, output) = self.process_large_blob(
                    session,
                    lb_input,
                    first.large_blob_key.as_deref(),
                    token.as_deref(),
                    protocol,
                );
                session = s;
                output
            } else {
                None
            }
        } else {
            None
        };

        let mut ext_outputs = ext_outputs;
        if let Some(lb_out) = large_blob_output {
            let outputs = ext_outputs.get_or_insert_with(Default::default);
            outputs.large_blob = Some(lb_out);
        }

        let mut responses = Vec::with_capacity(total);
        responses.push(AuthenticationResponse {
            id: first_cred_id,
            response: AuthenticatorAssertionResponse {
                client_data_json: client_data_json.clone(),
                authenticator_data: first.auth_data,
                signature: first.signature,
                user_handle: first.user.map(|u| u.id),
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            type_: PublicKeyCredentialType::PublicKey,
            client_extension_results: ext_outputs,
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

            let next_ext_outputs =
                self.parse_authentication_extensions(options, &next.auth_data, hmac_state.as_ref());

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
                client_extension_results: next_ext_outputs,
            });
        }

        self.restore_session(session);
        Ok(responses)
    }

    // -----------------------------------------------------------------------
    // Extension building and parsing
    // -----------------------------------------------------------------------

    /// Build CTAP2 extension CBOR for makeCredential.
    fn build_make_credential_extensions(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        protocol: Option<PinProtocol>,
    ) -> Result<(Option<cbor::Value>, Option<prf::HmacSecretState>), ClientError<C::Error>> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok((None, None)),
        };

        let mut entries: Vec<(String, cbor::Value)> = Vec::new();
        let mut hmac_state = None;

        // PRF / hmac-secret
        if let Some(ref prf_input) = ext.prf {
            let info = self.session().info().clone();
            if info.extensions.iter().any(|e| e == "hmac-secret") {
                if let Some(ref eval) = prf_input.eval {
                    // hmac-secret-mc: need key agreement + salt encryption
                    if let Some(state) = self.get_hmac_secret_state(protocol)? {
                        for entry in prf::make_credential_salts_cbor(eval, &state) {
                            entries.push(entry);
                        }
                        hmac_state = Some(state);
                    }
                } else {
                    // Simple enable
                    entries.push(prf::make_credential_enable_cbor());
                }
            }
        }

        // credProtect
        if let Some(ref cp) = ext.cred_protect {
            let info = self.session().info().clone();
            if cp.enforce && !info.extensions.iter().any(|e| e == "credProtect") {
                return Err(ClientError::ConfigurationUnsupported(
                    "credProtect not supported by authenticator".into(),
                ));
            }
            entries.push(extensions::cred_protect::to_cbor(cp.policy));
        }

        // credBlob
        if let Some(ref cb) = ext.cred_blob {
            let info = self.session().info().clone();
            if info.extensions.iter().any(|e| e == "credBlob") {
                if let Some(max_len) = info.max_cred_blob_length
                    && cb.blob.len() > max_len
                {
                    return Err(ClientError::BadRequest(format!(
                        "credBlob too large: {} > {}",
                        cb.blob.len(),
                        max_len,
                    )));
                }
                entries.push(extensions::cred_blob::make_credential_to_cbor(&cb.blob));
            }
        }

        // largeBlobKey
        if let Some(ref lb) = ext.large_blob {
            let info = self.session().info().clone();
            let supported = info.extensions.iter().any(|e| e == "largeBlobKey");
            if lb.support == extensions::large_blob::LargeBlobSupport::Required && !supported {
                return Err(ClientError::ConfigurationUnsupported(
                    "largeBlob not supported by authenticator".into(),
                ));
            }
            if supported {
                entries.push(extensions::large_blob::to_cbor());
            }
        }

        // minPinLength
        if ext.min_pin_length == Some(true) {
            let info = self.session().info().clone();
            if info.extensions.iter().any(|e| e == "minPinLength") {
                entries.push(extensions::min_pin_length::to_cbor());
            }
        }

        Ok((extensions::build_extensions_cbor(entries), hmac_state))
    }

    /// Build CTAP2 extension CBOR for getAssertion.
    fn build_get_assertion_extensions(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        protocol: Option<PinProtocol>,
        selected_cred_id: Option<&[u8]>,
    ) -> Result<(Option<cbor::Value>, Option<prf::HmacSecretState>), ClientError<C::Error>> {
        let ext = match &options.extensions {
            Some(e) => e,
            None => return Ok((None, None)),
        };

        let mut entries: Vec<(String, cbor::Value)> = Vec::new();
        let mut hmac_state = None;

        // PRF / hmac-secret
        if let Some(ref prf_input) = ext.prf {
            let info = self.session().info().clone();
            if info.extensions.iter().any(|e| e == "hmac-secret")
                && let Some(eval) = prf::select_eval(prf_input, selected_cred_id)
                && let Some(state) = self.get_hmac_secret_state(protocol)?
            {
                entries.push(prf::get_assertion_cbor(eval, &state));
                hmac_state = Some(state);
            }
        }

        // credBlob (getCredBlob)
        if ext.get_cred_blob == Some(true) {
            let info = self.session().info().clone();
            if info.extensions.iter().any(|e| e == "credBlob") {
                entries.push(extensions::cred_blob::get_assertion_to_cbor());
            }
        }

        // largeBlobKey
        if ext.large_blob.is_some() {
            let info = self.session().info().clone();
            if info.extensions.iter().any(|e| e == "largeBlobKey") {
                entries.push(extensions::large_blob::to_cbor());
            }
        }

        Ok((extensions::build_extensions_cbor(entries), hmac_state))
    }

    /// Perform ECDH key agreement for hmac-secret.
    fn get_hmac_secret_state(
        &mut self,
        protocol: Option<PinProtocol>,
    ) -> Result<Option<prf::HmacSecretState>, ClientError<C::Error>> {
        let proto = match protocol {
            Some(p) => p,
            None => {
                // Select a protocol for key agreement
                let info = self.session().info().clone();
                if info.pin_uv_protocols.contains(&2) {
                    PinProtocol::V2
                } else if info.pin_uv_protocols.contains(&1) {
                    PinProtocol::V1
                } else {
                    return Ok(None);
                }
            }
        };

        // Get authenticator's key agreement key via clientPin
        let mut session = self.take_session();
        let result = session.client_pin(
            proto.version(),
            0x02, // getKeyAgreement
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        self.restore_session(session);

        let resp = result.map_err(ClientError::Ctap)?;
        let peer_key = resp
            .map_get_int(0x01) // keyAgreement
            .ok_or_else(|| ClientError::BadRequest("missing keyAgreement in response".into()))?;

        prf::HmacSecretState::new(proto, peer_key)
            .map(Some)
            .map_err(|e| ClientError::BadRequest(format!("hmac-secret key agreement failed: {e}")))
    }

    /// Parse extension outputs from a makeCredential response.
    fn parse_registration_extensions(
        &self,
        options: &PublicKeyCredentialCreationOptions,
        auth_data: &[u8],
        hmac_state: Option<&prf::HmacSecretState>,
        has_large_blob_key: bool,
        rk: bool,
    ) -> Option<extensions::RegistrationExtensionOutputs> {
        let ext = options.extensions.as_ref()?;
        let auth_exts = extensions::parse_auth_data_extensions(auth_data);

        let mut outputs = extensions::RegistrationExtensionOutputs::default();
        let mut has_output = false;

        // PRF
        if ext.prf.is_some()
            && let Some(ref exts) = auth_exts
        {
            match prf::make_credential_from_auth_data(exts, hmac_state) {
                Ok(Some(prf_out)) => {
                    outputs.prf = Some(prf_out);
                    has_output = true;
                }
                Ok(None) => {}
                Err(_) => {} // Silently ignore parse errors
            }
        }

        // credProtect
        if ext.cred_protect.is_some()
            && let Some(ref exts) = auth_exts
            && let Some((_, val)) = exts.iter().find(|(k, _)| k == "credProtect")
            && let Some(policy) = extensions::cred_protect::from_cbor(val)
        {
            outputs.cred_protect = Some(extensions::cred_protect::RegistrationOutput { policy });
            has_output = true;
        }

        // credBlob
        if ext.cred_blob.is_some()
            && let Some(ref exts) = auth_exts
            && let Some((_, val)) = exts.iter().find(|(k, _)| k == "credBlob")
            && let Some(stored) = extensions::cred_blob::make_credential_from_cbor(val)
        {
            outputs.cred_blob = Some(extensions::cred_blob::RegistrationOutput { stored });
            has_output = true;
        }

        // largeBlob
        if ext.large_blob.is_some() {
            outputs.large_blob = Some(extensions::large_blob::RegistrationOutput {
                supported: has_large_blob_key,
            });
            has_output = true;
        }

        // credProps (client-side only)
        if ext.cred_props == Some(true) {
            outputs.cred_props = Some(extensions::cred_props::RegistrationOutput { rk });
            has_output = true;
        }

        // minPinLength
        if ext.min_pin_length == Some(true)
            && let Some(ref exts) = auth_exts
            && let Some((_, val)) = exts.iter().find(|(k, _)| k == "minPinLength")
            && let Some(length) = extensions::min_pin_length::from_cbor(val)
        {
            outputs.min_pin_length =
                Some(extensions::min_pin_length::RegistrationOutput { length });
            has_output = true;
        }

        if has_output { Some(outputs) } else { None }
    }

    /// Parse extension outputs from a getAssertion response.
    fn parse_authentication_extensions(
        &self,
        options: &PublicKeyCredentialRequestOptions,
        auth_data: &[u8],
        hmac_state: Option<&prf::HmacSecretState>,
    ) -> Option<extensions::AuthenticationExtensionOutputs> {
        let ext = options.extensions.as_ref()?;
        let auth_exts = extensions::parse_auth_data_extensions(auth_data);

        let mut outputs = extensions::AuthenticationExtensionOutputs::default();
        let mut has_output = false;

        // PRF
        if ext.prf.is_some()
            && let (Some(exts), Some(state)) = (&auth_exts, hmac_state)
        {
            match prf::get_assertion_from_auth_data(exts, state) {
                Ok(Some(results)) => {
                    outputs.prf = Some(prf::AuthenticationOutput { results });
                    has_output = true;
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        // credBlob
        if ext.get_cred_blob == Some(true)
            && let Some(ref exts) = auth_exts
            && let Some((_, val)) = exts.iter().find(|(k, _)| k == "credBlob")
            && let Some(blob) = extensions::cred_blob::get_assertion_from_cbor(val)
        {
            outputs.cred_blob = Some(extensions::cred_blob::AuthenticationOutput { blob });
            has_output = true;
        }

        // Note: largeBlob output is handled separately via process_large_blob

        if has_output { Some(outputs) } else { None }
    }

    /// Process large blob read/write after authentication.
    /// Takes ownership of the session and returns it.
    fn process_large_blob(
        &self,
        session: Ctap2Session<C>,
        input: &extensions::large_blob::AuthenticationInput,
        large_blob_key: Option<&[u8]>,
        token: Option<&[u8]>,
        protocol: Option<PinProtocol>,
    ) -> (
        Ctap2Session<C>,
        Option<extensions::large_blob::AuthenticationOutput>,
    ) {
        use crate::ctap2::LargeBlobs;

        let Some(key) = large_blob_key else {
            return (session, None);
        };

        // For reads we don't need a PIN token, but LargeBlobs::new requires
        // a protocol.  Use V2 as a default for read-only operations — the
        // protocol/token are only exercised on writes.
        let proto = protocol.unwrap_or(PinProtocol::V2);
        let token_bytes = token.unwrap_or(&[]);

        let mut large_blobs = match LargeBlobs::new(session, proto, token_bytes.to_vec()) {
            Ok(lb) => lb,
            Err(_) => {
                unreachable!("LargeBlobs::new failed after support check");
            }
        };

        let output = if input.read == Some(true) {
            // Read does not use the PIN token at all
            match large_blobs.get_blob(key) {
                Ok(blob) => Some(extensions::large_blob::AuthenticationOutput {
                    blob,
                    written: None,
                }),
                Err(_) => Some(extensions::large_blob::AuthenticationOutput {
                    blob: None,
                    written: None,
                }),
            }
        } else if let Some(ref data) = input.write {
            match large_blobs.put_blob(key, data) {
                Ok(()) => Some(extensions::large_blob::AuthenticationOutput {
                    blob: None,
                    written: Some(true),
                }),
                Err(_) => Some(extensions::large_blob::AuthenticationOutput {
                    blob: None,
                    written: Some(false),
                }),
            }
        } else {
            None
        };

        (large_blobs.into_session(), output)
    }

    // -----------------------------------------------------------------------
    // Pre-flight credential filtering
    // -----------------------------------------------------------------------

    /// Filter a credential list against the authenticator using silent
    /// `getAssertion` calls (UP=false).
    ///
    /// Returns the first matching credential, or `None` if no matches.
    /// Credentials whose ID exceeds the authenticator's `max_cred_id_length`
    /// are silently skipped.
    fn filter_creds(
        &mut self,
        rp_id: &str,
        cred_list: &[PublicKeyCredentialDescriptor],
        protocol: Option<PinProtocol>,
        token: Option<&[u8]>,
    ) -> Result<Option<PublicKeyCredentialDescriptor>, ClientError<C::Error>> {
        let info = self.session().info().clone();

        // Filter out credential IDs that are too long
        let filtered: Vec<&PublicKeyCredentialDescriptor> =
            if let Some(max_len) = info.max_cred_id_length {
                cred_list.iter().filter(|c| c.id.len() <= max_len).collect()
            } else {
                cred_list.iter().collect()
            };

        if filtered.is_empty() {
            return Ok(None);
        }

        // Compute pin_uv_param for the silent assertion (dummy client_data_hash)
        let dummy_hash = [0u8; 32];
        let (pin_uv_param, pin_uv_protocol) = compute_pin_uv_param(token, protocol, &dummy_hash);

        let no_up = AuthenticatorOptions {
            rk: None,
            uv: None,
            up: Some(false),
        };

        let mut max_creds = info.max_creds_in_list.unwrap_or(1);
        let mut remaining: &[&PublicKeyCredentialDescriptor] = &filtered;

        while !remaining.is_empty() {
            let chunk_size = max_creds.min(remaining.len());
            let chunk: Vec<PublicKeyCredentialDescriptor> = remaining[..chunk_size]
                .iter()
                .map(|c| (*c).clone())
                .collect();

            let mut session = self.take_session();
            let result = session.get_assertion(
                rp_id,
                &dummy_hash,
                Some(&chunk),
                None,
                Some(&no_up),
                pin_uv_param.as_deref(),
                pin_uv_protocol,
                None,
                None,
            );
            self.restore_session(session);

            match result {
                Ok(resp) => {
                    if chunk.len() == 1 {
                        // Credential ID may be omitted from single-cred responses
                        return Ok(Some(chunk.into_iter().next().unwrap()));
                    }
                    // Multiple creds in chunk — use the returned credential
                    if let Some(cred) = resp.credential {
                        return Ok(Some(cred));
                    }
                    return Ok(Some(chunk.into_iter().next().unwrap()));
                }
                Err(Ctap2Error::StatusError(CtapStatus::NoCredentials)) => {
                    // None in this chunk, try next
                    remaining = &remaining[chunk_size..];
                }
                Err(Ctap2Error::StatusError(CtapStatus::RequestTooLarge)) if max_creds > 1 => {
                    // Message too large, try smaller chunks
                    max_creds = (max_creds - 1).max(1);
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // PIN / UV helpers
    // -----------------------------------------------------------------------

    /// Determine whether UV should be used, and if so, obtain a PIN/UV token.
    ///
    /// Returns `(token, protocol, internal_uv)`.
    fn get_token(
        &mut self,
        uv_requirement: UserVerificationRequirement,
        permissions: Permissions,
        rp_id: Option<&str>,
    ) -> Result<(Option<Vec<u8>>, Option<PinProtocol>, bool), ClientError<C::Error>> {
        if !self.should_use_uv(uv_requirement, permissions)? {
            return Ok((None, None, false));
        }

        let session = self.take_session();
        match self.obtain_token(session, permissions, rp_id) {
            Ok((session, token, protocol, internal_uv)) => {
                self.restore_session(session);
                Ok((token, Some(protocol), internal_uv))
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

        let mut client_pin = ClientPin::new_with_protocol(session, protocol);

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

/// Compute the `pin_uv_param` and protocol version from a token and protocol.
fn compute_pin_uv_param(
    token: Option<&[u8]>,
    protocol: Option<PinProtocol>,
    client_data_hash: &[u8],
) -> (Option<Vec<u8>>, Option<u32>) {
    match (token, protocol) {
        (Some(token), Some(protocol)) => {
            let param = protocol.authenticate(token, client_data_hash);
            (Some(param), Some(protocol.version()))
        }
        (None, Some(protocol)) => (None, Some(protocol.version())),
        _ => (None, None),
    }
}

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
