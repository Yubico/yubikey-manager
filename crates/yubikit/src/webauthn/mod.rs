// Copyright 2026 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! WebAuthn client implementation.
//!
//! Provides [`WebAuthnClient`](crate::webauthn::WebAuthnClient) for performing
//! WebAuthn registration and authentication ceremonies using a CTAP2
//! authenticator, along with the WebAuthn types needed for the public API.
//!
//! # Example
//!
//! ```no_run
//! use yubikit::ctap::CtapSession;
//! use yubikit::ctap2::Ctap2Session;
//! use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
//! use yubikit::webauthn::{
//!     WebAuthnClient, ClientDataCollector, CollectedClientData, UserInteraction,
//!     types::{
//!         PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity,
//!         PublicKeyCredentialUserEntity, PublicKeyCredentialParameters,
//!         PublicKeyCredentialRequestOptions,
//!     },
//! };
//!
//! # struct MyInteraction;
//! # impl UserInteraction for MyInteraction {
//! #     fn request_pin(&self) -> Option<String> { None }
//! #     fn request_uv(&self) -> bool { true }
//! # }
//! # struct MyCollector;
//! # impl ClientDataCollector for MyCollector {
//! #     fn collect_create(&self, _: &PublicKeyCredentialCreationOptions) -> Result<(CollectedClientData, String), String> { todo!() }
//! #     fn collect_get(&self, _: &PublicKeyCredentialRequestOptions) -> Result<(CollectedClientData, String), String> { todo!() }
//! # }
//! let devices = list_fido_devices()?;
//! let dev = devices.first().expect("no FIDO device found");
//! let conn = HidFidoConnection::open(dev)?;
//! let ctap = CtapSession::new_fido(conn).map_err(|(e, _)| e)?;
//! let session = Ctap2Session::new(ctap).map_err(|(e, _)| e)?;
//!
//! let mut client = WebAuthnClient::new(session, MyInteraction, MyCollector);
//! // Use client.make_credential(...) and client.get_assertion(...)
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod client;
/// WebAuthn extension types and CBOR encoding/decoding.
pub mod extensions;
/// WebAuthn ceremony types (options, responses, enums, and entity descriptors).
pub mod types;

/// Client-side WebAuthn types: data collector, error, user interaction, and client.
pub use client::{ClientDataCollector, ClientError, UserInteraction, WebAuthnClient};
/// Re-exported WebAuthn types used in the public API.
pub use types::{
    AttestationConveyancePreference, AuthenticationResponse, AuthenticatorAssertionResponse,
    AuthenticatorAttachment, AuthenticatorAttestationResponse, AuthenticatorSelectionCriteria,
    AuthenticatorTransport, CollectedClientData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialHint, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, RegistrationResponse, ResidentKeyRequirement,
    UserVerificationRequirement,
};
