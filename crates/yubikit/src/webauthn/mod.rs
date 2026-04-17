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
