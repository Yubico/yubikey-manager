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

//! Rust SDK for interacting with YubiKey devices.
//!
//! **yubikit** provides a complete API for communicating with YubiKeys over
//! USB (CCID/SmartCard, FIDO HID, OTP HID) and NFC. It covers the full
//! range of YubiKey applications: OATH, PIV, OpenPGP, FIDO2/CTAP2, WebAuthn,
//! YubiOTP, HSM Auth, and device management.
//!
//! # Getting started
//!
//! Most workflows follow the same pattern: discover devices, open a connection
//! over the desired transport, then create a session for the application you
//! want to use.
//!
//! ```no_run
//! use yubikit::device::list_devices;
//! use yubikit::management::UsbInterface;
//! use yubikit::oath::OathSession;
//!
//! // 1. Discover connected YubiKeys
//! let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
//! let devices = list_devices(all).expect("enumeration failed");
//! let dev = devices.first().expect("no YubiKey found");
//!
//! // 2. Open a SmartCard (CCID) connection
//! let conn = dev.open_smartcard().expect("connection failed");
//!
//! // 3. Create an OATH session and list accounts
//! let mut session = OathSession::new(conn).expect("OATH init failed");
//! let creds = session.list_credentials().expect("list failed");
//! for cred in &creds {
//!     println!("{cred:?}");
//! }
//! ```
//!
//! # Transports and connections
//!
//! YubiKeys expose different USB interfaces, each requiring its own
//! connection type:
//!
//! | Interface | Connection | Used by |
//! |-----------|-----------|---------|
//! | CCID (SmartCard) | [`smartcard::SmartCardConnection`] | OATH, PIV, OpenPGP, Management, FIDO2, HSM Auth, Security Domain |
//! | FIDO HID | [`transport::ctaphid::HidFidoConnection`] | FIDO2/CTAP2, WebAuthn, Management |
//! | OTP HID | [`transport::otphid::HidOtpConnection`] | YubiOTP, Management |
//!
//! All connection types implement [`core::Connection`]. Session types are
//! generic over their connection type, so the same [`ctap2::Ctap2Session`]
//! works over both SmartCard and FIDO HID.
//!
//! # Module overview
//!
//! ## Device discovery and management
//! - [`device`] — Enumerate connected YubiKeys, open connections
//! - [`management`] — Read/write device configuration, capabilities, and mode
//!
//! ## YubiKey applications
//! - [`oath`] — OATH TOTP/HOTP credential management and code calculation
//! - [`piv`] — PIV (FIPS 201) smart card operations (keys, certificates, PIN)
//! - [`openpgp`] — OpenPGP card operations (keys, certificates, PIN)
//! - [`hsmauth`] — YubiHSM Auth credential management
//! - [`yubiotp`] — YubiOTP slot configuration (challenge-response, static passwords, HOTP)
//! - [`securitydomain`] — GlobalPlatform Security Domain (SCP03 key management)
//!
//! ## FIDO2 and WebAuthn
//! - [`ctap`] — Low-level CTAP transport session (CTAP1/CTAP2 dispatch)
//! - [`ctap2`] — CTAP2 commands: credentials, assertions, PIN/UV, bio enrollment, large blobs
//! - [`webauthn`] — High-level WebAuthn client with extension support (PRF, credProtect, largeBlob, etc.)
//!
//! ## Transport and protocol infrastructure
//! - [`transport`] — USB HID (FIDO and OTP) and PC/SC transport implementations
//! - [`smartcard`] — ISO 7816 SmartCard / CCID connection and APDU handling
//! - [`scp`] — SCP03 secure channel parameters
//! - [`otp`] — OTP HID framing protocol
//! - [`core`] — Shared types: [`core::Version`], [`core::Connection`] trait
//! - [`cbor`] — CBOR encoding/decoding helpers for CTAP2
//! - [`tlv`] — TLV (Tag-Length-Value) encoding/decoding for SmartCard APDUs

pub mod cbor;
pub mod core;
pub mod ctap;
pub mod ctap2;
pub mod device;
pub mod fido;
pub mod hsmauth;
pub mod logging;
pub mod management;
pub mod oath;
pub mod openpgp;
pub mod otp;
pub mod piv;
pub mod scp;
pub mod securitydomain;
pub mod smartcard;
pub mod tlv;
pub mod transport;
pub mod webauthn;
pub mod yubiotp;
