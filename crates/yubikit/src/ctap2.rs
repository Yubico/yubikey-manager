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

//! CTAP2 protocol session.
//!
//! Provides [`Ctap2Session`], which wraps a [`CtapSession`] and implements
//! CTAP2-specific command framing and response parsing.

use crate::core::Connection;
use crate::ctap::{CtapError, CtapSession};

// ---------------------------------------------------------------------------
// CTAP2 command bytes
// ---------------------------------------------------------------------------

/// CTAP2 authenticator command identifiers.
pub mod cmd {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const BIO_ENROLLMENT: u8 = 0x09;
    pub const CREDENTIAL_MGMT: u8 = 0x0A;
    pub const SELECTION: u8 = 0x0B;
    pub const LARGE_BLOBS: u8 = 0x0C;
    pub const CONFIG: u8 = 0x0D;
    pub const BIO_ENROLLMENT_PRE: u8 = 0x40;
    pub const CREDENTIAL_MGMT_PRE: u8 = 0x41;
}

// ---------------------------------------------------------------------------
// CTAP2 status codes
// ---------------------------------------------------------------------------

/// CTAP2 error status codes returned by the authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapStatus {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    FpDatabaseFull = 0x17,
    LargeBlobStorageFull = 0x18,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    UnsupportedOption = 0x2B,
    InvalidOption = 0x2C,
    KeepaliveCancel = 0x2D,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x36,
    PukRequired = 0x39,
    PinPolicyViolation = 0x37,
    UvBlocked = 0x3C,
    IntegrityFailure = 0x3D,
    InvalidSubcommand = 0x3E,
    UvInvalid = 0x3F,
    UnauthorizedPermission = 0x40,
    Other = 0x7F,
}

impl CtapStatus {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Success,
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidParameter,
            0x03 => Self::InvalidLength,
            0x04 => Self::InvalidSeq,
            0x05 => Self::Timeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x11 => Self::CborUnexpectedType,
            0x12 => Self::InvalidCbor,
            0x14 => Self::MissingParameter,
            0x15 => Self::LimitExceeded,
            0x17 => Self::FpDatabaseFull,
            0x18 => Self::LargeBlobStorageFull,
            0x19 => Self::CredentialExcluded,
            0x21 => Self::Processing,
            0x22 => Self::InvalidCredential,
            0x23 => Self::UserActionPending,
            0x24 => Self::OperationPending,
            0x25 => Self::NoOperations,
            0x26 => Self::UnsupportedAlgorithm,
            0x27 => Self::OperationDenied,
            0x28 => Self::KeyStoreFull,
            0x2B => Self::UnsupportedOption,
            0x2C => Self::InvalidOption,
            0x2D => Self::KeepaliveCancel,
            0x2E => Self::NoCredentials,
            0x2F => Self::UserActionTimeout,
            0x30 => Self::NotAllowed,
            0x31 => Self::PinInvalid,
            0x32 => Self::PinBlocked,
            0x33 => Self::PinAuthInvalid,
            0x34 => Self::PinAuthBlocked,
            0x36 => Self::PinNotSet,
            0x39 => Self::PukRequired,
            0x37 => Self::PinPolicyViolation,
            0x3C => Self::UvBlocked,
            0x3D => Self::IntegrityFailure,
            0x3E => Self::InvalidSubcommand,
            0x3F => Self::UvInvalid,
            0x40 => Self::UnauthorizedPermission,
            _ => Self::Other,
        }
    }
}

impl std::fmt::Display for CtapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?} (0x{:02X})", *self as u8)
    }
}

// ---------------------------------------------------------------------------
// Ctap2Error
// ---------------------------------------------------------------------------

/// Error type for [`Ctap2Session`] CTAP2 protocol operations.
#[derive(Debug)]
pub enum Ctap2Error<E: std::error::Error + Send + Sync + 'static> {
    /// The authenticator returned a non-success status code.
    StatusError(CtapStatus),
    /// The underlying transport or session returned an error.
    Transport(CtapError<E>),
    /// The response from the authenticator was malformed.
    InvalidResponse(String),
}

impl<E: std::error::Error + Send + Sync + 'static> std::fmt::Display for Ctap2Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusError(status) => write!(f, "CTAP2 error: {status}"),
            Self::Transport(e) => write!(f, "{e}"),
            Self::InvalidResponse(msg) => write!(f, "Invalid CTAP2 response: {msg}"),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error for Ctap2Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<CtapError<E>> for Ctap2Error<E> {
    fn from(e: CtapError<E>) -> Self {
        Self::Transport(e)
    }
}

// ---------------------------------------------------------------------------
// Ctap2Session
// ---------------------------------------------------------------------------

/// CTAP2 protocol session.
///
/// Wraps a [`CtapSession`] and provides CTAP2-specific command framing:
/// each command is sent as `[cmd_byte] ++ cbor_data` via CBOR transport,
/// and responses are parsed as `[status_byte] ++ cbor_data`.
pub struct Ctap2Session<C: Connection> {
    session: CtapSession<C>,
}

impl<C: Connection + 'static> Ctap2Session<C> {
    /// Create a new `Ctap2Session` wrapping the given [`CtapSession`].
    pub fn new(session: CtapSession<C>) -> Self {
        Self { session }
    }

    /// Access the underlying [`CtapSession`].
    pub fn session(&self) -> &CtapSession<C> {
        &self.session
    }

    /// Consume the `Ctap2Session`, returning the underlying [`CtapSession`].
    pub fn into_session(self) -> CtapSession<C> {
        self.session
    }

    /// Send a CTAP2 CBOR command and parse the status + response.
    ///
    /// Frames the request as `[cmd_byte] ++ data` and sends it via the
    /// underlying transport. Parses the response status byte and returns
    /// the remaining response data on success.
    pub fn send_cbor(
        &mut self,
        cmd_byte: u8,
        data: Option<&[u8]>,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, Ctap2Error<C::Error>> {
        let mut request = vec![cmd_byte];
        if let Some(payload) = data {
            request.extend_from_slice(payload);
        }

        let response = self.session.call_cbor(&request, on_keepalive, cancel)?;

        if response.is_empty() {
            return Err(Ctap2Error::InvalidResponse("Empty response".into()));
        }

        let status = CtapStatus::from_byte(response[0]);
        if status != CtapStatus::Success {
            return Err(Ctap2Error::StatusError(status));
        }

        Ok(response[1..].to_vec())
    }

    /// authenticatorSelection command (CTAP 2.1+).
    ///
    /// Asks the user to confirm presence on the authenticator. Returns
    /// successfully once the user touches the device, or fails with
    /// [`CtapStatus::KeepaliveCancel`] if cancelled.
    pub fn selection(
        &mut self,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<(), Ctap2Error<C::Error>> {
        self.send_cbor(cmd::SELECTION, None, on_keepalive, cancel)?;
        Ok(())
    }
}
