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

//! FIDO connection trait and error types.

// ---------------------------------------------------------------------------
// CTAP HID protocol types (transport-independent)
// ---------------------------------------------------------------------------

/// Capability flags reported by an authenticator during CTAP HID INIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtapHidCapability(pub u8);

impl CtapHidCapability {
    /// Device supports the WINK command.
    #[allow(dead_code)]
    pub const WINK: u8 = 0x01;
    /// Device supports CBOR (CTAP2) commands.
    pub const CBOR: u8 = 0x04;
    /// Device does **not** support the MSG (CTAP1/U2F) command.
    pub const NMSG: u8 = 0x08;

    /// Create from a raw capability byte.
    pub fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns `true` if the device supports CBOR (CTAP2) commands.
    pub fn has_cbor(self) -> bool {
        self.0 & Self::CBOR != 0
    }

    /// Returns `true` if the device supports the WINK command.
    pub fn has_wink(self) -> bool {
        self.0 & Self::WINK != 0
    }

    /// Returns `true` if the device does **not** support MSG (CTAP1/U2F).
    pub fn has_nmsg(self) -> bool {
        self.0 & Self::NMSG != 0
    }

    /// Returns the raw capability byte.
    pub fn raw(self) -> u8 {
        self.0
    }
}

/// Error codes returned in CTAP HID error frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidError {
    /// The command byte is not recognized.
    InvalidCmd = 0x01,
    /// Invalid parameter in the command.
    InvalidPar = 0x02,
    /// Invalid message length.
    InvalidLen = 0x03,
    /// Unexpected continuation sequence number.
    InvalidSeq = 0x04,
    /// Message timed out.
    MsgTimeout = 0x05,
    /// The channel is busy processing another request.
    ChannelBusy = 0x06,
    /// A channel lock is required for this command.
    LockRequired = 0x0A,
    /// The channel ID is not valid.
    InvalidChannel = 0x0B,
    /// Unspecified error.
    Other = 0x7F,
}

impl CtapHidError {
    /// Parse a CTAP HID error byte into an enum variant.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::InvalidCmd,
            0x02 => Self::InvalidPar,
            0x03 => Self::InvalidLen,
            0x04 => Self::InvalidSeq,
            0x05 => Self::MsgTimeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            _ => Self::Other,
        }
    }
}

// ---------------------------------------------------------------------------
// FidoError
// ---------------------------------------------------------------------------

/// Errors that can occur during FIDO HID communication.
#[derive(Debug, thiserror::Error)]
pub enum FidoError {
    /// Low-level transport error (e.g. HID I/O failure).
    #[error("Transport error: {0}")]
    Transport(Box<dyn std::error::Error + Send + Sync>),
    /// The device path is not a valid C string.
    #[error("Invalid device path")]
    InvalidPath,
    /// The connection has already been closed.
    #[error("Connection is closed")]
    ConnectionClosed,
    /// The INIT response contained an unexpected nonce.
    #[error("Wrong nonce in INIT response")]
    WrongNonce,
    /// A response packet arrived on the wrong channel.
    #[error("Wrong channel in response")]
    WrongChannel,
    /// A continuation packet had an unexpected sequence number.
    #[error("Wrong sequence number in response")]
    WrongSequence,
    /// The authenticator returned a CTAP HID error frame.
    #[error("CTAP HID error: {0:?}")]
    CtapHidError(CtapHidError),
    /// The response could not be parsed.
    #[error("Invalid response")]
    InvalidResponse,
    /// No response was received within the timeout period.
    #[error("Timeout")]
    Timeout,
    /// Any other error with a descriptive message.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// FidoConnection trait
// ---------------------------------------------------------------------------

/// Abstract FIDO connection — send CTAP HID commands.
pub trait FidoConnection: crate::core::Connection<Error = FidoError> {
    /// Send a CTAP HID command and receive the response.
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError>;
    /// Return the firmware version as `(major, minor, patch)`.
    fn device_version(&self) -> (u8, u8, u8);
    /// Return the CTAP HID capability flags reported by the device.
    fn capabilities(&self) -> CtapHidCapability;
}

impl crate::core::Connection for Box<dyn FidoConnection + Send> {
    type Error = FidoError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl FidoConnection for Box<dyn FidoConnection + Send> {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        (**self).call(cmd, data, on_keepalive, cancel)
    }
    fn device_version(&self) -> (u8, u8, u8) {
        (**self).device_version()
    }
    fn capabilities(&self) -> CtapHidCapability {
        (**self).capabilities()
    }
}

impl crate::core::Connection for Box<dyn FidoConnection + Send + Sync> {
    type Error = FidoError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl FidoConnection for Box<dyn FidoConnection + Send + Sync> {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        (**self).call(cmd, data, on_keepalive, cancel)
    }
    fn device_version(&self) -> (u8, u8, u8) {
        (**self).device_version()
    }
    fn capabilities(&self) -> CtapHidCapability {
        (**self).capabilities()
    }
}
