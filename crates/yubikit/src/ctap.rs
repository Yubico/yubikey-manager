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

//! CTAP session for FIDO2 authenticator communication.
//!
//! Provides [`CtapSession`](crate::ctap::CtapSession), a transport-agnostic session for communicating
//! with FIDO2 authenticators using the CTAP2 protocol. Supports both
//! CTAP HID (USB) via [`FidoConnection`](crate::fido::FidoConnection) and NFCCTAP (SmartCard/NFC)
//! via [`SmartCardConnection`](crate::smartcard::SmartCardConnection).

use std::time::Duration;

use crate::core::{Connection, Version, patch_version};
use crate::fido::FidoConnection;
use crate::smartcard::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol};
use crate::transport::ctaphid::FidoError;

// ---------------------------------------------------------------------------
// CTAP2 constants
// ---------------------------------------------------------------------------

/// CTAP HID command byte for CBOR messages.
const CTAPHID_CBOR: u8 = 0x10;

/// CTAP HID command byte for raw U2F/CTAP1 messages.
const CTAPHID_MSG: u8 = 0x03;

/// NFCCTAP APDU instruction for CBOR commands.
const NFCCTAP_MSG: u8 = 0x10;

/// NFCCTAP APDU instruction for getResponse / cancel.
const NFCCTAP_GETRESPONSE: u8 = 0x11;

/// Status word indicating a keepalive during NFCCTAP polling.
const SW_KEEPALIVE: u16 = 0x9100;

/// Polling interval for NFCCTAP keepalive responses.
const NFCCTAP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// NFCCTAP P1 value to cancel a pending operation.
const NFCCTAP_CANCEL: u8 = 0x11;

// ---------------------------------------------------------------------------
// CtapError
// ---------------------------------------------------------------------------

/// Error type for [`CtapSession`] operations.
///
/// Generic over the underlying connection error type `E`.
#[derive(Debug)]
pub enum CtapError<E: std::error::Error + Send + Sync + 'static> {
    /// The underlying transport returned an error.
    Connection(E),
    /// The device is not supported (no CTAP2 capabilities).
    NotSupported(String),
    /// The response from the device was malformed.
    InvalidResponse(String),
}

impl<E: std::error::Error + Send + Sync + 'static> std::fmt::Display for CtapError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(e) => write!(f, "Connection error: {e}"),
            Self::NotSupported(msg) => write!(f, "Not supported: {msg}"),
            Self::InvalidResponse(msg) => write!(f, "Invalid response: {msg}"),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error for CtapError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(e) => Some(e),
            _ => None,
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> CtapError<E> {
    /// Erase the generic connection error type for uniform handling.
    pub fn erase(self) -> String {
        self.to_string()
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for CtapError<E> {
    fn from(e: E) -> Self {
        Self::Connection(e)
    }
}

// ---------------------------------------------------------------------------
// CtapBackend (private, object-safe trait for internal dispatch)
// ---------------------------------------------------------------------------

/// Object-safe trait for transport-specific CTAP2 operations.
///
/// Each transport (CCID/NFC, CTAP HID) implements this trait. The public
/// [`CtapSession`] dispatches through this.
trait CtapBackend<E: std::error::Error + Send + Sync + 'static>: Send {
    /// Device firmware version.
    fn version(&self) -> Version;

    /// Send a CTAP CBOR command and receive the response.
    fn call_cbor(
        &mut self,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError<E>>;

    /// Send a CTAP1/U2F (MSG) command and receive the response.
    fn call_msg(&mut self, data: &[u8]) -> Result<Vec<u8>, CtapError<E>>;

    /// Whether the device supports CTAP2 CBOR commands.
    fn has_ctap2(&self) -> bool;

    /// Whether the device supports CTAP1/U2F MSG commands.
    fn has_ctap1(&self) -> bool;

    /// Consume the backend and return the connection as `Box<dyn Any>`.
    fn into_connection_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

// ---------------------------------------------------------------------------
// CtapSession
// ---------------------------------------------------------------------------

/// CTAP session for FIDO2 authenticator communication.
///
/// Generic over the connection type `C`. Construct with [`CtapSession::new`]
/// for SmartCard/NFC (CCID) or [`CtapSession::new_fido`] for CTAP HID.
pub struct CtapSession<C: Connection> {
    inner: Box<dyn CtapBackend<C::Error>>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: Connection + 'static> CtapSession<C> {
    /// The firmware version of the device.
    pub fn version(&self) -> Version {
        self.inner.version()
    }

    /// Whether the device supports CTAP2 CBOR commands.
    pub fn has_ctap2(&self) -> bool {
        self.inner.has_ctap2()
    }

    /// Whether the device supports CTAP1/U2F MSG commands.
    pub fn has_ctap1(&self) -> bool {
        self.inner.has_ctap1()
    }

    /// Send a CTAP2 CBOR command and receive the response.
    pub fn call_cbor(
        &mut self,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError<C::Error>> {
        self.inner.call_cbor(data, on_keepalive, cancel)
    }

    /// Send a CTAP1/U2F MSG command and receive the response.
    pub fn call_msg(&mut self, data: &[u8]) -> Result<Vec<u8>, CtapError<C::Error>> {
        self.inner.call_msg(data)
    }

    /// Consume the session, returning the underlying connection.
    pub fn into_connection(self) -> C {
        *self
            .inner
            .into_connection_any()
            .downcast::<C>()
            .expect("CtapSession inner type mismatch (this is a bug)")
    }

    fn from_inner(inner: Box<dyn CtapBackend<C::Error>>) -> Self {
        Self {
            inner,
            _phantom: std::marker::PhantomData,
        }
    }
}

// SmartCard (CCID / NFC) constructors
impl<C: SmartCardConnection + Send + 'static> CtapSession<C> {
    /// Open a CTAP session over SmartCard (CCID / NFC).
    ///
    /// Selects the FIDO applet and probes for CTAP2 and CTAP1 support.
    /// On error, returns the connection so the caller can recover it.
    pub fn new(connection: C) -> Result<Self, (CtapError<SmartCardError>, C)> {
        CcidCtap::open(connection).map(|inner| Self::from_inner(Box::new(inner)))
    }

    /// Open a CTAP session over SmartCard with SCP (Secure Channel Protocol).
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, (CtapError<SmartCardError>, C)> {
        CcidCtap::open_with_scp(connection, scp_key_params)
            .map(|inner| Self::from_inner(Box::new(inner)))
    }
}

// FIDO HID constructors
impl<C: FidoConnection + Send + 'static> CtapSession<C> {
    /// Open a CTAP session over FIDO HID.
    ///
    /// On error, returns the connection so the caller can recover it.
    pub fn new_fido(connection: C) -> Result<Self, (CtapError<FidoError>, C)> {
        HidCtap::open(connection).map(|inner| Self::from_inner(Box::new(inner)))
    }
}

// ---------------------------------------------------------------------------
// CcidCtap — SmartCard / NFC backend (internal)
// ---------------------------------------------------------------------------

struct CcidCtap<C: SmartCardConnection> {
    protocol: SmartCardProtocol<C>,
    version: Version,
    has_ctap2: bool,
    has_ctap1: bool,
}

impl<C: SmartCardConnection> CcidCtap<C> {
    fn open(connection: C) -> Result<Self, (CtapError<SmartCardError>, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let resp = match protocol.select(Aid::FIDO) {
            Ok(resp) => resp,
            Err(e) => return Err((CtapError::Connection(e), protocol.into_connection())),
        };
        Self::init(protocol, &resp)
    }

    fn open_with_scp(
        connection: C,
        scp_key_params: &crate::scp::ScpKeyParams,
    ) -> Result<Self, (CtapError<SmartCardError>, C)> {
        let mut protocol = SmartCardProtocol::new(connection);
        let resp = match protocol.select(Aid::FIDO) {
            Ok(resp) => resp,
            Err(e) => return Err((CtapError::Connection(e), protocol.into_connection())),
        };
        if let Err(e) = protocol.init_scp(scp_key_params) {
            return Err((CtapError::Connection(e), protocol.into_connection()));
        }
        Self::init(protocol, &resp)
    }

    fn init(
        mut protocol: SmartCardProtocol<C>,
        select_resp: &[u8],
    ) -> Result<Self, (CtapError<SmartCardError>, C)> {
        log::debug!("Opening CcidCtap (SmartCard/NFC)");

        let has_ctap1 = select_resp == b"U2F_V2";

        // Probe for CTAP2 via authenticatorGetInfo (0x04)
        let has_ctap2 = protocol
            .send_apdu(0x80, NFCCTAP_MSG, 0x80, 0x00, &[0x04])
            .is_ok();

        if !has_ctap2 && !has_ctap1 {
            return Err((
                CtapError::NotSupported("Device supports neither CTAP2 nor CTAP1".into()),
                protocol.into_connection(),
            ));
        }

        // Derive version from the CTAP HID equivalent (not available over NFC,
        // so default to 0.0.0 and let callers override from DeviceInfo).
        let version = patch_version(Version(0, 0, 0));

        Ok(Self {
            protocol,
            version,
            has_ctap2,
            has_ctap1,
        })
    }

    /// NFCCTAP CBOR framing with keepalive polling and cancel support.
    fn nfcctap_call_cbor(
        &mut self,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError<SmartCardError>> {
        // Initial CBOR command
        match self.protocol.send_apdu(0x80, NFCCTAP_MSG, 0x80, 0x00, data) {
            Ok(resp) => Ok(resp),
            Err(SmartCardError::Apdu { data: ka_data, sw }) if sw == SW_KEEPALIVE => {
                // Enter keepalive polling loop
                self.nfcctap_poll(ka_data, on_keepalive, cancel)
            }
            Err(SmartCardError::Apdu { sw, .. }) => Err(CtapError::InvalidResponse(format!(
                "NFCCTAP error: SW={sw:04X}"
            ))),
            Err(e) => Err(CtapError::Connection(e)),
        }
    }

    /// Keepalive polling loop for NFCCTAP.
    fn nfcctap_poll(
        &mut self,
        initial_ka: Vec<u8>,
        mut on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError<SmartCardError>> {
        let mut last_ka: Option<u8> = None;

        // Handle initial keepalive data
        if let Some(&status) = initial_ka.first() {
            last_ka = Some(status);
            if let Some(ref mut cb) = on_keepalive {
                cb(status);
            }
        }

        loop {
            std::thread::sleep(NFCCTAP_POLL_INTERVAL);

            let p1 = if cancel.is_some_and(|f| f()) {
                NFCCTAP_CANCEL
            } else {
                0x00
            };

            match self
                .protocol
                .send_apdu(0x80, NFCCTAP_GETRESPONSE, p1, 0x00, &[])
            {
                Ok(resp) => return Ok(resp),
                Err(SmartCardError::Apdu { data, sw }) if sw == SW_KEEPALIVE => {
                    if let Some(&status) = data.first()
                        && last_ka != Some(status)
                    {
                        last_ka = Some(status);
                        if let Some(ref mut cb) = on_keepalive {
                            cb(status);
                        }
                    }
                }
                Err(SmartCardError::Apdu { sw, .. }) => {
                    return Err(CtapError::InvalidResponse(format!(
                        "NFCCTAP error: SW={sw:04X}"
                    )));
                }
                Err(e) => return Err(CtapError::Connection(e)),
            }
        }
    }

    /// NFCCTAP MSG (CTAP1/U2F) framing — simple APDU pass-through.
    fn nfcctap_call_msg(&mut self, data: &[u8]) -> Result<Vec<u8>, CtapError<SmartCardError>> {
        if data.len() < 4 {
            return Err(CtapError::InvalidResponse("APDU too short".into()));
        }
        let (cla, ins, p1, p2) = (data[0], data[1], data[2], data[3]);
        let payload = if data.len() > 5 {
            let end = 5 + data[4] as usize;
            if end > data.len() {
                return Err(CtapError::InvalidResponse(
                    "Payload length exceeds data".into(),
                ));
            }
            &data[5..end]
        } else {
            &[]
        };

        match self.protocol.send_apdu(cla, ins, p1, p2, payload) {
            Ok(resp) => {
                let mut result = resp;
                result.push(0x90);
                result.push(0x00);
                Ok(result)
            }
            Err(SmartCardError::Apdu { data, sw }) => {
                let mut result = data;
                result.push((sw >> 8) as u8);
                result.push((sw & 0xFF) as u8);
                Ok(result)
            }
            Err(e) => Err(CtapError::Connection(e)),
        }
    }
}

impl<C: SmartCardConnection + Send + 'static> CtapBackend<SmartCardError> for CcidCtap<C> {
    fn version(&self) -> Version {
        self.version
    }

    fn call_cbor(
        &mut self,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError<SmartCardError>> {
        self.nfcctap_call_cbor(data, on_keepalive, cancel)
    }

    fn call_msg(&mut self, data: &[u8]) -> Result<Vec<u8>, CtapError<SmartCardError>> {
        self.nfcctap_call_msg(data)
    }

    fn has_ctap2(&self) -> bool {
        self.has_ctap2
    }

    fn has_ctap1(&self) -> bool {
        self.has_ctap1
    }

    fn into_connection_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        Box::new(self.protocol.into_connection())
    }
}

// ---------------------------------------------------------------------------
// HidCtap — FIDO HID backend (internal)
// ---------------------------------------------------------------------------

struct HidCtap<C: FidoConnection> {
    connection: C,
    version: Version,
    has_ctap2: bool,
    has_ctap1: bool,
}

impl<C: FidoConnection> HidCtap<C> {
    fn open(connection: C) -> Result<Self, (CtapError<FidoError>, C)> {
        log::debug!("Opening HidCtap (FIDO HID)");
        let caps = connection.capabilities();
        let has_ctap2 = caps.has_cbor();
        let has_ctap1 = !caps.has_nmsg();

        if !has_ctap2 && !has_ctap1 {
            return Err((
                CtapError::NotSupported("Device supports neither CTAP2 nor CTAP1".into()),
                connection,
            ));
        }

        let (v1, v2, v3) = connection.device_version();
        let version = patch_version(Version(v1, v2, v3));

        Ok(Self {
            connection,
            version,
            has_ctap2,
            has_ctap1,
        })
    }
}

impl<C: FidoConnection + Send + 'static> CtapBackend<FidoError> for HidCtap<C> {
    fn version(&self) -> Version {
        self.version
    }

    fn call_cbor(
        &mut self,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError<FidoError>> {
        self.connection
            .call(CTAPHID_CBOR, data, on_keepalive, cancel)
            .map_err(CtapError::Connection)
    }

    fn call_msg(&mut self, data: &[u8]) -> Result<Vec<u8>, CtapError<FidoError>> {
        self.connection
            .call(CTAPHID_MSG, data, None, None)
            .map_err(CtapError::Connection)
    }

    fn has_ctap2(&self) -> bool {
        self.has_ctap2
    }

    fn has_ctap1(&self) -> bool {
        self.has_ctap1
    }

    fn into_connection_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        Box::new(self.connection)
    }
}
