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

//! Smart card communication primitives — APDU encoding, status words, and
//! ISO 7816-4 command/response handling.

use std::fmt;
use std::time::Instant;

use thiserror::Error;

use crate::core::{Transport, Version};
use crate::scp::{ScpError, ScpState, aes_cmac, x963_kdf};
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// AID — YubiKey application identifiers
// ---------------------------------------------------------------------------

/// Known YubiKey application identifiers (AIDs).
pub struct Aid;

impl Aid {
    /// AID for the OTP applet.
    pub const OTP: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];
    /// AID for the Management applet.
    pub const MANAGEMENT: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
    /// AID for the OpenPGP applet.
    pub const OPENPGP: &[u8] = &[0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    /// AID for the OATH applet.
    pub const OATH: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
    /// AID for the PIV applet.
    pub const PIV: &[u8] = &[0xa0, 0x00, 0x00, 0x03, 0x08];
    /// AID for the FIDO applet.
    pub const FIDO: &[u8] = &[0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
    /// AID for the YubiHSM Auth applet.
    pub const HSMAUTH: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];
    /// AID for the Security Domain.
    pub const SECURE_DOMAIN: &[u8] = &[0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
}

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

/// Well-known ISO 7816 status words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Sw {
    /// No input data (`0x6285`).
    NoInputData = 0x6285,
    /// Verification failed, no retries remaining (`0x63C0`).
    VerifyFailNoRetry = 0x63C0,
    /// Memory failure (`0x6581`).
    MemoryFailure = 0x6581,
    /// Wrong length (`0x6700`).
    WrongLength = 0x6700,
    /// Security condition not satisfied (`0x6982`).
    SecurityConditionNotSatisfied = 0x6982,
    /// Authentication method blocked (`0x6983`).
    AuthMethodBlocked = 0x6983,
    /// Data invalid (`0x6984`).
    DataInvalid = 0x6984,
    /// Conditions of use not satisfied (`0x6985`).
    ConditionsNotSatisfied = 0x6985,
    /// Command not allowed (`0x6986`).
    CommandNotAllowed = 0x6986,
    /// Incorrect parameters in command data (`0x6A80`).
    IncorrectParameters = 0x6A80,
    /// Function not supported (`0x6A81`).
    FunctionNotSupported = 0x6A81,
    /// File or application not found (`0x6A82`).
    FileNotFound = 0x6A82,
    /// Record not found (`0x6A83`).
    RecordNotFound = 0x6A83,
    /// Not enough memory space (`0x6A84`).
    NoSpace = 0x6A84,
    /// Referenced data not found (`0x6A88`).
    ReferenceDataNotFound = 0x6A88,
    /// Applet selection failed (`0x6999`).
    AppletSelectFailed = 0x6999,
    /// Wrong parameters P1/P2 (`0x6B00`).
    WrongParametersP1P2 = 0x6B00,
    /// Invalid instruction byte (`0x6D00`).
    InvalidInstruction = 0x6D00,
    /// Class not supported (`0x6E00`).
    ClassNotSupported = 0x6E00,
    /// Command aborted — unknown error (`0x6F00`).
    CommandAborted = 0x6F00,
    /// Success (`0x9000`).
    Ok = 0x9000,
}

impl Sw {
    /// Convert a raw `u16` status word to the corresponding [`Sw`] variant, if known.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x6285 => Some(Self::NoInputData),
            0x63C0 => Some(Self::VerifyFailNoRetry),
            0x6581 => Some(Self::MemoryFailure),
            0x6700 => Some(Self::WrongLength),
            0x6982 => Some(Self::SecurityConditionNotSatisfied),
            0x6983 => Some(Self::AuthMethodBlocked),
            0x6984 => Some(Self::DataInvalid),
            0x6985 => Some(Self::ConditionsNotSatisfied),
            0x6986 => Some(Self::CommandNotAllowed),
            0x6A80 => Some(Self::IncorrectParameters),
            0x6A81 => Some(Self::FunctionNotSupported),
            0x6A82 => Some(Self::FileNotFound),
            0x6A83 => Some(Self::RecordNotFound),
            0x6A84 => Some(Self::NoSpace),
            0x6A88 => Some(Self::ReferenceDataNotFound),
            0x6999 => Some(Self::AppletSelectFailed),
            0x6B00 => Some(Self::WrongParametersP1P2),
            0x6D00 => Some(Self::InvalidInstruction),
            0x6E00 => Some(Self::ClassNotSupported),
            0x6F00 => Some(Self::CommandAborted),
            0x9000 => Some(Self::Ok),
            _ => None,
        }
    }
}

impl fmt::Display for Sw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04X}", *self as u16)
    }
}

/// Raw status word constant for success (`0x9000`).
const SW_OK: u16 = 0x9000;
const SW1_HAS_MORE_DATA: u8 = 0x61;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors related to APDU construction.
#[derive(Debug, Error)]
pub enum ApduError {
    /// Data exceeds the 255-byte limit for short APDUs.
    #[error("Data length {0} exceeds maximum APDU size 255")]
    ShortApduTooLong(usize),
    /// APDU length exceeds the device capability.
    #[error("APDU length exceeds YubiKey capability")]
    ExtendedApduTooLong,
}

/// Errors returned by smart card operations.
#[derive(Debug, Error)]
pub enum SmartCardError {
    /// The device returned a non-success status word.
    #[error("APDU error: SW=0x{sw:04X}")]
    Apdu {
        /// Response data preceding the status word.
        data: Vec<u8>,
        /// The status word returned by the card.
        sw: u16,
    },
    /// The requested application is not available on the device.
    #[error("Application not available")]
    ApplicationNotAvailable,
    /// The operation is not supported.
    #[error("Not supported: {0}")]
    NotSupported(String),
    /// The provided data is invalid.
    #[error("Invalid data: {0}")]
    InvalidData(String),
    /// The session or device is in an invalid state.
    #[error("Invalid state: {0}")]
    InvalidState(String),
    /// An underlying transport error occurred.
    #[error("Transport error: {0}")]
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl From<ApduError> for SmartCardError {
    fn from(e: ApduError) -> Self {
        SmartCardError::InvalidData(e.to_string())
    }
}

impl From<crate::scp::ScpError> for SmartCardError {
    fn from(e: crate::scp::ScpError) -> Self {
        use crate::scp::ScpError;
        match e {
            ScpError::WrongMac | ScpError::ResponseTooShort => {
                SmartCardError::InvalidState(e.to_string())
            }
            _ => SmartCardError::InvalidData(e.to_string()),
        }
    }
}

impl SmartCardError {
    /// Get the status word if this is an APDU error.
    pub fn sw(&self) -> Option<u16> {
        match self {
            Self::Apdu { sw, .. } => Some(*sw),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Connection trait
// ---------------------------------------------------------------------------

/// Abstract smart card connection — send raw APDU bytes, get response + SW.
pub trait SmartCardConnection: crate::core::Connection<Error = SmartCardError> {
    /// Send a raw APDU and receive the response data and status word.
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError>;
    /// Return the transport type (USB or NFC) of this connection.
    fn transport(&self) -> Transport;
}

impl crate::core::Connection for Box<dyn SmartCardConnection + Send> {
    type Error = SmartCardError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl SmartCardConnection for Box<dyn SmartCardConnection + Send> {
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        (**self).send_and_receive(apdu)
    }
    fn transport(&self) -> Transport {
        (**self).transport()
    }
}

impl crate::core::Connection for Box<dyn SmartCardConnection + Send + Sync> {
    type Error = SmartCardError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl SmartCardConnection for Box<dyn SmartCardConnection + Send + Sync> {
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        (**self).send_and_receive(apdu)
    }
    fn transport(&self) -> Transport {
        (**self).transport()
    }
}

// ---------------------------------------------------------------------------
// APDU formatting (kept from original)
// ---------------------------------------------------------------------------

const SHORT_APDU_MAX_CHUNK: usize = 0xFF;

/// Format a short APDU (ISO 7816-4, case 1-4).
fn format_short_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: u8,
) -> Result<Vec<u8>, ApduError> {
    if data.len() > 0xFF {
        return Err(ApduError::ShortApduTooLong(data.len()));
    }
    let mut buf = Vec::with_capacity(5 + data.len() + 1);
    buf.extend_from_slice(&[cla, ins, p1, p2]);
    if !data.is_empty() {
        buf.push(data.len() as u8);
        buf.extend_from_slice(data);
    }
    if le > 0 {
        buf.push(le);
    } else if data.is_empty() {
        buf.push(0);
    }
    Ok(buf)
}

/// Format an extended APDU (ISO 7816-4 extended length).
fn format_extended_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: u16,
    max_apdu_size: usize,
) -> Result<Vec<u8>, ApduError> {
    let mut buf = Vec::with_capacity(7 + data.len() + 2);
    buf.extend_from_slice(&[cla, ins, p1, p2]);
    if !data.is_empty() {
        buf.push(0); // Extended length marker
        buf.push((data.len() >> 8) as u8);
        buf.push(data.len() as u8);
        buf.extend_from_slice(data);
    }
    if le > 0 {
        if data.is_empty() {
            buf.push(0); // 3-byte Le
        }
        buf.push((le >> 8) as u8);
        buf.push(le as u8);
    }
    if max_apdu_size > 0 && buf.len() > max_apdu_size {
        return Err(ApduError::ExtendedApduTooLong);
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// APDU format enum & max sizes
// ---------------------------------------------------------------------------

/// APDU encoding format: short (up to 255 bytes) or extended length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduFormat {
    /// Short APDU encoding (up to 255 bytes of data).
    Short,
    /// Extended length APDU encoding.
    Extended,
}

#[derive(Debug, Clone, Copy)]
enum MaxApduSize {
    Neo = 1390,
    Yk4 = 2038,
    Yk4_3 = 3062,
}

// ---------------------------------------------------------------------------
// INS constants
// ---------------------------------------------------------------------------

const INS_SELECT: u8 = 0xA4;
const P1_SELECT: u8 = 0x04;
const P2_SELECT: u8 = 0x00;
const INS_SEND_REMAINING: u8 = 0xC0;

// ---------------------------------------------------------------------------
// SmartCardProtocol
// ---------------------------------------------------------------------------

/// High-level smart card protocol handler.
///
/// Wraps a [`SmartCardConnection`] and handles APDU formatting, command
/// and response chaining, and optional SCP03 secure messaging.
pub struct SmartCardProtocol<C: SmartCardConnection> {
    connection: C,
    apdu_format: ApduFormat,
    max_apdu_size: usize,
    ins_send_remaining: u8,
    scp_state: Option<ScpState>,
    touch_workaround: bool,
    last_long_resp: Option<Instant>,
}

impl<C: SmartCardConnection> SmartCardProtocol<C> {
    /// Create a new protocol handler wrapping the given connection.
    pub fn new(connection: C) -> Self {
        Self {
            connection,
            apdu_format: ApduFormat::Short,
            max_apdu_size: MaxApduSize::Neo as usize,
            ins_send_remaining: INS_SEND_REMAINING,
            scp_state: None,
            touch_workaround: false,
            last_long_resp: None,
        }
    }

    /// Override the INS byte used when fetching remaining response data.
    pub fn with_ins_send_remaining(mut self, ins: u8) -> Self {
        self.ins_send_remaining = ins;
        self
    }

    /// Consume the protocol and return the underlying connection.
    pub fn into_connection(self) -> C {
        self.connection
    }

    /// Configure the protocol optimally for the given YubiKey version.
    pub fn configure(&mut self, version: Version) {
        self.configure_inner(version, false);
    }

    /// Configure with an option to force short APDUs.
    pub fn configure_force_short(&mut self, version: Version, force_short: bool) {
        self.configure_inner(version, force_short);
    }

    fn configure_inner(&mut self, version: Version, force_short: bool) {
        // Touch workaround for YK 4.2.0-4.2.6
        if self.connection.transport() == Transport::Usb
            && version >= Version(4, 2, 0)
            && version <= Version(4, 2, 6)
        {
            self.max_apdu_size = MaxApduSize::Yk4 as usize;
            if !force_short {
                self.apdu_format = ApduFormat::Extended;
            }
            self.touch_workaround = true;
            return;
        }

        if version.0 <= 3 {
            // YubiKey NEO — keep defaults
            return;
        }

        if self.connection.transport() == Transport::Usb && !force_short {
            self.apdu_format = ApduFormat::Extended;
        }
        self.max_apdu_size = if version >= Version(4, 3, 0) {
            MaxApduSize::Yk4_3 as usize
        } else {
            MaxApduSize::Yk4 as usize
        };
    }

    /// SELECT an application by AID.
    pub fn select(&mut self, aid: &[u8]) -> Result<Vec<u8>, SmartCardError> {
        log::debug!("Selecting AID: {}", crate::logging::hex_encode(aid));
        // Reset SCP state for SELECT
        self.scp_state = None;

        match self.send_apdu(0, INS_SELECT, P1_SELECT, P2_SELECT, aid) {
            Ok(resp) => Ok(resp),
            Err(SmartCardError::Apdu { sw, .. })
                if matches!(
                    Sw::from_u16(sw),
                    Some(
                        Sw::FileNotFound
                            | Sw::AppletSelectFailed
                            | Sw::InvalidInstruction
                            | Sw::WrongParametersP1P2
                    )
                ) =>
            {
                Err(SmartCardError::ApplicationNotAvailable)
            }
            Err(e) => Err(e),
        }
    }

    /// Send an APDU, handling chaining, SCP, and touch workaround.
    pub fn send_apdu(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, SmartCardError> {
        self.send_apdu_with_le(cla, ins, p1, p2, data, 0)
    }

    /// Send a pre-formatted APDU (raw bytes), handling response chaining only.
    /// Does NOT apply SCP wrapping or command chaining.
    pub fn send_raw_apdu(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        let (resp, sw) = self.connection.send_and_receive(apdu)?;
        self.read_chained_response(resp, sw)
    }

    /// Send an APDU with an explicit Le (expected response length).
    pub fn send_apdu_with_le(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: u16,
    ) -> Result<Vec<u8>, SmartCardError> {
        let (resp, sw) = if self.scp_state.is_some() {
            self.send_apdu_scp(cla, ins, p1, p2, data, le, true)?
        } else {
            self.send_apdu_raw(cla, ins, p1, p2, data, le)?
        };

        if sw != SW_OK {
            return Err(SmartCardError::Apdu { data: resp, sw });
        }
        Ok(resp)
    }

    /// Low-level: send a single APDU with command chaining and response chaining.
    /// No SCP wrapping.
    fn send_apdu_raw(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: u16,
    ) -> Result<(Vec<u8>, u16), SmartCardError> {
        // Touch workaround
        if self.touch_workaround
            && let Some(last) = self.last_long_resp
            && last.elapsed().as_secs_f64() < 2.0
        {
            // Send dummy APDU
            let _ = self.send_single_apdu(0, 0, 0, 0, &[], 0);
            self.last_long_resp = None;
        }

        // Command chaining for short APDUs
        let (resp, sw) =
            if self.apdu_format == ApduFormat::Short && data.len() > SHORT_APDU_MAX_CHUNK {
                self.send_chained(cla, ins, p1, p2, data, le as u8)?
            } else {
                self.send_single_apdu(cla, ins, p1, p2, data, le)?
            };

        // Response chaining
        let (resp, sw) = self.read_chained_response(resp, sw)?;

        // Touch workaround tracking
        if self.touch_workaround {
            self.last_long_resp = if resp.len() > 54 {
                Some(Instant::now())
            } else {
                None
            };
        }

        Ok((resp, sw))
    }

    /// Send with command chaining (short APDUs, split data into 255-byte chunks).
    fn send_chained(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: u8,
    ) -> Result<(Vec<u8>, u16), SmartCardError> {
        let mut remaining = data;
        while remaining.len() > SHORT_APDU_MAX_CHUNK {
            let (chunk, rest) = remaining.split_at(SHORT_APDU_MAX_CHUNK);
            remaining = rest;
            let apdu = format_short_apdu(0x10 | cla, ins, p1, p2, chunk, 0)?;
            let (_, sw) = self.connection.send_and_receive(&apdu)?;
            if sw != SW_OK {
                return Ok((Vec::new(), sw));
            }
        }
        let apdu = format_short_apdu(cla, ins, p1, p2, remaining, le)?;
        self.connection.send_and_receive(&apdu)
    }

    /// Format and send a single APDU (short or extended).
    fn send_single_apdu(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: u16,
    ) -> Result<(Vec<u8>, u16), SmartCardError> {
        let apdu = match self.apdu_format {
            ApduFormat::Short => format_short_apdu(cla, ins, p1, p2, data, le as u8)?,
            ApduFormat::Extended => {
                format_extended_apdu(cla, ins, p1, p2, data, le, self.max_apdu_size)?
            }
        };
        self.connection.send_and_receive(&apdu)
    }

    /// Read response chaining (SW1 = 0x61).
    fn read_chained_response(
        &mut self,
        mut resp: Vec<u8>,
        mut sw: u16,
    ) -> Result<(Vec<u8>, u16), SmartCardError> {
        let mut buf = Vec::new();
        while (sw >> 8) as u8 == SW1_HAS_MORE_DATA {
            buf.extend_from_slice(&resp);
            let apdu = format_short_apdu(0, self.ins_send_remaining, 0, 0, &[], 0)?;
            let result = self.connection.send_and_receive(&apdu)?;
            resp = result.0;
            sw = result.1;
        }
        buf.extend_from_slice(&resp);
        Ok((buf, sw))
    }

    // -----------------------------------------------------------------------
    // SCP03 support
    // -----------------------------------------------------------------------

    /// Set the SCP state for encrypted messaging.
    pub fn set_scp_state(&mut self, state: ScpState) {
        log::debug!("SCP secure channel established");
        self.scp_state = Some(state);
    }

    /// Check if SCP is active.
    pub fn has_scp(&self) -> bool {
        self.scp_state.is_some()
    }

    /// Send an APDU through the SCP layer.
    fn send_apdu_scp(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        le: u16,
        encrypt: bool,
    ) -> Result<(Vec<u8>, u16), SmartCardError> {
        let scp = self.scp_state.as_mut().unwrap();
        let cla = cla | 0x04;

        let enc_data = if encrypt {
            scp.encrypt(data)?
        } else {
            data.to_vec()
        };

        // Build APDU for MAC calculation (always use extended format for long data)
        let mac_apdu = if enc_data.len() + 8 > SHORT_APDU_MAX_CHUNK {
            format_extended_apdu(
                cla,
                ins,
                p1,
                p2,
                &[&enc_data[..], &[0u8; 8]].concat(),
                0,
                MaxApduSize::Yk4_3 as usize,
            )?
        } else {
            match self.apdu_format {
                ApduFormat::Short => {
                    format_short_apdu(cla, ins, p1, p2, &[&enc_data[..], &[0u8; 8]].concat(), 0)?
                }
                ApduFormat::Extended => format_extended_apdu(
                    cla,
                    ins,
                    p1,
                    p2,
                    &[&enc_data[..], &[0u8; 8]].concat(),
                    0,
                    MaxApduSize::Yk4_3 as usize,
                )?,
            }
        };

        // Calculate MAC over the APDU (minus the 8 zero bytes placeholder)
        let mac = scp.mac(&mac_apdu[..mac_apdu.len() - 8])?;

        // Append MAC to encrypted data
        let full_data = [&enc_data[..], &mac[..]].concat();

        // Send the APDU with the original LE
        let (mut resp, sw) = self.send_apdu_raw(cla, ins, p1, p2, &full_data, le)?;

        // Un-MAC and decrypt response
        let scp = self.scp_state.as_mut().unwrap();
        if !resp.is_empty() {
            resp = scp.unmac(&resp, sw)?;
            if !resp.is_empty() {
                resp = scp.decrypt(&resp)?;
            }
        }

        Ok((resp, sw))
    }

    /// Send an SCP APDU without encrypting the data (for EXTERNAL AUTHENTICATE).
    pub fn send_apdu_scp_no_encrypt(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<(Vec<u8>, u16), SmartCardError> {
        self.send_apdu_scp(cla, ins, p1, p2, data, 0, false)
    }

    // -------------------------------------------------------------------
    // SCP03 initialization
    // -------------------------------------------------------------------

    /// Perform the SCP03 handshake and establish a secure channel.
    /// Returns the static DEK if provided in key params.
    pub fn init_scp03(
        &mut self,
        kvn: u8,
        key_enc: &[u8],
        key_mac: &[u8],
        key_dek: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, SmartCardError> {
        // 1. Generate host challenge
        let mut host_challenge = [0u8; 8];
        getrandom::fill(&mut host_challenge)
            .map_err(|e| SmartCardError::InvalidState(format!("RNG error: {e}")))?;

        // 2. INITIALIZE UPDATE
        let resp = self.send_apdu(0x80, 0x50, kvn, 0x00, &host_challenge)?;
        if resp.len() < 29 {
            return Err(SmartCardError::InvalidData(format!(
                "INITIALIZE UPDATE response too short: {} bytes",
                resp.len()
            )));
        }

        // 3. Parse response
        let card_challenge = &resp[13..21];
        let card_cryptogram = &resp[21..29];

        // 4. Derive session keys
        let mut context = Vec::with_capacity(16);
        context.extend_from_slice(&host_challenge);
        context.extend_from_slice(card_challenge);

        let key_senc: [u8; 16] = scp03_derive(key_enc, 0x04, &context, 0x80)?
            .as_slice()
            .try_into()
            .map_err(|_| SmartCardError::InvalidData("bad derive length".into()))?;
        let key_smac: [u8; 16] = scp03_derive(key_mac, 0x06, &context, 0x80)?
            .as_slice()
            .try_into()
            .map_err(|_| SmartCardError::InvalidData("bad derive length".into()))?;
        let key_srmac: [u8; 16] = scp03_derive(key_mac, 0x07, &context, 0x80)?
            .as_slice()
            .try_into()
            .map_err(|_| SmartCardError::InvalidData("bad derive length".into()))?;

        // 5. Verify card cryptogram
        let gen_card_crypto = scp03_derive(&key_smac, 0x00, &context, 0x40)?;
        if !bool::from(gen_card_crypto.ct_eq(card_cryptogram)) {
            return Err(SmartCardError::InvalidState(
                "Card cryptogram verification failed".into(),
            ));
        }

        // 6. Compute host cryptogram
        let host_cryptogram = scp03_derive(&key_smac, 0x01, &context, 0x40)?;

        // 7. Set SCP state
        let state = ScpState::new(key_senc, key_smac, key_srmac, None, None);
        self.set_scp_state(state);

        // 8. EXTERNAL AUTHENTICATE (MAC but no encryption)
        self.send_apdu_scp_no_encrypt(0x84, 0x82, 0x33, 0x00, &host_cryptogram)?;

        Ok(key_dek.map(|d| d.to_vec()))
    }

    // -------------------------------------------------------------------
    // SCP11 initialization
    // -------------------------------------------------------------------

    /// Perform the SCP11 key agreement and establish a secure channel.
    ///
    /// - `kid`: SCP key ID (`0x11` for 11a, `0x13` for 11b, `0x15` for 11c)
    /// - `kvn`: key version number
    /// - `pk_sd_ecka`: card's static public key (uncompressed SEC1 point)
    /// - `sk_oce_ecka`: OCE private key (raw 32-byte scalar, for 11a/c)
    /// - `certificates`: DER-encoded certificate chain, leaf-last (for 11a/c)
    /// - `oce_ref`: `(kid, kvn)` for the OCE key reference (for 11a/c)
    pub fn init_scp11(
        &mut self,
        kid: u8,
        kvn: u8,
        pk_sd_ecka: &[u8],
        sk_oce_ecka: Option<&[u8]>,
        certificates: &[&[u8]],
        oce_ref: Option<(u8, u8)>,
    ) -> Result<Option<Vec<u8>>, SmartCardError> {
        use crate::tlv::tlv_encode;
        use elliptic_curve::sec1::FromEncodedPoint;
        use p256::{
            EncodedPoint, PublicKey, SecretKey,
            elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
        };

        // SCP11 params byte
        let params = match kid {
            0x11 => 0x01u8, // SCP11a
            0x13 => 0x00u8, // SCP11b
            0x15 => 0x03u8, // SCP11c
            _ => {
                return Err(SmartCardError::InvalidData(format!(
                    "Unknown SCP11 KID: 0x{kid:02X}"
                )));
            }
        };
        let is_scp11b = kid == 0x13;

        // 2. Upload certificate chain for SCP11a/c
        if !is_scp11b {
            let (oce_kid, oce_kvn) = oce_ref.ok_or_else(|| {
                SmartCardError::InvalidState("OCE key reference required for SCP11a/c".into())
            })?;
            let n = certificates.len();
            for (i, cert) in certificates.iter().enumerate() {
                let p2 = if i < n - 1 { oce_kid | 0x80 } else { oce_kid };
                self.send_apdu(0x80, 0x2A, oce_kvn, p2, cert)?;
            }
        }

        // Generate host ephemeral P-256 key pair.
        // Use SecretKey so the scalar remains available for a second ECDH in SCP11b.
        let eph_sk = SecretKey::random(&mut OsRng);
        let eph_pk = eph_sk.public_key();
        let epk_bytes = eph_pk.to_encoded_point(false);

        // Build key agreement TLV data
        let key_usage: u8 = 0x3C;
        let key_type: u8 = 0x88;
        let key_len: u8 = 0x10;

        let inner_a6 = {
            let mut v = Vec::new();
            v.extend_from_slice(&tlv_encode(0x90, &[0x11, params]));
            v.extend_from_slice(&tlv_encode(0x95, &[key_usage]));
            v.extend_from_slice(&tlv_encode(0x80, &[key_type]));
            v.extend_from_slice(&tlv_encode(0x81, &[key_len]));
            v
        };
        let a6 = tlv_encode(0xA6, &inner_a6);
        let tag_5f49 = tlv_encode(0x5F49, epk_bytes.as_bytes());

        let mut key_agreement_data = Vec::new();
        key_agreement_data.extend_from_slice(&a6);
        key_agreement_data.extend_from_slice(&tag_5f49);

        // Send key agreement
        let ins = if is_scp11b { 0x88 } else { 0x82 };
        let resp = self.send_apdu(0x80, ins, kvn, kid, &key_agreement_data)?;

        // Parse response TLVs
        let mut epk_sd_ecka_bytes: Option<&[u8]> = None;
        let mut epk_sd_ecka_tlv_range: Option<(usize, usize)> = None;
        let mut receipt_bytes: Option<&[u8]> = None;
        {
            let mut offset = 0;
            while offset < resp.len() {
                let (tag, val_off, val_len, end) = crate::tlv::tlv_parse(&resp, offset)
                    .map_err(|e| SmartCardError::InvalidData(format!("TLV parse error: {e}")))?;
                match tag {
                    0x5F49 => {
                        epk_sd_ecka_bytes = Some(&resp[val_off..val_off + val_len]);
                        epk_sd_ecka_tlv_range = Some((offset, end));
                    }
                    0x86 => receipt_bytes = Some(&resp[val_off..val_off + val_len]),
                    _ => {}
                }
                offset = end;
            }
        }
        let epk_sd_ecka_bytes = epk_sd_ecka_bytes.ok_or_else(|| {
            SmartCardError::InvalidData("Missing ephemeral public key (5F49) in response".into())
        })?;
        let (tlv_start, tlv_end) = epk_sd_ecka_tlv_range.unwrap();
        let receipt = receipt_bytes
            .ok_or_else(|| SmartCardError::InvalidData("Missing receipt (86) in response".into()))?
            .to_vec();

        // key_agreement_data = request data + card's ephemeral public key TLV
        key_agreement_data.extend_from_slice(&resp[tlv_start..tlv_end]);

        // Perform ECDH
        let card_eph_point = EncodedPoint::from_bytes(epk_sd_ecka_bytes)
            .map_err(|e| SmartCardError::InvalidData(format!("Invalid card ephemeral key: {e}")))?;
        let card_eph_pk = Option::<PublicKey>::from(PublicKey::from_encoded_point(&card_eph_point))
            .ok_or_else(|| SmartCardError::InvalidData("Card ephemeral key not on curve".into()))?;

        let card_static_point = EncodedPoint::from_bytes(pk_sd_ecka)
            .map_err(|e| SmartCardError::InvalidData(format!("Invalid card static key: {e}")))?;
        let card_static_pk =
            Option::<PublicKey>::from(PublicKey::from_encoded_point(&card_static_point))
                .ok_or_else(|| {
                    SmartCardError::InvalidData("Card static key not on curve".into())
                })?;

        // shared1 = ECDH(eph_sk, card_eph_pk)
        let shared1 =
            p256::ecdh::diffie_hellman(eph_sk.to_nonzero_scalar(), card_eph_pk.as_affine());

        // shared2: for SCP11b reuse eph_sk, for 11a/c use the static OCE key
        let shared2 = if is_scp11b {
            p256::ecdh::diffie_hellman(eph_sk.to_nonzero_scalar(), card_static_pk.as_affine())
        } else {
            let oce_scalar = sk_oce_ecka.ok_or_else(|| {
                SmartCardError::InvalidState("OCE private key required for SCP11a/c".into())
            })?;
            let oce_sk = SecretKey::from_slice(oce_scalar).map_err(|e| {
                SmartCardError::InvalidData(format!("Invalid OCE private key: {e}"))
            })?;
            p256::ecdh::diffie_hellman(oce_sk.to_nonzero_scalar(), card_static_pk.as_affine())
        };

        // Concatenate shared secrets
        let mut shared_secret = Vec::with_capacity(64);
        shared_secret.extend_from_slice(shared1.raw_secret_bytes().as_slice());
        shared_secret.extend_from_slice(shared2.raw_secret_bytes().as_slice());

        // X9.63 KDF: derive 80 bytes (5 × 16-byte keys)
        let shared_info = [key_usage, key_type, key_len];
        let keybytes = x963_kdf(&shared_secret, &shared_info, 80);

        // Verify receipt: CMAC(keys[0], key_agreement_data) == receipt
        let receipt_key = &keybytes[0..16];
        let expected_receipt = aes_cmac(receipt_key, &key_agreement_data)?;
        if !bool::from(expected_receipt[..receipt.len()].ct_eq(&receipt)) {
            return Err(SmartCardError::InvalidState(
                "SCP11 receipt verification failed".into(),
            ));
        }

        // Session keys (keys[1..4]) + DEK (keys[4])
        let key_senc: [u8; 16] = keybytes[16..32].try_into().unwrap();
        let key_smac: [u8; 16] = keybytes[32..48].try_into().unwrap();
        let key_srmac: [u8; 16] = keybytes[48..64].try_into().unwrap();
        let key_dek: [u8; 16] = keybytes[64..80].try_into().unwrap();

        // For SCP11 the MAC chain starts with the receipt
        let state = ScpState::new(key_senc, key_smac, key_srmac, Some(receipt), Some(1));
        self.set_scp_state(state);

        Ok(Some(key_dek.to_vec()))
    }

    /// Initialize SCP using key parameters. Returns the DEK if available.
    pub fn init_scp(
        &mut self,
        params: &crate::scp::ScpKeyParams,
    ) -> Result<Option<Vec<u8>>, SmartCardError> {
        match params {
            crate::scp::ScpKeyParams::Scp03 {
                kvn,
                key_enc,
                key_mac,
                key_dek,
            } => self.init_scp03(
                *kvn,
                key_enc.as_slice(),
                key_mac.as_slice(),
                key_dek.as_ref().map(|v| v.as_slice()),
            ),
            crate::scp::ScpKeyParams::Scp11b {
                kid,
                kvn,
                pk_sd_ecka,
            } => self.init_scp11(*kid, *kvn, pk_sd_ecka, None, &[], None),
            crate::scp::ScpKeyParams::Scp11ac {
                kid,
                kvn,
                pk_sd_ecka,
                sk_oce_ecka,
                certificates,
                oce_ref,
            } => {
                let cert_refs: Vec<&[u8]> = certificates.iter().map(|c| c.as_slice()).collect();
                self.init_scp11(
                    *kid,
                    *kvn,
                    pk_sd_ecka,
                    Some(sk_oce_ecka.as_slice()),
                    &cert_refs,
                    *oce_ref,
                )
            }
        }
    }
}

/// SCP03 key derivation using AES-CMAC.
fn scp03_derive(key: &[u8], t: u8, context: &[u8], l: u16) -> Result<Vec<u8>, ScpError> {
    if l != 0x80 && l != 0x40 {
        return Err(ScpError::InvalidDerivationLength);
    }
    let mut input = vec![0u8; 11];
    input.push(t);
    input.push(0);
    input.push((l >> 8) as u8);
    input.push(l as u8);
    input.push(1);
    input.extend_from_slice(context);

    let result = aes_cmac(key, &input)?;
    Ok(result[..(l as usize / 8)].to_vec())
}
