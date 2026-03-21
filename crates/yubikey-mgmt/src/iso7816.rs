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

use std::fmt;
use std::time::Instant;

use thiserror::Error;

use crate::scp::ScpState;

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// 3-digit firmware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u8, pub u8, pub u8);

impl Version {
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(
            data.first().copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
        )
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

// ---------------------------------------------------------------------------
// AID — YubiKey application identifiers
// ---------------------------------------------------------------------------

pub struct Aid;

impl Aid {
    pub const OTP: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];
    pub const MANAGEMENT: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
    pub const OPENPGP: &[u8] = &[0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
    pub const OATH: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
    pub const PIV: &[u8] = &[0xa0, 0x00, 0x00, 0x03, 0x08];
    pub const FIDO: &[u8] = &[0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
    pub const HSMAUTH: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];
    pub const SECURE_DOMAIN: &[u8] = &[0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
}

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

/// Well-known ISO 7816 status words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Sw {
    NoInputData = 0x6285,
    VerifyFailNoRetry = 0x63C0,
    MemoryFailure = 0x6581,
    WrongLength = 0x6700,
    SecurityConditionNotSatisfied = 0x6982,
    AuthMethodBlocked = 0x6983,
    DataInvalid = 0x6984,
    ConditionsNotSatisfied = 0x6985,
    CommandNotAllowed = 0x6986,
    IncorrectParameters = 0x6A80,
    FunctionNotSupported = 0x6A81,
    FileNotFound = 0x6A82,
    RecordNotFound = 0x6A83,
    NoSpace = 0x6A84,
    ReferenceDataNotFound = 0x6A88,
    AppletSelectFailed = 0x6999,
    WrongParametersP1P2 = 0x6B00,
    InvalidInstruction = 0x6D00,
    ClassNotSupported = 0x6E00,
    CommandAborted = 0x6F00,
    Ok = 0x9000,
}

impl Sw {
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

pub const SW_OK: u16 = 0x9000;
const SW1_HAS_MORE_DATA: u8 = 0x61;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ApduError {
    #[error("Data length {0} exceeds maximum APDU size 255")]
    ShortApduTooLong(usize),
    #[error("APDU length exceeds YubiKey capability")]
    ExtendedApduTooLong,
}

#[derive(Debug, Error)]
pub enum SmartCardError {
    #[error("APDU error: SW=0x{sw:04X}")]
    Apdu { data: Vec<u8>, sw: u16 },
    #[error("Application not available")]
    ApplicationNotAvailable,
    #[error("Transport error: {0}")]
    Transport(Box<dyn std::error::Error + Send + Sync>),
    #[error("APDU formatting error: {0}")]
    ApduFormat(#[from] ApduError),
    #[error("SCP error: {0}")]
    Scp(#[from] crate::scp::ScpError),
    #[error("Bad response: {0}")]
    BadResponse(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("Invalid PIN, {0} attempts remaining")]
    InvalidPin(u32),
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

/// Transport type for a smart card connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Usb,
    Nfc,
}

/// Abstract smart card connection — send raw APDU bytes, get response + SW.
pub trait SmartCardConnection {
    fn send_and_receive(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError>;
    fn transport(&self) -> Transport;
}

// ---------------------------------------------------------------------------
// APDU formatting (kept from original)
// ---------------------------------------------------------------------------

const SHORT_APDU_MAX_CHUNK: usize = 0xFF;

/// Format a short APDU (ISO 7816-4, case 1-4).
pub fn format_short_apdu(
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
pub fn format_extended_apdu(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduFormat {
    Short,
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
/// Wraps a [`SmartCardConnection`] and handles:
/// - APDU formatting (short vs extended)
/// - Command chaining (splitting large payloads)
/// - Response chaining (reading continuation data)
/// - Touch workaround for YK 4.2.0–4.2.6
/// - SCP03 secure messaging
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

    pub fn with_ins_send_remaining(mut self, ins: u8) -> Self {
        self.ins_send_remaining = ins;
        self
    }

    /// Get reference to the underlying connection.
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// Get mutable reference to the underlying connection.
    pub fn connection_mut(&mut self) -> &mut C {
        &mut self.connection
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
        let (resp, sw) = if self.scp_state.is_some() {
            self.send_apdu_scp(cla, ins, p1, p2, data, true)?
        } else {
            self.send_apdu_raw(cla, ins, p1, p2, data, 0)?
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
        if self.touch_workaround {
            if let Some(last) = self.last_long_resp {
                if last.elapsed().as_secs_f64() < 2.0 {
                    // Send dummy APDU
                    let _ = self.send_single_apdu(0, 0, 0, 0, &[], 0);
                    self.last_long_resp = None;
                }
            }
        }

        // Command chaining for short APDUs
        let (resp, sw) = if self.apdu_format == ApduFormat::Short
            && data.len() > SHORT_APDU_MAX_CHUNK
        {
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
        &self,
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
            let apdu =
                format_short_apdu(0x10 | cla, ins, p1, p2, chunk, 0)?;
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
        &self,
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
        &self,
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
        encrypt: bool,
    ) -> Result<(Vec<u8>, u16), SmartCardError> {
        let scp = self.scp_state.as_mut().unwrap();
        let cla = cla | 0x04;

        let enc_data = if encrypt && !data.is_empty() {
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
                ApduFormat::Short => format_short_apdu(
                    cla,
                    ins,
                    p1,
                    p2,
                    &[&enc_data[..], &[0u8; 8]].concat(),
                    0,
                )?,
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

        // Send the APDU
        let (mut resp, sw) = self.send_apdu_raw(cla, ins, p1, p2, &full_data, 0)?;

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
        self.send_apdu_scp(cla, ins, p1, p2, data, false)
    }
}
