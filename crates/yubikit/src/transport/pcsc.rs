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

use ::pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::ffi::CString;

use crate::log_traffic;
use crate::smartcard::{SmartCardConnection, SmartCardError, Transport};

#[derive(Debug, thiserror::Error)]
pub enum PcscError {
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] ::pcsc::Error),
    #[error("Invalid reader name")]
    InvalidReaderName,
    #[error("Connection is closed")]
    ConnectionClosed,
}

impl PcscError {
    /// Returns true if this error indicates the card is temporarily absent.
    pub fn is_no_card(&self) -> bool {
        matches!(
            self,
            PcscError::Pcsc(::pcsc::Error::NoSmartcard | ::pcsc::Error::RemovedCard)
        )
    }
}

impl From<PcscError> for SmartCardError {
    fn from(e: PcscError) -> Self {
        SmartCardError::Transport(Box::new(e))
    }
}

/// List available PC/SC reader names.
pub fn list_readers() -> Result<Vec<String>, PcscError> {
    let ctx = Context::establish(Scope::User)?;
    let len = ctx.list_readers_len()?;
    let mut buf = vec![0u8; len];
    let names: Vec<String> = ctx
        .list_readers(&mut buf)?
        .map(|r| r.to_string_lossy().into_owned())
        .collect();
    Ok(names)
}

/// A connection to a smart card via PC/SC.
pub struct PcscSmartCardConnection {
    card: Option<Card>,
    reader_name: String,
    transport: Transport,
}

impl std::fmt::Debug for PcscSmartCardConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcscSmartCardConnection")
            .field("reader_name", &self.reader_name)
            .finish_non_exhaustive()
    }
}

impl PcscSmartCardConnection {
    /// Connect to a reader, optionally using exclusive mode.
    pub fn new(reader_name: &str, exclusive: bool) -> Result<Self, PcscError> {
        log_traffic!("Opening PCSC connection to '{}'", reader_name);
        let ctx = Context::establish(Scope::User)?;
        let reader = CString::new(reader_name).map_err(|_| PcscError::InvalidReaderName)?;
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        let card = ctx.connect(&reader, share_mode, Protocols::ANY)?;
        log_traffic!("PCSC connection opened to '{}'", reader_name);
        Ok(Self {
            card: Some(card),
            reader_name: reader_name.to_owned(),
            transport: Transport::Usb,
        })
    }

    /// Set the transport type (USB or NFC).
    pub fn set_transport(&mut self, transport: Transport) {
        self.transport = transport;
    }

    /// Get the ATR (Answer-To-Reset) of the connected card.
    pub fn get_atr(&self) -> Result<Vec<u8>, PcscError> {
        let card = self.card.as_ref().ok_or(PcscError::ConnectionClosed)?;
        Ok(card.get_attribute_owned(::pcsc::Attribute::AtrString)?)
    }

    /// Transmit an APDU command and return the response bytes.
    pub fn transmit(&self, apdu: &[u8]) -> Result<Vec<u8>, PcscError> {
        let card = self.card.as_ref().ok_or(PcscError::ConnectionClosed)?;
        let mut resp_buf = vec![0u8; 65538];
        let resp = card.transmit(apdu, &mut resp_buf)?;
        Ok(resp.to_vec())
    }

    /// Disconnect from the card.
    pub fn disconnect(&mut self) -> Result<(), PcscError> {
        if let Some(card) = self.card.take() {
            log_traffic!("Closing PCSC connection to '{}'", self.reader_name);
            card.disconnect(::pcsc::Disposition::ResetCard)
                .map_err(|(_, e)| PcscError::Pcsc(e))?;
        }
        Ok(())
    }

    /// Connect (or reconnect) to the card.
    pub fn connect(&mut self, exclusive: bool) -> Result<(), PcscError> {
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        if let Some(card) = self.card.as_mut() {
            card.reconnect(share_mode, Protocols::ANY, ::pcsc::Disposition::ResetCard)?;
        } else {
            let ctx = Context::establish(Scope::User)?;
            let reader = CString::new(self.reader_name.as_str())
                .map_err(|_| PcscError::InvalidReaderName)?;
            let card = ctx.connect(&reader, share_mode, Protocols::ANY)?;
            self.card = Some(card);
        }
        Ok(())
    }

    /// Reconnect to the card.
    pub fn reconnect(&mut self, exclusive: bool) -> Result<(), PcscError> {
        let card = self.card.as_mut().ok_or(PcscError::ConnectionClosed)?;
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        card.reconnect(share_mode, Protocols::ANY, ::pcsc::Disposition::ResetCard)?;
        Ok(())
    }
}

impl SmartCardConnection for PcscSmartCardConnection {
    fn send_and_receive(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        use crate::logging::hex_encode;
        log_traffic!("SEND: {}", hex_encode(apdu));
        let resp = self.transmit(apdu).map_err(SmartCardError::from)?;
        if resp.len() < 2 {
            return Err(SmartCardError::BadResponse(
                "Response too short (no status word)".into(),
            ));
        }
        let sw = ((resp[resp.len() - 2] as u16) << 8) | (resp[resp.len() - 1] as u16);
        let data = resp[..resp.len() - 2].to_vec();
        log_traffic!("RECV: {} SW={:04x}", hex_encode(&data), sw);
        Ok((data, sw))
    }

    fn transport(&self) -> Transport {
        self.transport
    }

    fn close(&mut self) {
        let _ = self.disconnect();
    }
}

impl Drop for PcscSmartCardConnection {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
