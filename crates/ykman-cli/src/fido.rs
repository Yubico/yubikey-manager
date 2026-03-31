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

//! FIDO CLI commands and CtapDevice adapters.
//!
//! Provides adapters that implement `fido2::ctap::CtapDevice` for ykman's
//! connection types, enabling use of the fido2 crate's CTAP2 protocol support.

use std::cell::RefCell;

use fido2::ctap::{CtapDevice, CtapError};
use yubikit::smartcard::{SmartCardConnection, SmartCardProtocol};
use yubikit::transport::ctaphid::HidFidoConnection;

#[allow(dead_code)]
const AID_FIDO: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
#[allow(dead_code)]
const SW_SUCCESS: (u8, u8) = (0x90, 0x00);
#[allow(dead_code)]
const SW_UPDATE: (u8, u8) = (0x91, 0x00);
#[allow(dead_code)]
const SW1_MORE_DATA: u8 = 0x61;

/// CtapDevice adapter for HidFidoConnection.
///
/// Thin wrapper that delegates to the existing CTAP HID implementation.
pub struct HidCtapDevice {
    conn: HidFidoConnection,
}

impl HidCtapDevice {
    pub fn new(conn: HidFidoConnection) -> Self {
        Self { conn }
    }

    pub fn into_connection(self) -> HidFidoConnection {
        self.conn
    }
}

impl CtapDevice for HidCtapDevice {
    fn call(
        &self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<Vec<u8>, CtapError> {
        self.conn
            .call_with_keepalive(cmd, data, on_keepalive)
            .map_err(|e| CtapError::TransportError(e.to_string()))
    }

    fn capabilities(&self) -> u8 {
        self.conn.capabilities().raw()
    }

    fn close(&mut self) {
        self.conn.close();
    }
}

/// CtapDevice adapter for SmartCardProtocol (FIDO over NFC/SCP).
///
/// Uses RefCell to bridge CtapDevice's `&self` requirement with
/// SmartCardProtocol's `&mut self` methods. Implements the NFCCTAP
/// protocol for framing CTAP commands as ISO 7816 APDUs.
#[allow(dead_code)]
pub struct SmartCardCtapDevice<C: SmartCardConnection> {
    protocol: RefCell<SmartCardProtocol<C>>,
    capabilities: u8,
}

#[allow(dead_code)]
impl<C: SmartCardConnection> SmartCardCtapDevice<C> {
    /// Create a new adapter, selecting the FIDO applet and probing for CTAP2.
    pub fn open(protocol: SmartCardProtocol<C>) -> Result<Self, CtapError> {
        let mut dev = Self {
            protocol: RefCell::new(protocol),
            capabilities: 0,
        };
        dev.select()?;

        // Probe for CTAP2 via GET_INFO
        match dev.call_cbor(b"\x04", &mut |_| {}) {
            Ok(_) => dev.capabilities |= fido2::ctap::capability::CBOR,
            Err(_) => {
                if dev.capabilities == 0 {
                    return Err(CtapError::TransportError("Unsupported device".to_string()));
                }
            }
        }

        Ok(dev)
    }

    /// Consume the adapter and return the underlying protocol.
    pub fn into_protocol(self) -> SmartCardProtocol<C> {
        self.protocol.into_inner()
    }

    fn transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8), CtapError> {
        let proto = self.protocol.borrow_mut();
        let (data, sw) = proto.connection().send_and_receive(apdu).map_err(
            |e: yubikit::smartcard::SmartCardError| CtapError::TransportError(e.to_string()),
        )?;
        let sw1 = (sw >> 8) as u8;
        let sw2 = (sw & 0xFF) as u8;
        Ok((data, sw1, sw2))
    }

    fn select(&mut self) -> Result<(), CtapError> {
        let (resp, sw1, sw2) = self.chain_apdus(0x00, 0xA4, 0x04, 0x00, AID_FIDO)?;
        if (sw1, sw2) != SW_SUCCESS {
            return Err(CtapError::TransportError(format!(
                "FIDO applet selection failed: SW={sw1:02X}{sw2:02X}"
            )));
        }
        if resp == b"U2F_V2" {
            self.capabilities |= fido2::ctap::capability::NMSG;
        }
        Ok(())
    }

    fn chain_apdus(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<(Vec<u8>, u8, u8), CtapError> {
        let mut remaining = data;

        while remaining.len() > 250 {
            let (chunk, rest) = remaining.split_at(250);
            remaining = rest;
            let mut apdu = vec![0x10 | cla, ins, p1, p2, chunk.len() as u8];
            apdu.extend_from_slice(chunk);
            let (_resp, sw1, sw2) = self.transmit(&apdu)?;
            if (sw1, sw2) != SW_SUCCESS {
                return Ok((_resp, sw1, sw2));
            }
        }

        let mut apdu = vec![cla, ins, p1, p2];
        if !remaining.is_empty() {
            apdu.push(remaining.len() as u8);
            apdu.extend_from_slice(remaining);
        }
        apdu.push(0x00); // Le
        let (mut resp, mut sw1, mut sw2) = self.transmit(&apdu)?;

        while sw1 == SW1_MORE_DATA {
            let get_resp = vec![0x00, 0xC0, 0x00, 0x00, sw2];
            let (more, s1, s2) = self.transmit(&get_resp)?;
            resp.extend_from_slice(&more);
            sw1 = s1;
            sw2 = s2;
        }

        Ok((resp, sw1, sw2))
    }

    fn call_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, CtapError> {
        if apdu.len() < 4 {
            return Err(CtapError::InvalidResponse("APDU too short".to_string()));
        }
        let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
        let data = if apdu.len() > 5 {
            &apdu[5..5 + apdu[4] as usize]
        } else {
            &[]
        };
        let (resp, sw1, sw2) = self.chain_apdus(cla, ins, p1, p2, data)?;
        let mut result = resp;
        result.push(sw1);
        result.push(sw2);
        Ok(result)
    }

    fn call_cbor(
        &self,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<Vec<u8>, CtapError> {
        let (mut resp, mut sw1, mut sw2) = self.chain_apdus(0x80, 0x10, 0x80, 0x00, data)?;

        while (sw1, sw2) == SW_UPDATE {
            if !resp.is_empty() {
                on_keepalive(resp[0]);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            let result = self.chain_apdus(0x80, 0x11, 0x00, 0x00, &[])?;
            resp = result.0;
            sw1 = result.1;
            sw2 = result.2;
        }

        if (sw1, sw2) != SW_SUCCESS {
            return Err(CtapError::TransportError(format!(
                "NFCCTAP error: SW={sw1:02X}{sw2:02X}"
            )));
        }

        Ok(resp)
    }
}

impl<C: SmartCardConnection> CtapDevice for SmartCardCtapDevice<C> {
    fn call(
        &self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
    ) -> Result<Vec<u8>, CtapError> {
        match cmd {
            fido2::ctap::cmd::CBOR => self.call_cbor(data, on_keepalive),
            fido2::ctap::cmd::MSG => self.call_apdu(data),
            _ => Err(CtapError::StatusError(
                fido2::ctap::CtapStatus::InvalidCommand,
            )),
        }
    }

    fn capabilities(&self) -> u8 {
        self.capabilities
    }

    fn close(&mut self) {
        // SmartCardProtocol handles cleanup on drop
    }
}
