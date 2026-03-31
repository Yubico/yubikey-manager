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
use fido2::ctap2::Ctap2;
use fido2::pin::ClientPin;
use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::smartcard::{SmartCardConnection, SmartCardProtocol};
use yubikit::transport::ctaphid::HidFidoConnection;

use crate::scp::{self, ScpParams};
use crate::util::CliError;

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

// --- CLI command implementations ---

/// Open a FIDO connection as a CtapDevice, preferring HID, falling back to SmartCard.
///
/// When SCP params are explicit, always uses SmartCard connection.
/// Otherwise tries HID first (USB direct), then SmartCard (NFC or USB CCID).
enum FidoDevice {
    Hid(HidCtapDevice),
    SmartCard(SmartCardCtapDevice<yubikit::transport::pcsc::PcscSmartCardConnection>),
}

impl FidoDevice {
    fn as_ctap_device(&self) -> &dyn CtapDevice {
        match self {
            Self::Hid(d) => d,
            Self::SmartCard(d) => d,
        }
    }
}

fn open_fido_device(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<FidoDevice, CliError> {
    if scp_params.is_explicit() {
        // SCP requires SmartCard transport
        let scp_config = scp::resolve_scp(dev, scp_params, Capability::FIDO2)?;
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        let mut protocol = SmartCardProtocol::new(conn);
        if let Some(params) = scp::to_scp_key_params(&scp_config) {
            protocol
                .init_scp(&params)
                .map_err(|e| CliError(format!("SCP authentication failed: {e}")))?;
        }
        SmartCardCtapDevice::open(protocol)
            .map(FidoDevice::SmartCard)
            .map_err(|e| CliError(format!("Failed to open FIDO over SmartCard: {e}")))
    } else if dev.open_fido().is_ok() {
        let conn = dev
            .open_fido()
            .map_err(|e| CliError(format!("Failed to open FIDO connection: {e}")))?;
        Ok(FidoDevice::Hid(HidCtapDevice::new(conn)))
    } else {
        // Fall back to SmartCard (NFC reader)
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        let protocol = SmartCardProtocol::new(conn);
        SmartCardCtapDevice::open(protocol)
            .map(FidoDevice::SmartCard)
            .map_err(|e| CliError(format!("Failed to open FIDO over SmartCard: {e}")))
    }
}

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let info = dev.info();
    let transport = dev.transport();

    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();

    // Check if FIDO2 is enabled
    let fido2_enabled = info
        .config
        .enabled_capabilities
        .get(&transport)
        .is_some_and(|caps: &Capability| caps.contains(Capability::FIDO2));

    if fido2_enabled {
        let ctap2 = Ctap2::new(ctap_dev, false)
            .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;
        let ctap_info = ctap2.info();

        // FIPS status
        if info.fips_capable.contains(Capability::FIDO2) {
            println!(
                "FIPS approved:  {}",
                if info.fips_approved.contains(Capability::FIDO2) {
                    "Yes"
                } else {
                    "No"
                }
            );
        }

        // AAGUID
        println!("AAGUID:         {}", ctap_info.aaguid);

        // PIN status
        let client_pin = ClientPin::new(&ctap2, None)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        if ctap_info.options.get("clientPin") == Some(&true) {
            if ctap_info.force_pin_change {
                println!(
                    "NOTE: The FIDO PIN is disabled and must be changed before it can be used!"
                );
            }
            match client_pin.get_pin_retries() {
                Ok((retries, power_cycle)) => {
                    if retries > 0 {
                        print!("PIN:            {retries} attempt(s) remaining");
                        if power_cycle.is_some_and(|pc| pc > 0) {
                            print!(
                                "\nPIN is temporarily blocked. \
                                 Remove and re-insert the YubiKey to unblock."
                            );
                        }
                        println!();
                    } else {
                        println!("PIN:            Blocked");
                    }
                }
                Err(e) => println!("PIN:            Error: {e}"),
            }
        } else {
            println!("PIN:            Not set");
        }

        // Minimum PIN length
        println!("Minimum PIN length: {}", ctap_info.min_pin_length);

        // Fingerprint status
        let bio_enroll = ctap_info.options.get("bioEnroll");
        match bio_enroll {
            Some(true) => match client_pin.get_uv_retries() {
                Ok(retries) => {
                    if retries > 0 {
                        println!("Fingerprints:   Registered, {retries} attempt(s) remaining");
                    } else {
                        println!("Fingerprints:   Registered, blocked until PIN is verified");
                    }
                }
                Err(e) => println!("Fingerprints:   Error: {e}"),
            },
            Some(false) => println!("Fingerprints:   Not registered"),
            None => {}
        }

        // Always Require UV
        if let Some(&always_uv) = ctap_info.options.get("alwaysUv") {
            println!(
                "Always Require UV: {}",
                if always_uv { "On" } else { "Off" }
            );
        }

        // Remaining discoverable credentials
        if let Some(remaining) = ctap_info.remaining_disc_creds {
            println!("Credential storage remaining: {remaining}");
        }

        // Enterprise Attestation
        if let Some(&ep) = ctap_info.options.get("ep") {
            println!(
                "Enterprise Attestation: {}",
                if ep { "Enabled" } else { "Disabled" }
            );
        }
    } else {
        // FIDO2 not enabled — check if supported
        let fido2_supported = info
            .supported_capabilities
            .get(&transport)
            .is_some_and(|caps: &Capability| caps.contains(Capability::FIDO2));
        if fido2_supported {
            println!("CTAP2:          Disabled");
            println!("PIN:            Disabled");
        } else {
            println!("CTAP2:          Not supported");
            println!("PIN:            Not supported");
        }
    }

    Ok(())
}
