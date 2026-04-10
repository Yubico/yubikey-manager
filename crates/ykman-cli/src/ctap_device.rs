//! CtapDevice adapters for YubiKey connection types.
//!
//! Provides adapters that implement [`fido2_client::ctap::CtapDevice`] for HID
//! and SmartCard connections, enabling use of the fido2 crate's CTAP2 protocol support.

use std::cell::RefCell;

use fido2_client::ctap::{self, CtapDevice, CtapError, CtapStatus};
use yubikit::fido::FidoConnection;
use yubikit::smartcard::{SmartCardConnection, SmartCardError, SmartCardProtocol};
use yubikit::transport::ctaphid::HidFidoConnection;

const AID_FIDO: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
const SW_KEEPALIVE: u16 = 0x9100;

/// CtapDevice adapter for HID FIDO connections.
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
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        self.conn
            .call_with_keepalive(cmd, data, on_keepalive, cancel)
            .map_err(|e| CtapError::TransportError(e.to_string()))
    }

    fn capabilities(&self) -> u8 {
        self.conn.capabilities().raw()
    }

    fn close(&mut self) {
        self.conn.close();
    }
}

/// CtapDevice adapter for SmartCard connections (FIDO over NFC/SCP).
///
/// Uses [`RefCell`] to bridge [`CtapDevice`]'s `&self` with the protocol's `&mut self`.
/// Implements the NFCCTAP protocol for CBOR framing with keepalive/cancel support.
pub struct SmartCardCtapDevice<C: SmartCardConnection> {
    protocol: RefCell<SmartCardProtocol<C>>,
    capabilities: u8,
}

impl<C: SmartCardConnection> SmartCardCtapDevice<C> {
    /// Open a FIDO device over SmartCard.
    pub fn new(connection: C) -> Result<Self, CtapError> {
        let mut protocol = SmartCardProtocol::new(connection);
        let resp = protocol
            .select(AID_FIDO)
            .map_err(|e| CtapError::TransportError(format!("FIDO applet select failed: {e}")))?;
        Self::init(protocol, &resp)
    }

    /// Open a FIDO device over SmartCard with SCP.
    pub fn new_with_scp(
        connection: C,
        scp_key_params: &yubikit::scp::ScpKeyParams,
    ) -> Result<Self, CtapError> {
        let mut protocol = SmartCardProtocol::new(connection);
        let resp = protocol
            .select(AID_FIDO)
            .map_err(|e| CtapError::TransportError(format!("FIDO applet select failed: {e}")))?;
        protocol
            .init_scp(scp_key_params)
            .map_err(|e| CtapError::TransportError(format!("SCP init failed: {e}")))?;
        Self::init(protocol, &resp)
    }

    fn init(protocol: SmartCardProtocol<C>, select_resp: &[u8]) -> Result<Self, CtapError> {
        let mut capabilities = 0u8;
        if select_resp == b"U2F_V2" {
            capabilities |= ctap::capability::NMSG;
        }

        let protocol = RefCell::new(protocol);

        // Probe for CTAP2 via GET_INFO
        {
            let mut proto = protocol.borrow_mut();
            if proto.send_apdu(0x80, 0x10, 0x80, 0x00, b"\x04").is_ok() {
                capabilities |= ctap::capability::CBOR;
            } else if capabilities == 0 {
                return Err(CtapError::TransportError("Unsupported device".to_string()));
            }
        }

        Ok(Self {
            protocol,
            capabilities,
        })
    }

    /// Consume the adapter and return the underlying connection.
    pub fn into_connection(self) -> C {
        self.protocol.into_inner().into_connection()
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

        let mut protocol = self.protocol.borrow_mut();
        match protocol.send_apdu(cla, ins, p1, p2, data) {
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
            Err(e) => Err(CtapError::TransportError(e.to_string())),
        }
    }

    fn call_cbor(
        &self,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        let resp = {
            let mut protocol = self.protocol.borrow_mut();
            match protocol.send_apdu(0x80, 0x10, 0x80, 0x00, data) {
                Ok(resp) => return Ok(resp),
                Err(SmartCardError::Apdu { data, sw }) if sw == SW_KEEPALIVE => data,
                Err(SmartCardError::Apdu { sw, .. }) => {
                    return Err(CtapError::TransportError(format!(
                        "NFCCTAP error: SW={sw:04X}"
                    )));
                }
                Err(e) => return Err(CtapError::TransportError(e.to_string())),
            }
        };

        // Keepalive loop with dedup
        let mut last_ka: Option<u8> = None;
        if !resp.is_empty() {
            last_ka = Some(resp[0]);
            on_keepalive(resp[0]);
        }

        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));

            let p1 = if cancel.is_some_and(|f| f()) {
                0x11
            } else {
                0x00
            };

            let mut protocol = self.protocol.borrow_mut();
            match protocol.send_apdu(0x80, 0x11, p1, 0x00, &[]) {
                Ok(resp) => return Ok(resp),
                Err(SmartCardError::Apdu { data, sw }) if sw == SW_KEEPALIVE => {
                    if let Some(&status) = data.first()
                        && last_ka != Some(status)
                    {
                        last_ka = Some(status);
                        on_keepalive(status);
                    }
                }
                Err(SmartCardError::Apdu { sw, .. }) => {
                    return Err(CtapError::TransportError(format!(
                        "NFCCTAP error: SW={sw:04X}"
                    )));
                }
                Err(e) => return Err(CtapError::TransportError(e.to_string())),
            }
        }
    }
}

impl<C: SmartCardConnection> CtapDevice for SmartCardCtapDevice<C> {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        match cmd {
            ctap::cmd::CBOR => self.call_cbor(data, on_keepalive, cancel),
            ctap::cmd::MSG => self.call_apdu(data),
            _ => Err(CtapError::StatusError(CtapStatus::InvalidCommand)),
        }
    }

    fn capabilities(&self) -> u8 {
        self.capabilities
    }
}

/// Enum wrapping both FIDO device types for use with generic `Ctap2<D>`.
pub enum FidoDevice {
    Hid(HidCtapDevice),
    SmartCard(SmartCardCtapDevice<yubikit::transport::pcsc::PcscSmartCardConnection>),
}

impl CtapDevice for FidoDevice {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        match self {
            Self::Hid(d) => d.call(cmd, data, on_keepalive, cancel),
            Self::SmartCard(d) => d.call(cmd, data, on_keepalive, cancel),
        }
    }

    fn capabilities(&self) -> u8 {
        match self {
            Self::Hid(d) => d.capabilities(),
            Self::SmartCard(d) => d.capabilities(),
        }
    }

    fn close(&mut self) {
        match self {
            Self::Hid(d) => d.close(),
            Self::SmartCard(_) => {}
        }
    }
}
