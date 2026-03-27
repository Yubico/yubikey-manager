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

//! CTAP HID transport for FIDO devices.
//!
//! Implements the CTAP HID protocol framing used to communicate with FIDO2
//! authenticators over USB HID. This is distinct from the OTP HID protocol
//! which uses feature reports.

use hidapi::HidApi;

use crate::log_traffic;

const YUBICO_VID: u16 = 0x1050;
const USAGE_PAGE_FIDO: u16 = 0xF1D0;
const USAGE_FIDO: u16 = 0x0001;

const BROADCAST_CID: u32 = 0xFFFF_FFFF;
const TYPE_INIT: u8 = 0x80;

// CTAP HID packet header sizes
const INIT_HEADER_SIZE: usize = 7; // CID(4) + CMD(1) + LEN(2)
const CONT_HEADER_SIZE: usize = 5; // CID(4) + SEQ(1)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidCommand {
    Ping = 0x01,
    Msg = 0x03,
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3B,
    Error = 0x3F,
    VendorFirst = 0x40,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidStatus {
    Processing = 1,
    UpNeeded = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidError {
    InvalidCmd = 0x01,
    InvalidPar = 0x02,
    InvalidLen = 0x03,
    InvalidSeq = 0x04,
    MsgTimeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    Other = 0x7F,
}

impl CtapHidError {
    fn from_byte(b: u8) -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtapHidCapability(u8);

impl CtapHidCapability {
    pub const WINK: u8 = 0x01;
    pub const CBOR: u8 = 0x04;
    pub const NMSG: u8 = 0x08;

    pub fn has_cbor(self) -> bool {
        self.0 & Self::CBOR != 0
    }

    pub fn has_wink(self) -> bool {
        self.0 & Self::WINK != 0
    }

    pub fn raw(self) -> u8 {
        self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CtapHidTransportError {
    #[error("HID error: {0}")]
    Hid(#[from] hidapi::HidError),
    #[error("Invalid device path")]
    InvalidPath,
    #[error("Connection is closed")]
    ConnectionClosed,
    #[error("Wrong nonce in INIT response")]
    WrongNonce,
    #[error("Wrong channel in response")]
    WrongChannel,
    #[error("Wrong sequence number in response")]
    WrongSequence,
    #[error("CTAP HID error: {0:?}")]
    CtapHidError(CtapHidError),
    #[error("Invalid response")]
    InvalidResponse,
    #[error("Timeout")]
    Timeout,
}

/// Information about an enumerated FIDO HID device.
#[derive(Clone, Debug)]
pub struct FidoDeviceInfo {
    pub path: String,
    pub pid: u16,
    pub report_size_in: usize,
    pub report_size_out: usize,
}

/// List Yubico FIDO HID devices.
pub fn list_fido_devices() -> Result<Vec<FidoDeviceInfo>, CtapHidTransportError> {
    let api = HidApi::new()?;
    let mut devices = Vec::new();
    for dev in api.device_list() {
        if dev.vendor_id() == YUBICO_VID
            && dev.usage_page() == USAGE_PAGE_FIDO
            && dev.usage() == USAGE_FIDO
        {
            devices.push(FidoDeviceInfo {
                path: dev.path().to_string_lossy().into_owned(),
                pid: dev.product_id(),
                // hidapi doesn't directly expose report sizes from the descriptor.
                // FIDO HID spec uses 64-byte packets; this is the standard for all
                // USB FIDO devices including YubiKeys.
                report_size_in: 64,
                report_size_out: 64,
            });
        }
    }
    Ok(devices)
}

/// An open CTAP HID connection to a FIDO device.
///
/// Implements the CTAP HID framing protocol including channel allocation,
/// packet fragmentation, and keepalive handling.
pub struct FidoConnection {
    device: Option<hidapi::HidDevice>,
    channel_id: u32,
    packet_size: usize,
    device_version: (u8, u8, u8),
    capabilities: CtapHidCapability,
}

impl FidoConnection {
    /// Open a FIDO connection to the device at the given path.
    ///
    /// Performs CTAP HID INIT to allocate a channel.
    pub fn open(info: &FidoDeviceInfo) -> Result<Self, CtapHidTransportError> {
        log_traffic!("Opening FIDO connection to '{}'", info.path);
        let api = HidApi::new()?;
        let cpath = std::ffi::CString::new(info.path.as_str())
            .map_err(|_| CtapHidTransportError::InvalidPath)?;
        let device = api.open_path(&cpath)?;

        let mut conn = Self {
            device: Some(device),
            channel_id: BROADCAST_CID,
            packet_size: info.report_size_out,
            device_version: (0, 0, 0),
            capabilities: CtapHidCapability(0),
        };

        // Perform INIT to allocate a channel
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| CtapHidTransportError::InvalidResponse)?;
        let response = conn.call_raw(CtapHidCommand::Init as u8, &nonce)?;

        if response.len() < 17 {
            return Err(CtapHidTransportError::InvalidResponse);
        }
        if response[..8] != nonce {
            return Err(CtapHidTransportError::WrongNonce);
        }

        let channel_id = u32::from_be_bytes([response[8], response[9], response[10], response[11]]);
        let _u2fhid_version = response[12];
        let v1 = response[13];
        let v2 = response[14];
        let v3 = response[15];
        let capabilities = CtapHidCapability(response[16]);

        conn.channel_id = channel_id;
        conn.device_version = (v1, v2, v3);
        conn.capabilities = capabilities;

        log_traffic!(
            "FIDO connection opened: channel={:#010X}, version={}.{}.{}, caps={:#04X}",
            channel_id,
            v1,
            v2,
            v3,
            capabilities.raw()
        );

        Ok(conn)
    }

    /// Device firmware version reported during INIT.
    pub fn device_version(&self) -> (u8, u8, u8) {
        self.device_version
    }

    /// Device capabilities flags.
    pub fn capabilities(&self) -> CtapHidCapability {
        self.capabilities
    }

    /// Send a CTAP HID command and receive the response.
    pub fn call(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>, CtapHidTransportError> {
        self.call_raw(cmd, data)
    }

    /// Close the connection.
    pub fn close(&mut self) {
        if self.device.is_some() {
            log_traffic!("Closing FIDO connection");
        }
        self.device.take();
    }

    fn device(&self) -> Result<&hidapi::HidDevice, CtapHidTransportError> {
        self.device
            .as_ref()
            .ok_or(CtapHidTransportError::ConnectionClosed)
    }

    fn call_raw(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>, CtapHidTransportError> {
        self.send_request(cmd, data)?;
        self.recv_response(cmd)
    }

    fn send_request(&self, cmd: u8, data: &[u8]) -> Result<(), CtapHidTransportError> {
        let dev = self.device()?;
        let mut remaining = data;
        let mut seq: u8 = 0;
        let mut first = true;

        while !remaining.is_empty() || first {
            let mut packet = Vec::with_capacity(self.packet_size + 1);
            // Report ID prefix for hidapi write
            packet.push(0x00);

            if first {
                // Initialization packet: CID(4) + CMD(1) + LEN(2) + DATA
                packet.extend_from_slice(&self.channel_id.to_be_bytes());
                packet.push(TYPE_INIT | cmd);
                packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
                let payload_size = (self.packet_size - INIT_HEADER_SIZE).min(remaining.len());
                packet.extend_from_slice(&remaining[..payload_size]);
                remaining = &remaining[payload_size..];
                first = false;
            } else {
                // Continuation packet: CID(4) + SEQ(1) + DATA
                packet.extend_from_slice(&self.channel_id.to_be_bytes());
                packet.push(seq & 0x7F);
                let payload_size = (self.packet_size - CONT_HEADER_SIZE).min(remaining.len());
                packet.extend_from_slice(&remaining[..payload_size]);
                remaining = &remaining[payload_size..];
                seq += 1;
            }

            // Pad to packet_size + 1 (report ID byte)
            packet.resize(self.packet_size + 1, 0);

            log_traffic!("SEND: {}", crate::logging::hex_encode(&packet[1..]));
            dev.write(&packet)?;
        }

        Ok(())
    }

    fn recv_response(&self, expected_cmd: u8) -> Result<Vec<u8>, CtapHidTransportError> {
        let dev = self.device()?;
        let mut response = Vec::new();
        let mut r_len: usize = 0;
        let mut seq: u8 = 0;
        let mut first = true;

        loop {
            let mut buf = vec![0u8; self.packet_size];
            let n = dev.read_timeout(&mut buf, 5000)?;
            if n == 0 {
                return Err(CtapHidTransportError::Timeout);
            }
            let recv = &buf[..n];
            log_traffic!("RECV: {}", crate::logging::hex_encode(recv));

            if recv.len() < 4 {
                return Err(CtapHidTransportError::InvalidResponse);
            }

            let r_channel = u32::from_be_bytes([recv[0], recv[1], recv[2], recv[3]]);
            if r_channel != self.channel_id {
                // Ignore packets from wrong channel (could be from broadcast)
                continue;
            }

            let payload = &recv[4..];

            if first {
                // Initialization packet
                if payload.len() < 3 {
                    return Err(CtapHidTransportError::InvalidResponse);
                }
                let r_cmd = payload[0];
                r_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
                let data = &payload[3..];

                if r_cmd == TYPE_INIT | CtapHidCommand::Keepalive as u8 {
                    // Keepalive — just log and continue waiting
                    if !data.is_empty() {
                        let status = data[0];
                        log::debug!("CTAP keepalive status: {:#04X}", status);
                    }
                    continue;
                } else if r_cmd == TYPE_INIT | CtapHidCommand::Error as u8 {
                    let err_code = if !data.is_empty() { data[0] } else { 0x7F };
                    let err = CtapHidError::from_byte(err_code);
                    return Err(CtapHidTransportError::CtapHidError(err));
                } else if r_cmd != TYPE_INIT | expected_cmd {
                    return Err(CtapHidTransportError::InvalidResponse);
                }

                response.extend_from_slice(data);
                first = false;
            } else {
                // Continuation packet
                if payload.is_empty() {
                    return Err(CtapHidTransportError::InvalidResponse);
                }
                let r_seq = payload[0] & 0x7F;
                if r_seq != seq {
                    return Err(CtapHidTransportError::WrongSequence);
                }
                seq += 1;
                response.extend_from_slice(&payload[1..]);
            }

            if response.len() >= r_len {
                break;
            }
        }

        response.truncate(r_len);
        Ok(response)
    }
}

impl Drop for FidoConnection {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_flags() {
        let caps = CtapHidCapability(0x05);
        assert!(caps.has_wink());
        assert!(caps.has_cbor());
        assert_eq!(caps.raw(), 0x05);

        let caps2 = CtapHidCapability(0x08);
        assert!(!caps2.has_wink());
        assert!(!caps2.has_cbor());
    }

    #[test]
    fn test_error_from_byte() {
        assert_eq!(CtapHidError::from_byte(0x06), CtapHidError::ChannelBusy);
        assert_eq!(CtapHidError::from_byte(0xFF), CtapHidError::Other);
    }
}
