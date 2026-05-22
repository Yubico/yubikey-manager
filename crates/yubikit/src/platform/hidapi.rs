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

//! HID transport implementations for YubiKey devices.
//!
//! This module provides two HID-based transports:
//!
//! - **CTAP HID** ([`HidFidoConnection`]) — FIDO2/U2F protocol using CTAP HID framing
//!   (64-byte packets with channel multiplexing, keepalive, etc.)
//! - **OTP HID** ([`HidOtpConnection`]) — YubiKey OTP protocol using USB HID feature reports
//!   (8-byte frames for slot configuration and challenge-response)

use hidapi::HidApi;

use crate::core::Version;
use crate::fido::{CtapHidCapability, CtapHidError, FidoError};
use crate::log_traffic;
use crate::otp::{OtpConnection, OtpError};

// ---------------------------------------------------------------------------
// Shared constants and helpers
// ---------------------------------------------------------------------------

const YUBICO_VID: u16 = 0x1050;

/// Parse a USB bcdDevice value into a firmware [`Version`].
///
/// bcdDevice uses BCD encoding: `0xMMmp` where MM = major, m = minor, p = patch.
fn version_from_bcd(bcd: u16) -> Version {
    let major = ((bcd >> 12) & 0xF) * 10 + ((bcd >> 8) & 0xF);
    let minor = ((bcd >> 4) & 0xF) as u8;
    let patch = (bcd & 0xF) as u8;
    Version(major as u8, minor, patch)
}

// ===========================================================================
// CTAP HID (FIDO)
// ===========================================================================

const USAGE_PAGE_FIDO: u16 = 0xF1D0;
const USAGE_FIDO: u16 = 0x0001;

const BROADCAST_CID: u32 = 0xFFFF_FFFF;
const TYPE_INIT: u8 = 0x80;

// CTAP HID packet header sizes
const INIT_HEADER_SIZE: usize = 7; // CID(4) + CMD(1) + LEN(2)
const CONT_HEADER_SIZE: usize = 5; // CID(4) + SEQ(1)

/// CTAP HID command identifiers.
///
/// These correspond to the command byte in a CTAP HID initialization packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidCommand {
    /// Echo data back from the authenticator.
    Ping = 0x01,
    /// Send a U2F/CTAP1 message.
    Msg = 0x03,
    /// Lock the channel for exclusive use.
    Lock = 0x04,
    /// Allocate a new channel or re-sync an existing one.
    Init = 0x06,
    /// Trigger a visual or audible indicator on the authenticator.
    Wink = 0x08,
    /// Send a CTAP2 CBOR-encoded command.
    Cbor = 0x10,
    /// Cancel an ongoing CTAP2 operation.
    Cancel = 0x11,
    /// Keepalive sent by the authenticator while processing.
    Keepalive = 0x3B,
    /// Error response from the authenticator.
    Error = 0x3F,
    /// First vendor-defined command (0x40–0x7F).
    VendorFirst = 0x40,
}

/// Status codes sent in CTAP HID keepalive messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidStatus {
    /// The authenticator is still processing the request.
    Processing = 1,
    /// The authenticator is waiting for user presence (e.g., a touch).
    UpNeeded = 2,
}

impl From<hidapi::HidError> for FidoError {
    fn from(e: hidapi::HidError) -> Self {
        FidoError::Transport(Box::new(e))
    }
}

/// Information about an enumerated FIDO HID device.
#[derive(Clone, Debug)]
pub struct FidoDeviceInfo {
    /// OS-specific HID device path.
    pub path: String,
    /// USB Product ID.
    pub pid: u16,
    /// Firmware version from USB bcdDevice descriptor.
    pub version: Version,
    /// HID input report size in bytes (typically 64).
    pub report_size_in: usize,
    /// HID output report size in bytes (typically 64).
    pub report_size_out: usize,
}

/// List Yubico FIDO HID devices.
pub fn list_fido_devices() -> Result<Vec<FidoDeviceInfo>, FidoError> {
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
                version: version_from_bcd(dev.release_number()),
                // FIDO HID spec uses 64-byte packets; standard for all USB FIDO devices.
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
pub struct HidFidoConnection {
    device: Option<hidapi::HidDevice>,
    channel_id: u32,
    packet_size: usize,
    device_version: (u8, u8, u8),
    capabilities: CtapHidCapability,
}

impl HidFidoConnection {
    /// Open a FIDO connection to the device at the given path.
    ///
    /// Performs CTAP HID INIT to allocate a channel.
    pub fn open(info: &FidoDeviceInfo) -> Result<Self, FidoError> {
        log_traffic!("Opening FIDO connection to '{}'", info.path);
        let api = HidApi::new()?;
        let cpath =
            std::ffi::CString::new(info.path.as_str()).map_err(|_| FidoError::InvalidPath)?;
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
        getrandom::fill(&mut nonce).map_err(|_| FidoError::InvalidResponse)?;
        let response = conn.call_raw(CtapHidCommand::Init as u8, &nonce)?;

        if response.len() < 17 {
            return Err(FidoError::InvalidResponse);
        }
        if response[..8] != nonce {
            return Err(FidoError::WrongNonce);
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

    /// Close the connection.
    pub fn close(&mut self) {
        if self.device.is_some() {
            log_traffic!("Closing FIDO connection");
        }
        self.device.take();
    }

    fn device(&self) -> Result<&hidapi::HidDevice, FidoError> {
        self.device.as_ref().ok_or(FidoError::ConnectionClosed)
    }

    fn call_raw(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>, FidoError> {
        self.send_request(cmd, data)?;
        self.recv_response(cmd, &mut |_| {}, None)
    }

    fn send_request(&self, cmd: u8, data: &[u8]) -> Result<(), FidoError> {
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

    fn recv_response(
        &self,
        expected_cmd: u8,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        let dev = self.device()?;
        let mut response = Vec::new();
        let mut r_len: usize = 0;
        let mut seq: u8 = 0;
        let mut first = true;
        let mut last_ka: Option<u8> = None;

        loop {
            let mut buf = vec![0u8; self.packet_size];
            let n = match dev.read_timeout(&mut buf, 5000) {
                Ok(n) => n,
                Err(hidapi::HidError::HidApiError { ref message })
                    if message.contains("Interrupted") =>
                {
                    // EINTR from signal handler (e.g. Ctrl+C) — retry read.
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(FidoError::Timeout);
            }
            let recv = &buf[..n];
            log_traffic!("RECV: {}", crate::logging::hex_encode(recv));

            if recv.len() < 4 {
                return Err(FidoError::InvalidResponse);
            }

            let r_channel = u32::from_be_bytes([recv[0], recv[1], recv[2], recv[3]]);
            if r_channel != self.channel_id {
                continue;
            }

            let payload = &recv[4..];

            if first {
                if payload.len() < 3 {
                    return Err(FidoError::InvalidResponse);
                }
                let r_cmd = payload[0];
                r_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
                let data = &payload[3..];

                if r_cmd == TYPE_INIT | CtapHidCommand::Keepalive as u8 {
                    if !data.is_empty() {
                        let status = data[0];
                        log::debug!("CTAP keepalive status: {:#04X}", status);
                        if last_ka != Some(status) {
                            last_ka = Some(status);
                            on_keepalive(status);
                        }
                    }
                    if cancel.is_some_and(|f| f()) {
                        let _ = self.send_request(CtapHidCommand::Cancel as u8, &[]);
                    }
                    continue;
                } else if r_cmd == TYPE_INIT | CtapHidCommand::Error as u8 {
                    let err_code = if !data.is_empty() { data[0] } else { 0x7F };
                    let err = CtapHidError::from_byte(err_code);
                    return Err(FidoError::CtapHidError(err));
                } else if r_cmd != TYPE_INIT | expected_cmd {
                    return Err(FidoError::InvalidResponse);
                }

                response.extend_from_slice(data);
                first = false;
            } else {
                if payload.is_empty() {
                    return Err(FidoError::InvalidResponse);
                }
                let r_seq = payload[0] & 0x7F;
                if r_seq != seq & 0x7F {
                    return Err(FidoError::WrongSequence);
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

impl crate::core::Connection for HidFidoConnection {
    type Error = FidoError;

    fn close(&mut self) {
        self.close()
    }
}

impl crate::fido::FidoConnection for HidFidoConnection {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        self.send_request(cmd, data)?;
        let mut noop = |_: u8| {};
        let on_keepalive = on_keepalive.unwrap_or(&mut noop);
        self.recv_response(cmd, on_keepalive, cancel)
    }

    fn device_version(&self) -> (u8, u8, u8) {
        self.device_version()
    }

    fn capabilities(&self) -> CtapHidCapability {
        self.capabilities()
    }
}

impl Drop for HidFidoConnection {
    fn drop(&mut self) {
        self.close();
    }
}

// ===========================================================================
// OTP HID
// ===========================================================================

const USAGE_PAGE_OTP: u16 = 0x0001;
const USAGE_OTP: u16 = 0x0006;

/// Errors that can occur during OTP HID communication.
#[derive(Debug, thiserror::Error)]
pub enum HidError {
    /// Low-level transport error (e.g. HID I/O failure).
    #[error("Transport error: {0}")]
    Transport(Box<dyn std::error::Error + Send + Sync>),
    /// The device path is not a valid C string.
    #[error("Invalid device path")]
    InvalidPath,
    /// The connection has already been closed.
    #[error("Connection is closed")]
    ConnectionClosed,
}

impl From<hidapi::HidError> for HidError {
    fn from(e: hidapi::HidError) -> Self {
        HidError::Transport(Box::new(e))
    }
}

/// Information about an enumerated OTP HID device.
#[derive(Clone, Debug)]
pub struct HidDeviceInfo {
    /// OS-specific HID device path.
    pub path: String,
    /// USB Product ID.
    pub pid: u16,
    /// Firmware version from USB bcdDevice descriptor.
    pub version: Version,
}

/// List Yubico OTP HID devices.
pub fn list_otp_devices() -> Result<Vec<HidDeviceInfo>, HidError> {
    let api = HidApi::new()?;
    let mut devices = Vec::new();
    for dev in api.device_list() {
        if dev.vendor_id() == YUBICO_VID
            && dev.usage_page() == USAGE_PAGE_OTP
            && dev.usage() == USAGE_OTP
        {
            devices.push(HidDeviceInfo {
                path: dev.path().to_string_lossy().into_owned(),
                pid: dev.product_id(),
                version: version_from_bcd(dev.release_number()),
            });
        }
    }
    Ok(devices)
}

/// An open connection to an OTP HID device for feature report I/O.
pub struct HidOtpConnection {
    device: Option<hidapi::HidDevice>,
}

impl std::fmt::Debug for HidOtpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HidOtpConnection").finish_non_exhaustive()
    }
}

impl HidOtpConnection {
    /// Open a connection to the OTP HID device at the given path.
    pub fn new(path: &str) -> Result<Self, HidError> {
        log_traffic!("Opening OTP HID connection to '{}'", path);
        let api = HidApi::new()?;
        let cpath = std::ffi::CString::new(path).map_err(|_| HidError::InvalidPath)?;
        let device = api.open_path(&cpath)?;
        log_traffic!("OTP HID connection opened to '{}'", path);
        Ok(Self {
            device: Some(device),
        })
    }

    /// Read an 8-byte feature report from the device.
    pub fn get_feature_report(&self) -> Result<Vec<u8>, HidError> {
        let dev = self.device.as_ref().ok_or(HidError::ConnectionClosed)?;
        let mut buf = [0u8; 9];
        buf[0] = 0; // report ID
        let n = dev.get_feature_report(&mut buf)?;
        let start = if n > 0 && buf[0] == 0 { 1 } else { 0 };
        let end = n.min(buf.len());
        let data = buf[start..end].to_vec();
        log_traffic!("RECV: {}", crate::logging::hex_encode(&data));
        Ok(data)
    }

    /// Write an 8-byte feature report to the device.
    pub fn set_feature_report(&self, data: &[u8]) -> Result<(), HidError> {
        log_traffic!("SEND: {}", crate::logging::hex_encode(data));
        let dev = self.device.as_ref().ok_or(HidError::ConnectionClosed)?;
        let mut buf = vec![0u8; data.len() + 1];
        buf[0] = 0; // report ID
        buf[1..].copy_from_slice(data);
        dev.send_feature_report(&buf)?;
        Ok(())
    }

    /// Close the connection to the device.
    pub fn close(&mut self) {
        if self.device.is_some() {
            log_traffic!("Closing OTP HID connection");
        }
        self.device.take();
    }
}

impl crate::core::Connection for HidOtpConnection {
    type Error = OtpError;

    fn close(&mut self) {
        HidOtpConnection::close(self);
    }
}

impl OtpConnection for HidOtpConnection {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError> {
        self.get_feature_report()
            .map_err(|e| OtpError::Transport(Box::new(e)))
    }
    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        self.set_feature_report(data)
            .map_err(|e| OtpError::Transport(Box::new(e)))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_from_bcd() {
        assert_eq!(version_from_bcd(0x5430), Version(54, 3, 0));
        assert_eq!(version_from_bcd(0x0501), Version(5, 0, 1));
    }

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
