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

//! Low-level OTP HID frame protocol, codec, and related helpers.

use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::core::Version;
use crate::transport::otphid::HidOtpConnection;

// --- OTP Codec ---

const MODHEX_ALPHABET: &[u8; 16] = b"cbdefghijklnrtuv";
const CRC_OK_RESIDUAL: u16 = 0xF0B8;

#[derive(Debug, Error)]
pub enum OtpCodecError {
    #[error("Length must be a multiple of 2")]
    OddLength,
    #[error("'{0}' is not a valid modhex character")]
    InvalidModhexChar(char),
}

/// Calculate CRC-16 (CCITT) over data.
pub fn calculate_crc(data: &[u8]) -> u16 {
    crc16(data)
}

/// Check if CRC-16 over data matches expected residual.
pub fn check_crc(data: &[u8]) -> bool {
    crc16(data) == CRC_OK_RESIDUAL
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry == 1 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// Encode bytes to modhex string.
pub fn modhex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push(MODHEX_ALPHABET[(byte >> 4) as usize] as char);
        result.push(MODHEX_ALPHABET[(byte & 0x0F) as usize] as char);
    }
    result
}

/// Decode modhex string to bytes.
pub fn modhex_decode(string: &str) -> Result<Vec<u8>, OtpCodecError> {
    if !string.len().is_multiple_of(2) {
        return Err(OtpCodecError::OddLength);
    }
    let bytes = string.as_bytes();
    let mut result = Vec::with_capacity(string.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = modhex_char_value(bytes[i])?;
        let lo = modhex_char_value(bytes[i + 1])?;
        result.push((hi << 4) | lo);
    }
    Ok(result)
}

fn modhex_char_value(ch: u8) -> Result<u8, OtpCodecError> {
    MODHEX_ALPHABET
        .iter()
        .position(|&c| c == ch)
        .map(|p| p as u8)
        .ok_or(OtpCodecError::InvalidModhexChar(ch as char))
}

// --- OTP Protocol ---

// Constants
// ---------------------------------------------------------------------------

pub(crate) const SLOT_DATA_SIZE: usize = 64;
const FRAME_SIZE: usize = SLOT_DATA_SIZE + 6; // 70
pub(crate) const FEATURE_RPT_SIZE: usize = 8;
pub(crate) const FEATURE_RPT_DATA_SIZE: usize = FEATURE_RPT_SIZE - 1; // 7

const RESP_PENDING_FLAG: u8 = 0x40;
const SLOT_WRITE_FLAG: u8 = 0x80;
const RESP_TIMEOUT_WAIT_FLAG: u8 = 0x20;
const SEQUENCE_MASK: u8 = 0x1F;

pub const STATUS_OFFSET_PROG_SEQ: usize = 4;
pub(crate) const STATUS_OFFSET_TOUCH_LOW: usize = 5;
pub(crate) const CONFIG_SLOTS_PROGRAMMED_MASK: u8 = 0b0000_0011;

/// ConfigSlot::ScanMap raw value, used to probe NEO devices.
const SCAN_MAP_SLOT: u8 = 0x12;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Connection-level error for OTP HID transport.
#[derive(Debug, Error)]
pub enum OtpError {
    #[error("Command rejected: {0}")]
    CommandRejected(String),
    #[error("Bad response: {0}")]
    BadResponse(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("HID error: {0}")]
    Hid(#[from] crate::transport::otphid::HidError),
}

// ---------------------------------------------------------------------------
// OTP transport trait
// ---------------------------------------------------------------------------

/// Trait for low-level OTP HID transport (feature report read/write).
pub trait OtpConnection: crate::core::Connection<Error = OtpError> {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError>;
    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError>;
}

impl crate::core::Connection for Box<dyn OtpConnection + Send> {
    type Error = OtpError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl OtpConnection for Box<dyn OtpConnection + Send> {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError> {
        (**self).otp_receive()
    }
    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        (**self).otp_send(data)
    }
}

impl crate::core::Connection for Box<dyn OtpConnection + Send + Sync> {
    type Error = OtpError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl OtpConnection for Box<dyn OtpConnection + Send + Sync> {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError> {
        (**self).otp_receive()
    }
    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        (**self).otp_send(data)
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
        self.get_feature_report().map_err(OtpError::from)
    }
    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        self.set_feature_report(data).map_err(OtpError::from)
    }
}

// ---------------------------------------------------------------------------
// OTP HID protocol
// ---------------------------------------------------------------------------

/// Low-level OTP frame protocol over HID feature reports.
pub struct OtpProtocol<T: OtpConnection> {
    connection: T,
    pub version: Version,
}

impl<T: OtpConnection> OtpProtocol<T> {
    pub fn new(connection: T) -> Result<Self, (OtpError, T)> {
        let mut proto = Self {
            connection,
            version: Version(0, 0, 0),
        };
        match proto.receive() {
            Ok(report) => proto.version = Version::from_bytes(&report[1..4]),
            Err(e) => return Err((e, proto.into_connection())),
        }

        // NEO (version 3.x): force communication to refresh pgmSeq
        if proto.version.0 == 3 {
            // Write an invalid scan map — expected to be rejected
            let _ = proto.send_and_receive(SCAN_MAP_SLOT, Some(&[b'c'; 51]), None);
        }

        Ok(proto)
    }

    /// Read status bytes from the YubiKey (first 3 bytes are firmware version).
    pub fn read_status(&mut self) -> Result<Vec<u8>, OtpError> {
        let report = self.receive()?;
        // Return bytes 1..7 (skip first byte, drop last byte = status flags)
        Ok(report[1..FEATURE_RPT_DATA_SIZE].to_vec())
    }

    /// Send a command and read the response.
    /// `expected_len >= 0`: verifies CRC and returns exactly that many bytes.
    /// `expected_len == -1`: returns the raw data response (with CRC/padding).
    /// `expected_len == None`: expects no data (status-only), returns `None`.
    pub fn send_and_receive(
        &mut self,
        slot: u8,
        data: Option<&[u8]>,
        expected_len: Option<i32>,
    ) -> Result<Option<Vec<u8>>, OtpError> {
        self.send_and_receive_with_cancel(slot, data, expected_len, None, None)
    }

    /// Send a command with optional cancellation and keepalive callback.
    /// `expected_len >= 0`: verifies CRC and returns exactly that many bytes.
    /// `expected_len == -1`: returns the raw data response (with CRC/padding).
    /// `expected_len == None`: expects no data (status-only), returns `None`.
    pub fn send_and_receive_with_cancel(
        &mut self,
        slot: u8,
        data: Option<&[u8]>,
        expected_len: Option<i32>,
        cancel: Option<&dyn Fn() -> bool>,
        on_keepalive: Option<&dyn Fn(u8)>,
    ) -> Result<Option<Vec<u8>>, OtpError> {
        let payload_data = data.unwrap_or(&[]);
        if payload_data.len() > SLOT_DATA_SIZE {
            return Err(OtpError::BadResponse(
                "Payload too large for HID frame".into(),
            ));
        }
        let mut payload = [0u8; SLOT_DATA_SIZE];
        payload[..payload_data.len()].copy_from_slice(payload_data);

        let frame = format_frame(slot, &payload);
        let prog_seq = self.send_frame(&frame)?;
        let response = self.read_frame(prog_seq, cancel, on_keepalive)?;

        match (response, expected_len) {
            (Some(raw), Some(len)) if len >= 0 => {
                verify_and_strip_crc(&raw, len as usize).map(Some)
            }
            (Some(raw), Some(_)) => Ok(Some(raw)), // -1: raw
            (Some(_), None) | (None, _) => Ok(None),
        }
    }

    fn receive(&mut self) -> Result<Vec<u8>, OtpError> {
        let report = self.connection.otp_receive()?;
        if report.len() != FEATURE_RPT_SIZE {
            return Err(OtpError::BadResponse(format!(
                "Incorrect feature report size (was {}, expected {FEATURE_RPT_SIZE})",
                report.len()
            )));
        }
        Ok(report)
    }

    fn await_ready_to_write(&mut self) -> Result<(), OtpError> {
        for _ in 0..20 {
            let report = self.receive()?;
            if report[FEATURE_RPT_DATA_SIZE] & SLOT_WRITE_FLAG == 0 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(OtpError::Timeout(
            "Timeout waiting for YubiKey to become ready to receive".into(),
        ))
    }

    fn send_frame(&mut self, buf: &[u8]) -> Result<u8, OtpError> {
        debug_assert_eq!(buf.len(), FRAME_SIZE);
        let prog_seq = self.receive()?[STATUS_OFFSET_PROG_SEQ];
        let mut seq: u8 = 0;
        let mut offset = 0;
        while offset < buf.len() {
            let end = (offset + FEATURE_RPT_DATA_SIZE).min(buf.len());
            let packet = &buf[offset..end];
            if should_send(packet, seq) {
                let mut report = [0u8; FEATURE_RPT_SIZE];
                report[..packet.len()].copy_from_slice(packet);
                report[FEATURE_RPT_DATA_SIZE] = 0x80 | seq;
                self.await_ready_to_write()?;
                self.connection.otp_send(&report)?;
            }
            seq += 1;
            offset += FEATURE_RPT_DATA_SIZE;
        }
        Ok(prog_seq)
    }

    fn read_frame(
        &mut self,
        prog_seq: u8,
        cancel: Option<&dyn Fn() -> bool>,
        on_keepalive: Option<&dyn Fn(u8)>,
    ) -> Result<Option<Vec<u8>>, OtpError> {
        let mut response = Vec::new();
        let mut seq: u8 = 0;
        let mut needs_touch = false;
        let mut last_ka: Option<u8> = None;

        loop {
            let report = self.receive()?;
            let status_byte = report[FEATURE_RPT_DATA_SIZE];

            if status_byte & RESP_PENDING_FLAG != 0 {
                // Response packet
                if seq == (status_byte & SEQUENCE_MASK) {
                    response.extend_from_slice(&report[..FEATURE_RPT_DATA_SIZE]);
                    seq += 1;
                } else if (status_byte & SEQUENCE_MASK) == 0 {
                    // Transmission complete
                    self.reset_state()?;
                    return Ok(Some(response));
                }
            } else if status_byte == 0 {
                // Status response
                if !response.is_empty() {
                    return Err(OtpError::BadResponse("Incomplete transfer".into()));
                } else if is_sequence_updated(&report, prog_seq) {
                    return Ok(None);
                } else if needs_touch {
                    return Err(OtpError::Timeout("Timed out waiting for touch".into()));
                } else {
                    return Err(OtpError::CommandRejected("No data".into()));
                }
            } else {
                // Need to wait
                let status = if status_byte & RESP_TIMEOUT_WAIT_FLAG != 0 {
                    needs_touch = true;
                    thread::sleep(Duration::from_millis(100));
                    2u8 // STATUS_UPNEEDED
                } else {
                    thread::sleep(Duration::from_millis(20));
                    1u8 // STATUS_PROCESSING
                };
                if let Some(cb) = on_keepalive
                    && last_ka != Some(status)
                {
                    last_ka = Some(status);
                    cb(status);
                }
                if cancel.is_some_and(|f| f()) {
                    self.reset_state()?;
                    return Err(OtpError::Timeout("Command cancelled".into()));
                }
            }
        }
    }

    fn reset_state(&mut self) -> Result<(), OtpError> {
        let mut report = [0u8; FEATURE_RPT_SIZE];
        report[FEATURE_RPT_DATA_SIZE] = 0xFF;
        self.connection.otp_send(&report)?;
        Ok(())
    }

    /// Consume the protocol, returning the underlying connection.
    pub fn into_connection(self) -> T {
        self.connection
    }
}

/// Verify and strip CRC from a raw OTP data response, returning `expected_len` bytes.
pub fn verify_and_strip_crc(response: &[u8], expected_len: usize) -> Result<Vec<u8>, OtpError> {
    if response.len() < expected_len + 2 {
        return Err(OtpError::BadResponse(format!(
            "Response too short: expected at least {}, got {}",
            expected_len + 2,
            response.len()
        )));
    }
    if check_crc(&response[..expected_len + 2]) {
        Ok(response[..expected_len].to_vec())
    } else {
        Err(OtpError::BadResponse("Invalid CRC".into()))
    }
}

fn should_send(packet: &[u8], seq: u8) -> bool {
    seq == 0 || seq == 9 || packet.iter().any(|&b| b != 0)
}

fn format_frame(slot: u8, payload: &[u8; SLOT_DATA_SIZE]) -> Vec<u8> {
    let crc = calculate_crc(payload);
    let mut frame = Vec::with_capacity(FRAME_SIZE);
    frame.extend_from_slice(payload);
    frame.push(slot);
    frame.extend_from_slice(&crc.to_le_bytes());
    frame.extend_from_slice(&[0u8; 3]);
    debug_assert_eq!(frame.len(), FRAME_SIZE);
    frame
}

fn is_sequence_updated(report: &[u8], prev_seq: u8) -> bool {
    let next_seq = report[STATUS_OFFSET_PROG_SEQ];
    next_seq == prev_seq.wrapping_add(1)
        || (next_seq == 0
            && prev_seq > 0
            && report[STATUS_OFFSET_TOUCH_LOW] & CONFIG_SLOTS_PROGRAMMED_MASK == 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc() {
        assert_eq!(calculate_crc(&[]), 0xFFFF);
        let crc = calculate_crc(b"hello");
        assert_ne!(crc, 0);
    }

    #[test]
    fn test_modhex_roundtrip() {
        let data = b"\x01\x02\x03\x04";
        let encoded = modhex_encode(data);
        let decoded = modhex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_format_frame_size() {
        let payload = [0u8; SLOT_DATA_SIZE];
        let frame = format_frame(0x01, &payload);
        assert_eq!(frame.len(), FRAME_SIZE);
    }

    #[test]
    fn test_should_send() {
        // First and last packets always sent
        assert!(should_send(&[0; 7], 0));
        assert!(should_send(&[0; 7], 9));
        // Zero packet in the middle is skipped
        assert!(!should_send(&[0; 7], 5));
        // Non-zero packet always sent
        assert!(should_send(&[0, 0, 1, 0, 0, 0, 0], 5));
    }

    #[test]
    fn test_is_sequence_updated() {
        let mut report = [0u8; FEATURE_RPT_SIZE];
        report[STATUS_OFFSET_PROG_SEQ] = 2;
        assert!(is_sequence_updated(&report, 1));
        assert!(!is_sequence_updated(&report, 2));

        // Wrap-around: prog_seq goes to 0, all slots empty
        report[STATUS_OFFSET_PROG_SEQ] = 0;
        report[STATUS_OFFSET_TOUCH_LOW] = 0; // no slots programmed
        assert!(is_sequence_updated(&report, 5));

        // Wrap-around but slots still programmed → not updated
        report[STATUS_OFFSET_TOUCH_LOW] = 0x01;
        assert!(!is_sequence_updated(&report, 5));
    }
}
