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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApduError {
    #[error("Data length {0} exceeds maximum APDU size 255")]
    ShortApduTooLong(usize),
    #[error("APDU length exceeds YubiKey capability")]
    ExtendedApduTooLong,
}

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
