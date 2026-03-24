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

use hidapi::HidApi;

use crate::log_traffic;

const YUBICO_VID: u16 = 0x1050;
const USAGE_PAGE_OTP: u16 = 0x0001;
const USAGE_OTP: u16 = 0x0006;

#[derive(Debug, thiserror::Error)]
pub enum HidError {
    #[error("HID error: {0}")]
    Hid(#[from] hidapi::HidError),
    #[error("Invalid device path")]
    InvalidPath,
    #[error("Connection is closed")]
    ConnectionClosed,
}

/// Information about an enumerated HID device.
#[derive(Clone, Debug)]
pub struct HidDeviceInfo {
    pub path: String,
    pub pid: u16,
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
            });
        }
    }
    Ok(devices)
}

/// List all Yubico HID devices regardless of usage page.
pub fn list_all_hid_devices() -> Result<Vec<HidDeviceInfo>, HidError> {
    let api = HidApi::new()?;
    let mut devices = Vec::new();
    for dev in api.device_list() {
        if dev.vendor_id() == YUBICO_VID {
            devices.push(HidDeviceInfo {
                path: dev.path().to_string_lossy().into_owned(),
                pid: dev.product_id(),
            });
        }
    }
    Ok(devices)
}

/// An open connection to an OTP HID device for feature report I/O.
pub struct OtpConnection {
    device: Option<hidapi::HidDevice>,
}

impl OtpConnection {
    pub fn new(path: &str) -> Result<Self, HidError> {
        log_traffic!("Opening HID connection to '{}'", path);
        let api = HidApi::new()?;
        let cpath =
            std::ffi::CString::new(path).map_err(|_| HidError::InvalidPath)?;
        let device = api.open_path(&cpath)?;
        log_traffic!("HID connection opened to '{}'", path);
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

    pub fn close(&mut self) {
        if self.device.is_some() {
            log_traffic!("Closing HID connection");
        }
        self.device.take();
    }
}
