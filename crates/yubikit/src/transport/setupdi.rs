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

//! Windows SetupDi-based HID device enumeration.
//!
//! Uses `SetupDiGetClassDevs` to enumerate HID devices without opening them,
//! which works even when the current user does not have permission to access
//! FIDO devices (requires running as Administrator on Windows 10 1809+).
//!
//! VID and PID are extracted from the device interface path string, which has
//! a format like `\\?\hid#vid_1050&pid_0407#...`.

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces,
    SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
};
use windows::Win32::Devices::HumanInterfaceDevice::HidD_GetHidGuid;

use std::mem;

const YUBICO_VID: u16 = 0x1050;

/// A Yubico HID device found via SetupDi enumeration.
#[derive(Clone, Debug)]
pub struct SetupDiDeviceInfo {
    /// USB Product ID.
    pub pid: u16,
    /// Device interface path (used as a fingerprint for change detection).
    pub path: String,
}

/// Enumerate all Yubico HID devices using the Windows SetupDi API.
///
/// This does not open any device handles, so it works for FIDO devices
/// even when the caller is not running as Administrator.
pub(crate) fn list_setupdi_devices() -> Vec<SetupDiDeviceInfo> {
    let mut devices = Vec::new();

    let hid_guid = unsafe { HidD_GetHidGuid() };

    let dev_info = unsafe {
        SetupDiGetClassDevsW(
            Some(&hid_guid),
            None,
            None,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        )
    };

    let dev_info = match dev_info {
        Ok(h) => h,
        Err(e) => {
            log::debug!("SetupDiGetClassDevsW failed: {e}");
            return devices;
        }
    };

    let mut index: u32 = 0;
    loop {
        let mut iface_data = SP_DEVICE_INTERFACE_DATA {
            cbSize: mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };

        let ok = unsafe {
            SetupDiEnumDeviceInterfaces(dev_info, None, &hid_guid, index, &mut iface_data)
        };
        if ok.is_err() {
            break;
        }
        index += 1;

        // First call to get required buffer size
        let mut required_size: u32 = 0;
        let _ = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface_data,
                None,
                0,
                Some(&mut required_size),
                None,
            )
        };

        if required_size == 0 {
            continue;
        }

        // Allocate buffer and set cbSize to the fixed part of the struct
        let mut buf = vec![0u8; required_size as usize];
        let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        unsafe {
            (*detail).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
        }

        let ok = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface_data,
                Some(detail),
                required_size,
                None,
                None,
            )
        };

        if ok.is_err() {
            continue;
        }

        // Extract the device path string
        let path = unsafe {
            let path_ptr = (*detail).DevicePath.as_ptr();
            // Calculate the number of WCHARs in the path
            let path_bytes = required_size as usize
                - mem::offset_of!(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath);
            let path_len = path_bytes / mem::size_of::<u16>();
            let slice = std::slice::from_raw_parts(path_ptr, path_len);
            // Find null terminator
            let len = slice.iter().position(|&c| c == 0).unwrap_or(path_len);
            String::from_utf16_lossy(&slice[..len])
        };

        if let Some(info) = parse_yubico_path(&path) {
            devices.push(info);
        }
    }

    unsafe {
        let _ = SetupDiDestroyDeviceInfoList(dev_info);
    }

    devices
}

/// Parse a device interface path to extract VID and PID.
///
/// Paths look like `\\?\hid#vid_1050&pid_0407#7&1234...`
fn parse_yubico_path(path: &str) -> Option<SetupDiDeviceInfo> {
    let lower = path.to_ascii_lowercase();

    // Check for Yubico VID
    let vid_needle = format!("vid_{:04x}", YUBICO_VID);
    if !lower.contains(&vid_needle) {
        return None;
    }

    // Extract PID
    let pid_prefix = "pid_";
    let pid_pos = lower.find(pid_prefix)? + pid_prefix.len();
    let pid_str = &lower[pid_pos..];
    let pid_end = pid_str
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(pid_str.len());
    let pid = u16::from_str_radix(&pid_str[..pid_end], 16).ok()?;

    Some(SetupDiDeviceInfo {
        pid,
        path: path.to_string(),
    })
}
