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

    // SAFETY: Plain FFI call without arguments.
    let hid_guid = unsafe { HidD_GetHidGuid() };

    // SAFETY: `hid_guid` is a valid GUID, the other arguments are optional.
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

        // SAFETY: `dev_info` is a valid device info set and `iface_data` has
        // its `cbSize` set.
        let ok = unsafe {
            SetupDiEnumDeviceInterfaces(dev_info, None, &hid_guid, index, &mut iface_data)
        };
        if ok.is_err() {
            break;
        }
        index += 1;

        // First call to get required buffer size
        let mut required_size: u32 = 0;
        // SAFETY: With a null output buffer and size 0, the call only writes
        // the required size to `required_size`.
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

        // Allocate a buffer aligned for the struct, and set cbSize to the
        // size of the fixed part of the struct.
        const _: () = assert!(mem::align_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() <= 4);
        let mut buf = vec![0u32; (required_size as usize).div_ceil(4)];
        let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        // SAFETY: `buf` is at least `required_size` bytes, which is larger
        // than the fixed part of the struct, and is suitably aligned.
        unsafe {
            (*detail).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
        }

        // SAFETY: `dev_info` and `iface_data` are valid, and `detail` points to
        // a writable buffer of `required_size` bytes.
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

        // Extract the device path string.
        // SAFETY: The call above filled `buf` with a struct whose `DevicePath`
        // extends to the end of the `required_size` bytes.
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

    // SAFETY: `dev_info` was returned by `SetupDiGetClassDevsW` and is not
    // used after this.
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
