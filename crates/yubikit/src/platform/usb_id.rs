//! Identification of the physical USB device behind an interface.
//!
//! A YubiKey exposes up to three USB interfaces (CCID, OTP HID, FIDO HID),
//! each of which is enumerated separately. The operating system knows which
//! interfaces belong to the same USB device, and this module exposes that
//! knowledge as a [`UsbDeviceId`] so interfaces can be grouped into physical
//! devices without reading and comparing device info over each of them.
//!
//! Coverage differs per platform:
//!
//! | Platform | HID interfaces | PC/SC readers |
//! |----------|----------------|---------------|
//! | Windows  | Device instance ID parent chain (CfgMgr32) | `SCardGetReaderDeviceInstanceId` + parent chain |
//! | Linux    | udev (`/sys/class/hidraw` → USB parent) | `SCARD_ATTR_CHANNEL_ID` of an open connection (libccid ≥ 1.4.32) |
//! | macOS    | IOKit registry (`DevSrvsID` → `IOUSBHostDevice`) | Not available |
//!
//! Where an identifier is unavailable, callers fall back to matching
//! interfaces by serial number or by USB Product ID.

use std::fmt;

#[cfg(feature = "pcsc")]
use super::pcsc::PcscSmartCardConnection;

/// An opaque, OS-assigned identifier for a physical USB device.
///
/// Interfaces that resolve to the same id belong to the same device. Ids are
/// only meaningful within one process on one host, and only while the device
/// remains connected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UsbDeviceId(String);

impl UsbDeviceId {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UsbDeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolve the USB device a HID interface path belongs to.
///
/// Returns `None` if the platform offers no mapping, or the lookup fails.
#[cfg(feature = "hid")]
pub fn hid_usb_device_id(hid_path: &str) -> Option<UsbDeviceId> {
    let id = platform::hid_usb_device_id(hid_path);
    log::trace!("USB device of HID '{hid_path}': {id:?}");
    id
}

/// Resolve the USB device a PC/SC reader belongs to, without connecting to it.
///
/// Returns `None` if the platform offers no mapping, or the lookup fails.
#[cfg(feature = "pcsc")]
pub fn reader_usb_device_id(reader_name: &str) -> Option<UsbDeviceId> {
    let id = platform::reader_usb_device_id(reader_name);
    log::trace!("USB device of reader '{reader_name}': {id:?}");
    id
}

/// Resolve the USB device behind an open PC/SC connection.
///
/// Some platforms can only identify a reader through an open connection; this
/// should be used when a connection is open anyway.
#[cfg(feature = "pcsc")]
pub fn connection_usb_device_id(conn: &PcscSmartCardConnection) -> Option<UsbDeviceId> {
    platform::connection_usb_device_id(conn)
}

/// Convert a Windows device interface path to a device instance ID.
///
/// `\\?\HID#VID_1050&PID_0407&MI_00#7&181685db&0&0000#{guid}\KBD` becomes
/// `HID\VID_1050&PID_0407&MI_00\7&181685db&0&0000`.
#[cfg(any(windows, test))]
pub(crate) fn device_instance_from_path(path: &str) -> Option<String> {
    let mut parts = path.strip_prefix(r"\\?\")?.split('#');
    let bus = parts.next().filter(|part| !part.is_empty())?;
    let device = parts.next().filter(|part| !part.is_empty())?;
    let instance = parts.next().filter(|part| !part.is_empty())?;
    let class = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    // The interface class GUID may be followed by a reference string.
    let guid_end = class.find('}')?;
    let rest = &class[guid_end + 1..];
    if !class.starts_with('{') || !(rest.is_empty() || rest.starts_with('\\')) {
        return None;
    }
    Some(format!(r"{bus}\{device}\{instance}"))
}

#[cfg(all(windows, feature = "pcsc"))]
pub(crate) use platform::{reader_device_instances, usb_device_id_from_instance};

#[cfg(windows)]
mod platform {
    use super::{UsbDeviceId, device_instance_from_path};
    #[cfg(feature = "pcsc")]
    use crate::platform::pcsc::PcscSmartCardConnection;
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Get_Device_IDW, CM_Get_Parent, CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CR_SUCCESS,
        MAX_DEVICE_ID_LEN,
    };
    use windows::core::PCWSTR;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Whether a device instance ID denotes a whole USB device rather than
    /// one function of a composite device (`USB\VID_xxxx&PID_xxxx&MI_xx\...`).
    fn is_usb_device_instance(instance: &str) -> bool {
        let upper = instance.to_ascii_uppercase();
        upper.starts_with(r"USB\VID_") && !upper.contains("&MI_")
    }

    /// Walk up the device tree from `instance` to the enclosing USB device.
    pub(crate) fn usb_device_id_from_instance(instance: &str) -> Option<UsbDeviceId> {
        let instance_w = wide(instance);
        let mut devinst = 0u32;
        // SAFETY: `instance_w` is NUL-terminated and `devinst` is a valid out-pointer.
        let status = unsafe {
            CM_Locate_DevNodeW(
                &mut devinst,
                PCWSTR(instance_w.as_ptr()),
                CM_LOCATE_DEVNODE_NORMAL,
            )
        };
        if status != CR_SUCCESS {
            log::debug!("CM_Locate_DevNodeW('{instance}') failed: {status:?}");
            return None;
        }
        // A HID collection sits at most a few levels below its USB device
        // (HID → USB interface → USB device); bound the walk regardless.
        for _ in 0..8 {
            let mut buffer = [0u16; MAX_DEVICE_ID_LEN as usize + 1];
            // SAFETY: `buffer` is a writable UTF-16 buffer of the documented maximum size.
            let status = unsafe { CM_Get_Device_IDW(devinst, &mut buffer, 0) };
            if status != CR_SUCCESS {
                log::debug!("CM_Get_Device_IDW failed: {status:?}");
                return None;
            }
            let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
            let id = String::from_utf16_lossy(&buffer[..end]);
            if is_usb_device_instance(&id) {
                return Some(UsbDeviceId(id.to_ascii_uppercase()));
            }
            if !id.to_ascii_uppercase().starts_with(r"USB\")
                && !id.to_ascii_uppercase().starts_with(r"HID\")
            {
                // Left the USB subtree (e.g. a virtual or Bluetooth device).
                return None;
            }
            let mut parent = 0u32;
            // SAFETY: `parent` is a valid out-pointer and `devinst` a located node.
            let status = unsafe { CM_Get_Parent(&mut parent, devinst, 0) };
            if status != CR_SUCCESS {
                return None;
            }
            devinst = parent;
        }
        None
    }

    #[cfg(feature = "hid")]
    pub(super) fn hid_usb_device_id(hid_path: &str) -> Option<UsbDeviceId> {
        let instance = device_instance_from_path(hid_path)?;
        usb_device_id_from_instance(&instance)
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn reader_usb_device_id(reader_name: &str) -> Option<UsbDeviceId> {
        let instance = match reader_device_instances(&[reader_name]) {
            Ok(mut results) => results.pop()?.ok()?,
            Err(e) => {
                log::debug!("Reading reader device instances failed: {e}");
                return None;
            }
        };
        usb_device_id_from_instance(&instance)
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn connection_usb_device_id(conn: &PcscSmartCardConnection) -> Option<UsbDeviceId> {
        reader_usb_device_id(conn.reader_name())
    }

    /// Look up the device instance IDs of readers using one smart card context.
    #[cfg(feature = "pcsc")]
    pub(crate) fn reader_device_instances(
        names: &[&str],
    ) -> std::io::Result<Vec<std::io::Result<String>>> {
        use windows_sys::Win32::Security::Credentials::{
            SCARD_SCOPE_USER, SCardEstablishContext, SCardGetReaderDeviceInstanceIdW,
            SCardReleaseContext,
        };

        struct Context(usize);
        impl Drop for Context {
            fn drop(&mut self) {
                // SAFETY: The context was established by `reader_device_instances`
                // and is released exactly once here.
                let status = unsafe { SCardReleaseContext(self.0) };
                if status != 0 {
                    log::debug!("Releasing smart card context failed: {status:#x}");
                }
            }
        }

        fn check(status: i32) -> std::io::Result<()> {
            if status == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(status))
            }
        }

        fn instance_id(context: usize, name: &str) -> std::io::Result<String> {
            let name = wide(name);
            let mut len = 0;
            // SAFETY: `name` is NUL-terminated; a null buffer requests the
            // required length, written to `len`.
            check(unsafe {
                SCardGetReaderDeviceInstanceIdW(
                    context,
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut len,
                )
            })?;
            let mut instance = vec![0; len as usize];
            // SAFETY: `instance` is a writable buffer of `len` UTF-16 units.
            check(unsafe {
                SCardGetReaderDeviceInstanceIdW(
                    context,
                    name.as_ptr(),
                    instance.as_mut_ptr(),
                    &mut len,
                )
            })?;
            let end = instance.iter().position(|&c| c == 0).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unterminated device instance ID",
                )
            })?;
            String::from_utf16(&instance[..end])
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }

        let mut context = 0;
        // SAFETY: Reserved arguments are null and `context` is a valid out-pointer.
        check(unsafe {
            SCardEstablishContext(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut context,
            )
        })?;
        let context = Context(context);
        Ok(names
            .iter()
            .map(|name| instance_id(context.0, name))
            .collect())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::UsbDeviceId;
    #[cfg(feature = "pcsc")]
    use crate::platform::pcsc::PcscSmartCardConnection;

    /// `SCARD_ATTR_CHANNEL_ID` channel type for USB readers.
    #[cfg(feature = "pcsc")]
    const CHANNEL_TYPE_USB: u32 = 0x0020;

    fn usb_device_id(bus: u32, address: u32) -> UsbDeviceId {
        UsbDeviceId(format!("usb:{bus}:{address}"))
    }

    #[cfg(feature = "hid")]
    pub(super) fn hid_usb_device_id(hid_path: &str) -> Option<UsbDeviceId> {
        // hidapi reports `/dev/hidrawN`; the matching sysfs node has the USB
        // device as an ancestor.
        let name = hid_path.strip_prefix("/dev/")?;
        if name.is_empty() || name.contains('/') {
            return None;
        }
        let syspath = std::path::Path::new("/sys/class/hidraw").join(name);
        let device = udev::Device::from_syspath(&syspath).ok()?;
        let usb = device
            .parent_with_subsystem_devtype("usb", "usb_device")
            .ok()??;
        let attr = |name: &str| -> Option<u32> {
            usb.attribute_value(name)?.to_str()?.trim().parse().ok()
        };
        Some(usb_device_id(attr("busnum")?, attr("devnum")?))
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn reader_usb_device_id(_reader_name: &str) -> Option<UsbDeviceId> {
        // pcsc-lite only exposes the USB location through a connection.
        None
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn connection_usb_device_id(conn: &PcscSmartCardConnection) -> Option<UsbDeviceId> {
        let channel = conn.channel_id()?;
        if channel >> 16 != CHANNEL_TYPE_USB {
            return None;
        }
        // libccid encodes `bus << 8 | address` in the low 16 bits.
        Some(usb_device_id((channel >> 8) & 0xff, channel & 0xff))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::UsbDeviceId;
    #[cfg(feature = "pcsc")]
    use crate::platform::pcsc::PcscSmartCardConnection;
    use core_foundation_sys::dictionary::CFMutableDictionaryRef;
    use std::ffi::{CStr, c_char};

    type IoObject = u32;
    type KernReturn = i32;

    // SAFETY: Signatures match the IOKit registry API declarations.
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IORegistryEntryIDMatching(entry_id: u64) -> CFMutableDictionaryRef;
        fn IOServiceGetMatchingService(
            main_port: u32,
            matching: CFMutableDictionaryRef,
        ) -> IoObject;
        fn IORegistryEntryGetParentEntry(
            entry: IoObject,
            plane: *const c_char,
            parent: *mut IoObject,
        ) -> KernReturn;
        fn IORegistryEntryGetRegistryEntryID(entry: IoObject, entry_id: *mut u64) -> KernReturn;
        fn IOObjectConformsTo(object: IoObject, class_name: *const c_char) -> u32;
        fn IOObjectRelease(object: IoObject) -> KernReturn;
    }

    /// An IOKit object reference that is released on drop.
    struct Object(IoObject);

    impl Drop for Object {
        fn drop(&mut self) {
            // SAFETY: The object was retained by the IOKit call that returned it.
            unsafe { IOObjectRelease(self.0) };
        }
    }

    const IO_SERVICE_PLANE: &CStr = c"IOService";
    const USB_DEVICE_CLASSES: [&CStr; 2] = [c"IOUSBHostDevice", c"IOUSBDevice"];

    #[cfg(feature = "hid")]
    pub(super) fn hid_usb_device_id(hid_path: &str) -> Option<UsbDeviceId> {
        // hidapi reports `DevSrvsID:<registry entry id>` for each HID device.
        let entry_id: u64 = hid_path.strip_prefix("DevSrvsID:")?.parse().ok()?;
        // SAFETY: The matching dictionary is consumed by IOServiceGetMatchingService.
        let service =
            unsafe { IOServiceGetMatchingService(0, IORegistryEntryIDMatching(entry_id)) };
        if service == 0 {
            return None;
        }
        let mut current = Object(service);
        // HID device → USB interface → USB device; bound the walk regardless.
        for _ in 0..8 {
            // SAFETY: `current` is a valid registry entry and the class names
            // are NUL-terminated.
            let is_usb_device = USB_DEVICE_CLASSES
                .iter()
                .any(|class| unsafe { IOObjectConformsTo(current.0, class.as_ptr()) } != 0);
            if is_usb_device {
                let mut id = 0u64;
                // SAFETY: `id` is a valid out-pointer.
                if unsafe { IORegistryEntryGetRegistryEntryID(current.0, &mut id) } != 0 {
                    return None;
                }
                return Some(UsbDeviceId(format!("iokit:{id}")));
            }
            let mut parent = 0;
            // SAFETY: `parent` is a valid out-pointer and the plane name is NUL-terminated.
            let status = unsafe {
                IORegistryEntryGetParentEntry(current.0, IO_SERVICE_PLANE.as_ptr(), &mut parent)
            };
            if status != 0 || parent == 0 {
                return None;
            }
            current = Object(parent);
        }
        None
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn reader_usb_device_id(_reader_name: &str) -> Option<UsbDeviceId> {
        // The macOS smart card stack does not expose the USB device of a reader.
        None
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn connection_usb_device_id(_conn: &PcscSmartCardConnection) -> Option<UsbDeviceId> {
        None
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use super::UsbDeviceId;
    #[cfg(feature = "pcsc")]
    use crate::platform::pcsc::PcscSmartCardConnection;

    #[cfg(feature = "hid")]
    pub(super) fn hid_usb_device_id(_hid_path: &str) -> Option<UsbDeviceId> {
        None
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn reader_usb_device_id(_reader_name: &str) -> Option<UsbDeviceId> {
        None
    }

    #[cfg(feature = "pcsc")]
    pub(super) fn connection_usb_device_id(_conn: &PcscSmartCardConnection) -> Option<UsbDeviceId> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_instance_from_interface_path() {
        assert_eq!(
            device_instance_from_path(
                r"\\?\HID#VID_1050&PID_0407&MI_01#7&181685db&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"
            )
            .as_deref(),
            Some(r"HID\VID_1050&PID_0407&MI_01\7&181685db&0&0000")
        );
        // A keyboard collection carries a reference string after the GUID.
        assert_eq!(
            device_instance_from_path(
                r"\\?\HID#VID_1050&PID_0407&MI_00#7&181685db&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}\KBD"
            )
            .as_deref(),
            Some(r"HID\VID_1050&PID_0407&MI_00\7&181685db&0&0000")
        );
        assert_eq!(
            device_instance_from_path(
                r"\\?\USB#VID_1050&PID_0407&MI_02#7&2c3d4e5f&0&0002#{50dd5230-ba8a-11d1-bf5d-0000f805f530}"
            )
            .as_deref(),
            Some(r"USB\VID_1050&PID_0407&MI_02\7&2c3d4e5f&0&0002")
        );
    }

    #[test]
    fn device_instance_from_malformed_path() {
        for path in [
            "",
            r"\\?\",
            r"\\?\HID#VID_1050#{guid}",
            r"\\?\HID##7&1#{guid}",
            r"\\?\HID#VID_1050#7&1#guid",
            r"\\?\HID#VID_1050#7&1#{guid}#extra",
            r"\\?\HID#VID_1050#7&1#{guid}x",
            r"HID#VID_1050#7&1#{guid}",
        ] {
            assert_eq!(device_instance_from_path(path), None, "{path}");
        }
    }
}
