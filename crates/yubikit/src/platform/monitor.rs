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

//! Event-based monitoring of connected YubiKey devices.
//!
//! [`monitor_device_events`] reports [`NodeEvent`]s as low-level device
//! interfaces appear and disappear. It first emits `Added` events for every
//! currently-connected interface, then blocks and reports changes as they
//! happen.
//!
//! Two transports are monitored:
//!
//! - **PC/SC** — YubiKeys connected over USB report both a
//!   [`DeviceNode::UsbReaderNode`] (the reader) and a
//!   [`DeviceNode::CardNode`] (the card). YubiKeys placed on an NFC reader
//!   report only a [`DeviceNode::CardNode`] — the reader itself is not
//!   tracked.
//! - **HID** — the OTP and FIDO interfaces are tracked separately as
//!   [`DeviceNode::HidOtpNode`] and [`DeviceNode::HidFidoNode`].
//!
//! PC/SC provides native change notifications. HID change detection is
//! platform-specific: `udev` on Linux, `WM_DEVICECHANGE` window messages on
//! Windows, and `IOHIDManager` callbacks on macOS.
//!
//! Card events reflect the live state of the reader: an ejected card is
//! reported removed immediately, and a re-inserted card is reported added
//! immediately. Note that older YubiKeys (e.g. the NEO) expose only a single
//! active USB transport at a time, so accessing their OTP/FIDO HID interface
//! transiently ejects and re-inserts the CCID card, which surfaces as a
//! matching pair of card removal/insertion events.

use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::device::DeviceError;
use crate::management::{DeviceInfo, UsbInterface};

#[cfg(feature = "pcsc")]
use super::device::pid_from_reader_name;
#[cfg(feature = "hid")]
use super::hidapi::{
    FidoDeviceInfo, HidFidoConnection, HidOtpConnection, list_fido_devices, list_otp_devices,
};
#[cfg(feature = "pcsc")]
use super::pcsc::{PcscSmartCardConnection, is_reader_usb, list_readers_with_state};
#[cfg(feature = "pcsc")]
use crate::device::read_info_ccid;
#[cfg(feature = "hid")]
use crate::device::{read_info_fido, read_info_otp};

/// A low-level device interface discovered by [`monitor_device_events`].
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceNode {
    /// A PC/SC reader belonging to a USB-connected YubiKey.
    UsbReaderNode {
        /// The PC/SC reader name.
        reader_name: String,
        /// The USB Product ID derived from the reader name.
        pid: u16,
    },
    /// A YubiKey card present in a PC/SC reader (USB or NFC).
    CardNode {
        /// The PC/SC reader name the card is present in.
        reader_name: String,
        /// Device info read from the card over CCID.
        device_info: DeviceInfo,
    },
    /// A YubiKey OTP HID interface.
    HidOtpNode {
        /// The OS-specific HID device path.
        hid_path: String,
        /// The USB Product ID.
        pid: u16,
        /// Device info read over the OTP interface.
        device_info: DeviceInfo,
    },
    /// A YubiKey FIDO HID interface.
    HidFidoNode {
        /// The OS-specific HID device path.
        hid_path: String,
        /// The USB Product ID.
        pid: u16,
        /// Device info read over the FIDO interface.
        device_info: DeviceInfo,
    },
}

/// A change in the set of connected [`DeviceNode`]s.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeEvent {
    /// A device interface was connected.
    Added(DeviceNode),
    /// A device interface was disconnected.
    Removed(DeviceNode),
}

/// A wake-up signal from one of the transport watchers.
enum Change {
    #[cfg(feature = "pcsc")]
    Pcsc,
    #[cfg(feature = "hid")]
    Hid,
}

/// Monitor connected YubiKey device interfaces and report [`NodeEvent`]s.
///
/// `usb_interfaces` selects which interfaces to monitor:
///
/// - [`UsbInterface::CCID`] enables PC/SC (reader and card) monitoring.
/// - [`UsbInterface::OTP`] enables OTP HID monitoring.
/// - [`UsbInterface::FIDO`] enables FIDO HID monitoring.
///
/// The function first emits an [`NodeEvent::Added`] for every currently
/// connected interface, then blocks and invokes `on_event` for each change.
/// It runs until the process is stopped (there is no graceful stop signal —
/// callers such as CLI tools terminate the process, e.g. on Ctrl+C).
pub fn monitor_device_events(
    usb_interfaces: UsbInterface,
    mut on_event: impl FnMut(NodeEvent),
) -> Result<(), DeviceError> {
    let (tx, rx) = mpsc::channel::<Change>();
    let mut state = MonitorState::default();

    // Emit events for the initial state before spawning watchers.
    #[cfg(feature = "pcsc")]
    if usb_interfaces.contains(UsbInterface::CCID) {
        state.refresh_pcsc(&mut on_event);
        spawn_pcsc_watcher(tx.clone());
    }
    #[cfg(feature = "hid")]
    if usb_interfaces.contains(UsbInterface::OTP) || usb_interfaces.contains(UsbInterface::FIDO) {
        state.refresh_hid(usb_interfaces, &mut on_event);
        spawn_hid_watcher(tx.clone());
    }

    // Drop our own sender so the loop can exit if every watcher thread stops.
    drop(tx);

    loop {
        let change = match rx.recv() {
            Ok(change) => change,
            Err(_) => return Ok(()),
        };

        match change {
            #[cfg(feature = "pcsc")]
            Change::Pcsc => state.refresh_pcsc(&mut on_event),
            #[cfg(feature = "hid")]
            Change::Hid => state.refresh_hid(usb_interfaces, &mut on_event),
        }
    }
}

/// Tracked state for the monitor loop.
#[derive(Default)]
struct MonitorState {
    /// USB reader nodes, keyed by reader name.
    #[cfg(feature = "pcsc")]
    usb_readers: HashMap<String, DeviceNode>,
    /// Card nodes, keyed by reader name.
    #[cfg(feature = "pcsc")]
    cards: HashMap<String, DeviceNode>,
    /// OTP HID nodes, keyed by HID path.
    #[cfg(feature = "hid")]
    hid_otp: HashMap<String, DeviceNode>,
    /// FIDO HID nodes, keyed by HID path.
    #[cfg(feature = "hid")]
    hid_fido: HashMap<String, DeviceNode>,
}

#[cfg(feature = "pcsc")]
impl MonitorState {
    /// Re-enumerate PC/SC readers and emit events for any changes.
    fn refresh_pcsc(&mut self, on_event: &mut impl FnMut(NodeEvent)) {
        let readers = match list_readers_with_state() {
            Ok(readers) => readers,
            Err(e) => {
                log::debug!("PC/SC enumeration failed: {e}");
                return;
            }
        };
        let present: HashMap<&str, bool> = readers.iter().map(|(n, p)| (n.as_str(), *p)).collect();

        // --- Handle readers that have disappeared entirely (USB unplug) ---
        let gone: Vec<String> = self
            .usb_readers
            .keys()
            .filter(|name| !present.contains_key(name.as_str()))
            .cloned()
            .collect();
        for name in gone {
            // Card first, then reader.
            if let Some(node) = self.cards.remove(&name) {
                on_event(NodeEvent::Removed(node));
            }
            if let Some(node) = self.usb_readers.remove(&name) {
                on_event(NodeEvent::Removed(node));
            }
        }
        // NFC cards whose reader disappeared.
        let gone_cards: Vec<String> = self
            .cards
            .keys()
            .filter(|name| !present.contains_key(name.as_str()))
            .cloned()
            .collect();
        for name in gone_cards {
            if let Some(node) = self.cards.remove(&name) {
                on_event(NodeEvent::Removed(node));
            }
        }

        // --- Process each currently-connected reader ---
        for (name, card_present) in &readers {
            let usb = is_reader_usb(name);

            // USB reader node.
            if usb
                && let Some(pid) = pid_from_reader_name(name)
                && !self.usb_readers.contains_key(name)
            {
                let node = DeviceNode::UsbReaderNode {
                    reader_name: name.clone(),
                    pid,
                };
                self.usb_readers.insert(name.clone(), node.clone());
                on_event(NodeEvent::Added(node));
            }

            if *card_present {
                if !self.cards.contains_key(name) {
                    match read_card_info(name, usb) {
                        Ok(info) => {
                            let node = DeviceNode::CardNode {
                                reader_name: name.clone(),
                                device_info: info,
                            };
                            self.cards.insert(name.clone(), node.clone());
                            on_event(NodeEvent::Added(node));
                        }
                        Err(e) => {
                            log::debug!("Reading card info from '{name}' failed: {e}");
                        }
                    }
                }
            } else if let Some(node) = self.cards.remove(name) {
                on_event(NodeEvent::Removed(node));
            }
        }
    }
}

#[cfg(feature = "hid")]
impl MonitorState {
    /// Re-enumerate HID devices and emit events for any changes.
    fn refresh_hid(&mut self, interfaces: UsbInterface, on_event: &mut impl FnMut(NodeEvent)) {
        if interfaces.contains(UsbInterface::OTP) {
            match list_otp_devices() {
                Ok(devices) => {
                    let current: HashMap<&str, u16> =
                        devices.iter().map(|d| (d.path.as_str(), d.pid)).collect();
                    // Removals.
                    let gone: Vec<String> = self
                        .hid_otp
                        .keys()
                        .filter(|path| !current.contains_key(path.as_str()))
                        .cloned()
                        .collect();
                    for path in gone {
                        if let Some(node) = self.hid_otp.remove(&path) {
                            on_event(NodeEvent::Removed(node));
                        }
                    }
                    // Additions.
                    for device in &devices {
                        if self.hid_otp.contains_key(&device.path) {
                            continue;
                        }
                        match read_otp_info(&device.path, device.pid) {
                            Ok(info) => {
                                let node = DeviceNode::HidOtpNode {
                                    hid_path: device.path.clone(),
                                    pid: device.pid,
                                    device_info: info,
                                };
                                self.hid_otp.insert(device.path.clone(), node.clone());
                                on_event(NodeEvent::Added(node));
                            }
                            Err(e) => {
                                log::debug!("Reading OTP info from '{}' failed: {e}", device.path);
                            }
                        }
                    }
                }
                Err(e) => log::debug!("OTP HID enumeration failed: {e}"),
            }
        }

        if interfaces.contains(UsbInterface::FIDO) {
            match list_fido_devices() {
                Ok(devices) => {
                    let current: HashMap<&str, u16> =
                        devices.iter().map(|d| (d.path.as_str(), d.pid)).collect();
                    // Removals.
                    let gone: Vec<String> = self
                        .hid_fido
                        .keys()
                        .filter(|path| !current.contains_key(path.as_str()))
                        .cloned()
                        .collect();
                    for path in gone {
                        if let Some(node) = self.hid_fido.remove(&path) {
                            on_event(NodeEvent::Removed(node));
                        }
                    }
                    // Additions.
                    for device in &devices {
                        if self.hid_fido.contains_key(&device.path) {
                            continue;
                        }
                        match read_fido_info(device) {
                            Ok(info) => {
                                let node = DeviceNode::HidFidoNode {
                                    hid_path: device.path.clone(),
                                    pid: device.pid,
                                    device_info: info,
                                };
                                self.hid_fido.insert(device.path.clone(), node.clone());
                                on_event(NodeEvent::Added(node));
                            }
                            Err(e) => {
                                log::debug!("Reading FIDO info from '{}' failed: {e}", device.path);
                            }
                        }
                    }
                }
                Err(e) => log::debug!("FIDO HID enumeration failed: {e}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Info readers
// ---------------------------------------------------------------------------

#[cfg(feature = "pcsc")]
fn read_card_info(reader_name: &str, usb: bool) -> Result<DeviceInfo, DeviceError> {
    let conn = PcscSmartCardConnection::open(reader_name)?;
    let pid = if usb {
        pid_from_reader_name(reader_name)
    } else {
        None
    };
    let (info, _conn) = read_info_ccid(conn, pid)?;
    Ok(info)
}

#[cfg(feature = "hid")]
fn read_otp_info(path: &str, pid: u16) -> Result<DeviceInfo, DeviceError> {
    let conn = HidOtpConnection::new(path)?;
    read_info_otp(conn, pid)
        .map(|(info, _)| info)
        .map_err(|(e, _)| e)
}

#[cfg(feature = "hid")]
fn read_fido_info(device: &FidoDeviceInfo) -> Result<DeviceInfo, DeviceError> {
    let conn = HidFidoConnection::open(device)?;
    read_info_fido(conn, device.pid)
        .map(|(info, _)| info)
        .map_err(|(e, _)| e)
}

// ---------------------------------------------------------------------------
// PC/SC watcher
// ---------------------------------------------------------------------------

#[cfg(feature = "pcsc")]
fn spawn_pcsc_watcher(tx: mpsc::Sender<Change>) {
    thread::spawn(move || pcsc_watch_loop(&tx));
}

/// Block on PC/SC status changes and signal the monitor loop on each change.
///
/// Uses the special `\\?PnP?\Notification` pseudo-reader to detect reader
/// arrival/removal in addition to per-reader card state changes. This relies
/// on `SCardGetStatusChange` blocking until a reader or card state changes.
#[cfg(all(feature = "pcsc", not(windows)))]
fn pcsc_watch_loop(tx: &mpsc::Sender<Change>) {
    use ::pcsc::{Context, PNP_NOTIFICATION, ReaderState, Scope, State};
    use std::ffi::CString;

    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(e) => {
            log::debug!("PC/SC watcher couldn't establish context: {e}");
            return;
        }
    };
    let mut states: Vec<ReaderState> = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];

    loop {
        // Refresh the tracked reader list (readers may have come or gone).
        let names = current_reader_names(&ctx);

        // Drop states for readers that no longer exist (keep the PnP sentinel).
        states.retain(|rs| {
            rs.name() == PNP_NOTIFICATION()
                || names
                    .iter()
                    .any(|n| n.as_str() == rs.name().to_string_lossy().as_ref())
        });
        // Add states for newly-appeared readers.
        for name in &names {
            let known = states
                .iter()
                .any(|rs| rs.name().to_string_lossy().as_ref() == name.as_str());
            if !known && let Ok(cname) = CString::new(name.as_str()) {
                states.push(ReaderState::new(cname, State::UNAWARE));
            }
        }

        match ctx.get_status_change(Some(Duration::from_secs(1)), &mut states) {
            Ok(()) => {
                for rs in &mut states {
                    rs.sync_current_state();
                }
                if tx.send(Change::Pcsc).is_err() {
                    return;
                }
            }
            Err(::pcsc::Error::Timeout) => {
                for rs in &mut states {
                    rs.sync_current_state();
                }
            }
            Err(e) => {
                log::debug!("PC/SC watcher stopped: {e}");
                return;
            }
        }
    }
}

/// Windows PC/SC watcher.
///
/// `SCardGetStatusChange` blocking waits are unreliable in some Windows
/// environments: once a `current_state` that matches the live reader state
/// (including the event count required to suppress spurious PnP change
/// notifications) is supplied, the call returns `ERROR_ACCESS_DENIED` instead
/// of blocking. Rather than depend on that behaviour, poll the reader list at
/// a fixed interval and let the monitor loop diff it. `list_readers` snapshots
/// (used by the monitor's `refresh_pcsc`) are reliable here.
#[cfg(all(feature = "pcsc", windows))]
fn pcsc_watch_loop(tx: &mpsc::Sender<Change>) {
    const POLL_INTERVAL: Duration = Duration::from_millis(750);
    loop {
        thread::sleep(POLL_INTERVAL);
        if tx.send(Change::Pcsc).is_err() {
            return;
        }
    }
}

/// List reader names for the given context, returning an empty list on error.
#[cfg(all(feature = "pcsc", not(windows)))]
fn current_reader_names(ctx: &::pcsc::Context) -> Vec<String> {
    let len = match ctx.list_readers_len() {
        Ok(len) => len,
        Err(_) => return Vec::new(),
    };
    let mut buf = vec![0u8; len];
    match ctx.list_readers(&mut buf) {
        Ok(readers) => readers.map(|r| r.to_string_lossy().into_owned()).collect(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// HID watcher (platform-specific)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "hid", target_os = "linux"))]
fn spawn_hid_watcher(tx: mpsc::Sender<Change>) {
    use std::os::fd::AsRawFd;

    thread::spawn(move || {
        let socket = match udev::MonitorBuilder::new()
            .and_then(|builder| builder.match_subsystem("hidraw"))
            .and_then(|builder| builder.listen())
        {
            Ok(socket) => socket,
            Err(e) => {
                log::debug!("Failed to start udev HID monitor: {e}");
                return;
            }
        };

        loop {
            let mut pollfd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut pollfd, 1, 1000) };
            if result < 0 {
                log::debug!(
                    "udev HID monitor poll failed: {}",
                    std::io::Error::last_os_error()
                );
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            if result == 0 {
                continue;
            }

            let mut relevant = false;
            for event in socket.iter() {
                if matches!(
                    event.event_type(),
                    udev::EventType::Add
                        | udev::EventType::Remove
                        | udev::EventType::Change
                        | udev::EventType::Bind
                        | udev::EventType::Unbind
                ) {
                    relevant = true;
                }
            }
            if relevant && tx.send(Change::Hid).is_err() {
                return;
            }
        }
    });
}

#[cfg(all(feature = "hid", target_os = "windows"))]
fn spawn_hid_watcher(tx: mpsc::Sender<Change>) {
    thread::spawn(move || windows_hid::run(tx));
}

#[cfg(all(feature = "hid", target_os = "macos"))]
fn spawn_hid_watcher(tx: mpsc::Sender<Change>) {
    thread::spawn(move || macos_hid::run(tx));
}

#[cfg(all(
    feature = "hid",
    not(any(target_os = "linux", target_os = "windows", target_os = "macos"))
))]
fn spawn_hid_watcher(tx: mpsc::Sender<Change>) {
    let _ = tx;
    log::warn!("HID device-event monitoring is not supported on this platform");
}

// ---------------------------------------------------------------------------
// Windows HID watcher: message-only window listening for WM_DEVICECHANGE.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "hid", target_os = "windows"))]
mod windows_hid {
    use super::Change;
    use std::cell::RefCell;
    use std::sync::mpsc;
    use windows_sys::Win32::Devices::HumanInterfaceDevice::GUID_DEVINTERFACE_HID;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE, DBT_DEVTYP_DEVICEINTERFACE,
        DEV_BROADCAST_DEVICEINTERFACE_W, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW,
        DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG, RegisterClassW,
        RegisterDeviceNotificationW, TranslateMessage, WM_DEVICECHANGE, WNDCLASSW,
    };

    thread_local! {
        static SENDER: RefCell<Option<mpsc::Sender<Change>>> = const { RefCell::new(None) };
    }

    /// Encode a NUL-terminated UTF-16 string for Win32 wide APIs.
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_DEVICECHANGE
            && (wparam == DBT_DEVICEARRIVAL as WPARAM
                || wparam == DBT_DEVICEREMOVECOMPLETE as WPARAM)
        {
            SENDER.with(|sender| {
                if let Some(tx) = sender.borrow().as_ref() {
                    let _ = tx.send(Change::Hid);
                }
            });
            return 0;
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    pub(super) fn run(tx: mpsc::Sender<Change>) {
        SENDER.with(|sender| *sender.borrow_mut() = Some(tx));

        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name = wide("YubiKitHidMonitor");

            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class_name.as_ptr();
            RegisterClassW(&wc);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                hinstance,
                std::ptr::null(),
            );
            if hwnd.is_null() {
                log::debug!("Failed to create HID monitor window");
                return;
            }

            // Register for HID device interface change notifications.
            let mut filter: DEV_BROADCAST_DEVICEINTERFACE_W = std::mem::zeroed();
            filter.dbcc_size = std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>() as u32;
            filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
            filter.dbcc_classguid = GUID_DEVINTERFACE_HID;
            let notify = RegisterDeviceNotificationW(
                hwnd as _,
                &mut filter as *mut _ as *mut _,
                DEVICE_NOTIFY_WINDOW_HANDLE,
            );
            if notify.is_null() {
                log::debug!("Failed to register for HID device notifications");
                return;
            }

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS HID watcher: IOHIDManager device matching/removal callbacks.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "hid", target_os = "macos"))]
mod macos_hid {
    use super::Change;
    use core_foundation_sys::base::{CFAllocatorRef, kCFAllocatorDefault};
    use core_foundation_sys::dictionary::CFDictionaryRef;
    use core_foundation_sys::runloop::{
        CFRunLoopGetCurrent, CFRunLoopRef, CFRunLoopRun, kCFRunLoopDefaultMode,
    };
    use core_foundation_sys::string::CFStringRef;
    use std::os::raw::c_void;
    use std::sync::mpsc;

    #[repr(C)]
    struct IOHIDManager(c_void);
    type IOHIDManagerRef = *mut IOHIDManager;
    type IOHIDDeviceRef = *mut c_void;
    type IOReturn = i32;
    type IOOptionBits = u32;
    type IOHIDDeviceCallback = extern "C" fn(
        context: *mut c_void,
        result: IOReturn,
        sender: *mut c_void,
        device: IOHIDDeviceRef,
    );

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOHIDManagerCreate(allocator: CFAllocatorRef, options: IOOptionBits) -> IOHIDManagerRef;
        fn IOHIDManagerSetDeviceMatching(manager: IOHIDManagerRef, matching: CFDictionaryRef);
        fn IOHIDManagerRegisterDeviceMatchingCallback(
            manager: IOHIDManagerRef,
            callback: IOHIDDeviceCallback,
            context: *mut c_void,
        );
        fn IOHIDManagerRegisterDeviceRemovalCallback(
            manager: IOHIDManagerRef,
            callback: IOHIDDeviceCallback,
            context: *mut c_void,
        );
        fn IOHIDManagerScheduleWithRunLoop(
            manager: IOHIDManagerRef,
            run_loop: CFRunLoopRef,
            run_loop_mode: CFStringRef,
        );
        fn IOHIDManagerOpen(manager: IOHIDManagerRef, options: IOOptionBits) -> IOReturn;
    }

    extern "C" fn device_callback(
        context: *mut c_void,
        _result: IOReturn,
        _sender: *mut c_void,
        _device: IOHIDDeviceRef,
    ) {
        // SAFETY: `context` is a pointer to a leaked `Sender<Change>` that
        // lives for the duration of the run loop (i.e. the process).
        let tx = unsafe { &*(context as *const mpsc::Sender<Change>) };
        let _ = tx.send(Change::Hid);
    }

    pub(super) fn run(tx: mpsc::Sender<Change>) {
        unsafe {
            let manager = IOHIDManagerCreate(kCFAllocatorDefault, 0);
            if manager.is_null() {
                log::debug!("Failed to create IOHIDManager");
                return;
            }
            // Match all HID devices; the monitor loop filters to YubiKeys.
            IOHIDManagerSetDeviceMatching(manager, std::ptr::null());

            // Leak the sender so it remains valid for the callbacks' lifetime.
            let context = Box::into_raw(Box::new(tx)) as *mut c_void;
            IOHIDManagerRegisterDeviceMatchingCallback(manager, device_callback, context);
            IOHIDManagerRegisterDeviceRemovalCallback(manager, device_callback, context);
            IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
            IOHIDManagerOpen(manager, 0);

            CFRunLoopRun();
        }
    }
}
