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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::core::Transport;
use crate::device::DeviceError;
use crate::management::{DeviceInfo, UsbInterface};
use crate::platform::device::LocalYubiKeyDevice;

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

/// A wake-up signal delivered to the coordination loop.
enum Change {
    /// A PC/SC reader or card state changed; re-diff the PC/SC transport.
    #[cfg(feature = "pcsc")]
    Pcsc,
    /// A HID device was added or removed; re-diff the HID transport.
    #[cfg(feature = "hid")]
    Hid,
    /// Shut down the coordination loop.
    Stop,
}

/// Shared shutdown state, used to stop the coordination loop and wake every
/// watcher thread out of its blocking wait.
struct Shutdown {
    /// Set once a stop has been requested. Polling watchers check this.
    stopped: AtomicBool,
    /// Retained sender used to wake the coordination loop's `recv`.
    stop_tx: mpsc::Sender<Change>,
    /// Cloned PC/SC context, used to cancel a blocking `get_status_change`.
    #[cfg(all(feature = "pcsc", not(windows)))]
    pcsc_ctx: std::sync::Mutex<Option<::pcsc::Context>>,
    /// Thread id of the Windows HID message loop, used to post `WM_QUIT`.
    #[cfg(all(feature = "hid", target_os = "windows"))]
    win_thread_id: std::sync::atomic::AtomicU32,
    /// `CFRunLoopRef` (as `usize`) of the macOS HID run loop, used to stop it.
    #[cfg(all(feature = "hid", target_os = "macos"))]
    macos_runloop: std::sync::Mutex<Option<usize>>,
}

impl Shutdown {
    fn new(stop_tx: mpsc::Sender<Change>) -> Self {
        Self {
            stopped: AtomicBool::new(false),
            stop_tx,
            #[cfg(all(feature = "pcsc", not(windows)))]
            pcsc_ctx: std::sync::Mutex::new(None),
            #[cfg(all(feature = "hid", target_os = "windows"))]
            win_thread_id: std::sync::atomic::AtomicU32::new(0),
            #[cfg(all(feature = "hid", target_os = "macos"))]
            macos_runloop: std::sync::Mutex::new(None),
        }
    }

    /// Whether a stop has been requested.
    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Request shutdown and wake every watcher out of its blocking wait.
    ///
    /// Idempotent: the wakeups only run on the first call.
    fn signal_stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }

        // Wake the coordination loop.
        let _ = self.stop_tx.send(Change::Stop);

        // Cancel a blocking PC/SC `get_status_change` (Unix event-driven path).
        #[cfg(all(feature = "pcsc", not(windows)))]
        if let Some(ctx) = self.pcsc_ctx.lock().unwrap().as_ref() {
            let _ = ctx.cancel();
        }

        // Post WM_QUIT to the Windows HID message loop.
        #[cfg(all(feature = "hid", target_os = "windows"))]
        {
            let tid = self.win_thread_id.load(Ordering::SeqCst);
            if tid != 0 {
                use windows_sys::Win32::UI::WindowsAndMessaging::{PostThreadMessageW, WM_QUIT};
                unsafe { PostThreadMessageW(tid, WM_QUIT, 0, 0) };
            }
        }

        // Stop the macOS HID run loop.
        #[cfg(all(feature = "hid", target_os = "macos"))]
        if let Some(rl) = *self.macos_runloop.lock().unwrap() {
            use core_foundation_sys::runloop::{CFRunLoopRef, CFRunLoopStop};
            unsafe { CFRunLoopStop(rl as CFRunLoopRef) };
        }
    }
}

/// A running device monitor.
///
/// Returned by [`monitor_device_events`]. The monitor runs on background
/// threads; call [`MonitorHandle::stop`] to shut it down and join those
/// threads. Dropping the handle also stops the monitor.
#[must_use = "the monitor stops when the handle is dropped"]
pub struct MonitorHandle {
    shutdown: Arc<Shutdown>,
    threads: Vec<JoinHandle<()>>,
}

impl MonitorHandle {
    /// Stop the monitor and wait for its threads to finish.
    ///
    /// No further [`NodeEvent`]s are delivered after this returns.
    pub fn stop(mut self) {
        self.shutdown_and_join();
    }

    fn shutdown_and_join(&mut self) {
        self.shutdown.signal_stop();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }

    /// Attach an extra thread to be joined when the monitor is stopped.
    ///
    /// Used by [`monitor_yubikeys`] to keep its aggregation thread alive for
    /// the lifetime of the handle.
    fn attach_thread(&mut self, handle: JoinHandle<()>) {
        self.threads.push(handle);
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}

/// Monitor connected YubiKey device interfaces and report [`NodeEvent`]s.
///
/// `usb_interfaces` selects which interfaces to monitor:
///
/// - [`UsbInterface::CCID`] enables PC/SC (reader and card) monitoring.
/// - [`UsbInterface::OTP`] enables OTP HID monitoring.
/// - [`UsbInterface::FIDO`] enables FIDO HID monitoring.
///
/// Monitoring runs on background threads. `on_event` is first invoked with an
/// [`NodeEvent::Added`] for every currently-connected interface, then once per
/// change. It is always called from a single dedicated thread, so it does not
/// need to be synchronized.
///
/// The returned [`MonitorHandle`] keeps the monitor running until
/// [`MonitorHandle::stop`] is called or the handle is dropped.
pub fn monitor_device_events(
    usb_interfaces: UsbInterface,
    mut on_event: impl FnMut(NodeEvent) + Send + 'static,
) -> MonitorHandle {
    let (tx, rx) = mpsc::channel::<Change>();
    let shutdown = Arc::new(Shutdown::new(tx.clone()));
    let mut threads: Vec<JoinHandle<()>> = Vec::new();

    #[cfg(feature = "pcsc")]
    if usb_interfaces.contains(UsbInterface::CCID) {
        threads.push(spawn_pcsc_watcher(tx.clone(), Arc::clone(&shutdown)));
    }
    #[cfg(feature = "hid")]
    if usb_interfaces.contains(UsbInterface::OTP) || usb_interfaces.contains(UsbInterface::FIDO) {
        threads.push(spawn_hid_watcher(tx.clone(), Arc::clone(&shutdown)));
    }
    drop(tx);

    // Coordination loop: owns the tracked state and calls `on_event`.
    let coordinator = thread::spawn(move || {
        let mut state = MonitorState::default();

        // Emit events for the initial state before processing changes.
        #[cfg(feature = "pcsc")]
        if usb_interfaces.contains(UsbInterface::CCID) {
            state.refresh_pcsc(&mut on_event);
        }
        #[cfg(feature = "hid")]
        if usb_interfaces.contains(UsbInterface::OTP) || usb_interfaces.contains(UsbInterface::FIDO)
        {
            state.refresh_hid(usb_interfaces, &mut on_event);
        }

        while let Ok(change) = rx.recv() {
            match change {
                Change::Stop => break,
                #[cfg(feature = "pcsc")]
                Change::Pcsc => state.refresh_pcsc(&mut on_event),
                #[cfg(feature = "hid")]
                Change::Hid => state.refresh_hid(usb_interfaces, &mut on_event),
            }
        }
    });
    threads.push(coordinator);

    MonitorHandle { shutdown, threads }
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
fn spawn_pcsc_watcher(tx: mpsc::Sender<Change>, shutdown: Arc<Shutdown>) -> JoinHandle<()> {
    thread::spawn(move || pcsc_watch_loop(&tx, &shutdown))
}

/// Block on PC/SC status changes and signal the monitor loop on each change.
///
/// Uses the special `\\?PnP?\Notification` pseudo-reader to detect reader
/// arrival/removal in addition to per-reader card state changes. This relies
/// on `SCardGetStatusChange` blocking until a reader or card state changes.
/// A concurrent [`Context::cancel`](::pcsc::Context::cancel) (issued by
/// [`Shutdown::signal_stop`]) unblocks the wait so the thread can exit.
#[cfg(all(feature = "pcsc", not(windows)))]
fn pcsc_watch_loop(tx: &mpsc::Sender<Change>, shutdown: &Shutdown) {
    use ::pcsc::{Context, PNP_NOTIFICATION, ReaderState, Scope, State};
    use std::ffi::CString;

    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(e) => {
            log::debug!("PC/SC watcher couldn't establish context: {e}");
            return;
        }
    };
    // Publish a cancel handle so shutdown can unblock get_status_change.
    *shutdown.pcsc_ctx.lock().unwrap() = Some(ctx.clone());
    if shutdown.is_stopped() {
        return;
    }
    let mut states: Vec<ReaderState> = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];

    loop {
        if shutdown.is_stopped() {
            return;
        }

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
                if shutdown.is_stopped() || tx.send(Change::Pcsc).is_err() {
                    return;
                }
            }
            Err(::pcsc::Error::Timeout) => {
                for rs in &mut states {
                    rs.sync_current_state();
                }
            }
            Err(e) => {
                if !shutdown.is_stopped() {
                    log::debug!("PC/SC watcher stopped: {e}");
                }
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
///
/// Stop latency is bounded by the poll interval, since the loop checks the
/// shutdown flag each iteration.
#[cfg(all(feature = "pcsc", windows))]
fn pcsc_watch_loop(tx: &mpsc::Sender<Change>, shutdown: &Shutdown) {
    const POLL_INTERVAL: Duration = Duration::from_millis(750);
    while !shutdown.is_stopped() {
        thread::sleep(POLL_INTERVAL);
        if shutdown.is_stopped() || tx.send(Change::Pcsc).is_err() {
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
fn spawn_hid_watcher(tx: mpsc::Sender<Change>, shutdown: Arc<Shutdown>) -> JoinHandle<()> {
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
            if shutdown.is_stopped() {
                return;
            }
            let mut pollfd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // Wake at least once a second to re-check the shutdown flag.
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
            if relevant && (shutdown.is_stopped() || tx.send(Change::Hid).is_err()) {
                return;
            }
        }
    })
}

#[cfg(all(feature = "hid", target_os = "windows"))]
fn spawn_hid_watcher(tx: mpsc::Sender<Change>, shutdown: Arc<Shutdown>) -> JoinHandle<()> {
    thread::spawn(move || windows_hid::run(tx, &shutdown))
}

#[cfg(all(feature = "hid", target_os = "macos"))]
fn spawn_hid_watcher(tx: mpsc::Sender<Change>, shutdown: Arc<Shutdown>) -> JoinHandle<()> {
    thread::spawn(move || macos_hid::run(tx, &shutdown))
}

#[cfg(all(
    feature = "hid",
    not(any(target_os = "linux", target_os = "windows", target_os = "macos"))
))]
fn spawn_hid_watcher(tx: mpsc::Sender<Change>, shutdown: Arc<Shutdown>) -> JoinHandle<()> {
    let _ = (tx, shutdown);
    log::warn!("HID device-event monitoring is not supported on this platform");
    thread::spawn(|| {})
}

// ---------------------------------------------------------------------------
// Windows HID watcher: message-only window listening for WM_DEVICECHANGE.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "hid", target_os = "windows"))]
mod windows_hid {
    use super::{Change, Shutdown};
    use std::cell::RefCell;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use windows_sys::Win32::Devices::HumanInterfaceDevice::GUID_DEVINTERFACE_HID;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE, DBT_DEVTYP_DEVICEINTERFACE,
        DEV_BROADCAST_DEVICEINTERFACE_W, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW,
        DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG, PM_NOREMOVE, PeekMessageW,
        RegisterClassW, RegisterDeviceNotificationW, TranslateMessage, WM_DEVICECHANGE, WM_USER,
        WNDCLASSW,
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

    pub(super) fn run(tx: mpsc::Sender<Change>, shutdown: &Shutdown) {
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

            // Force creation of this thread's message queue, then publish the
            // thread id so shutdown can post WM_QUIT to it. If a stop was
            // requested before we got here, bail out instead of blocking.
            let mut msg: MSG = std::mem::zeroed();
            PeekMessageW(
                &mut msg,
                std::ptr::null_mut(),
                WM_USER,
                WM_USER,
                PM_NOREMOVE,
            );
            shutdown
                .win_thread_id
                .store(GetCurrentThreadId(), Ordering::SeqCst);
            if shutdown.is_stopped() {
                return;
            }

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
    use super::{Change, Shutdown};
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
        fn IOHIDManagerUnscheduleFromRunLoop(
            manager: IOHIDManagerRef,
            run_loop: CFRunLoopRef,
            run_loop_mode: CFStringRef,
        );
        fn IOHIDManagerOpen(manager: IOHIDManagerRef, options: IOOptionBits) -> IOReturn;
        fn IOHIDManagerClose(manager: IOHIDManagerRef, options: IOOptionBits) -> IOReturn;
    }

    extern "C" fn device_callback(
        context: *mut c_void,
        _result: IOReturn,
        _sender: *mut c_void,
        _device: IOHIDDeviceRef,
    ) {
        // SAFETY: `context` is a pointer to a `Sender<Change>` owned by `run`,
        // which outlives the run loop (and hence every callback invocation).
        let tx = unsafe { &*(context as *const mpsc::Sender<Change>) };
        let _ = tx.send(Change::Hid);
    }

    pub(super) fn run(tx: mpsc::Sender<Change>, shutdown: &Shutdown) {
        // Keep the sender alive on the stack for the duration of the run loop;
        // callbacks borrow it via a raw pointer.
        let tx = Box::new(tx);
        let context = (&*tx as *const mpsc::Sender<Change>) as *mut c_void;

        unsafe {
            let manager = IOHIDManagerCreate(kCFAllocatorDefault, 0);
            if manager.is_null() {
                log::debug!("Failed to create IOHIDManager");
                return;
            }
            // Match all HID devices; the monitor loop filters to YubiKeys.
            IOHIDManagerSetDeviceMatching(manager, std::ptr::null());
            IOHIDManagerRegisterDeviceMatchingCallback(manager, device_callback, context);
            IOHIDManagerRegisterDeviceRemovalCallback(manager, device_callback, context);

            let run_loop = CFRunLoopGetCurrent();
            IOHIDManagerScheduleWithRunLoop(manager, run_loop, kCFRunLoopDefaultMode);
            IOHIDManagerOpen(manager, 0);

            // Publish the run loop so shutdown can stop it. If a stop was
            // requested before we got here, don't enter the run loop.
            *shutdown.macos_runloop.lock().unwrap() = Some(run_loop as usize);
            if !shutdown.is_stopped() {
                CFRunLoopRun();
            }

            IOHIDManagerUnscheduleFromRunLoop(manager, run_loop, kCFRunLoopDefaultMode);
            IOHIDManagerClose(manager, 0);
        }
        // `tx` is dropped here, after the run loop and its callbacks are done.
        drop(tx);
    }
}

// ---------------------------------------------------------------------------
// Higher-level aggregation: physical YubiKey devices.
// ---------------------------------------------------------------------------

/// A stable identifier for a monitored [`YubiKey`].
///
/// The id remains the same across [`YubiKeyEvent::Added`],
/// [`YubiKeyEvent::Changed`], and [`YubiKeyEvent::Removed`] for a given
/// physical device, so callers can correlate events over time.
pub type YubiKeyId = u64;

/// A physical YubiKey aggregated from one or more [`DeviceNode`]s.
///
/// Produced by [`monitor_yubikeys`]. The underlying [`LocalYubiKeyDevice`]
/// (returned by [`YubiKey::device`]) can be used to open connections.
#[derive(Debug, Clone)]
pub struct YubiKey {
    id: YubiKeyId,
    device: LocalYubiKeyDevice,
    nodes: Vec<DeviceNode>,
}

impl YubiKey {
    /// The stable identifier for this device.
    pub fn id(&self) -> YubiKeyId {
        self.id
    }

    /// The underlying device, which can open connections.
    pub fn device(&self) -> &LocalYubiKeyDevice {
        &self.device
    }

    /// Consume this `YubiKey`, returning the underlying device.
    pub fn into_device(self) -> LocalYubiKeyDevice {
        self.device
    }

    /// The [`DeviceNode`]s that make up this physical device.
    pub fn nodes(&self) -> &[DeviceNode] {
        &self.nodes
    }

    /// The device info.
    pub fn info(&self) -> &DeviceInfo {
        self.device.info()
    }

    /// The device serial number, if available.
    pub fn serial(&self) -> Option<u32> {
        self.device.info().serial
    }
}

/// A change in the set of connected physical [`YubiKey`]s.
#[derive(Debug, Clone)]
pub enum YubiKeyEvent {
    /// A new physical device was connected.
    Added(YubiKey),
    /// An existing device's underlying [`DeviceNode`]s changed.
    Changed(YubiKey),
    /// A device was disconnected (all its nodes were removed).
    Removed(YubiKey),
}

/// Monitor connected physical YubiKeys and report [`YubiKeyEvent`]s.
///
/// This is a higher-level version of [`monitor_device_events`] that aggregates
/// the low-level [`DeviceNode`] events into physical devices. Nodes that
/// belong to the same physical device (matched by serial number, or by USB
/// Product ID when a serial is not available) are merged into a single
/// [`YubiKey`].
///
/// Connecting or disconnecting a YubiKey produces several node events in quick
/// succession (one per interface). Events already queued when a change is
/// processed are drained together, so a burst is coalesced where possible, but
/// interfaces that are enumerated with a delay (a YubiKey's HID interfaces
/// often appear after its PC/SC reader) surface as [`YubiKeyEvent::Changed`].
///
/// A device that is only visible as a PC/SC reader (with no readable device
/// info yet) is held back and not reported until an info-bearing node appears.
///
/// Like [`monitor_device_events`], monitoring runs on background threads and
/// `on_event` is called from a single dedicated thread. The returned
/// [`MonitorHandle`] keeps the monitor running until stopped or dropped.
pub fn monitor_yubikeys(
    usb_interfaces: UsbInterface,
    mut on_event: impl FnMut(YubiKeyEvent) + Send + 'static,
) -> MonitorHandle {
    let (node_tx, node_rx) = mpsc::channel::<NodeEvent>();

    // Aggregation thread: applies node events and emits device events.
    let aggregator = thread::spawn(move || {
        let mut state = Aggregator::default();
        loop {
            match node_rx.recv() {
                Ok(event) => state.apply(event),
                // The monitor stopped; exit without emitting removals.
                Err(_) => return,
            }
            // Drain any events already queued so a burst of interface events
            // (a single physical insert/removal) is coalesced into one pass.
            while let Ok(event) = node_rx.try_recv() {
                state.apply(event);
            }
            state.reconcile(&mut on_event);
        }
    });

    let mut handle = monitor_device_events(usb_interfaces, move |event| {
        let _ = node_tx.send(event);
    });
    handle.attach_thread(aggregator);
    handle
}

/// Aggregates [`DeviceNode`]s into physical [`YubiKey`]s.
#[derive(Default)]
struct Aggregator {
    /// USB PC/SC reader nodes, keyed by reader name.
    usb_readers: HashMap<String, DeviceNode>,
    /// Card nodes (USB or NFC), keyed by reader name.
    cards: HashMap<String, DeviceNode>,
    /// OTP HID nodes, keyed by HID path.
    otp: HashMap<String, DeviceNode>,
    /// FIDO HID nodes, keyed by HID path.
    fido: HashMap<String, DeviceNode>,
    /// Currently-reported devices.
    devices: Vec<YubiKey>,
    /// Next id to assign.
    next_id: YubiKeyId,
}

impl Aggregator {
    /// Apply a single node event to the tracked node set.
    fn apply(&mut self, event: NodeEvent) {
        let (added, node) = match event {
            NodeEvent::Added(node) => (true, node),
            NodeEvent::Removed(node) => (false, node),
        };
        let (map, key) = match &node {
            DeviceNode::UsbReaderNode { reader_name, .. } => {
                (&mut self.usb_readers, reader_name.clone())
            }
            DeviceNode::CardNode { reader_name, .. } => (&mut self.cards, reader_name.clone()),
            DeviceNode::HidOtpNode { hid_path, .. } => (&mut self.otp, hid_path.clone()),
            DeviceNode::HidFidoNode { hid_path, .. } => (&mut self.fido, hid_path.clone()),
        };
        if added {
            map.insert(key, node);
        } else {
            map.remove(&key);
        }
    }

    /// Reconcile the aggregated device set with the last-reported set and emit
    /// events for the differences.
    ///
    /// Removals are emitted first, then additions, then changes.
    fn reconcile(&mut self, on_event: &mut impl FnMut(YubiKeyEvent)) {
        let built = self.build_devices();
        let prev = std::mem::take(&mut self.devices);
        let mut used = vec![false; prev.len()];

        let mut new_devices: Vec<YubiKey> = Vec::new();
        let mut added = Vec::new();
        let mut changed = Vec::new();

        for b in built {
            let b_serial = b.device.info().serial;
            let idx = (0..prev.len()).find(|&i| {
                if used[i] {
                    return false;
                }
                let p_serial = prev[i].device.info().serial;
                match (b_serial, p_serial) {
                    (Some(a), Some(c)) => a == c,
                    (Some(_), None) | (None, None) => shares_path(&b.device, &prev[i].device),
                    (None, Some(_)) => false,
                }
            });

            match idx {
                Some(i) => {
                    used[i] = true;
                    let yk = YubiKey {
                        id: prev[i].id,
                        device: b.device,
                        nodes: b.nodes,
                    };
                    if yk.nodes != prev[i].nodes {
                        changed.push(yk.clone());
                    }
                    new_devices.push(yk);
                }
                None => {
                    let id = self.next_id;
                    self.next_id += 1;
                    let yk = YubiKey {
                        id,
                        device: b.device,
                        nodes: b.nodes,
                    };
                    added.push(yk.clone());
                    new_devices.push(yk);
                }
            }
        }

        // Devices that lost all of their nodes are removed.
        let mut removed = Vec::new();
        for (i, p) in prev.into_iter().enumerate() {
            if !used[i] {
                removed.push(p);
            }
        }

        self.devices = new_devices;

        for p in removed {
            on_event(YubiKeyEvent::Removed(p));
        }
        for yk in added {
            on_event(YubiKeyEvent::Added(yk));
        }
        for yk in changed {
            on_event(YubiKeyEvent::Changed(yk));
        }
    }

    /// Group the current node set into physical devices.
    fn build_devices(&self) -> Vec<BuiltDevice> {
        let mut built = Vec::new();

        // NFC devices: a card in a reader with no matching USB reader node.
        // Each is a standalone device with a single card node.
        for (reader_name, node) in &self.cards {
            if self.usb_readers.contains_key(reader_name) {
                continue;
            }
            if let DeviceNode::CardNode { device_info, .. } = node {
                built.push(BuiltDevice {
                    device: LocalYubiKeyDevice::from_parts(
                        Some(reader_name.clone()),
                        None,
                        None,
                        None,
                        Transport::Nfc,
                        device_info.clone(),
                    ),
                    nodes: vec![node.clone()],
                });
            }
        }

        // Count physical USB devices per PID (max across interfaces).
        let mut counts: HashMap<u16, usize> = HashMap::new();
        {
            let mut per_iface: [HashMap<u16, usize>; 3] = Default::default();
            for node in self.usb_readers.values() {
                if let DeviceNode::UsbReaderNode { pid, .. } = node {
                    *per_iface[0].entry(*pid).or_insert(0) += 1;
                }
            }
            for node in self.otp.values() {
                if let DeviceNode::HidOtpNode { pid, .. } = node {
                    *per_iface[1].entry(*pid).or_insert(0) += 1;
                }
            }
            for node in self.fido.values() {
                if let DeviceNode::HidFidoNode { pid, .. } = node {
                    *per_iface[2].entry(*pid).or_insert(0) += 1;
                }
            }
            for map in &per_iface {
                for (&pid, &c) in map {
                    let e = counts.entry(pid).or_insert(0);
                    *e = (*e).max(c);
                }
            }
        }

        // USB partials, one per interface node.
        let mut readers: Vec<Partial> = Vec::new();
        for (reader_name, node) in &self.usb_readers {
            if let DeviceNode::UsbReaderNode { pid, .. } = node {
                let mut nodes = vec![node.clone()];
                let info = match self.cards.get(reader_name) {
                    Some(card @ DeviceNode::CardNode { device_info, .. }) => {
                        nodes.push(card.clone());
                        Some(device_info.clone())
                    }
                    _ => None,
                };
                readers.push(Partial {
                    reader_name: Some(reader_name.clone()),
                    hid_path: None,
                    fido_path: None,
                    pid: Some(*pid),
                    info,
                    nodes,
                });
            }
        }
        let otp: Vec<Partial> = self
            .otp
            .iter()
            .filter_map(|(path, node)| {
                if let DeviceNode::HidOtpNode {
                    pid, device_info, ..
                } = node
                {
                    Some(Partial {
                        reader_name: None,
                        hid_path: Some(path.clone()),
                        fido_path: None,
                        pid: Some(*pid),
                        info: Some(device_info.clone()),
                        nodes: vec![node.clone()],
                    })
                } else {
                    None
                }
            })
            .collect();
        let fido: Vec<Partial> = self
            .fido
            .iter()
            .filter_map(|(path, node)| {
                if let DeviceNode::HidFidoNode {
                    pid, device_info, ..
                } = node
                {
                    Some(Partial {
                        reader_name: None,
                        hid_path: None,
                        fido_path: Some(path.clone()),
                        pid: Some(*pid),
                        info: Some(device_info.clone()),
                        nodes: vec![node.clone()],
                    })
                } else {
                    None
                }
            })
            .collect();

        let mut base = readers;
        merge_partials(&mut base, otp, &counts);
        merge_partials(&mut base, fido, &counts);

        // A device is only reported once it has readable info; reader-only
        // devices are held back until an info-bearing node appears.
        for mut p in base {
            if let Some(info) = p.info.take() {
                p.nodes.sort_by(node_sort_key);
                built.push(BuiltDevice {
                    device: LocalYubiKeyDevice::from_parts(
                        p.reader_name,
                        p.hid_path,
                        p.fido_path,
                        p.pid,
                        Transport::Usb,
                        info,
                    ),
                    nodes: p.nodes,
                });
            }
        }

        built
    }
}

/// A device built from a group of merged nodes.
struct BuiltDevice {
    device: LocalYubiKeyDevice,
    nodes: Vec<DeviceNode>,
}

/// A partially-assembled USB device during merging.
struct Partial {
    reader_name: Option<String>,
    hid_path: Option<String>,
    fido_path: Option<String>,
    pid: Option<u16>,
    info: Option<DeviceInfo>,
    nodes: Vec<DeviceNode>,
}

impl Partial {
    fn serial(&self) -> Option<u32> {
        self.info.as_ref().and_then(|i| i.serial)
    }

    /// Absorb another partial representing the same physical device.
    fn merge(&mut self, other: Partial) {
        if self.reader_name.is_none() {
            self.reader_name = other.reader_name;
        }
        if self.hid_path.is_none() {
            self.hid_path = other.hid_path;
        }
        if self.fido_path.is_none() {
            self.fido_path = other.fido_path;
        }
        if self.pid.is_none() {
            self.pid = other.pid;
        }
        // Prefer info with a serial number, or a higher firmware version.
        let take = match (&self.info, &other.info) {
            (None, Some(_)) => true,
            (Some(a), Some(b)) => {
                (a.serial.is_none() && b.serial.is_some())
                    || (a.serial == b.serial && b.version > a.version)
            }
            _ => false,
        };
        if take {
            self.info = other.info;
        }
        self.nodes.extend(other.nodes);
    }
}

/// Merge `incoming` partials into `base`, combining entries that represent the
/// same physical device. Matching is by serial number first, then by PID when
/// exactly one device of that PID exists.
fn merge_partials(base: &mut Vec<Partial>, incoming: Vec<Partial>, counts: &HashMap<u16, usize>) {
    for inc in incoming {
        let serial = inc.serial();
        let pid = inc.pid;
        let unique_pid = pid.map(|p| counts.get(&p) == Some(&1)).unwrap_or(false);

        let idx = serial
            .and_then(|s| base.iter().position(|b| b.serial() == Some(s)))
            .or_else(|| {
                if unique_pid {
                    base.iter().position(|b| b.pid == pid)
                } else {
                    None
                }
            });

        match idx {
            Some(i) => base[i].merge(inc),
            None => base.push(inc),
        }
    }
}

/// Whether two devices share any transport path (and are thus the same key).
fn shares_path(a: &LocalYubiKeyDevice, b: &LocalYubiKeyDevice) -> bool {
    fn eq(x: &Option<String>, y: &Option<String>) -> bool {
        matches!((x, y), (Some(x), Some(y)) if x == y)
    }
    eq(&a.reader_name, &b.reader_name)
        || eq(&a.hid_path, &b.hid_path)
        || eq(&a.fido_path, &b.fido_path)
}

/// Stable sort key for a device node, for deterministic change detection.
fn node_sort_key(a: &DeviceNode, b: &DeviceNode) -> std::cmp::Ordering {
    fn key(n: &DeviceNode) -> (u8, &str) {
        match n {
            DeviceNode::UsbReaderNode { reader_name, .. } => (0, reader_name),
            DeviceNode::CardNode { reader_name, .. } => (1, reader_name),
            DeviceNode::HidOtpNode { hid_path, .. } => (2, hid_path),
            DeviceNode::HidFidoNode { hid_path, .. } => (3, hid_path),
        }
    }
    key(a).cmp(&key(b))
}
