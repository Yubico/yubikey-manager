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
//! [`monitor_device_events`](crate::platform::monitor::monitor_device_events)
//! reports [`NodeEvent`](crate::platform::monitor::NodeEvent)s as low-level device
//! interfaces appear and disappear. It first emits `Added` events for every
//! currently-connected interface, then blocks and reports changes as they
//! happen.
//!
//! Two transports are monitored:
//!
//! - **PC/SC** — YubiKeys connected over USB report both a
//!   [`DeviceNode::UsbReaderNode`](crate::platform::monitor::DeviceNode::UsbReaderNode)
//!   (the reader) and a
//!   [`DeviceNode::CardNode`](crate::platform::monitor::DeviceNode::CardNode)
//!   (the card). YubiKeys placed on an NFC reader
//!   report only a
//!   [`DeviceNode::CardNode`](crate::platform::monitor::DeviceNode::CardNode).
//!   The reader itself is not tracked.
//! - **HID** — the OTP and FIDO interfaces are tracked separately as
//!   [`DeviceNode::HidOtpNode`](crate::platform::monitor::DeviceNode::HidOtpNode)
//!   and [`DeviceNode::HidFidoNode`](crate::platform::monitor::DeviceNode::HidFidoNode).
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
//!
//! Uncertain reader changes do not by themselves remove cards. Metadata
//! refreshes require exclusive access, retaining cached information while
//! cards are busy. Successful unchanged refreshes emit no events.
//!
//! A local device's [`reinsert`](crate::device::YubiKeyDevice::reinsert) operation
//! pauses in-process monitor probes and
//! supplies its verified identity and paths for the ensuing reconciliation.
//! Unannounced hotplugs still require DeviceInfo reads.

use std::collections::HashMap;
#[cfg(feature = "pcsc")]
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

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
use super::pcsc::{PcscSmartCardConnection, ReaderStatus, is_reader_usb, list_reader_statuses};
pub use super::usb_id::UsbDeviceId;
#[cfg(feature = "pcsc")]
use super::usb_id::connection_usb_device_id;
#[cfg(feature = "hid")]
use super::usb_id::hid_usb_device_id;
#[cfg(all(feature = "pcsc", windows))]
use super::usb_id::{reader_device_instances, usb_device_id_from_instance};
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
        /// The USB device this reader belongs to, if known to the OS.
        usb_id: Option<UsbDeviceId>,
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
        /// The USB device this interface belongs to, if known to the OS.
        usb_id: Option<UsbDeviceId>,
        /// Device info read over the OTP interface, or over another
        /// interface of the same USB device.
        device_info: DeviceInfo,
    },
    /// A YubiKey FIDO HID interface.
    HidFidoNode {
        /// The OS-specific HID device path.
        hid_path: String,
        /// The USB Product ID.
        pid: u16,
        /// The USB device this interface belongs to, if known to the OS.
        usb_id: Option<UsbDeviceId>,
        /// Device info read over the FIDO interface, or over another
        /// interface of the same USB device.
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
    /// A smart card reader's device instance was removed, or `None` if unrecognised.
    #[cfg(all(feature = "pcsc", windows))]
    PcscReaderRemoved(Option<String>),
    /// A HID device was added or removed; re-diff the HID transport.
    #[cfg(feature = "hid")]
    Hid,
    /// Reconcile a device whose identity and paths were verified by reinsert.
    VerifiedReinsert(u64),
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
                // SAFETY: Plain FFI call with value arguments; a stale thread
                // id only makes the call fail.
                unsafe { PostThreadMessageW(tid, WM_QUIT, 0, 0) };
            }
        }

        // Stop the macOS HID run loop. The lock is held across the call so
        // the watcher thread cannot exit (and release the run loop) while it
        // is being stopped.
        #[cfg(all(feature = "hid", target_os = "macos"))]
        {
            let run_loop = self.macos_runloop.lock().unwrap();
            if let Some(rl) = *run_loop {
                use core_foundation_sys::runloop::{CFRunLoopRef, CFRunLoopStop};
                // SAFETY: The slot is only set while the watcher thread, which
                // owns the run loop, is alive and holds a reference to it.
                unsafe { CFRunLoopStop(rl as CFRunLoopRef) };
            }
        }
    }
}

/// A latch that lets callers wait until the monitor's initial device
/// enumeration has been processed.
///
/// The monitor emits events for every currently-connected device before it
/// starts reporting changes. Callers that need an accurate device inventory
/// immediately after starting the monitor can block on
/// [`MonitorHandle::wait_ready`] until that initial pass is complete.
#[derive(Clone)]
struct ReadySignal {
    inner: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl ReadySignal {
    fn new() -> Self {
        Self {
            inner: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
        }
    }

    /// Mark the initial scan as complete, waking any waiters. Idempotent.
    fn signal(&self) {
        let (lock, cvar) = &*self.inner;
        let mut ready = lock.lock().unwrap_or_else(|p| p.into_inner());
        *ready = true;
        cvar.notify_all();
    }

    /// Block until signalled or `timeout` elapses. Returns `true` if ready.
    fn wait_timeout(&self, timeout: Duration) -> bool {
        let (lock, cvar) = &*self.inner;
        let deadline = Instant::now() + timeout;
        let mut ready = lock.lock().unwrap_or_else(|p| p.into_inner());
        while !*ready {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, _) = cvar
                .wait_timeout(ready, deadline - now)
                .unwrap_or_else(|p| p.into_inner());
            ready = guard;
        }
        true
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
    coordinator: Arc<ProbeCoordinator>,
    /// Signalled once the initial device enumeration has been processed.
    ready: ReadySignal,
}

struct ProbeCoordinator {
    probe_gate: Mutex<()>,
    verified: Mutex<Vec<(u64, LocalYubiKeyDevice)>>,
    next_verification: AtomicU64,
    change_tx: mpsc::Sender<Change>,
}

static MONITORS: OnceLock<Mutex<Vec<Weak<ProbeCoordinator>>>> = OnceLock::new();

/// Run a reinsert without concurrent DeviceInfo reads by monitors in this
/// process. Publish the device's newly verified identity for reconciliation.
pub(crate) fn with_paused_monitors(
    reinsert: impl FnOnce() -> Result<LocalYubiKeyDevice, DeviceError>,
) -> Result<(), DeviceError> {
    let mut registry = MONITORS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    registry.retain(|monitor| monitor.strong_count() > 0);
    let monitors: Vec<_> = registry.iter().filter_map(Weak::upgrade).collect();
    let mut guards = Vec::new();
    for monitor in &monitors {
        guards.push(
            MonitorHandle::lock_probe_gate(&monitor.probe_gate, Duration::from_secs(10))
                .ok_or_else(|| {
                    DeviceError::Transport(Box::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Timed out waiting for device monitor probes",
                    )))
                })?,
        );
    }

    let verified = reinsert()?;
    if verified.info().serial.is_some() {
        for monitor in &monitors {
            let id = monitor.next_verification.fetch_add(1, Ordering::Relaxed);
            monitor
                .verified
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((id, verified.clone()));
            monitor
                .change_tx
                .send(Change::VerifiedReinsert(id))
                .map_err(|_| {
                    DeviceError::Transport(Box::new(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Device monitor stopped during reinsert",
                    )))
                })?;
        }
    }
    drop(guards);
    drop(registry);
    Ok(())
}

#[derive(Clone, Copy)]
enum VerifiedInterface {
    Ccid,
    Otp,
    Fido,
}

fn verified_info(
    devices: &[LocalYubiKeyDevice],
    interface: VerifiedInterface,
    path: &str,
    pid: Option<u16>,
) -> Option<DeviceInfo> {
    devices
        .iter()
        .rev()
        .find(|dev| {
            dev.pid() == pid
                && match interface {
                    VerifiedInterface::Ccid => dev.reader_name.as_deref() == Some(path),
                    VerifiedInterface::Otp => dev.hid_path.as_deref() == Some(path),
                    VerifiedInterface::Fido => dev.fido_path.as_deref() == Some(path),
                }
        })
        .map(|dev| dev.info().clone())
}

/// Prevents the monitor from probing device interfaces until dropped.
pub struct MonitorPauseGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl MonitorHandle {
    /// Stop the monitor and wait for its threads to finish.
    ///
    /// No further [`NodeEvent`]s are delivered after this returns.
    pub fn stop(mut self) {
        self.shutdown_and_join();
    }

    /// Block until the monitor's initial device enumeration has been processed,
    /// or `timeout` elapses. Returns `true` if the initial scan completed.
    ///
    /// Once this returns `true`, every currently-connected device has been
    /// reported to the event callback.
    pub fn wait_ready(&self, timeout: Duration) -> bool {
        self.ready.wait_timeout(timeout)
    }

    /// Wait for an in-flight probe to finish, then pause further probes.
    /// Device-change notifications remain queued and are processed on drop.
    /// Do not hold this guard when calling `LocalYubiKeyDevice::reinsert`,
    /// which coordinates with monitors automatically.
    pub fn pause(&self, timeout: Duration) -> Option<MonitorPauseGuard<'_>> {
        Self::lock_probe_gate(&self.coordinator.probe_gate, timeout)
            .map(|guard| MonitorPauseGuard { _guard: guard })
    }

    fn shutdown_and_join(&mut self) {
        self.shutdown.signal_stop();
        // Unblock anything still waiting on readiness; the monitor is stopping.
        self.ready.signal();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }

    fn lock_probe_gate(gate: &Mutex<()>, timeout: Duration) -> Option<MutexGuard<'_, ()>> {
        let deadline = Instant::now() + timeout;
        loop {
            match gate.try_lock() {
                Ok(guard) => return Some(guard),
                Err(TryLockError::Poisoned(error)) => return Some(error.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(TryLockError::WouldBlock) => return None,
            }
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
    let ready = ReadySignal::new();
    let coordinator = Arc::new(ProbeCoordinator {
        probe_gate: Mutex::new(()),
        verified: Mutex::new(Vec::new()),
        next_verification: AtomicU64::new(0),
        change_tx: tx.clone(),
    });
    MONITORS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(Arc::downgrade(&coordinator));
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
    let coordinator_ready = ready.clone();
    let probe_coordinator = Arc::clone(&coordinator);
    let coordinator_thread = thread::spawn(move || {
        let mut state = MonitorState::default();

        // Emit events for the initial state before processing changes.
        let gate = probe_coordinator
            .probe_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        #[cfg(feature = "pcsc")]
        if usb_interfaces.contains(UsbInterface::CCID) {
            let _ = state.refresh_pcsc(&mut on_event, &[]);
        }
        #[cfg(feature = "hid")]
        if usb_interfaces.contains(UsbInterface::OTP) || usb_interfaces.contains(UsbInterface::FIDO)
        {
            state.refresh_hid(usb_interfaces, &mut on_event, &[]);
        }

        // The initial device enumeration is complete.
        coordinator_ready.signal();
        drop(gate);

        while let Ok(change) = rx.recv() {
            let _gate = probe_coordinator
                .probe_gate
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let verified: Vec<_> = probe_coordinator
                .verified
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|(_, device)| device.clone())
                .collect();
            match change {
                Change::Stop => break,
                #[cfg(feature = "pcsc")]
                Change::Pcsc => {
                    state.refresh_pcsc_and_hid(usb_interfaces, &mut on_event, &verified)
                }
                #[cfg(all(feature = "pcsc", windows))]
                Change::PcscReaderRemoved(instance) => {
                    state.invalidate_usb_cards(instance.as_deref(), &mut on_event);
                    state.refresh_pcsc_and_hid(usb_interfaces, &mut on_event, &verified);
                }
                #[cfg(feature = "hid")]
                Change::Hid => state.refresh_hid(usb_interfaces, &mut on_event, &verified),
                Change::VerifiedReinsert(id) => {
                    #[cfg(feature = "pcsc")]
                    if usb_interfaces.contains(UsbInterface::CCID) {
                        let _ = state.refresh_pcsc(&mut on_event, &verified);
                    }
                    #[cfg(feature = "hid")]
                    if usb_interfaces.contains(UsbInterface::OTP)
                        || usb_interfaces.contains(UsbInterface::FIDO)
                    {
                        state.refresh_hid(usb_interfaces, &mut on_event, &verified);
                    }
                    probe_coordinator
                        .verified
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|(token, _)| *token != id);
                }
            }
        }
    });
    threads.push(coordinator_thread);

    MonitorHandle {
        shutdown,
        threads,
        coordinator,
        ready,
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
    /// Event counter of each tracked card, to detect replacement.
    #[cfg(feature = "pcsc")]
    card_events: HashMap<String, u32>,
    /// Cards scheduled for a non-intrusive metadata refresh.
    #[cfg(feature = "pcsc")]
    stale_cards: HashSet<String>,
    /// Cached Windows device instance IDs, available even after a reader disappears.
    #[cfg(all(feature = "pcsc", any(windows, test)))]
    reader_instances: HashMap<String, ReaderInstance>,
    /// The USB device of each USB reader, where the OS could tell us.
    #[cfg(feature = "pcsc")]
    reader_ids: HashMap<String, UsbDeviceId>,
    /// OTP HID nodes, keyed by HID path.
    #[cfg(feature = "hid")]
    hid_otp: HashMap<String, DeviceNode>,
    /// FIDO HID nodes, keyed by HID path.
    #[cfg(feature = "hid")]
    hid_fido: HashMap<String, DeviceNode>,
}

/// The Windows device instance ID of a USB reader, if it could be read.
#[cfg(all(feature = "pcsc", any(windows, test)))]
#[derive(Debug, Clone, PartialEq)]
enum ReaderInstance {
    Known(String),
    /// The lookup failed; it is retried once `retry_at` has passed.
    Unknown {
        retry_at: Instant,
    },
}

/// How long to wait before retrying a failed reader instance lookup.
#[cfg(all(feature = "pcsc", windows))]
const READER_INSTANCE_RETRY: Duration = Duration::from_secs(5);

#[cfg(feature = "pcsc")]
impl MonitorState {
    /// Invalidate a confirmed removal, or schedule uncertain readers for refresh.
    ///
    /// A rebooting YubiKey (e.g. after a configuration change) can remove and
    /// re-create its reader between two polls, reusing the reader name and
    /// card event count, which would otherwise keep the stale device info.
    ///
    /// Uncertain readers retain their cards until a probe succeeds or PC/SC
    /// confirms removal. Failed instance lookups keep their retry deadlines.
    #[cfg(any(windows, test))]
    fn invalidate_usb_cards(
        &mut self,
        instance: Option<&str>,
        on_event: &mut impl FnMut(NodeEvent),
    ) {
        let names: Vec<(String, bool)> = self
            .usb_readers
            .keys()
            .filter_map(|name| match (instance, self.reader_instances.get(name)) {
                (Some(removed), Some(ReaderInstance::Known(known))) => known
                    .eq_ignore_ascii_case(removed)
                    .then(|| (name.clone(), true)),
                _ => Some((name.clone(), false)),
            })
            .collect();
        for (name, removed) in names {
            if !removed {
                // Readers without a cached card keep using the regular read
                // path, which can fall back to shared access.
                if self.cards.contains_key(&name) {
                    self.stale_cards.insert(name.clone());
                }
                if matches!(
                    self.reader_instances.get(&name),
                    Some(ReaderInstance::Known(_))
                ) {
                    self.reader_instances.remove(&name);
                }
                continue;
            }
            self.reader_instances.remove(&name);
            self.card_events.remove(&name);
            self.stale_cards.remove(&name);
            if let Some(node) = self.cards.remove(&name) {
                on_event(NodeEvent::Removed(node));
            }
        }
    }

    /// Look up device instance IDs of USB readers not yet cached, using one
    /// smart card context, and back off after failures.
    #[cfg(windows)]
    fn lookup_reader_instances(&mut self, readers: &[ReaderStatus]) {
        let now = Instant::now();
        let names: Vec<&str> = readers
            .iter()
            .map(|status| status.name.as_str())
            .filter(|name| is_reader_usb(name))
            .filter(|name| match self.reader_instances.get(*name) {
                None => true,
                Some(ReaderInstance::Known(_)) => false,
                Some(ReaderInstance::Unknown { retry_at }) => now >= *retry_at,
            })
            .collect();
        if names.is_empty() {
            return;
        }
        let results = match reader_device_instances(&names) {
            Ok(results) => results,
            Err(e) => {
                log::debug!("Reading reader device instances failed: {e}");
                names
                    .iter()
                    .map(|_| Err(std::io::Error::other("no smart card context")))
                    .collect()
            }
        };
        for (name, result) in names.into_iter().zip(results) {
            let instance = match result {
                Ok(instance) => {
                    if let Some(id) = usb_device_id_from_instance(&instance) {
                        self.reader_ids.insert(name.to_string(), id);
                    }
                    ReaderInstance::Known(instance)
                }
                Err(e) => {
                    log::debug!("Reading device instance for '{name}' failed: {e}");
                    ReaderInstance::Unknown {
                        retry_at: now + READER_INSTANCE_RETRY,
                    }
                }
            };
            self.reader_instances.insert(name.to_string(), instance);
        }
    }

    /// Re-enumerate PC/SC readers and, if device info was read from a USB
    /// card, re-check HID interfaces: those of the same USB device that could
    /// not be opened earlier can now be reported using the card's info.
    fn refresh_pcsc_and_hid(
        &mut self,
        interfaces: UsbInterface,
        on_event: &mut impl FnMut(NodeEvent),
        verified: &[LocalYubiKeyDevice],
    ) {
        let read = self.refresh_pcsc(on_event, verified);
        #[cfg(feature = "hid")]
        if read
            && (interfaces.contains(UsbInterface::OTP) || interfaces.contains(UsbInterface::FIDO))
        {
            self.refresh_hid(interfaces, on_event, verified);
        }
        #[cfg(not(feature = "hid"))]
        let _ = (read, interfaces);
    }

    /// Re-enumerate PC/SC readers and emit events for any changes.
    ///
    /// Returns `true` if device info was read from a USB card.
    fn refresh_pcsc(
        &mut self,
        on_event: &mut impl FnMut(NodeEvent),
        verified: &[LocalYubiKeyDevice],
    ) -> bool {
        let readers = match list_reader_statuses() {
            Ok(readers) => readers,
            Err(e) => {
                log::debug!("PC/SC enumeration failed: {e}");
                return false;
            }
        };
        let present: HashMap<&str, bool> = readers
            .iter()
            .map(|r| (r.name.as_str(), r.card_present))
            .collect();

        // --- Handle readers that have disappeared entirely (USB unplug) ---
        let gone: Vec<String> = self
            .usb_readers
            .keys()
            .filter(|name| !present.contains_key(name.as_str()))
            .cloned()
            .collect();
        for name in gone {
            #[cfg(windows)]
            self.reader_instances.remove(&name);
            self.reader_ids.remove(&name);
            self.card_events.remove(&name);
            self.stale_cards.remove(&name);
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

        #[cfg(windows)]
        self.lookup_reader_instances(&readers);

        self.refresh_pcsc_cards(&readers, on_event, verified, read_card_info)
    }

    fn refresh_pcsc_cards(
        &mut self,
        readers: &[ReaderStatus],
        on_event: &mut impl FnMut(NodeEvent),
        verified: &[LocalYubiKeyDevice],
        mut read_info: impl FnMut(
            &str,
            CardProbe,
        ) -> Result<(DeviceInfo, Option<UsbDeviceId>), DeviceError>,
    ) -> bool {
        let mut usb_info_read = false;

        // --- Process each currently-connected reader ---
        for status in readers {
            let name = &status.name;
            let card_present = &status.card_present;
            let usb = is_reader_usb(name);
            let pid = if usb {
                pid_from_reader_name(name)
            } else {
                None
            };

            // A card swapped faster than the polling interval never shows as
            // absent; the changed event counter reveals the replacement.
            if *card_present
                && self.cards.contains_key(name)
                && self.card_events.get(name) != Some(&status.event_count)
                && let Some(node) = self.cards.remove(name)
            {
                self.stale_cards.remove(name);
                on_event(NodeEvent::Removed(node));
            }

            // USB reader node.
            if let Some(pid) = pid {
                self.update_usb_reader(name, pid, on_event);
            }

            if *card_present {
                let refresh = self.stale_cards.contains(name);
                if refresh || !self.cards.contains_key(name) {
                    let probe = CardProbe {
                        usb,
                        exclusive_only: refresh,
                        want_usb_id: pid.is_some() && !self.reader_ids.contains_key(name),
                    };
                    let info = verified_info(verified, VerifiedInterface::Ccid, name, pid)
                        .map(|info| Ok((info, None)))
                        .unwrap_or_else(|| read_info(name, probe));
                    match info {
                        Ok((info, usb_id)) => {
                            if let (Some(pid), Some(usb_id)) = (pid, usb_id) {
                                self.reader_ids.insert(name.clone(), usb_id);
                                self.update_usb_reader(name, pid, on_event);
                            }
                            let node = DeviceNode::CardNode {
                                reader_name: name.clone(),
                                device_info: info.clone(),
                            };
                            let previous = self.cards.insert(name.clone(), node.clone());
                            self.card_events.insert(name.clone(), status.event_count);
                            self.stale_cards.remove(name);
                            if previous.as_ref() != Some(&node) {
                                if let Some(previous) = previous {
                                    on_event(NodeEvent::Removed(previous));
                                }
                                on_event(NodeEvent::Added(node));
                            }
                            if pid.is_some() {
                                usb_info_read = true;
                                #[cfg(feature = "hid")]
                                if let Some(usb_id) = self.reader_ids.get(name).cloned() {
                                    self.adopt_hid_info(&usb_id, &info, on_event);
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!("Reading card info from '{name}' failed: {e}");
                        }
                    }
                }
            } else {
                self.stale_cards.remove(name);
                if let Some(node) = self.cards.remove(name) {
                    on_event(NodeEvent::Removed(node));
                }
            }
        }
        usb_info_read
    }

    /// Insert the reader node for `name`, or replace it if its USB device has
    /// since become known.
    fn update_usb_reader(&mut self, name: &str, pid: u16, on_event: &mut impl FnMut(NodeEvent)) {
        let node = DeviceNode::UsbReaderNode {
            reader_name: name.to_owned(),
            pid,
            usb_id: self.reader_ids.get(name).cloned(),
        };
        match self.usb_readers.get(name) {
            Some(existing) if *existing == node => {}
            Some(_) => {
                let previous = self.usb_readers.insert(name.to_owned(), node.clone());
                if let Some(previous) = previous {
                    on_event(NodeEvent::Removed(previous));
                }
                on_event(NodeEvent::Added(node));
            }
            None => {
                self.usb_readers.insert(name.to_owned(), node.clone());
                on_event(NodeEvent::Added(node));
            }
        }
    }

    /// Device info already read from the card of the USB device `usb_id`.
    fn card_info_for(&self, usb_id: &UsbDeviceId) -> Option<&DeviceInfo> {
        self.usb_readers.iter().find_map(|(name, node)| match node {
            DeviceNode::UsbReaderNode {
                usb_id: Some(id), ..
            } if id == usb_id => match self.cards.get(name) {
                Some(DeviceNode::CardNode { device_info, .. }) => Some(device_info),
                _ => None,
            },
            _ => None,
        })
    }
}

/// How a card's device info should be read.
#[cfg(feature = "pcsc")]
#[derive(Debug, Clone, Copy)]
struct CardProbe {
    /// Whether the reader is a USB YubiKey (as opposed to an NFC reader).
    usb: bool,
    /// Only use exclusive access, to detect a card that is in use elsewhere.
    exclusive_only: bool,
    /// Also resolve the reader's USB device through the connection.
    want_usb_id: bool,
}

#[cfg(feature = "hid")]
impl MonitorState {
    /// Re-enumerate HID devices and emit events for any changes.
    fn refresh_hid(
        &mut self,
        interfaces: UsbInterface,
        on_event: &mut impl FnMut(NodeEvent),
        verified: &[LocalYubiKeyDevice],
    ) {
        if interfaces.contains(UsbInterface::OTP) {
            match list_otp_devices() {
                Ok(devices) => {
                    let devices: Vec<(String, u16)> =
                        devices.into_iter().map(|d| (d.path, d.pid)).collect();
                    self.refresh_hid_interface(
                        HidInterface::Otp,
                        &devices,
                        on_event,
                        verified,
                        read_otp_info,
                    );
                }
                Err(e) => log::debug!("OTP HID enumeration failed: {e}"),
            }
        }

        if interfaces.contains(UsbInterface::FIDO) {
            match list_fido_devices() {
                Ok(devices) => {
                    let current: Vec<(String, u16)> =
                        devices.iter().map(|d| (d.path.clone(), d.pid)).collect();
                    self.refresh_hid_interface(
                        HidInterface::Fido,
                        &current,
                        on_event,
                        verified,
                        |path, _| {
                            let device = devices
                                .iter()
                                .find(|d| d.path == path)
                                .expect("enumerated device");
                            read_fido_info(device)
                        },
                    );
                }
                Err(e) => log::debug!("FIDO HID enumeration failed: {e}"),
            }
        }
    }

    /// Diff the enumerated `(path, pid)` devices of one HID interface against
    /// the tracked nodes.
    ///
    /// New interfaces whose USB device already has device info (read over
    /// another interface) reuse it instead of being opened. This also allows
    /// interfaces that cannot be opened (e.g. FIDO without administrator
    /// rights on Windows) to be reported.
    fn refresh_hid_interface(
        &mut self,
        interface: HidInterface,
        devices: &[(String, u16)],
        on_event: &mut impl FnMut(NodeEvent),
        verified: &[LocalYubiKeyDevice],
        mut read_info: impl FnMut(&str, u16) -> Result<DeviceInfo, DeviceError>,
    ) {
        let (verified_interface, label) = match interface {
            HidInterface::Otp => (VerifiedInterface::Otp, "OTP"),
            HidInterface::Fido => (VerifiedInterface::Fido, "FIDO"),
        };
        // Removals.
        let gone: Vec<String> = self
            .hid_nodes(interface)
            .keys()
            .filter(|path| !devices.iter().any(|(p, _)| p == *path))
            .cloned()
            .collect();
        for path in gone {
            if let Some(node) = self.hid_nodes_mut(interface).remove(&path) {
                on_event(NodeEvent::Removed(node));
            }
        }
        // Additions.
        for (path, pid) in devices {
            if self.hid_nodes(interface).contains_key(path) {
                continue;
            }
            let usb_id = hid_usb_device_id(path);
            let info = verified_info(verified, verified_interface, path, Some(*pid))
                .or_else(|| usb_id.as_ref().and_then(|id| self.group_info(id).cloned()))
                .map(Ok)
                .unwrap_or_else(|| read_info(path, *pid));
            match info {
                Ok(info) => {
                    let node = interface.node(path.clone(), *pid, usb_id, info);
                    self.hid_nodes_mut(interface)
                        .insert(path.clone(), node.clone());
                    on_event(NodeEvent::Added(node));
                }
                Err(e) => {
                    log::debug!("Reading {label} info from '{path}' failed: {e}");
                }
            }
        }
    }

    fn hid_nodes(&self, interface: HidInterface) -> &HashMap<String, DeviceNode> {
        match interface {
            HidInterface::Otp => &self.hid_otp,
            HidInterface::Fido => &self.hid_fido,
        }
    }

    fn hid_nodes_mut(&mut self, interface: HidInterface) -> &mut HashMap<String, DeviceNode> {
        match interface {
            HidInterface::Otp => &mut self.hid_otp,
            HidInterface::Fido => &mut self.hid_fido,
        }
    }

    /// Device info already known for the USB device `usb_id`, preferring the
    /// card (CCID) as the most complete source.
    fn group_info(&self, usb_id: &UsbDeviceId) -> Option<&DeviceInfo> {
        #[cfg(feature = "pcsc")]
        if let Some(info) = self.card_info_for(usb_id) {
            return Some(info);
        }
        self.hid_otp
            .values()
            .chain(self.hid_fido.values())
            .find_map(|node| match node {
                DeviceNode::HidOtpNode {
                    usb_id: Some(id),
                    device_info,
                    ..
                }
                | DeviceNode::HidFidoNode {
                    usb_id: Some(id),
                    device_info,
                    ..
                } if id == usb_id => Some(device_info),
                _ => None,
            })
    }

    /// Update the HID nodes of the USB device `usb_id` with device info read
    /// over its card, which is the authoritative source.
    #[cfg(feature = "pcsc")]
    fn adopt_hid_info(
        &mut self,
        usb_id: &UsbDeviceId,
        info: &DeviceInfo,
        on_event: &mut impl FnMut(NodeEvent),
    ) {
        for interface in [HidInterface::Otp, HidInterface::Fido] {
            let outdated: Vec<(String, u16)> = self
                .hid_nodes(interface)
                .values()
                .filter_map(|node| match node {
                    DeviceNode::HidOtpNode {
                        hid_path,
                        pid,
                        usb_id: Some(id),
                        device_info,
                    }
                    | DeviceNode::HidFidoNode {
                        hid_path,
                        pid,
                        usb_id: Some(id),
                        device_info,
                    } if id == usb_id && device_info != info => Some((hid_path.clone(), *pid)),
                    _ => None,
                })
                .collect();
            for (path, pid) in outdated {
                let node = interface.node(path.clone(), pid, Some(usb_id.clone()), info.clone());
                if let Some(previous) = self.hid_nodes_mut(interface).insert(path, node.clone()) {
                    on_event(NodeEvent::Removed(previous));
                }
                on_event(NodeEvent::Added(node));
            }
        }
    }
}

/// A HID interface type tracked by the monitor.
#[cfg(feature = "hid")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HidInterface {
    Otp,
    Fido,
}

#[cfg(feature = "hid")]
impl HidInterface {
    fn node(
        self,
        hid_path: String,
        pid: u16,
        usb_id: Option<UsbDeviceId>,
        device_info: DeviceInfo,
    ) -> DeviceNode {
        match self {
            HidInterface::Otp => DeviceNode::HidOtpNode {
                hid_path,
                pid,
                usb_id,
                device_info,
            },
            HidInterface::Fido => DeviceNode::HidFidoNode {
                hid_path,
                pid,
                usb_id,
                device_info,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Info readers
// ---------------------------------------------------------------------------

#[cfg(feature = "pcsc")]
fn read_card_info(
    reader_name: &str,
    probe: CardProbe,
) -> Result<(DeviceInfo, Option<UsbDeviceId>), DeviceError> {
    let conn = if probe.exclusive_only {
        PcscSmartCardConnection::new(reader_name, true)
    } else {
        PcscSmartCardConnection::open(reader_name)
    }?;
    let pid = if probe.usb {
        pid_from_reader_name(reader_name)
    } else {
        None
    };
    let (info, conn) = read_info_ccid(conn, pid)?;
    let usb_id = if probe.want_usb_id {
        connection_usb_device_id(&conn)
    } else {
        None
    };
    Ok((info, usb_id))
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
/// Polling alone can miss a reader that is removed and re-created between two
/// polls, so smart card reader removal notifications are also forwarded.
///
/// Stop latency is bounded by the poll interval, since the loop checks the
/// shutdown flag each iteration.
#[cfg(all(feature = "pcsc", windows))]
fn pcsc_watch_loop(tx: &mpsc::Sender<Change>, shutdown: &Shutdown) {
    windows_pcsc::run(tx, shutdown);
}

#[cfg(all(feature = "pcsc", windows))]
mod windows_pcsc {
    use super::{Change, Shutdown};
    use crate::platform::usb_id::device_instance_from_path;
    use std::cell::RefCell;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DBT_DEVICEREMOVECOMPLETE, DBT_DEVTYP_DEVICEINTERFACE,
        DEV_BROADCAST_DEVICEINTERFACE_W, DEV_BROADCAST_HDR, DEVICE_NOTIFY_WINDOW_HANDLE,
        DefWindowProcW, DestroyWindow, DispatchMessageW, HWND_MESSAGE, MSG,
        MsgWaitForMultipleObjects, PM_REMOVE, PeekMessageW, QS_ALLINPUT, RegisterClassW,
        RegisterDeviceNotificationW, TranslateMessage, UnregisterDeviceNotification,
        WM_DEVICECHANGE, WNDCLASSW,
    };
    use windows_sys::core::GUID;

    const POLL_INTERVAL: Duration = Duration::from_millis(750);
    const GUID_DEVINTERFACE_SMARTCARD_READER: GUID =
        GUID::from_u128(0x50dd5230_ba8a_11d1_bf5d_0000f805f530);

    thread_local! {
        static SENDER: RefCell<Option<mpsc::Sender<Change>>> = const { RefCell::new(None) };
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_DEVICECHANGE && wparam == DBT_DEVICEREMOVECOMPLETE as WPARAM {
            let header = lparam as *const DEV_BROADCAST_HDR;
            // SAFETY: For WM_DEVICECHANGE with DBT_DEVICEREMOVECOMPLETE, a
            // non-null lparam points to a DEV_BROADCAST_HDR supplied by the
            // system for the duration of the call.
            if !header.is_null()
                && unsafe { (*header).dbch_devicetype } == DBT_DEVTYP_DEVICEINTERFACE
            {
                let broadcast = lparam as *const DEV_BROADCAST_DEVICEINTERFACE_W;
                let offset = std::mem::offset_of!(DEV_BROADCAST_DEVICEINTERFACE_W, dbcc_name);
                // SAFETY: `header` was checked to be non-null above.
                let size = unsafe { (*header).dbch_size } as usize;
                if size < offset + std::mem::size_of::<u16>() {
                    log::debug!("Smart card removal notification has no interface path");
                    return 1;
                }
                // SAFETY: The device type says this is a
                // DEV_BROADCAST_DEVICEINTERFACE_W of `size` bytes, so the
                // name occupies the `size - offset` bytes after `dbcc_name`.
                let name = unsafe {
                    let start = std::ptr::addr_of!((*broadcast).dbcc_name).cast::<u16>();
                    std::slice::from_raw_parts(start, (size - offset) / 2)
                };
                let Some(end) = name.iter().position(|&c| c == 0) else {
                    log::debug!("Smart card removal notification has an unterminated path");
                    return 1;
                };
                let name = String::from_utf16_lossy(&name[..end]);
                log::debug!("Smart card reader removed: {name}");
                let instance = device_instance_from_path(&name);
                if instance.is_none() {
                    log::debug!("Unrecognised reader path; re-reading all USB readers");
                }
                SENDER.with(|sender| {
                    if let Some(tx) = sender.borrow().as_ref() {
                        let _ = tx.send(Change::PcscReaderRemoved(instance));
                    }
                });
            }
            return 1;
        }
        // SAFETY: Forwarding the message arguments exactly as received.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    /// Create a message-only window registered for reader notifications.
    fn register_notifications() -> Option<(HWND, *mut core::ffi::c_void)> {
        // SAFETY: All pointer arguments refer to locals that outlive the
        // calls; zeroed WNDCLASSW and DEV_BROADCAST_DEVICEINTERFACE_W are
        // valid values; handles are only used while valid.
        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name = wide("YubiKitPcscMonitor");
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class_name.as_ptr();
            // Fails harmlessly if the class is already registered.
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
                return None;
            }
            let mut filter: DEV_BROADCAST_DEVICEINTERFACE_W = std::mem::zeroed();
            filter.dbcc_size = std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>() as u32;
            filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
            filter.dbcc_classguid = GUID_DEVINTERFACE_SMARTCARD_READER;
            let notify = RegisterDeviceNotificationW(
                hwnd as _,
                &mut filter as *mut _ as *mut _,
                DEVICE_NOTIFY_WINDOW_HANDLE,
            );
            if notify.is_null() {
                DestroyWindow(hwnd);
                return None;
            }
            Some((hwnd, notify))
        }
    }

    pub(super) fn run(tx: &mpsc::Sender<Change>, shutdown: &Shutdown) {
        SENDER.with(|sender| *sender.borrow_mut() = Some(tx.clone()));
        let registration = register_notifications();
        if registration.is_none() {
            log::debug!("Failed to register for smart card reader notifications");
        }

        let mut next_poll = Instant::now() + POLL_INTERVAL;
        while !shutdown.is_stopped() {
            let timeout = next_poll.saturating_duration_since(Instant::now());
            // SAFETY: No handles are waited on, and `msg` is a valid local for
            // the message calls to fill in.
            unsafe {
                MsgWaitForMultipleObjects(
                    0,
                    std::ptr::null(),
                    0,
                    timeout.as_millis() as u32,
                    QS_ALLINPUT,
                );
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            if Instant::now() >= next_poll {
                if shutdown.is_stopped() || tx.send(Change::Pcsc).is_err() {
                    break;
                }
                next_poll = Instant::now() + POLL_INTERVAL;
            }
        }

        if let Some((hwnd, notify)) = registration {
            // SAFETY: Both handles were returned by `register_notifications`
            // and are released once, on the thread that created them.
            unsafe {
                UnregisterDeviceNotification(notify);
                DestroyWindow(hwnd);
            }
        }
        SENDER.with(|sender| *sender.borrow_mut() = None);
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
            // SAFETY: `pollfd` is a valid array of one entry.
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
        DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG, PM_NOREMOVE, PeekMessageW,
        RegisterClassW, RegisterDeviceNotificationW, TranslateMessage,
        UnregisterDeviceNotification, WM_DEVICECHANGE, WM_USER, WNDCLASSW,
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
        // SAFETY: Forwarding the message arguments exactly as received.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    pub(super) fn run(tx: mpsc::Sender<Change>, shutdown: &Shutdown) {
        SENDER.with(|sender| *sender.borrow_mut() = Some(tx));

        // SAFETY: All pointer arguments refer to locals that outlive the
        // calls; zeroed WNDCLASSW, DEV_BROADCAST_DEVICEINTERFACE_W and MSG are
        // valid values; the window and notification handles are released on
        // every exit path below, on the thread that created them.
        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name = wide("YubiKitHidMonitor");

            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class_name.as_ptr();
            // Fails harmlessly if the class is already registered.
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
                DestroyWindow(hwnd);
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
            if !shutdown.is_stopped() {
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }

            UnregisterDeviceNotification(notify);
            DestroyWindow(hwnd);
        }
        SENDER.with(|sender| *sender.borrow_mut() = None);
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
        CFRunLoopGetCurrent, CFRunLoopRef, CFRunLoopRunInMode, kCFRunLoopDefaultMode,
        kCFRunLoopRunFinished,
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

    // SAFETY: Signatures match the IOKit IOHIDManager API declarations.
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

        // SAFETY: `manager` is checked for null before use and closed before
        // this block ends; `context` points to `tx`, which outlives the run
        // loop and hence every callback invocation.
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

            // Publish the run loop so shutdown can wake it. Run the loop in
            // bounded slices and re-check the stop flag between them, so a
            // stop that arrives before the loop is entered (when
            // `CFRunLoopStop` is a no-op) is still noticed.
            *shutdown.macos_runloop.lock().unwrap() = Some(run_loop as usize);
            while !shutdown.is_stopped() {
                if CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, 0) == kCFRunLoopRunFinished {
                    log::debug!("HID monitor run loop has no sources");
                    break;
                }
            }
            // Taking the lock here waits for any in-progress `CFRunLoopStop`
            // before the run loop can be torn down with the thread.
            *shutdown.macos_runloop.lock().unwrap() = None;

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
    usb_id: Option<UsbDeviceId>,
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

    /// The OS identity of the USB device, if known.
    pub fn usb_id(&self) -> Option<&UsbDeviceId> {
        self.usb_id.as_ref()
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
/// belong to the same physical device are merged into a single [`YubiKey`].
/// Nodes are grouped by the USB device the OS reports them under (see
/// [`UsbDeviceId`]); where that is unavailable, by serial number, or by USB
/// Product ID when only one device with that Product ID is connected.
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
///
/// [`MonitorHandle::wait_ready`] blocks until every currently-connected device
/// has been enumerated, merged, and reported to `on_event`.
pub fn monitor_yubikeys(
    usb_interfaces: UsbInterface,
    mut on_event: impl FnMut(YubiKeyEvent) + Send + 'static,
) -> MonitorHandle {
    // Messages from the low-level monitor to the aggregation thread. `Ready`
    // is injected once the initial low-level enumeration is complete so the
    // aggregator can signal high-level readiness after processing it.
    enum AggMsg {
        Node(Box<NodeEvent>),
        Ready,
    }

    let (node_tx, node_rx) = mpsc::channel::<AggMsg>();
    let ready_tx = node_tx.clone();

    // Readiness reported to callers: the initial devices have been aggregated.
    let ready = ReadySignal::new();
    let agg_ready = ready.clone();

    // Aggregation thread: applies node events and emits device events.
    let aggregator = thread::spawn(move || {
        let mut state = Aggregator::default();
        loop {
            let first = match node_rx.recv() {
                Ok(msg) => msg,
                // The monitor stopped; exit without emitting removals.
                Err(_) => return,
            };
            // Drain any messages already queued so a burst of interface events
            // (a single physical insert/removal) is coalesced into one pass.
            let mut batch = vec![first];
            while let Ok(msg) = node_rx.try_recv() {
                batch.push(msg);
            }
            let mut became_ready = false;
            for msg in batch {
                match msg {
                    AggMsg::Node(event) => state.apply(*event),
                    AggMsg::Ready => became_ready = true,
                }
            }
            state.reconcile(&mut on_event);
            if became_ready {
                agg_ready.signal();
            }
        }
    });

    let low_handle = monitor_device_events(usb_interfaces, move |event| {
        let _ = node_tx.send(AggMsg::Node(Box::new(event)));
    });

    // Forwarder: once the low-level initial scan is done, tell the aggregator
    // so it can flush the initial state and report high-level readiness.
    // Ordering is guaranteed: the low-level ready signal fires only after every
    // initial node event has been enqueued ahead of this `Ready` message.
    let low_ready = low_handle.ready.clone();
    let low_shutdown = Arc::clone(&low_handle.shutdown);
    let forwarder = thread::spawn(move || {
        loop {
            if low_shutdown.is_stopped() {
                return;
            }
            if low_ready.wait_timeout(Duration::from_millis(100)) {
                let _ = ready_tx.send(AggMsg::Ready);
                return;
            }
        }
    });

    let mut handle = low_handle;
    handle.attach_thread(aggregator);
    handle.attach_thread(forwarder);
    // Report readiness based on the aggregated initial state, not the raw scan.
    handle.ready = ready;
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
                if let (Some(a), Some(c)) = (&b.usb_id, &prev[i].usb_id) {
                    return a == c;
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
                        usb_id: b.usb_id,
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
                        usb_id: b.usb_id,
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
                    usb_id: None,
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
            if let DeviceNode::UsbReaderNode { pid, usb_id, .. } = node {
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
                    usb_id: usb_id.clone(),
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
                    pid,
                    usb_id,
                    device_info,
                    ..
                } = node
                {
                    Some(Partial {
                        reader_name: None,
                        hid_path: Some(path.clone()),
                        fido_path: None,
                        pid: Some(*pid),
                        usb_id: usb_id.clone(),
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
                    pid,
                    usb_id,
                    device_info,
                    ..
                } = node
                {
                    Some(Partial {
                        reader_name: None,
                        hid_path: None,
                        fido_path: Some(path.clone()),
                        pid: Some(*pid),
                        usb_id: usb_id.clone(),
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
                    usb_id: p.usb_id,
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
    usb_id: Option<UsbDeviceId>,
    nodes: Vec<DeviceNode>,
}

/// A partially-assembled USB device during merging.
struct Partial {
    reader_name: Option<String>,
    hid_path: Option<String>,
    fido_path: Option<String>,
    pid: Option<u16>,
    usb_id: Option<UsbDeviceId>,
    info: Option<DeviceInfo>,
    nodes: Vec<DeviceNode>,
}

impl Partial {
    fn serial(&self) -> Option<u32> {
        self.info.as_ref().and_then(|i| i.serial)
    }

    /// Whether `other` could be the same device as far as OS identity goes:
    /// either identity is unknown, or both are equal.
    fn identity_compatible(&self, other: &Partial) -> bool {
        match (&self.usb_id, &other.usb_id) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
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
        if self.usb_id.is_none() {
            self.usb_id = other.usb_id;
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
/// same physical device.
///
/// Partials belonging to the same USB device (per the OS) are always merged.
/// Otherwise, a partial is matched by serial number, or by PID when exactly
/// one device of that PID exists, but never with a partial the OS attributes
/// to a different USB device.
fn merge_partials(base: &mut Vec<Partial>, incoming: Vec<Partial>, counts: &HashMap<u16, usize>) {
    for inc in incoming {
        let serial = inc.serial();
        let pid = inc.pid;
        let unique_pid = pid.map(|p| counts.get(&p) == Some(&1)).unwrap_or(false);

        let idx = inc
            .usb_id
            .as_ref()
            .and_then(|id| base.iter().position(|b| b.usb_id.as_ref() == Some(id)))
            .or_else(|| {
                let serial = serial?;
                base.iter()
                    .position(|b| b.serial() == Some(serial) && b.identity_compatible(&inc))
            })
            .or_else(|| {
                if unique_pid {
                    base.iter()
                        .position(|b| b.pid == pid && b.identity_compatible(&inc))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Version;

    #[test]
    fn monitor_pause_is_exclusive_and_resumes_on_drop() {
        let handle = monitor_device_events(UsbInterface(0), |_| {});
        assert!(handle.wait_ready(Duration::from_secs(1)));

        let pause = handle.pause(Duration::from_secs(1)).unwrap();
        assert!(handle.pause(Duration::ZERO).is_none());
        drop(pause);
        assert!(handle.pause(Duration::from_secs(1)).is_some());
    }

    #[test]
    fn verified_reinsert_info_requires_matching_path_and_pid() {
        let mut info = DeviceInfo::parse_tlvs(&HashMap::new(), Version(5, 8, 0)).unwrap();
        info.serial = Some(1234);
        let device = LocalYubiKeyDevice::from_parts(
            Some("reader".into()),
            Some("otp".into()),
            Some("fido".into()),
            Some(0x407),
            Transport::Usb,
            info.clone(),
        );
        let verified = [device];

        for (interface, path) in [
            (VerifiedInterface::Ccid, "reader"),
            (VerifiedInterface::Otp, "otp"),
            (VerifiedInterface::Fido, "fido"),
        ] {
            assert_eq!(
                verified_info(&verified, interface, path, Some(0x407)),
                Some(info.clone())
            );
            assert_eq!(
                verified_info(&verified, interface, "another device", Some(0x407)),
                None
            );
            assert_eq!(verified_info(&verified, interface, path, Some(0x408)), None);
        }
    }

    #[cfg(feature = "pcsc")]
    fn state_with_usb_cards(readers: &[(&str, Option<ReaderInstance>)]) -> MonitorState {
        let info = DeviceInfo::parse_tlvs(&HashMap::new(), Version(5, 8, 0)).unwrap();
        let mut state = MonitorState::default();
        for (name, instance) in readers {
            let name = *name;
            state.usb_readers.insert(
                name.into(),
                DeviceNode::UsbReaderNode {
                    reader_name: name.into(),
                    pid: 0x407,
                    usb_id: None,
                },
            );
            state.cards.insert(
                name.into(),
                DeviceNode::CardNode {
                    reader_name: name.into(),
                    device_info: info.clone(),
                },
            );
            state.card_events.insert(name.into(), 1);
            if let Some(instance) = instance {
                state.reader_instances.insert(name.into(), instance.clone());
            }
        }
        state
    }

    #[cfg(feature = "pcsc")]
    #[test]
    fn uncertain_reader_removal_preserves_cards_and_retry_deadlines() {
        let known = |id: &str| Some(ReaderInstance::Known(id.into()));
        let failed = ReaderInstance::Unknown {
            retry_at: Instant::now() + Duration::from_secs(5),
        };
        let mut state = state_with_usb_cards(&[
            ("known", known(r"USB\VID_1050&PID_0407\1")),
            ("failed", Some(failed.clone())),
            ("uncached", None),
        ]);
        let cards = state.cards.clone();
        let counters = state.card_events.clone();
        let mut removed = Vec::new();
        state.invalidate_usb_cards(Some(r"USB\VID_1050&PID_0407\0"), &mut |e| removed.push(e));
        assert!(removed.is_empty());
        assert_eq!(state.cards, cards);
        assert_eq!(state.card_events, counters);
        assert_eq!(state.reader_instances.get("failed"), Some(&failed));
        assert_eq!(state.stale_cards.len(), 2);
        assert!(!state.stale_cards.contains("known"));

        state.invalidate_usb_cards(None, &mut |e| removed.push(e));
        assert!(removed.is_empty());
        assert_eq!(state.cards, cards);
        assert_eq!(state.card_events, counters);
        assert_eq!(state.stale_cards.len(), 3);
        assert_eq!(state.reader_instances.get("failed"), Some(&failed));
        assert!(!state.reader_instances.contains_key("known"));
    }

    #[cfg(feature = "pcsc")]
    #[test]
    fn uncertain_refresh_keeps_busy_card_and_retries_without_invalidating_it() {
        let reader = "Yubico YubiKey OTP+FIDO+CCID 0";
        let failed = ReaderInstance::Unknown {
            retry_at: Instant::now() + Duration::from_secs(5),
        };
        for (instance, removed) in [
            (Some(failed.clone()), Some(r"USB\VID_1050&PID_0407\other")),
            (Some(failed), None),
            (
                Some(ReaderInstance::Known(r"USB\VID_1050&PID_0407\0".into())),
                None,
            ),
            (None, Some(r"USB\VID_1050&PID_0407\other")),
        ] {
            let mut state = state_with_usb_cards(&[(reader, instance)]);
            let cards = state.cards.clone();
            let counters = state.card_events.clone();
            let info = match &cards[reader] {
                DeviceNode::CardNode { device_info, .. } => device_info.clone(),
                _ => unreachable!(),
            };
            let statuses = [ReaderStatus {
                name: reader.into(),
                card_present: true,
                event_count: 1,
            }];
            let mut events = Vec::new();
            state.invalidate_usb_cards(removed, &mut |e| events.push(e));
            let instances = state.reader_instances.clone();
            let mut probes = 0;
            state.refresh_pcsc_cards(&statuses, &mut |e| events.push(e), &[], |name, probe| {
                assert_eq!(name, reader);
                assert!(probe.usb && probe.exclusive_only);
                probes += 1;
                Err(crate::platform::pcsc::PcscError::Pcsc(::pcsc::Error::SharingViolation).into())
            });
            assert_eq!(probes, 1);
            assert!(events.is_empty());
            assert_eq!(state.cards, cards);
            assert_eq!(state.card_events, counters);
            assert_eq!(state.reader_instances, instances);
            assert!(state.stale_cards.contains(reader));

            state.refresh_pcsc_cards(&statuses, &mut |e| events.push(e), &[], |_, probe| {
                assert!(probe.exclusive_only);
                Ok((info.clone(), None))
            });
            assert!(events.is_empty());
            assert_eq!(state.cards, cards);
            assert_eq!(state.card_events, counters);
            assert_eq!(state.reader_instances, instances);
            assert!(state.stale_cards.is_empty());
            state.refresh_pcsc_cards(&statuses, &mut |e| events.push(e), &[], |_, _| {
                panic!("An unchanged card should not be probed again")
            });
        }
    }

    #[cfg(feature = "pcsc")]
    #[test]
    fn uncertain_refresh_publishes_changed_metadata_after_successful_probe() {
        let reader = "Yubico YubiKey OTP+FIDO+CCID 0";
        let mut state = state_with_usb_cards(&[(reader, None)]);
        let previous = state.cards[reader].clone();
        let mut events = Vec::new();
        state.invalidate_usb_cards(None, &mut |e| events.push(e));
        assert!(events.is_empty());
        let info = DeviceInfo::parse_tlvs(&HashMap::new(), Version(5, 8, 1)).unwrap();
        let node = DeviceNode::CardNode {
            reader_name: reader.into(),
            device_info: info.clone(),
        };
        state.refresh_pcsc_cards(
            &[ReaderStatus {
                name: reader.into(),
                card_present: true,
                event_count: 1,
            }],
            &mut |e| events.push(e),
            &[],
            |_, probe| {
                assert!(probe.exclusive_only);
                Ok((info.clone(), None))
            },
        );
        assert_eq!(
            events,
            vec![NodeEvent::Removed(previous), NodeEvent::Added(node.clone())]
        );
        assert_eq!(state.cards[reader], node);
        assert!(state.stale_cards.is_empty());
    }

    #[cfg(feature = "pcsc")]
    #[test]
    fn uncertain_refresh_uses_regular_read_for_uncached_card() {
        let reader = "Yubico YubiKey OTP+FIDO+CCID 0";
        let mut state = state_with_usb_cards(&[(reader, None)]);
        let node = state.cards.remove(reader).unwrap();
        state.card_events.remove(reader);
        let info = match &node {
            DeviceNode::CardNode { device_info, .. } => device_info.clone(),
            _ => unreachable!(),
        };
        let mut events = Vec::new();
        state.invalidate_usb_cards(None, &mut |e| events.push(e));
        assert!(state.stale_cards.is_empty());
        state.refresh_pcsc_cards(
            &[ReaderStatus {
                name: reader.into(),
                card_present: true,
                event_count: 1,
            }],
            &mut |e| events.push(e),
            &[],
            |_, probe| {
                assert!(!probe.exclusive_only);
                Ok((info.clone(), None))
            },
        );
        assert_eq!(events, vec![NodeEvent::Added(node)]);
    }

    #[cfg(feature = "pcsc")]
    #[test]
    fn uncertain_refresh_does_not_hide_confirmed_card_removal() {
        let reader = "Yubico YubiKey OTP+FIDO+CCID 0";
        let mut state = state_with_usb_cards(&[(reader, None)]);
        let previous = state.cards[reader].clone();
        let mut events = Vec::new();
        state.invalidate_usb_cards(None, &mut |e| events.push(e));
        state.refresh_pcsc_cards(
            &[ReaderStatus {
                name: reader.into(),
                card_present: false,
                event_count: 2,
            }],
            &mut |e| events.push(e),
            &[],
            |_, _| panic!("An absent card should not be probed"),
        );
        assert_eq!(events, vec![NodeEvent::Removed(previous)]);
        assert!(!state.cards.contains_key(reader));
        assert!(state.stale_cards.is_empty());
    }

    #[cfg(feature = "pcsc")]
    #[test]
    fn uncertain_refresh_does_not_hide_confirmed_card_replacement() {
        let reader = "Yubico YubiKey OTP+FIDO+CCID 0";
        let mut state = state_with_usb_cards(&[(reader, None)]);
        let previous = state.cards[reader].clone();
        let info = match &previous {
            DeviceNode::CardNode { device_info, .. } => device_info.clone(),
            _ => unreachable!(),
        };
        let mut events = Vec::new();
        state.invalidate_usb_cards(None, &mut |e| events.push(e));
        state.refresh_pcsc_cards(
            &[ReaderStatus {
                name: reader.into(),
                card_present: true,
                event_count: 2,
            }],
            &mut |e| events.push(e),
            &[],
            |_, probe| {
                assert!(!probe.exclusive_only);
                Ok((info.clone(), None))
            },
        );
        assert_eq!(
            events,
            vec![
                NodeEvent::Removed(previous.clone()),
                NodeEvent::Added(previous)
            ]
        );
        assert_eq!(state.card_events.get(reader), Some(&2));
        assert!(state.stale_cards.is_empty());
    }

    #[cfg(feature = "pcsc")]
    #[test]
    fn removed_reader_preserves_other_cards_with_the_same_pid() {
        let info = DeviceInfo::parse_tlvs(&HashMap::new(), Version(5, 8, 0)).unwrap();
        let mut state = MonitorState::default();
        for (name, instance) in [
            ("yk 0", r"USB\VID_1050&PID_0407\0"),
            ("yk 1", r"USB\VID_1050&PID_0407\1"),
        ] {
            state.usb_readers.insert(
                name.into(),
                DeviceNode::UsbReaderNode {
                    reader_name: name.into(),
                    pid: 0x407,
                    usb_id: None,
                },
            );
            state.cards.insert(
                name.into(),
                DeviceNode::CardNode {
                    reader_name: name.into(),
                    device_info: info.clone(),
                },
            );
            state.card_events.insert(name.into(), 1);
            state
                .reader_instances
                .insert(name.into(), ReaderInstance::Known(instance.into()));
        }

        let mut removed = Vec::new();
        state.invalidate_usb_cards(Some(r"usb\vid_1050&pid_0407\0"), &mut |event| {
            removed.push(event)
        });
        assert_eq!(removed.len(), 1);
        assert!(!state.cards.contains_key("yk 0") && !state.card_events.contains_key("yk 0"));
        assert!(state.cards.contains_key("yk 1") && state.usb_readers.contains_key("yk 0"));
        assert_eq!(state.card_events.get("yk 1"), Some(&1));
        assert!(!state.reader_instances.contains_key("yk 0"));
        assert!(state.reader_instances.contains_key("yk 1"));

        for instance in [r"SWD\ScReader\unknown", r"USB\VID_1050&PID_0407\unknown"] {
            state.invalidate_usb_cards(Some(instance), &mut |event| removed.push(event));
        }
        assert_eq!(removed.len(), 1);
        assert!(state.cards.contains_key("yk 1"));
    }

    fn info(version: Version, serial: Option<u32>) -> DeviceInfo {
        let mut info = DeviceInfo::parse_tlvs(&HashMap::new(), version).unwrap();
        info.serial = serial;
        info
    }

    fn reader(name: &str, usb_id: Option<&str>) -> DeviceNode {
        DeviceNode::UsbReaderNode {
            reader_name: name.into(),
            pid: 0x407,
            usb_id: usb_id.map(UsbDeviceId::new),
        }
    }

    fn card(name: &str, info: &DeviceInfo) -> DeviceNode {
        DeviceNode::CardNode {
            reader_name: name.into(),
            device_info: info.clone(),
        }
    }

    fn otp(path: &str, usb_id: Option<&str>, info: &DeviceInfo) -> DeviceNode {
        DeviceNode::HidOtpNode {
            hid_path: path.into(),
            pid: 0x407,
            usb_id: usb_id.map(UsbDeviceId::new),
            device_info: info.clone(),
        }
    }

    fn fido(path: &str, usb_id: Option<&str>, info: &DeviceInfo) -> DeviceNode {
        DeviceNode::HidFidoNode {
            hid_path: path.into(),
            pid: 0x407,
            usb_id: usb_id.map(UsbDeviceId::new),
            device_info: info.clone(),
        }
    }

    fn aggregate(nodes: Vec<DeviceNode>) -> Vec<BuiltDevice> {
        let mut agg = Aggregator::default();
        for node in nodes {
            agg.apply(NodeEvent::Added(node));
        }
        let mut built = agg.build_devices();
        built.sort_by(|a, b| a.device.reader_name.cmp(&b.device.reader_name));
        built
    }

    #[test]
    fn aggregator_groups_serial_less_keys_by_usb_identity() {
        // Two identical same-version keys without serials (e.g. hidden serial
        // API) would be indistinguishable from DeviceInfo alone.
        let hidden = info(Version(5, 4, 3), None);
        let built = aggregate(vec![
            reader("yk 0", Some("a")),
            card("yk 0", &hidden),
            reader("yk 1", Some("b")),
            card("yk 1", &hidden),
            otp("otp0", Some("a"), &hidden),
            otp("otp1", Some("b"), &hidden),
            fido("fido1", Some("b"), &hidden),
            fido("fido0", Some("a"), &hidden),
        ]);
        assert_eq!(built.len(), 2);
        assert_eq!(built[0].device.reader_name.as_deref(), Some("yk 0"));
        assert_eq!(built[0].device.hid_path.as_deref(), Some("otp0"));
        assert_eq!(built[0].device.fido_path.as_deref(), Some("fido0"));
        assert_eq!(built[0].usb_id, Some(UsbDeviceId::new("a")));
        assert_eq!(built[1].device.reader_name.as_deref(), Some("yk 1"));
        assert_eq!(built[1].device.hid_path.as_deref(), Some("otp1"));
        assert_eq!(built[1].device.fido_path.as_deref(), Some("fido1"));
    }

    #[test]
    fn aggregator_never_merges_across_usb_identities() {
        // A single physical key would merge on unique PID; the OS says these
        // are two devices, so they must stay apart even with equal info.
        let same = info(Version(5, 4, 3), Some(42));
        let built = aggregate(vec![
            reader("yk 0", Some("a")),
            card("yk 0", &same),
            fido("fido1", Some("b"), &same),
        ]);
        assert_eq!(built.len(), 2);
    }

    #[test]
    fn aggregator_falls_back_to_heuristics_without_identity() {
        // macOS-style: readers have no identity, HID interfaces do.
        let first = info(Version(5, 4, 3), Some(1));
        let second = info(Version(5, 4, 3), Some(2));
        let built = aggregate(vec![
            reader("yk 0", None),
            card("yk 0", &first),
            reader("yk 1", None),
            card("yk 1", &second),
            otp("otp0", Some("a"), &first),
            otp("otp1", Some("b"), &second),
            fido("fido1", Some("b"), &second),
            fido("fido0", Some("a"), &first),
        ]);
        assert_eq!(built.len(), 2);
        assert_eq!(built[0].device.hid_path.as_deref(), Some("otp0"));
        assert_eq!(built[0].device.fido_path.as_deref(), Some("fido0"));
        assert_eq!(built[0].usb_id, Some(UsbDeviceId::new("a")));
        assert_eq!(built[1].device.hid_path.as_deref(), Some("otp1"));
        assert_eq!(built[1].device.fido_path.as_deref(), Some("fido1"));

        // A single device of its PID still merges without any identity.
        let only = info(Version(5, 7, 1), Some(3));
        let built = aggregate(vec![
            reader("yk 0", None),
            card("yk 0", &only),
            otp("otp0", None, &only),
            fido("fido0", None, &only),
        ]);
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].nodes.len(), 4);
    }

    #[test]
    fn aggregator_reconcile_tracks_identity_across_info_changes() {
        // A key whose reported info changes (e.g. HID node adopting card info)
        // stays the same YubiKey when the OS identity matches.
        let hid_info = info(Version(5, 4, 3), None);
        let card_info = info(Version(5, 4, 3), Some(7));
        let mut agg = Aggregator::default();
        let mut events = Vec::new();
        agg.apply(NodeEvent::Added(fido("fido0", Some("a"), &hid_info)));
        agg.reconcile(&mut |e| events.push(e));
        let id = match events.as_slice() {
            [YubiKeyEvent::Added(yk)] => yk.id(),
            other => panic!("unexpected events: {other:?}"),
        };
        events.clear();
        agg.apply(NodeEvent::Added(reader("yk 0", Some("a"))));
        agg.apply(NodeEvent::Added(card("yk 0", &card_info)));
        agg.apply(NodeEvent::Removed(fido("fido0", Some("a"), &hid_info)));
        agg.apply(NodeEvent::Added(fido("fido0", Some("a"), &card_info)));
        agg.reconcile(&mut |e| events.push(e));
        match events.as_slice() {
            [YubiKeyEvent::Changed(yk)] => {
                assert_eq!(yk.id(), id);
                assert_eq!(yk.info().serial, Some(7));
                assert_eq!(yk.usb_id(), Some(&UsbDeviceId::new("a")));
            }
            other => panic!("unexpected events: {other:?}"),
        }
    }

    #[cfg(all(feature = "pcsc", feature = "hid"))]
    #[test]
    fn hid_nodes_adopt_card_info_for_the_same_usb_device() {
        let hid_info = info(Version(5, 4, 3), None);
        let card_info = info(Version(5, 4, 3), Some(7));
        let mut state = MonitorState::default();
        state
            .usb_readers
            .insert("yk 0".into(), reader("yk 0", Some("a")));
        state.cards.insert("yk 0".into(), card("yk 0", &card_info));
        state
            .hid_fido
            .insert("fido0".into(), fido("fido0", Some("a"), &hid_info));
        state
            .hid_fido
            .insert("fido1".into(), fido("fido1", Some("b"), &hid_info));
        state
            .hid_otp
            .insert("otp0".into(), otp("otp0", Some("a"), &card_info));

        let id = UsbDeviceId::new("a");
        assert_eq!(state.group_info(&id), Some(&card_info));
        assert_eq!(state.group_info(&UsbDeviceId::new("b")), Some(&hid_info));
        assert_eq!(state.group_info(&UsbDeviceId::new("c")), None);

        let mut events = Vec::new();
        state.adopt_hid_info(&id, &card_info, &mut |e| events.push(e));
        assert!(matches!(
            events.as_slice(),
            [NodeEvent::Removed(DeviceNode::HidFidoNode { hid_path: r, .. }), NodeEvent::Added(DeviceNode::HidFidoNode { hid_path: a, device_info, .. })]
                if r == "fido0" && a == "fido0" && *device_info == card_info
        ));
        assert!(matches!(
            state.hid_fido.get("fido1"),
            Some(DeviceNode::HidFidoNode { device_info, .. }) if *device_info == hid_info
        ));
    }
}
