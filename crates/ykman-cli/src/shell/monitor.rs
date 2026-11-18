//! Event-based key detection using yubikit's device monitor, so the shell
//! learns about inserted and removed keys immediately instead of polling.

use super::*;
use std::collections::HashMap;
use yubikit::management::UsbInterface;
use yubikit::platform::monitor::{MonitorHandle, YubiKeyEvent, monitor_yubikeys};

/// How long the first full scan may take; a NEO needs a while to probe.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a NEO placeholder is held back while its interfaces are probed.
const GHOST_DELAY: Duration = Duration::from_millis(800);

#[derive(Default)]
struct Shared {
    devices: HashMap<u64, Device>,
    ready: bool,
    /// Ids in the list last sent to the shell.
    sent: Vec<u64>,
    /// Bumped on every send so a held-back list can tell it was superseded.
    generation: u64,
}

impl Shared {
    fn send(&mut self, tx: &Sender<Msg>) {
        self.generation += 1;
        self.sent = self.devices.keys().copied().collect();
        let _ = tx.send(Msg::Monitored(sorted(&self.devices)));
    }

    /// Whether the list holds a placeholder the shell hasn't seen yet.
    fn has_new_ghost(&self) -> bool {
        self.devices
            .iter()
            .any(|(id, d)| is_probe_placeholder(d) && !self.sent.contains(id))
    }
}

/// The bare 1.1.0 stand-in for a NEO whose interfaces haven't been read yet.
/// Keys without a serial but with a real version are shown right away.
fn is_probe_placeholder(d: &Device) -> bool {
    d.serial == NO_SERIAL && d.version == "1.1.0"
}

/// Longest a command start waits for an in-flight probe to finish.
const PAUSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Dropping it lets the monitor probe keys again.
pub(super) struct Pause(#[allow(dead_code)] Sender<()>);

/// Stops the monitor from probing keys until the result is dropped, so a
/// command doesn't compete with it for the same key. Waits for a probe that is
/// already running; `None` if there is no monitor or it didn't finish in time.
pub(super) fn pause(monitor: Option<&dyn std::any::Any>) -> Option<Pause> {
    let handle = Arc::clone(monitor?.downcast_ref::<Arc<MonitorHandle>>()?);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let guard = handle.pause(PAUSE_TIMEOUT);
        let _ = held_tx.send(guard.is_some());
        if guard.is_some() {
            // Returns once the `Pause` (the sender) is dropped.
            let _ = release_rx.recv();
        }
    });
    held_rx.recv().ok()?.then_some(Pause(release_tx))
}

/// Starts the monitor without waiting for it. Every change, starting with the
/// first full scan, sends the complete device list as `Msg::Monitored`; until
/// then the shell keeps polling.
pub(super) fn start(tx: Sender<Msg>) -> Arc<MonitorHandle> {
    // The key map, and whether the first scan is done. Events before that
    // only fill the map, so the shell never sees a half-built list.
    let state = Arc::new(Mutex::new(Shared::default()));
    let shared = Arc::clone(&state);
    let sender = tx.clone();
    let handle = monitor_yubikeys(
        UsbInterface::CCID | UsbInterface::FIDO | UsbInterface::OTP,
        move |event| {
            let Ok(mut s) = shared.lock() else { return };
            match event {
                YubiKeyEvent::Added(yk) | YubiKeyEvent::Changed(yk) => {
                    let info = yk.device().info();
                    s.devices.insert(
                        yk.id(),
                        Device {
                            serial: info.serial.unwrap_or(NO_SERIAL),
                            name: yk.device().name(),
                            version: info.version_name(),
                        },
                    );
                }
                YubiKeyEvent::Removed(yk) => {
                    s.devices.remove(&yk.id());
                }
            }
            if !s.ready {
                return;
            }
            if s.has_new_ghost() {
                // Wait to see whether it settles into a real key; any later
                // send supersedes this one.
                let (state, tx, generation) = (Arc::clone(&shared), sender.clone(), s.generation);
                std::thread::spawn(move || {
                    std::thread::sleep(GHOST_DELAY);
                    if let Ok(mut s) = state.lock()
                        && s.generation == generation
                    {
                        s.send(&tx);
                    }
                });
            } else {
                s.send(&sender);
            }
        },
    );
    let handle = Arc::new(handle);
    let waiting = Arc::clone(&handle);
    std::thread::spawn(move || {
        if !waiting.wait_ready(READY_TIMEOUT) {
            return;
        }
        if let Ok(mut s) = state.lock() {
            s.ready = true;
            s.send(&tx);
        }
    });
    handle
}

/// Same order as `parse_devices`: newest (highest serial) first.
fn sorted(map: &HashMap<u64, Device>) -> Vec<Device> {
    let mut devices: Vec<Device> = map.values().cloned().collect();
    devices.sort_by_key(|d| std::cmp::Reverse(d.serial));
    devices
}
