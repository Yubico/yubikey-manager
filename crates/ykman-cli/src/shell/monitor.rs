//! Event-based key detection using yubikit's device monitor, so the shell
//! learns about inserted and removed keys immediately instead of polling.

use super::*;
use std::collections::HashMap;
use yubikit::management::UsbInterface;
use yubikit::platform::monitor::{MonitorHandle, YubiKeyEvent, monitor_yubikeys};

/// How long the first full scan may take; a NEO needs a while to probe.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Starts the monitor without waiting for it. Every change, starting with the
/// first full scan, sends the complete device list as `Msg::Monitored`; until
/// then the shell keeps polling.
pub(super) fn start(tx: Sender<Msg>) -> Arc<MonitorHandle> {
    // The key map, and whether the first scan is done. Events before that
    // only fill the map, so the shell never sees a half-built list.
    let state = Arc::new(Mutex::new((HashMap::<u64, Device>::new(), false)));
    let shared = Arc::clone(&state);
    let sender = tx.clone();
    let handle = monitor_yubikeys(
        UsbInterface::CCID | UsbInterface::FIDO | UsbInterface::OTP,
        move |event| {
            let Ok(mut s) = shared.lock() else { return };
            match event {
                YubiKeyEvent::Added(yk) | YubiKeyEvent::Changed(yk) => {
                    let info = yk.device().info();
                    s.0.insert(
                        yk.id(),
                        Device {
                            serial: info.serial.unwrap_or(NO_SERIAL),
                            name: yk.device().name(),
                            version: info.version_name(),
                        },
                    );
                }
                YubiKeyEvent::Removed(yk) => {
                    s.0.remove(&yk.id());
                }
            }
            if s.1 {
                let _ = sender.send(Msg::Monitored(sorted(&s.0)));
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
            s.1 = true;
            let _ = tx.send(Msg::Monitored(sorted(&s.0)));
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
