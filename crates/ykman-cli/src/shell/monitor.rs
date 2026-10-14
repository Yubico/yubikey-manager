//! Event-based key detection using yubikit's device monitor, so the shell
//! learns about inserted and removed keys immediately instead of polling.

use super::*;
use std::collections::HashMap;
use yubikit::management::UsbInterface;
use yubikit::platform::monitor::{MonitorHandle, YubiKeyEvent, monitor_yubikeys};

/// How long to wait for the monitor's first full scan before falling back to polling.
const READY_TIMEOUT: Duration = Duration::from_secs(3);

/// Starts the monitor. Every change sends the complete device list as
/// `Msg::Monitored`. Returns `None` if the first scan doesn't finish in time.
pub(super) fn start(tx: Sender<Msg>) -> Option<MonitorHandle> {
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
    if !handle.wait_ready(READY_TIMEOUT) {
        return None;
    }
    let mut s = state.lock().ok()?;
    s.1 = true;
    let _ = tx.send(Msg::Monitored(sorted(&s.0)));
    drop(s);
    Some(handle)
}

/// Same order as `parse_devices`: newest (highest serial) first.
fn sorted(map: &HashMap<u64, Device>) -> Vec<Device> {
    let mut devices: Vec<Device> = map.values().cloned().collect();
    devices.sort_by_key(|d| std::cmp::Reverse(d.serial));
    devices
}
