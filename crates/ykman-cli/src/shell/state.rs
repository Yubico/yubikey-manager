use super::*;

#[cfg(test)]
mod tests;

pub(super) fn state_file() -> Option<std::path::PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)?
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
            })?
    };
    Some(base.join("ykman").join("shell-state"))
}

/// Loads the saved log level and command history (best effort).
#[derive(Default)]
pub(super) struct SavedState {
    pub(super) level: Option<&'static str>,
    pub(super) tab: usize,
    pub(super) history: Vec<String>,
}

pub(super) fn load_state() -> SavedState {
    let mut state = SavedState::default();
    let Some(text) = state_file().and_then(|p| std::fs::read_to_string(p).ok()) else {
        return state;
    };
    for line in text.lines() {
        if let Some(l) = line.strip_prefix("log=") {
            state.level = LEVELS.iter().map(|(n, _)| *n).find(|n| *n == l);
        } else if let Some(t) = line.strip_prefix("tab=") {
            state.tab = t.parse().ok().filter(|t| *t < TABS.len()).unwrap_or(0);
        } else if line.starts_with('/') {
            state.history.push(line.to_string());
        }
    }
    state
}

pub(super) fn save_state(level: &str, tab: usize, history: &[String]) {
    let Some(path) = state_file() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut text = format!("log={level}\ntab={tab}\n");
    for h in history {
        text.push_str(h);
        text.push('\n');
    }
    let _ = std::fs::write(path, text);
}

/// Lists keys through a child process: enumerating HID devices inside the
/// shell crashes macOS IOKit when a key re-enumerates (e.g. after a reset).
pub(super) fn list_devices() -> Vec<Device> {
    std::process::Command::new(exe())
        .arg("list")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| parse_devices(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

pub(super) fn parse_devices(stdout: &str) -> Vec<Device> {
    let mut devices: Vec<Device> = stdout
        .lines()
        .filter_map(|line| {
            // Keys such as the FIDO U2F Security Key have no serial number.
            let (head, serial) = match line.rsplit_once("Serial:") {
                Some((head, serial)) => (head, serial.trim().parse().ok()?),
                None => (line, NO_SERIAL),
            };
            let (name, rest) = head.split_once('(')?;
            let version = rest.split_once(')')?.0;
            Some(Device {
                serial,
                name: name.trim().to_string(),
                version: version.to_string(),
            })
        })
        .collect();
    // ykman's order can change between polls; keep the picker steady, newest
    // (highest serial) first.
    devices.sort_by_key(|d| std::cmp::Reverse(d.serial));
    devices
}

impl App {
    pub(super) fn save(&mut self) {
        self.saved_tab = self.tab;
        save_state(self.log_level, self.tab, &self.saved);
    }

    pub(super) fn refresh_devices(&mut self) {
        self.polling = true;
        POLLS_IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let devices = list_devices();
            POLLS_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            let _ = tx.send(Msg::Devices(devices));
        });
    }
}

/// Device polls running right now. A command must not open the key at the same
/// time as a poll, or one of them may see no YubiKey.
pub(super) static POLLS_IN_FLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Wait (briefly) for a device poll in progress to finish.
pub(super) fn wait_for_poll() {
    let start = std::time::Instant::now();
    while POLLS_IN_FLIGHT.load(std::sync::atomic::Ordering::SeqCst) > 0
        && start.elapsed() < std::time::Duration::from_secs(3)
    {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
