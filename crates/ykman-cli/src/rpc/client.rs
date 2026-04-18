//! RPC client — spawns `ykman rpc --tcp` as a subprocess and communicates via TCP.
//!
//! On Windows, if not running as administrator the subprocess is launched
//! elevated via `ShellExecuteExW` with the `runas` verb, since FIDO HID
//! access requires administrator rights.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::util::CliError;

/// Handle to the spawned subprocess — platform-specific.
enum ChildProcess {
    #[allow(dead_code)]
    Std(std::process::Child),
    #[cfg(target_os = "windows")]
    Elevated(windows_elevated::ElevatedProcess),
}

/// An RPC client connected to a `ykman rpc` subprocess over TCP.
pub struct RpcClient {
    child: ChildProcess,
    reader: BufReader<TcpStream>,
    writer: Arc<Mutex<TcpStream>>,
    _listener: TcpListener,
}

impl RpcClient {
    /// Spawn `ykman rpc --tcp PORT NONCE` and connect over TCP.
    ///
    /// If `elevate` is true (Windows only), the subprocess is launched with
    /// administrator privileges via UAC.
    pub fn spawn(global_args: &[String], elevate: bool) -> Result<Self, CliError> {
        let exe = std::env::current_exe()
            .map_err(|e| CliError(format!("Failed to determine executable path: {e}")))?;

        // Bind a random port on localhost
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| CliError(format!("Failed to bind TCP listener: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| CliError(format!("Failed to get listener address: {e}")))?
            .port();

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 16];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| CliError(format!("Failed to generate nonce: {e}")))?;
        let nonce = hex::encode(nonce_bytes);

        let mut rpc_args = global_args.to_vec();
        rpc_args.extend([
            "rpc".into(),
            "--tcp".into(),
            port.to_string(),
            nonce.clone(),
        ]);

        let child = if elevate {
            #[cfg(target_os = "windows")]
            {
                ChildProcess::Elevated(windows_elevated::spawn_elevated(&exe, &rpc_args)?)
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = elevate;
                return Err(CliError(
                    "Elevated spawn is only supported on Windows".into(),
                ));
            }
        } else {
            ChildProcess::Std(spawn_normal(&exe, &rpc_args)?)
        };

        // Accept the connection from the subprocess
        let (stream, _addr) = listener
            .accept()
            .map_err(|e| CliError(format!("Failed to accept TCP connection: {e}")))?;

        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| CliError(format!("Failed to clone stream: {e}")))?,
        );

        // Verify the nonce
        let mut nonce_line = String::new();
        reader
            .read_line(&mut nonce_line)
            .map_err(|e| CliError(format!("Failed to read nonce: {e}")))?;
        if nonce_line.trim() != nonce {
            return Err(CliError("Nonce verification failed".into()));
        }

        let writer = Arc::new(Mutex::new(stream));

        Ok(Self {
            child,
            reader,
            writer,
            _listener: listener,
        })
    }

    fn write_message(&self, msg: &Value) -> Result<(), CliError> {
        let json_str = serde_json::to_string(msg)
            .map_err(|e| CliError(format!("Failed to serialize RPC message: {e}")))?;
        let mut writer = self.writer.lock().unwrap();
        writer
            .write_all(json_str.as_bytes())
            .map_err(|e| CliError(format!("Failed to write to RPC subprocess: {e}")))?;
        writer
            .write_all(b"\n")
            .map_err(|e| CliError(format!("Failed to write to RPC subprocess: {e}")))?;
        writer
            .flush()
            .map_err(|e| CliError(format!("Failed to flush RPC subprocess: {e}")))?;
        Ok(())
    }

    /// Send a command and return the response body. Signals are dispatched via
    /// the callback. Returns `Err` for RPC errors.
    ///
    /// If `cancellable` is true, a Ctrl+C handler is installed that sends a
    /// cancel signal to the subprocess.
    pub fn call(
        &mut self,
        action: &str,
        target: &[&str],
        body: Value,
        signal_handler: Option<&dyn Fn(&str, &Value)>,
        cancellable: bool,
    ) -> Result<RpcResult, CliError> {
        let request = json!({
            "kind": "command",
            "action": action,
            "target": target,
            "body": body,
        });
        self.write_message(&request)?;

        // Install Ctrl+C handler that sends cancel to subprocess
        if cancellable {
            let writer = self.writer.clone();
            let _ = ctrlc::set_handler(move || {
                let signal = json!({"kind": "signal", "status": "cancel"});
                let json_str = serde_json::to_string(&signal).unwrap();
                if let Ok(mut w) = writer.lock() {
                    let _ = w.write_all(json_str.as_bytes());
                    let _ = w.write_all(b"\n");
                    let _ = w.flush();
                }
            });
        }

        loop {
            let mut buf = String::new();
            let n = self
                .reader
                .read_line(&mut buf)
                .map_err(|e| CliError(format!("Failed to read from RPC subprocess: {e}")))?;
            if n == 0 {
                return Err(CliError("RPC subprocess closed unexpectedly".into()));
            }

            // TCP messages are prefixed: "O" = output/JSON, "E" = stderr/log
            let line = buf.trim();
            let (prefix, json_str) = if line.starts_with('O') || line.starts_with('E') {
                (line.as_bytes()[0], &line[1..])
            } else {
                (b'O', line)
            };

            if prefix == b'E' {
                eprint!("{json_str}");
                continue;
            }

            let resp: Value = serde_json::from_str(json_str)
                .map_err(|e| CliError(format!("Invalid JSON from RPC subprocess: {e}")))?;

            match resp.get("kind").and_then(|v| v.as_str()) {
                Some("success") => {
                    let body = resp.get("body").cloned().unwrap_or(json!({}));
                    let flags: Vec<String> = resp
                        .get("flags")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    return Ok(RpcResult { body, flags });
                }
                Some("error") => {
                    let status = resp
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let message = resp
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error")
                        .to_string();
                    let body = resp.get("body").cloned().unwrap_or(json!({}));
                    return Err(CliError(format!("RPC error ({status}): {message} {body}")));
                }
                Some("signal") => {
                    if let Some(handler) = signal_handler {
                        let status = resp.get("status").and_then(|v| v.as_str()).unwrap_or("");
                        let empty = json!({});
                        let body = resp.get("body").unwrap_or(&empty);
                        handler(status, body);
                    }
                }
                _ => {
                    return Err(CliError(format!(
                        "Unexpected RPC response kind: {}",
                        resp.get("kind").unwrap_or(&json!(null))
                    )));
                }
            }
        }
    }

    /// Call `get` on a target to retrieve node info.
    pub fn get(&mut self, target: &[&str]) -> Result<RpcResult, CliError> {
        self.call("get", target, json!({}), None, false)
    }
}

impl Drop for RpcClient {
    fn drop(&mut self) {
        // Shut down the write side to signal the subprocess to exit
        if let Ok(w) = self.writer.lock() {
            let _ = w.shutdown(std::net::Shutdown::Write);
        }
        match &mut self.child {
            ChildProcess::Std(child) => {
                let _ = child.wait();
            }
            #[cfg(target_os = "windows")]
            ChildProcess::Elevated(proc) => {
                proc.wait();
            }
        }
    }
}

/// Spawn the subprocess normally (no elevation).
fn spawn_normal(exe: &std::path::Path, args: &[String]) -> Result<std::process::Child, CliError> {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(exe);
    cmd.args(args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::inherit());

    // On Unix, put child in its own process group so Ctrl+C doesn't kill it
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    cmd.spawn()
        .map_err(|e| CliError(format!("Failed to spawn ykman rpc: {e}")))
}

/// Successful RPC response.
pub struct RpcResult {
    pub body: Value,
    #[allow(dead_code)]
    pub flags: Vec<String>,
}

// --- Windows-specific: elevated process spawning and admin detection ---

#[cfg(target_os = "windows")]
pub(crate) mod windows_elevated {
    use crate::util::CliError;

    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        IsUserAnAdmin, SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        SHELLEXECUTEINFOW_0, ShellExecuteExW,
    };

    /// Check whether the current process is running with administrator rights.
    pub fn is_admin() -> bool {
        // SAFETY: IsUserAnAdmin has no preconditions.
        unsafe { IsUserAnAdmin() != 0 }
    }

    /// A process spawned with elevated (administrator) privileges via UAC.
    pub struct ElevatedProcess {
        handle: HANDLE,
    }

    // SAFETY: The process handle is owned exclusively and can be sent across threads.
    unsafe impl Send for ElevatedProcess {}

    impl ElevatedProcess {
        /// Wait for the elevated process to exit.
        pub fn wait(&self) {
            if !self.handle.is_null() {
                // SAFETY: handle is a valid process handle from ShellExecuteExW.
                unsafe {
                    WaitForSingleObject(self.handle, INFINITE);
                }
            }
        }
    }

    impl Drop for ElevatedProcess {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: handle is a valid process handle, dropped exactly once.
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }
    }

    fn to_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Spawn a process with administrator privileges using ShellExecuteExW("runas").
    pub fn spawn_elevated(exe: &Path, args: &[String]) -> Result<ElevatedProcess, CliError> {
        let verb = to_wide(OsStr::new("runas"));
        let file = to_wide(exe.as_os_str());
        let params_str = args
            .iter()
            .map(|a| {
                if a.contains(' ') || a.contains('"') {
                    format!("\"{}\"", a.replace('"', "\\\""))
                } else {
                    a.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let params = to_wide(OsStr::new(&params_str));

        let mut sei = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
            hwnd: std::ptr::null_mut(),
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: params.as_ptr(),
            lpDirectory: std::ptr::null(),
            nShow: 0, // SW_HIDE
            hInstApp: std::ptr::null_mut(),
            lpIDList: std::ptr::null_mut(),
            lpClass: std::ptr::null(),
            hkeyClass: std::ptr::null_mut(),
            dwHotKey: 0,
            Anonymous: SHELLEXECUTEINFOW_0 {
                hIcon: std::ptr::null_mut(),
            },
            hProcess: std::ptr::null_mut(),
        };

        // SAFETY: sei is correctly initialized with valid pointers to
        // null-terminated wide strings that outlive this call.
        let ok = unsafe { ShellExecuteExW(&mut sei) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(CliError(format!(
                "Failed to launch elevated ykman rpc: {err}"
            )));
        }

        if sei.hProcess.is_null() {
            return Err(CliError(
                "ShellExecuteEx succeeded but returned no process handle".into(),
            ));
        }

        Ok(ElevatedProcess {
            handle: sei.hProcess,
        })
    }
}

/// Returns true if FIDO commands should use the RPC mechanism.
///
/// On Windows, this is true when the current process is not running as
/// administrator, since FIDO HID access requires elevation.
/// On other platforms, this is controlled by the `RPC=1` environment variable
/// (for development/testing purposes only).
pub fn should_use_fido_rpc() -> bool {
    #[cfg(target_os = "windows")]
    {
        !windows_elevated::is_admin()
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("RPC").is_ok()
    }
}
