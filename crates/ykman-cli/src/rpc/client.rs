//! RPC client — spawns `ykman rpc --tcp` as a subprocess and communicates via TCP.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::util::CliError;

/// An RPC client connected to a `ykman rpc` subprocess over TCP.
pub struct RpcClient {
    child: Child,
    reader: BufReader<TcpStream>,
    writer: Arc<Mutex<TcpStream>>,
    _listener: TcpListener,
}

impl RpcClient {
    /// Spawn `ykman rpc --tcp PORT NONCE` and connect over TCP.
    pub fn spawn(global_args: &[String]) -> Result<Self, CliError> {
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

        let mut cmd = Command::new(exe);
        for arg in global_args {
            cmd.arg(arg);
        }
        cmd.args(["rpc", "--tcp", &port.to_string(), &nonce]);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::inherit());
        // Own process group so Ctrl+C doesn't kill the child directly
        cmd.process_group(0);

        let child = cmd
            .spawn()
            .map_err(|e| CliError(format!("Failed to spawn ykman rpc: {e}")))?;

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
        let _ = self.child.wait();
    }
}

/// Successful RPC response.
pub struct RpcResult {
    pub body: Value,
    #[allow(dead_code)]
    pub flags: Vec<String>,
}
