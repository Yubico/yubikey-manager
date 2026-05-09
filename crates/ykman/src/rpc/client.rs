//! RPC client — connects to ykman-svc Named Pipe.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::cancel;
use crate::util::CliError;

/// Transport abstraction for the RPC client's read/write streams.
enum Transport {
    /// Generic stream (Named Pipe file handle, Unix socket, etc).
    Stream {
        reader: BufReader<Box<dyn Read + Send>>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
    },
}

/// An RPC client connected to a ykman RPC server.
pub struct RpcClient {
    transport: Transport,
}

/// Thread-safe writer handle for sending cancel signals from the Ctrl+C handler.
struct CancelWriter(Arc<Mutex<Box<dyn Write + Send>>>);

// SAFETY: Box<dyn Write + Send> is Send; Arc<Mutex<>> ensures thread-safe access.
unsafe impl Send for CancelWriter {}
unsafe impl Sync for CancelWriter {}

impl CancelWriter {
    fn send_cancel(&self, data: &[u8]) {
        if let Ok(mut w) = self.0.lock() {
            let _ = w.write_all(data);
            let _ = w.write_all(b"\n");
            let _ = w.flush();
        }
    }
}

impl RpcClient {
    /// Connect to the ykman-svc Named Pipe (Windows) or Unix socket (dev).
    ///
    /// Returns `Err` if the service is not available.
    pub fn connect_pipe() -> Result<Self, CliError> {
        #[cfg(target_os = "windows")]
        {
            use std::fs::OpenOptions;
            use std::os::windows::fs::OpenOptionsExt;

            let pipe_path = r"\\.\pipe\ykman-svc";
            log::debug!("Connecting to Named Pipe: {pipe_path}");

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(0) // FILE_FLAG_NORMAL
                .open(pipe_path)
                .map_err(|e| CliError(format!("Failed to connect to ykman-svc pipe: {e}")))?;

            let reader: Box<dyn Read + Send> = Box::new(
                file.try_clone()
                    .map_err(|e| CliError(format!("Failed to clone pipe handle: {e}")))?,
            );
            let writer: Box<dyn Write + Send> = Box::new(file);

            log::debug!("Connected to ykman-svc pipe");
            Ok(Self {
                transport: Transport::Stream {
                    reader: BufReader::new(reader),
                    writer: Arc::new(Mutex::new(writer)),
                },
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::net::UnixStream;

            let socket_path = "/tmp/ykman-svc.sock";
            log::debug!("Connecting to Unix socket: {socket_path}");

            let stream = UnixStream::connect(socket_path)
                .map_err(|e| CliError(format!("Failed to connect to ykman-svc socket: {e}")))?;

            let reader: Box<dyn Read + Send> = Box::new(
                stream
                    .try_clone()
                    .map_err(|e| CliError(format!("Failed to clone socket: {e}")))?,
            );
            let writer: Box<dyn Write + Send> = Box::new(stream);

            log::debug!("Connected to ykman-svc socket");
            Ok(Self {
                transport: Transport::Stream {
                    reader: BufReader::new(reader),
                    writer: Arc::new(Mutex::new(writer)),
                },
            })
        }
    }

    fn write_message(&self, msg: &Value) -> Result<(), CliError> {
        let json_str = serde_json::to_string(msg)
            .map_err(|e| CliError(format!("Failed to serialize RPC message: {e}")))?;
        let Transport::Stream { writer, .. } = &self.transport;
        let mut writer = writer.lock().unwrap();
        writer
            .write_all(json_str.as_bytes())
            .map_err(|e| CliError(format!("Failed to write to RPC: {e}")))?;
        writer
            .write_all(b"\n")
            .map_err(|e| CliError(format!("Failed to write to RPC: {e}")))?;
        writer
            .flush()
            .map_err(|e| CliError(format!("Failed to flush RPC: {e}")))?;
        Ok(())
    }

    fn cancel_writer(&self) -> CancelWriter {
        let Transport::Stream { writer, .. } = &self.transport;
        CancelWriter(writer.clone())
    }

    /// Send a command and return the response body. Signals are dispatched via
    /// the callback. Returns `Err` for RPC errors.
    ///
    /// If `cancellable` is true, Ctrl+C will send a cancel signal to the
    /// subprocess via the shared cancel mechanism.
    pub fn call(
        &mut self,
        action: &str,
        target: &[impl AsRef<str>],
        body: Value,
        signal_handler: Option<&dyn Fn(&str, &Value)>,
        cancellable: bool,
    ) -> Result<RpcResult, RpcCallError> {
        let target_strs: Vec<&str> = target.iter().map(|s| s.as_ref()).collect();
        let request = json!({
            "kind": "command",
            "action": action,
            "target": target_strs,
            "body": body,
        });
        self.write_message(&request)
            .map_err(RpcCallError::Transport)?;

        // Register a cancel callback that sends cancel signal
        let _guard = if cancellable {
            let writer = self.cancel_writer();
            Some(cancel::on_cancel(move || {
                let signal = json!({"kind": "signal", "status": "cancel"});
                let json_str = serde_json::to_string(&signal).unwrap();
                writer.send_cancel(json_str.as_bytes());
            }))
        } else {
            None
        };

        loop {
            let mut buf = String::new();
            let n = self.read_line(&mut buf).map_err(|e| {
                RpcCallError::Transport(CliError(format!("Failed to read from RPC: {e}")))
            })?;
            if n == 0 {
                return Err(RpcCallError::Transport(CliError(
                    "RPC subprocess closed unexpectedly".into(),
                )));
            }

            let line = buf.trim();
            if line.is_empty() {
                continue;
            }

            let resp: Value = serde_json::from_str(line).map_err(|e| {
                RpcCallError::Transport(CliError(format!("Invalid JSON from RPC subprocess: {e}")))
            })?;

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
                    return Err(RpcCallError::Rpc(RpcClientError {
                        status,
                        message,
                        body,
                    }));
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
                    return Err(RpcCallError::Transport(CliError(format!(
                        "Unexpected RPC response kind: {}",
                        resp.get("kind").unwrap_or(&json!(null))
                    ))));
                }
            }
        }
    }

    /// Call `get` on a target to retrieve node info.
    pub fn get(&mut self, target: &[impl AsRef<str>]) -> Result<RpcResult, RpcCallError> {
        self.call("get", target, json!({}), None, false)
    }

    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        let Transport::Stream { reader, .. } = &mut self.transport;
        reader.read_line(buf)
    }
}

impl Drop for RpcClient {
    fn drop(&mut self) {
        // Dropping the Transport::Stream writer closes the handle, signaling EOF to the server.
    }
}

/// Successful RPC response.
pub struct RpcResult {
    pub body: Value,
    pub flags: Vec<String>,
}

/// Error returned by an RPC call.
#[derive(Debug)]
pub struct RpcClientError {
    /// The RPC error status code (e.g. "pin-validation", "device-error").
    pub status: String,
    /// Human-readable error message from the server.
    pub message: String,
    /// Structured error body with additional details.
    pub body: Value,
}

impl std::fmt::Display for RpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Error from an RPC call — either a transport/protocol failure or a
/// structured error response from the server.
#[derive(Debug)]
pub enum RpcCallError {
    /// Transport or protocol error (not from the RPC server).
    Transport(CliError),
    /// Structured error response from the RPC server.
    Rpc(RpcClientError),
}

impl std::fmt::Display for RpcCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{}", e.0),
            Self::Rpc(e) => write!(f, "RPC error ({}): {}", e.status, e.message),
        }
    }
}

impl std::error::Error for RpcCallError {}

impl From<RpcCallError> for CliError {
    fn from(e: RpcCallError) -> Self {
        match e {
            RpcCallError::Transport(e) => e,
            RpcCallError::Rpc(e) => CliError(format!(
                "RPC error ({}): {} {}",
                e.status, e.message, e.body
            )),
        }
    }
}
