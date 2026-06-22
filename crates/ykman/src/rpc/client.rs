//! RPC client — connects to ykman-svc Named Pipe.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::{Value, json};
use yubikit::__internal::SecretValue;

use crate::cancel;

use super::protocol::{ClientMessage, CommandMessage, ServerMessage, SignalMessage};

/// Transport abstraction for the RPC client's read/write streams.
enum Transport {
    /// Generic stream (Named Pipe file handle, Unix socket, etc).
    Stream {
        reader: BufReader<Box<dyn Read + Send>>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
        #[cfg(target_os = "windows")]
        reader_handle: windows_sys::Win32::Foundation::HANDLE,
    },
}

/// An RPC client connected to a ykman RPC server.
pub struct RpcClient {
    transport: Transport,
}

/// Thread-safe writer handle for sending cancel signals from the Ctrl+C handler.
struct CancelWriter(Arc<Mutex<Box<dyn Write + Send>>>);

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
    pub fn connect_pipe() -> Result<Self, RpcCallError> {
        #[cfg(target_os = "windows")]
        {
            use std::fs::OpenOptions;
            use std::os::windows::fs::OpenOptionsExt;
            use std::os::windows::io::AsRawHandle;

            let pipe_path = r"\\.\pipe\ykman-svc";
            log::debug!("Connecting to Named Pipe: {pipe_path}");

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(0) // FILE_FLAG_NORMAL
                .open(pipe_path)
                .map_err(|e| {
                    RpcCallError::Transport(format!("Failed to connect to ykman-svc pipe: {e}"))
                })?;

            // Verify the server is signed with the same certificate as us
            Self::verify_pipe_server(file.as_raw_handle() as _)?;

            let reader_file = file.try_clone().map_err(|e| {
                RpcCallError::Transport(format!("Failed to clone pipe handle: {e}"))
            })?;
            let reader_handle = reader_file.as_raw_handle() as _;

            let reader: Box<dyn Read + Send> = Box::new(reader_file);
            let writer: Box<dyn Write + Send> = Box::new(file);

            log::debug!("Connected to ykman-svc pipe");
            Ok(Self {
                transport: Transport::Stream {
                    reader: BufReader::new(reader),
                    writer: Arc::new(Mutex::new(writer)),
                    reader_handle,
                },
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::net::UnixStream;

            let socket_path =
                super::socket_path().map_err(|e| RpcCallError::Transport(e.to_string()))?;
            log::debug!("Connecting to Unix socket: {}", socket_path.display());

            let stream = UnixStream::connect(&socket_path).map_err(|e| {
                RpcCallError::Transport(format!("Failed to connect to ykman-svc socket: {e}"))
            })?;

            let reader: Box<dyn Read + Send> =
                Box::new(stream.try_clone().map_err(|e| {
                    RpcCallError::Transport(format!("Failed to clone socket: {e}"))
                })?);
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

    /// Verify that the server on the other end of the pipe is signed with
    /// the same certificate as this process. Skipped if unsigned (dev mode).
    #[cfg(target_os = "windows")]
    fn verify_pipe_server(
        pipe_handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), RpcCallError> {
        use super::signing::verify_peer_by_pid;
        use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

        let mut server_pid: u32 = 0;
        let ok = unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut server_pid) };
        if ok == 0 {
            return Err(RpcCallError::Transport(format!(
                "GetNamedPipeServerProcessId failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        verify_peer_by_pid(server_pid)
            .map_err(|e| RpcCallError::Transport(format!("Server verification failed: {e}")))
    }

    fn write_message(&self, msg: &impl Serialize) -> Result<(), RpcCallError> {
        let json_str = SecretValue::new(serde_json::to_string(msg).map_err(|e| {
            RpcCallError::Transport(format!("Failed to serialize RPC message: {e}"))
        })?);
        let Transport::Stream { writer, .. } = &self.transport;
        let mut writer = writer.lock().unwrap();
        writer
            .write_all(json_str.expose_secret().as_bytes())
            .map_err(|e| RpcCallError::Transport(format!("Failed to write to RPC: {e}")))?;
        writer
            .write_all(b"\n")
            .map_err(|e| RpcCallError::Transport(format!("Failed to write to RPC: {e}")))?;
        writer
            .flush()
            .map_err(|e| RpcCallError::Transport(format!("Failed to flush RPC: {e}")))?;
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
        let request =
            ClientMessage::Command(CommandMessage::new(action, target, body).map_err(|e| {
                RpcCallError::Transport(format!("Failed to build RPC request: {e}"))
            })?);
        self.write_message(&request)?;

        if cancellable {
            cancel::clear();
        }

        #[cfg(not(target_os = "windows"))]
        let _guard = if cancellable {
            let writer = self.cancel_writer();
            Some(cancel::on_cancel(move || {
                if let Ok(json_str) =
                    serde_json::to_string(&ClientMessage::Signal(SignalMessage::cancel()))
                {
                    let json_str = SecretValue::new(json_str);
                    writer.send_cancel(json_str.expose_secret().as_bytes());
                }
            }))
        } else {
            None
        };

        #[cfg(target_os = "windows")]
        let mut cancel_sent = false;
        loop {
            #[cfg(target_os = "windows")]
            if cancellable && !cancel_sent && cancel::is_cancelled() {
                self.write_message(&ClientMessage::Signal(SignalMessage::cancel()))?;
                cancel_sent = true;
            }

            #[cfg(target_os = "windows")]
            match self.windows_read_state()? {
                PipeReadState::NoData => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                PipeReadState::Disconnected => {
                    return Err(RpcCallError::Transport(
                        "RPC subprocess closed unexpectedly".into(),
                    ));
                }
                PipeReadState::DataAvailable => {}
            }

            let mut buf = SecretValue::new(String::new());
            let n = match self.read_line(buf.expose_secret_mut()) {
                Ok(n) => n,
                Err(e) => {
                    return Err(RpcCallError::Transport(format!(
                        "Failed to read from RPC: {e}"
                    )));
                }
            };
            if n == 0 {
                return Err(RpcCallError::Transport(
                    "RPC subprocess closed unexpectedly".into(),
                ));
            }

            let line = buf.expose_secret().trim();
            if line.is_empty() {
                continue;
            }

            let resp: ServerMessage = serde_json::from_str(line).map_err(|e| {
                RpcCallError::Transport(format!("Invalid JSON from RPC subprocess: {e}"))
            })?;

            match resp {
                ServerMessage::Success(success) => {
                    let body = success.body.to_value().map_err(|e| {
                        RpcCallError::Transport(format!("Malformed RPC success body: {e}"))
                    })?;
                    return Ok(RpcResult {
                        body,
                        flags: success.flags,
                    });
                }
                ServerMessage::Error(error) => {
                    let body = error.body.to_value().map_err(|e| {
                        RpcCallError::Transport(format!("Malformed RPC error body: {e}"))
                    })?;
                    return Err(RpcCallError::Rpc(RpcClientError {
                        status: error.status,
                        message: error.message,
                        body,
                    }));
                }
                ServerMessage::Signal(signal) => {
                    if let Some(handler) = signal_handler {
                        let body = signal.body.to_value().map_err(|e| {
                            RpcCallError::Transport(format!("Malformed RPC signal body: {e}"))
                        })?;
                        handler(&signal.status, &body);
                    }
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

    #[cfg(target_os = "windows")]
    fn windows_read_state(&self) -> Result<PipeReadState, RpcCallError> {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;

        let Transport::Stream { reader_handle, .. } = &self.transport;
        let mut available = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                *reader_handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Ok(PipeReadState::Disconnected);
        }
        if available == 0 {
            Ok(PipeReadState::NoData)
        } else {
            Ok(PipeReadState::DataAvailable)
        }
    }
}

#[cfg(target_os = "windows")]
enum PipeReadState {
    DataAvailable,
    NoData,
    Disconnected,
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
    Transport(String),
    /// Structured error response from the RPC server.
    Rpc(RpcClientError),
}

impl std::fmt::Display for RpcCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::Rpc(e) => write!(f, "RPC error ({}): {}", e.status, e.message),
        }
    }
}

impl std::error::Error for RpcCallError {}
