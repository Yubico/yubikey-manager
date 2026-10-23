//! RPC client — connects to ykman-svc Named Pipe.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use yubikit::__internal::SecretValue;

use crate::cancel;

use super::protocol::{
    ClientMessage, CommandMessage, RPC_PROTOCOL_VERSION, ServerMessage, SignalMessage,
    rpc_protocol_version_parts,
};

/// Transport abstraction for the RPC client's read/write streams.
enum Transport {
    /// Generic stream (Named Pipe file handle, Unix socket, etc).
    Stream {
        reader: BufReader<Box<dyn Read + Send>>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
        #[cfg(target_os = "windows")]
        reader_handle: usize,
    },
}

/// An RPC client connected to a ykman RPC server.
pub struct RpcClient {
    transport: Transport,
    open_connections: HashMap<Vec<String>, usize>,
}

struct CallCancellation<'a> {
    cancelled: &'a dyn Fn() -> bool,
    sent: bool,
}

impl RpcClient {
    #[cfg(all(test, not(target_os = "windows")))]
    pub(crate) fn from_test_stream(stream: std::os::unix::net::UnixStream) -> Self {
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(10)))
            .expect("set test socket read timeout");
        let reader = stream.try_clone().expect("clone test socket");
        Self {
            transport: Transport::Stream {
                reader: BufReader::new(Box::new(reader)),
                writer: Arc::new(Mutex::new(Box::new(stream))),
            },
            open_connections: HashMap::new(),
        }
    }

    /// Connect to the ykman-svc Named Pipe (Windows) or Unix socket (dev).
    ///
    /// Returns `Err` if the service is not available.
    pub fn connect_pipe() -> Result<Self, RpcCallError> {
        #[cfg(target_os = "windows")]
        {
            use std::fs::OpenOptions;
            use std::os::windows::fs::OpenOptionsExt;
            use std::os::windows::io::AsRawHandle;

            let service = super::windows::client_service().map_err(|e| {
                RpcCallError::Transport(format!("Failed to determine package identity: {e}"))
            })?;
            let pipe_path = service.pipe();
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
            let reader_handle = reader_file.as_raw_handle() as usize;

            let reader: Box<dyn Read + Send> = Box::new(reader_file);
            let writer: Box<dyn Write + Send> = Box::new(file);

            let mut client = Self {
                transport: Transport::Stream {
                    reader: BufReader::new(reader),
                    writer: Arc::new(Mutex::new(writer)),
                    reader_handle,
                },
                open_connections: HashMap::new(),
            };
            client.handshake()?;

            log::debug!("Connected to ykman-svc pipe");
            Ok(client)
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
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(10)))
                .map_err(|e| {
                    RpcCallError::Transport(format!("Failed to set socket read timeout: {e}"))
                })?;

            let reader: Box<dyn Read + Send> =
                Box::new(stream.try_clone().map_err(|e| {
                    RpcCallError::Transport(format!("Failed to clone socket: {e}"))
                })?);
            let writer: Box<dyn Write + Send> = Box::new(stream);

            let mut client = Self {
                transport: Transport::Stream {
                    reader: BufReader::new(reader),
                    writer: Arc::new(Mutex::new(writer)),
                },
                open_connections: HashMap::new(),
            };
            client.handshake()?;

            log::debug!("Connected to ykman-svc socket");
            Ok(client)
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

    fn write_line(&self, line: &str) -> Result<(), RpcCallError> {
        let Transport::Stream { writer, .. } = &self.transport;
        let mut writer = writer.lock().unwrap();
        writer
            .write_all(line.as_bytes())
            .map_err(|e| RpcCallError::Transport(format!("Failed to write to RPC: {e}")))?;
        writer
            .write_all(b"\n")
            .map_err(|e| RpcCallError::Transport(format!("Failed to write to RPC: {e}")))?;
        writer
            .flush()
            .map_err(|e| RpcCallError::Transport(format!("Failed to flush RPC: {e}")))?;
        Ok(())
    }

    fn handshake(&mut self) -> Result<(), RpcCallError> {
        self.write_line(RPC_PROTOCOL_VERSION)?;
        let server_version = self.read_rpc_line()?;
        let (server_major, _server_minor) = rpc_protocol_version_parts(&server_version)
            .ok_or_else(|| {
                RpcCallError::Transport(format!(
                    "Invalid ykman-svc RPC protocol version: {server_version}"
                ))
            })?;
        let (client_major, _client_minor) = rpc_protocol_version_parts(RPC_PROTOCOL_VERSION)
            .expect("RPC_PROTOCOL_VERSION is valid");
        if server_major > client_major {
            return Err(RpcCallError::Transport(format!(
                "ykman-svc RPC protocol version {server_version} is not supported by client version {RPC_PROTOCOL_VERSION}"
            )));
        }
        log::debug!("ykman-svc RPC protocol version {server_version}");
        Ok(())
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
        if cancellable {
            cancel::clear();
        }
        self.call_with_cancel(
            action,
            target,
            body,
            signal_handler,
            cancellable.then_some(&cancel::is_cancelled as &dyn Fn() -> bool),
        )
    }

    /// Send a command while polling the caller's cancellation callback.
    /// Cancellation is forwarded once; the response is still consumed so the
    /// connection remains usable for the next command.
    pub fn call_with_cancel(
        &mut self,
        action: &str,
        target: &[impl AsRef<str>],
        body: Value,
        signal_handler: Option<&dyn Fn(&str, &Value)>,
        cancelled: Option<&dyn Fn() -> bool>,
    ) -> Result<RpcResult, RpcCallError> {
        let request =
            ClientMessage::Command(CommandMessage::new(action, target, body).map_err(|e| {
                RpcCallError::Transport(format!("Failed to build RPC request: {e}"))
            })?);
        self.write_message(&request)?;

        let mut cancellation = cancelled.map(|cancelled| CallCancellation {
            cancelled,
            sent: false,
        });
        loop {
            match self.read_server_message(signal_handler, &mut cancellation)? {
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

    fn read_server_message(
        &mut self,
        signal_handler: Option<&dyn Fn(&str, &Value)>,
        cancellation: &mut Option<CallCancellation<'_>>,
    ) -> Result<ServerMessage, RpcCallError> {
        loop {
            let line = self.read_rpc_line_with_cancel(cancellation)?;
            if line.is_empty() {
                continue;
            }

            let resp: ServerMessage = serde_json::from_str(&line).map_err(|e| {
                RpcCallError::Transport(format!("Invalid JSON from RPC subprocess: {e}"))
            })?;

            if let ServerMessage::Signal(signal) = &resp
                && let Some(handler) = signal_handler
            {
                let body = signal.body.to_value().map_err(|e| {
                    RpcCallError::Transport(format!("Malformed RPC signal body: {e}"))
                })?;
                handler(&signal.status, &body);
                continue;
            }

            return Ok(resp);
        }
    }

    /// Call `get` on a target to retrieve node info.
    pub fn get(&mut self, target: &[impl AsRef<str>]) -> Result<RpcResult, RpcCallError> {
        self.call("get", target, json!({}), None, false)
    }

    pub(crate) fn track_connection(&mut self, target: &[String]) {
        *self.open_connections.entry(target.to_vec()).or_default() += 1;
    }

    pub(crate) fn close_connection(&mut self, target: &[String]) -> Result<(), RpcCallError> {
        let (device, connection) = match target {
            [device, connection] => (device.clone(), connection.clone()),
            _ => {
                return Err(RpcCallError::Transport(
                    "Invalid RPC connection target".into(),
                ));
            }
        };
        let count = self
            .open_connections
            .get_mut(target)
            .ok_or_else(|| RpcCallError::Transport("RPC connection was not tracked".into()))?;
        *count -= 1;
        if *count == 0 {
            self.open_connections.remove(target);
            self.call(
                "close",
                &[device],
                json!({"child": connection}),
                None,
                false,
            )?;
        }
        Ok(())
    }

    fn read_line(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        let Transport::Stream { reader, .. } = &mut self.transport;
        reader.read_until(b'\n', buf)
    }

    fn read_rpc_line(&mut self) -> Result<String, RpcCallError> {
        self.read_rpc_line_with_cancel(&mut None)
    }

    fn read_rpc_line_with_cancel(
        &mut self,
        cancellation: &mut Option<CallCancellation<'_>>,
    ) -> Result<String, RpcCallError> {
        let mut buf = SecretValue::new(Vec::new());
        loop {
            if let Some(cancel) = cancellation
                && !cancel.sent
                && (cancel.cancelled)()
            {
                self.write_message(&ClientMessage::Signal(SignalMessage::cancel()))?;
                cancel.sent = true;
            }

            #[cfg(target_os = "windows")]
            if cancellation.is_some() {
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
            }

            match self.read_line(buf.expose_secret_mut()) {
                Ok(0) => {
                    return Err(RpcCallError::Transport(
                        "RPC subprocess closed unexpectedly".into(),
                    ));
                }
                Ok(_) if buf.expose_secret().last() == Some(&b'\n') => {
                    return std::str::from_utf8(buf.expose_secret())
                        .map(|line| line.trim().to_string())
                        .map_err(|e| {
                            RpcCallError::Transport(format!("Invalid UTF-8 from RPC: {e}"))
                        });
                }
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => {
                    return Err(RpcCallError::Transport(format!(
                        "Failed to read from RPC: {e}"
                    )));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_read_state(&self) -> Result<PipeReadState, RpcCallError> {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;

        let Transport::Stream {
            reader,
            reader_handle,
            ..
        } = &self.transport;
        if !reader.buffer().is_empty() {
            return Ok(PipeReadState::DataAvailable);
        }
        let mut available = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                *reader_handle as windows_sys::Win32::Foundation::HANDLE,
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

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;

    #[test]
    fn buffered_pipe_response_does_not_wait_for_more_pipe_data() {
        let signal =
            ServerMessage::Signal(SignalMessage::new("keepalive", json!({"status": 1})).unwrap());
        let response = ServerMessage::success(json!({"ready": true}), vec![]).unwrap();
        let data = format!(
            "{}\n{}\n",
            serde_json::to_string(&signal).unwrap(),
            serde_json::to_string(&response).unwrap()
        );
        let mut reader: BufReader<Box<dyn Read + Send>> =
            BufReader::new(Box::new(Cursor::new(data.into_bytes())));
        reader.fill_buf().unwrap();
        let mut client = RpcClient {
            transport: Transport::Stream {
                reader,
                writer: Arc::new(Mutex::new(Box::new(Vec::<u8>::new()))),
                reader_handle: 0,
            },
            open_connections: HashMap::new(),
        };
        assert!(matches!(
            client.windows_read_state().unwrap(),
            PipeReadState::DataAvailable
        ));
        let signals = Cell::new(0);
        let on_signal = |status: &str, _: &Value| {
            assert_eq!(status, "keepalive");
            signals.set(signals.get() + 1);
        };
        let result = client
            .call_with_cancel(
                "get",
                &[] as &[&str],
                json!({}),
                Some(&on_signal),
                Some(&|| false),
            )
            .unwrap();
        assert_eq!(result.body, json!({"ready": true}));
        assert_eq!(signals.get(), 1);
    }
}

/// Successful RPC response.
pub struct RpcResult {
    pub body: Value,
    pub flags: Vec<String>,
}

/// Error returned by an RPC call.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct RpcClientError {
    /// The RPC error status code (e.g. "pin-validation", "device-error").
    pub status: String,
    /// Human-readable error message from the server.
    pub message: String,
    /// Structured error body with additional details.
    pub body: Value,
}

/// Error from an RPC call — either a transport/protocol failure or a
/// structured error response from the server.
#[derive(Debug, Error)]
pub enum RpcCallError {
    /// Transport or protocol error (not from the RPC server).
    #[error("{0}")]
    Transport(String),
    /// Structured error response from the RPC server.
    #[error("RPC error ({}): {}", .0.status, .0.message)]
    Rpc(#[source] RpcClientError),
}

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn socket_timeouts_preserve_fragmented_response_lines() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            let response = serde_json::to_vec(
                &ServerMessage::success(json!({"ready": true}), vec![]).unwrap(),
            )
            .unwrap();
            server.write_all(&response[..12]).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            server.write_all(&response[12..]).unwrap();
            server.write_all(b"\n").unwrap();
        });
        let mut client = RpcClient::from_test_stream(client);
        assert_eq!(
            client.get(&[] as &[&str]).unwrap().body,
            json!({"ready": true})
        );
        worker.join().unwrap();
    }
}
