//! Per-client session management.
//!
//! Each connected client gets a `ClientSession` with its own NodeHost tree.
//! Device locks are released on disconnect.
//!
//! The pipe/socket is put in nonblocking mode by `pipe_server`, and this loop
//! owns all I/O. RPC work runs on a worker thread and communicates back via a
//! channel, which lets the I/O loop process cancel signals while an action is
//! running without concurrent writes to the same endpoint.

use std::io::{BufRead, BufReader, Read, Write};
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use yubikit::__internal::SecretValue;
use zeroize::Zeroize;

use ykman::rpc::node::NodeHost;
use ykman::rpc::protocol::{
    ClientMessage, CommandMessage, RPC_PROTOCOL_VERSION, ServerMessage, SignalMessage,
    rpc_protocol_version_parts,
};

use crate::device_manager::DeviceManager;
use crate::root_node::ServiceRootNode;

const MAX_RPC_LINE_LEN: usize = 1_048_576;

#[cfg(target_os = "windows")]
pub(crate) trait SessionIo: Read + Write + Send + AsRawHandle {}
#[cfg(target_os = "windows")]
impl<T: Read + Write + Send + AsRawHandle> SessionIo for T {}

#[cfg(not(target_os = "windows"))]
pub(crate) trait SessionIo: Read + Write + Send {}
#[cfg(not(target_os = "windows"))]
impl<T: Read + Write + Send> SessionIo for T {}

/// A session for a single connected client.
pub struct ClientSession {
    manager: Arc<DeviceManager>,
}

impl ClientSession {
    pub fn new(manager: Arc<DeviceManager>) -> Option<Self> {
        manager.client_connected().then_some(Self { manager })
    }

    /// Run the RPC loop for this client session.
    pub fn run<T: SessionIo + 'static>(self, io: T) {
        let mut reader = BufReader::new(io);
        let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();
        let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();
        let manager = self.manager.clone();
        let worker = std::thread::spawn(move || run_worker(manager, command_rx, event_tx));
        let mut active_cancel: Option<Arc<AtomicBool>> = None;
        let mut handshaken = false;
        let mut pending_line = SecretValue::new(Vec::new());

        log::debug!("Client session started");

        loop {
            let mut disconnected = false;
            loop {
                match read_request(&mut reader, &mut pending_line) {
                    ReadRequest::Version(version) => {
                        if !handle_version(version, reader.get_mut(), &mut handshaken) {
                            disconnected = true;
                            break;
                        }
                    }
                    ReadRequest::Request(request) => {
                        if !handle_request(
                            request,
                            reader.get_mut(),
                            &command_tx,
                            &mut active_cancel,
                            handshaken,
                        ) {
                            disconnected = true;
                            break;
                        }
                    }
                    ReadRequest::Invalid(message) => {
                        if !write_invalid_request(reader.get_mut(), message) {
                            disconnected = true;
                            break;
                        }
                    }
                    ReadRequest::WouldBlock => break,
                    ReadRequest::Disconnected => {
                        disconnected = true;
                        break;
                    }
                }
            }

            if disconnected {
                break;
            }

            loop {
                match event_rx.try_recv() {
                    Ok(WorkerEvent::Signal(signal)) => {
                        if write_response(reader.get_mut(), &signal).is_err() {
                            disconnected = true;
                            break;
                        }
                    }
                    Ok(WorkerEvent::Response(response)) => {
                        active_cancel = None;
                        if write_response(reader.get_mut(), &response).is_err() {
                            disconnected = true;
                            break;
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }

            if disconnected {
                break;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        if let Some(cancel) = active_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        drop(command_tx);
        if worker.join().is_err() {
            log::warn!("Client session worker panicked");
        }
        log::info!("Client disconnected");
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.manager.client_disconnected();
    }
}

fn write_response<W: Write>(w: &mut W, data: &impl Serialize) -> std::io::Result<()> {
    let mut bytes = SecretValue::new(serde_json::to_vec(data).map_err(std::io::Error::other)?);
    bytes.expose_secret_mut().push(b'\n');
    w.write_all(bytes.expose_secret())
}

fn write_line<W: Write>(w: &mut W, line: &str) -> std::io::Result<()> {
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")
}

enum ReadRequest {
    Version(String),
    Request(ClientMessage),
    Invalid(&'static str),
    WouldBlock,
    Disconnected,
}

struct WorkerCommand {
    action: String,
    target: Vec<String>,
    body: ykman::rpc::protocol::RawJson,
    cancel: Arc<AtomicBool>,
}

enum WorkerEvent {
    Signal(ServerMessage),
    Response(ServerMessage),
}

fn read_request<T: SessionIo>(
    reader: &mut BufReader<T>,
    pending_line: &mut SecretValue<Vec<u8>>,
) -> ReadRequest {
    loop {
        #[cfg(target_os = "windows")]
        match windows_pipe_read_state(reader.get_ref()) {
            PipeReadState::NoData => return ReadRequest::WouldBlock,
            PipeReadState::Disconnected => return ReadRequest::Disconnected,
            PipeReadState::DataAvailable => {}
        }

        let available = match reader.fill_buf() {
            Ok([]) => return ReadRequest::Disconnected,
            Ok(buf) => buf,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return ReadRequest::WouldBlock;
            }
            Err(e) => {
                log::debug!("Client read failed: {e}");
                return ReadRequest::Disconnected;
            }
        };

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            pending_line
                .expose_secret_mut()
                .extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            if pending_line.expose_secret().is_empty() {
                return ReadRequest::Disconnected;
            }
            let request = parse_pending_request(pending_line.expose_secret());
            pending_line.expose_secret_mut().zeroize();
            pending_line.expose_secret_mut().clear();
            return request;
        }

        let len = available.len();
        pending_line
            .expose_secret_mut()
            .extend_from_slice(available);
        reader.consume(len);
        if pending_line.expose_secret().len() > MAX_RPC_LINE_LEN {
            pending_line.expose_secret_mut().zeroize();
            pending_line.expose_secret_mut().clear();
            return ReadRequest::Invalid("RPC request is too large");
        }
    }

    #[cfg(target_os = "windows")]
    enum PipeReadState {
        DataAvailable,
        NoData,
        Disconnected,
    }

    #[cfg(target_os = "windows")]
    fn windows_pipe_read_state<T: AsRawHandle>(io: &T) -> PipeReadState {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;

        let mut available = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                io.as_raw_handle() as _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            log::debug!("PeekNamedPipe failed: {err}");
            PipeReadState::Disconnected
        } else if available == 0 {
            PipeReadState::NoData
        } else {
            PipeReadState::DataAvailable
        }
    }
}

fn parse_pending_request(pending_line: &[u8]) -> ReadRequest {
    let line = match std::str::from_utf8(pending_line) {
        Ok(line) => line.trim(),
        Err(_) => {
            return ReadRequest::Invalid("Invalid UTF-8");
        }
    };
    if line.is_empty() {
        ReadRequest::Disconnected
    } else if rpc_protocol_version_parts(line).is_some() {
        ReadRequest::Version(line.to_string())
    } else {
        match serde_json::from_str(line) {
            Ok(v) => ReadRequest::Request(v),
            Err(_) => ReadRequest::Invalid("Invalid JSON"),
        }
    }
}

fn handle_request<T: Write>(
    request: ClientMessage,
    writer: &mut T,
    command_tx: &mpsc::Sender<WorkerCommand>,
    active_cancel: &mut Option<Arc<AtomicBool>>,
    handshaken: bool,
) -> bool {
    match request {
        ClientMessage::Signal(signal) => {
            if !handshaken {
                return write_protocol_error(writer, "RPC handshake required");
            }
            if signal.status == "cancel" {
                log::debug!("Got cancel signal");
                if let Some(cancel) = active_cancel {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
            true
        }
        ClientMessage::Command(command) => {
            if !handshaken {
                return write_protocol_error(writer, "RPC handshake required");
            }
            handle_command(command, writer, command_tx, active_cancel)
        }
    }
}

fn handle_version<T: Write>(client_version: String, writer: &mut T, handshaken: &mut bool) -> bool {
    if *handshaken {
        return write_protocol_error(writer, "RPC handshake already completed");
    }
    let server_version =
        rpc_protocol_version_parts(RPC_PROTOCOL_VERSION).expect("RPC_PROTOCOL_VERSION is valid");
    let client_version_parts =
        rpc_protocol_version_parts(&client_version).expect("client version was parsed");
    if server_version < client_version_parts {
        return write_line(
            writer,
            &format!(
                "ERROR RPC protocol version {client_version} is not supported by server version {RPC_PROTOCOL_VERSION}"
            ),
        )
        .is_ok();
    }

    *handshaken = true;
    write_line(writer, RPC_PROTOCOL_VERSION).is_ok()
}

fn handle_command<T: Write>(
    command: CommandMessage,
    writer: &mut T,
    command_tx: &mpsc::Sender<WorkerCommand>,
    active_cancel: &mut Option<Arc<AtomicBool>>,
) -> bool {
    if active_cancel.is_some() {
        let err = ServerMessage::error(
            "invalid-command",
            "Another command is already running",
            json!({}),
        )
        .expect("empty error body is valid JSON");
        return write_response(writer, &err).is_ok();
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_command = WorkerCommand {
        action: command.action,
        target: command.target,
        body: command.body,
        cancel: cancel.clone(),
    };
    if command_tx.send(worker_command).is_err() {
        return false;
    }
    *active_cancel = Some(cancel);
    true
}

fn write_invalid_request<T: Write>(writer: &mut T, message: &'static str) -> bool {
    let err = ServerMessage::error("invalid-command", message, json!({}))
        .expect("empty error body is valid JSON");
    write_response(writer, &err).is_ok()
}

fn write_protocol_error<T: Write>(writer: &mut T, message: &'static str) -> bool {
    let err = ServerMessage::error("protocol-error", message, json!({}))
        .expect("empty error body is valid JSON");
    write_response(writer, &err).is_ok()
}

fn run_worker(
    manager: Arc<DeviceManager>,
    command_rx: mpsc::Receiver<WorkerCommand>,
    event_tx: mpsc::Sender<WorkerEvent>,
) {
    let root = Box::new(ServiceRootNode::new(manager));
    let mut host = NodeHost::new(root);

    for command in command_rx {
        let signal_tx = event_tx.clone();
        let signal_fn = move |status: &str, body: Value| {
            let signal = SignalMessage::new(status, body)
                .map(ServerMessage::Signal)
                .expect("signal body serializes to valid JSON");
            let _ = signal_tx.send(WorkerEvent::Signal(signal));
        };

        let mut params = match command.body.to_value() {
            Ok(params) => params,
            Err(e) => {
                let response = ServerMessage::error(
                    "invalid-command",
                    format!("Invalid parameters: {e}"),
                    json!({}),
                )
                .expect("empty error body is valid JSON");
                if event_tx.send(WorkerEvent::Response(response)).is_err() {
                    break;
                }
                continue;
            }
        };
        let response_json = match host.call(
            &command.action,
            &command.target,
            &params,
            &signal_fn,
            &command.cancel,
        ) {
            Ok(response) => {
                log::debug!(
                    "RPC {} [{}] -> success",
                    command.action,
                    command.target.join("/")
                );
                ServerMessage::success(response.body, response.flags)
                    .expect("RPC success body serializes to valid JSON")
            }
            Err(e) => {
                log::debug!(
                    "RPC {} [{}] -> error: {} {}",
                    command.action,
                    command.target.join("/"),
                    e.status,
                    e.message
                );
                ServerMessage::error(e.status, e.message, e.body)
                    .expect("RPC error body serializes to valid JSON")
            }
        };
        zeroize_value(&mut params);
        if event_tx.send(WorkerEvent::Response(response_json)).is_err() {
            break;
        }
    }
}

pub fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_value(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_value(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
