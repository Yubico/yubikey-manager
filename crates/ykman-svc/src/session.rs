//! Per-client session management.
//!
//! Each connected client gets a `ClientSession` with its own NodeHost tree.
//! Device locks are released on disconnect.
//!
//! A reader thread performs blocking reads from the pipe/socket and forwards
//! parsed requests over a channel. RPC work runs on a worker thread which
//! reports signals and responses over the same channel. The session loop
//! blocks on that channel and is the only writer to the endpoint, which lets
//! it process cancel signals while an action is running, without polling and
//! without concurrent writes.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

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

/// A bidirectional client endpoint which can be read from a separate thread.
pub(crate) trait SessionIo: Write + Send + 'static {
    type Reader: Read + Send + 'static;

    /// Create an independent blocking reader for the endpoint.
    fn reader(&self) -> std::io::Result<Self::Reader>;

    /// Close the endpoint, unblocking any pending read.
    fn shutdown(&self);
}

/// A session for a single connected client.
pub struct ClientSession {
    manager: Arc<DeviceManager>,
}

impl ClientSession {
    pub fn new(manager: Arc<DeviceManager>) -> Option<Self> {
        manager.client_connected().then_some(Self { manager })
    }

    /// Run the RPC loop for this client session.
    pub fn run<T: SessionIo>(self, mut io: T) {
        let reader = match io.reader() {
            Ok(reader) => reader,
            Err(e) => {
                log::error!("Failed to create client reader: {e}");
                io.shutdown();
                return;
            }
        };
        let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();
        let (event_tx, event_rx) = mpsc::channel::<SessionEvent>();
        let manager = self.manager.clone();
        let worker_tx = event_tx.clone();
        let worker = std::thread::spawn(move || run_worker(manager, command_rx, worker_tx));
        let reader_thread = std::thread::spawn(move || run_reader(reader, event_tx));
        let mut active_cancel: Option<Arc<AtomicBool>> = None;
        let mut handshaken = false;

        log::debug!("Client session started");

        // Both senders are dropped once the reader and worker have exited.
        while let Ok(event) = event_rx.recv() {
            let connected = match event {
                SessionEvent::Client(ReadRequest::Version(version)) => {
                    handle_version(version, &mut io, &mut handshaken)
                }
                SessionEvent::Client(ReadRequest::Request(request)) => handle_request(
                    request,
                    &mut io,
                    &command_tx,
                    &mut active_cancel,
                    handshaken,
                ),
                SessionEvent::Client(ReadRequest::Invalid(message)) => {
                    write_invalid_request(&mut io, message)
                }
                SessionEvent::Client(ReadRequest::Disconnected) => false,
                SessionEvent::Signal(signal) => write_response(&mut io, &signal).is_ok(),
                SessionEvent::Response(response) => {
                    active_cancel = None;
                    write_response(&mut io, &response).is_ok()
                }
            };
            if !connected {
                break;
            }
        }

        if let Some(cancel) = active_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        drop(command_tx);
        io.shutdown();
        if reader_thread.join().is_err() {
            log::warn!("Client session reader panicked");
        }
        if let Err(payload) = worker.join() {
            if payload
                .downcast_ref::<String>()
                .is_some_and(|message| message.contains("unknown PCSC error code"))
            {
                log::warn!("Client session worker panicked on an unrecognised PC/SC status");
            } else {
                log::warn!("Client session worker panicked");
            }
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
    Disconnected,
}

struct WorkerCommand {
    action: String,
    target: Vec<String>,
    body: ykman::rpc::protocol::RawJson,
    cancel: Arc<AtomicBool>,
}

enum SessionEvent {
    Client(ReadRequest),
    Signal(ServerMessage),
    Response(ServerMessage),
}

fn run_reader<R: Read>(reader: R, event_tx: mpsc::Sender<SessionEvent>) {
    let mut reader = BufReader::new(reader);
    let mut pending_line = SecretValue::new(Vec::new());
    loop {
        let request = read_request(&mut reader, &mut pending_line);
        let disconnected = matches!(request, ReadRequest::Disconnected);
        if event_tx.send(SessionEvent::Client(request)).is_err() || disconnected {
            break;
        }
    }
}

fn read_request<R: Read>(
    reader: &mut BufReader<R>,
    pending_line: &mut SecretValue<Vec<u8>>,
) -> ReadRequest {
    loop {
        let available = match reader.fill_buf() {
            Ok([]) => return ReadRequest::Disconnected,
            Ok(buf) => buf,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
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
    event_tx: mpsc::Sender<SessionEvent>,
) {
    let root = Box::new(ServiceRootNode::new(manager));
    let mut host = NodeHost::new(root);

    for command in command_rx {
        let signal_tx = event_tx.clone();
        let signal_fn = move |status: &str, body: Value| {
            let signal = SignalMessage::new(status, body)
                .map(ServerMessage::Signal)
                .expect("signal body serializes to valid JSON");
            let _ = signal_tx.send(SessionEvent::Signal(signal));
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
                if event_tx.send(SessionEvent::Response(response)).is_err() {
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
        if event_tx
            .send(SessionEvent::Response(response_json))
            .is_err()
        {
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
