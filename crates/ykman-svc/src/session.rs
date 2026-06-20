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

use serde_json::{Value, json};

use ykman::rpc::node::NodeHost;

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
        let mut pending_line = Vec::new();

        log::debug!("Client session started");

        loop {
            let mut disconnected = false;
            loop {
                match read_request(&mut reader, &mut pending_line) {
                    ReadRequest::Request(request) => {
                        if !handle_request(
                            request,
                            reader.get_mut(),
                            &command_tx,
                            &mut active_cancel,
                        ) {
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

/// Serialize `data` as JSON followed by a newline and write it to `w`.
fn write_response<W: Write>(w: &mut W, data: &Value) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(data).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    w.write_all(&bytes)
}

enum ReadRequest {
    Request(Value),
    WouldBlock,
    Disconnected,
}

struct WorkerCommand {
    action: String,
    target: Vec<String>,
    params: Value,
    cancel: Arc<AtomicBool>,
}

enum WorkerEvent {
    Signal(Value),
    Response(Value),
}

fn read_request<T: SessionIo>(
    reader: &mut BufReader<T>,
    pending_line: &mut Vec<u8>,
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
            pending_line.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            if pending_line.is_empty() {
                return ReadRequest::Disconnected;
            }
            let request = parse_pending_request(pending_line);
            pending_line.clear();
            return request;
        }

        let len = available.len();
        pending_line.extend_from_slice(available);
        reader.consume(len);
        if pending_line.len() > MAX_RPC_LINE_LEN {
            pending_line.clear();
            return ReadRequest::Request(json!({
                "kind": "invalid",
                "message": "RPC request is too large"
            }));
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
            return ReadRequest::Request(json!({
                "kind": "invalid",
                "message": "Invalid UTF-8"
            }));
        }
    };
    if line.is_empty() {
        ReadRequest::Disconnected
    } else {
        match serde_json::from_str(line) {
            Ok(v) => ReadRequest::Request(v),
            Err(_) => ReadRequest::Request(json!({
                "kind": "invalid",
                "message": "Invalid JSON"
            })),
        }
    }
}

fn handle_request<T: Write>(
    request: Value,
    writer: &mut T,
    command_tx: &mpsc::Sender<WorkerCommand>,
    active_cancel: &mut Option<Arc<AtomicBool>>,
) -> bool {
    match request.get("kind").and_then(|v| v.as_str()) {
        Some("signal") => {
            if request.get("status").and_then(|v| v.as_str()) == Some("cancel") {
                log::debug!("Got cancel signal");
                if let Some(cancel) = active_cancel {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
            true
        }
        Some("command") => {
            if active_cancel.is_some() {
                let err = json!({"kind":"error","status":"invalid-command","message":"Another command is already running","body":{}});
                return write_response(writer, &err).is_ok();
            }
            let Some(action) = request.get("action").and_then(|v| v.as_str()) else {
                let err = json!({"kind":"error","status":"invalid-command","message":"Missing action","body":{}});
                return write_response(writer, &err).is_ok();
            };
            let target = match parse_target(&request) {
                Ok(target) => target,
                Err(message) => {
                    let err = json!({"kind":"error","status":"invalid-command","message":message,"body":{}});
                    return write_response(writer, &err).is_ok();
                }
            };
            let cancel = Arc::new(AtomicBool::new(false));
            let command = WorkerCommand {
                action: action.to_string(),
                target,
                params: request.get("body").cloned().unwrap_or_else(|| json!({})),
                cancel: cancel.clone(),
            };
            if command_tx.send(command).is_err() {
                return false;
            }
            *active_cancel = Some(cancel);
            true
        }
        Some("invalid") => {
            let message = request
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Invalid request");
            let err =
                json!({"kind":"error","status":"invalid-command","message":message,"body":{}});
            write_response(writer, &err).is_ok()
        }
        _ => {
            let err = json!({"kind":"error","status":"invalid-command","message":"Unsupported request type","body":{}});
            write_response(writer, &err).is_ok()
        }
    }
}

fn parse_target(request: &Value) -> Result<Vec<String>, &'static str> {
    let Some(target) = request.get("target") else {
        return Ok(Vec::new());
    };
    let Some(arr) = target.as_array() else {
        return Err("Target must be an array");
    };
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(String::from)
                .ok_or("Target entries must be strings")
        })
        .collect()
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
            let signal = json!({"kind":"signal","status":status,"body":body});
            let _ = signal_tx.send(WorkerEvent::Signal(signal));
        };

        let response_json = match host.call(
            &command.action,
            &command.target,
            command.params,
            &signal_fn,
            &command.cancel,
        ) {
            Ok(response) => {
                log::debug!(
                    "RPC {} [{}] -> success",
                    command.action,
                    command.target.join("/")
                );
                json!({"kind":"success","body":response.body,"flags":response.flags})
            }
            Err(e) => {
                log::debug!(
                    "RPC {} [{}] -> error: {} {}",
                    command.action,
                    command.target.join("/"),
                    e.status,
                    e.message
                );
                json!({"kind":"error","status":e.status,"message":e.message,"body":e.body})
            }
        };
        if event_tx.send(WorkerEvent::Response(response_json)).is_err() {
            break;
        }
    }
}
