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
//! without concurrent writes. The channel is bounded so slow clients apply
//! backpressure instead of accumulating requests in memory.

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
const MAX_QUEUED_EVENTS: usize = 16;

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
    pub fn run<T: SessionIo>(self, io: T) {
        let manager = self.manager.clone();
        run_session(io, move |commands, events| {
            run_worker(manager, commands, events)
        });
    }
}

fn run_session<T: SessionIo>(
    mut io: T,
    worker: impl FnOnce(mpsc::Receiver<WorkerCommand>, mpsc::SyncSender<SessionEvent>) + Send + 'static,
) {
    let reader = match io.reader() {
        Ok(reader) => reader,
        Err(e) => {
            log::error!("Failed to create client reader: {e}");
            io.shutdown();
            return;
        }
    };
    let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();
    let (event_tx, event_rx) = mpsc::sync_channel::<SessionEvent>(MAX_QUEUED_EVENTS);
    let worker_tx = event_tx.clone();
    let worker = std::thread::spawn(move || {
        let _exit = SessionExitNotifier(worker_tx.clone());
        worker(command_rx, worker_tx);
    });
    let reader_thread = std::thread::spawn(move || {
        let _exit = SessionExitNotifier(event_tx.clone());
        run_reader(reader, event_tx);
    });
    let mut active_cancel: Option<Arc<AtomicBool>> = None;
    let mut handshaken = false;

    log::debug!("Client session started");

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
            SessionEvent::Client(ReadRequest::Disconnected) | SessionEvent::ThreadExited => false,
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
    // Release senders blocked on a full event queue before joining them.
    drop(event_rx);
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
    ThreadExited,
}

struct SessionExitNotifier(mpsc::SyncSender<SessionEvent>);

impl Drop for SessionExitNotifier {
    fn drop(&mut self) {
        let _ = self.0.send(SessionEvent::ThreadExited);
    }
}

fn run_reader<R: Read>(reader: R, event_tx: mpsc::SyncSender<SessionEvent>) {
    let mut reader = BufReader::new(reader);
    let mut pending_line = SecretValue::new(Vec::new());
    let mut discarding = false;
    loop {
        let request = read_request(&mut reader, &mut pending_line, &mut discarding);
        let disconnected = matches!(request, ReadRequest::Disconnected);
        if event_tx.send(SessionEvent::Client(request)).is_err() || disconnected {
            break;
        }
    }
}

/// Read the next request line.
///
/// After an oversized line is rejected, `discarding` is set and the rest of
/// that line is skipped, rather than being parsed as further requests.
fn read_request<R: Read>(
    reader: &mut BufReader<R>,
    pending_line: &mut SecretValue<Vec<u8>>,
    discarding: &mut bool,
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

        let newline = available.iter().position(|&b| b == b'\n');
        let len = newline.unwrap_or(available.len());
        if *discarding {
            reader.consume(len + usize::from(newline.is_some()));
            *discarding = newline.is_none();
            continue;
        }
        pending_line
            .expose_secret_mut()
            .extend_from_slice(&available[..len]);
        reader.consume(len + usize::from(newline.is_some()));
        if pending_line.expose_secret().len() > MAX_RPC_LINE_LEN {
            pending_line.expose_secret_mut().zeroize();
            pending_line.expose_secret_mut().clear();
            *discarding = newline.is_none();
            return ReadRequest::Invalid("RPC request is too large");
        }

        if newline.is_some() {
            if pending_line.expose_secret().is_empty() {
                return ReadRequest::Disconnected;
            }
            let request = parse_pending_request(pending_line.expose_secret());
            pending_line.expose_secret_mut().zeroize();
            pending_line.expose_secret_mut().clear();
            return request;
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
    event_tx: mpsc::SyncSender<SessionEvent>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_secs(5);

    struct TestReader {
        input: mpsc::Receiver<Vec<u8>>,
        pending: Cursor<Vec<u8>>,
        reads: mpsc::Sender<()>,
    }

    impl Read for TestReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                let len = self.pending.read(buf)?;
                if len > 0 || buf.is_empty() {
                    return Ok(len);
                }
                match self.input.recv() {
                    Ok(bytes) if !bytes.is_empty() => {
                        let _ = self.reads.send(());
                        self.pending = Cursor::new(bytes);
                    }
                    _ => return Ok(0),
                }
            }
        }
    }

    struct TestIo {
        reader: Mutex<Option<TestReader>>,
        input: mpsc::Sender<Vec<u8>>,
        output: mpsc::SyncSender<Vec<u8>>,
    }

    impl TestIo {
        fn pair() -> (Self, TestClient) {
            let (input_tx, input_rx) = mpsc::channel();
            let (output_tx, output_rx) = mpsc::sync_channel(0);
            let (read_tx, read_rx) = mpsc::channel();
            (
                Self {
                    reader: Mutex::new(Some(TestReader {
                        input: input_rx,
                        pending: Cursor::new(Vec::new()),
                        reads: read_tx,
                    })),
                    input: input_tx.clone(),
                    output: output_tx,
                },
                TestClient {
                    input: input_tx,
                    output: output_rx,
                    reads: read_rx,
                },
            )
        }
    }

    impl Write for TestIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output
                .send(buf.to_vec())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SessionIo for TestIo {
        type Reader = TestReader;

        fn reader(&self) -> std::io::Result<Self::Reader> {
            Ok(self.reader.lock().unwrap().take().unwrap())
        }

        fn shutdown(&self) {
            let _ = self.input.send(Vec::new());
        }
    }

    struct TestClient {
        input: mpsc::Sender<Vec<u8>>,
        output: mpsc::Receiver<Vec<u8>>,
        reads: mpsc::Receiver<()>,
    }

    impl TestClient {
        fn send(&self, line: &str) {
            self.input.send(format!("{line}\n").into_bytes()).unwrap();
        }

        fn read_line(&self) -> String {
            let mut line = Vec::new();
            while !line.ends_with(b"\n") {
                line.extend(self.output.recv_timeout(TIMEOUT).unwrap());
            }
            String::from_utf8(line).unwrap()
        }

        fn handshake(&self) {
            self.send(RPC_PROTOCOL_VERSION);
            assert_eq!(self.read_line(), format!("{RPC_PROTOCOL_VERSION}\n"));
        }
    }

    #[test]
    fn worker_panic_disconnects_session_while_reader_is_still_connected() {
        let (io, client) = TestIo::pair();
        let (done_tx, done_rx) = mpsc::channel();
        let session = std::thread::spawn(move || {
            run_session(io, |commands, _events| {
                commands.recv().unwrap();
                panic!("unexpected backend failure");
            });
            done_tx.send(()).unwrap();
        });

        client.handshake();
        client.send(r#"{"kind":"command","action":"panic"}"#);
        done_rx.recv_timeout(TIMEOUT).unwrap();
        session.join().unwrap();
        assert!(client.input.send(b"still connected\n".to_vec()).is_err());
        assert_eq!(
            client.output.recv_timeout(TIMEOUT),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn normal_worker_exit_disconnects_session() {
        let (io, client) = TestIo::pair();
        let (done_tx, done_rx) = mpsc::channel();
        let session = std::thread::spawn(move || {
            run_session(io, |_commands, _events| {});
            done_tx.send(()).unwrap();
        });

        done_rx.recv_timeout(TIMEOUT).unwrap();
        session.join().unwrap();
        assert!(client.input.send(b"still connected\n".to_vec()).is_err());
    }

    #[test]
    fn cancellation_and_subsequent_commands_remain_usable() {
        let (io, client) = TestIo::pair();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let session = std::thread::spawn(move || {
            run_session(io, move |commands, events| {
                for command in commands {
                    if command.action == "wait" {
                        started_tx.send(()).unwrap();
                        let deadline = Instant::now() + TIMEOUT;
                        while !command.cancel.load(Ordering::Relaxed) {
                            assert!(Instant::now() < deadline, "Cancellation was not delivered");
                            std::thread::yield_now();
                        }
                    }
                    let response =
                        ServerMessage::success(json!({"action": command.action}), vec![]).unwrap();
                    if events.send(SessionEvent::Response(response)).is_err() {
                        break;
                    }
                }
            });
            done_tx.send(()).unwrap();
        });

        client.handshake();
        client.send(r#"{"kind":"command","action":"wait"}"#);
        started_rx.recv_timeout(TIMEOUT).unwrap();
        client.send(r#"{"kind":"signal","status":"cancel"}"#);
        let response: Value = serde_json::from_str(&client.read_line()).unwrap();
        assert_eq!(response["kind"], "success");
        assert_eq!(response["body"]["action"], "wait");
        client.send(r#"{"kind":"command","action":"next"}"#);
        let response: Value = serde_json::from_str(&client.read_line()).unwrap();
        assert_eq!(response["kind"], "success");
        assert_eq!(response["body"]["action"], "next");
        client.input.send(Vec::new()).unwrap();
        done_rx.recv_timeout(TIMEOUT).unwrap();
        session.join().unwrap();
    }

    #[test]
    fn slow_client_bounds_request_queue_and_disconnect_unblocks_senders() {
        let (io, client) = TestIo::pair();
        let (done_tx, done_rx) = mpsc::channel();
        let session = std::thread::spawn(move || {
            run_session(io, |commands, _events| for _ in commands {});
            done_tx.send(()).unwrap();
        });
        client.send(RPC_PROTOCOL_VERSION);
        for _ in 0..MAX_QUEUED_EVENTS + 2 {
            client.send(r#"{"kind":"command","action":"noop"}"#);
        }
        // One handshake, a full queue, and one request waiting to be enqueued.
        for _ in 0..MAX_QUEUED_EVENTS + 2 {
            client.reads.recv_timeout(TIMEOUT).unwrap();
        }
        assert_eq!(
            client.reads.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        drop(client.output);
        done_rx.recv_timeout(TIMEOUT).unwrap();
        session.join().unwrap();
        assert_eq!(
            client.reads.recv_timeout(TIMEOUT),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn request_size_limit_includes_the_final_fragment_before_newline() {
        for len in [MAX_RPC_LINE_LEN, MAX_RPC_LINE_LEN + 1] {
            let prefix = r#"{"kind":"command","action":"noop","body":""#;
            let mut line = prefix.as_bytes().to_vec();
            line.resize(len - 2, b'x');
            line.extend_from_slice(b"\"}\n");
            assert_eq!(line.len(), len + 1);
            let mut reader = BufReader::with_capacity(line.len(), Cursor::new(line));
            let mut pending = SecretValue::new(Vec::new());
            let mut discarding = false;
            let request = read_request(&mut reader, &mut pending, &mut discarding);
            if len == MAX_RPC_LINE_LEN {
                assert!(matches!(request, ReadRequest::Request(_)));
            } else {
                assert!(matches!(
                    request,
                    ReadRequest::Invalid("RPC request is too large")
                ));
            }
            assert!(pending.expose_secret().is_empty());
            assert!(!discarding);
        }
    }

    #[test]
    fn rest_of_oversized_request_is_discarded() {
        let mut input = vec![b'{'; MAX_RPC_LINE_LEN + 8192];
        input.extend_from_slice(b"\"} garbage\n");
        input.extend_from_slice(br#"{"kind":"command","action":"noop","body":{}}"#);
        input.push(b'\n');
        let mut reader = BufReader::with_capacity(4096, Cursor::new(input));
        let mut pending = SecretValue::new(Vec::new());
        let mut discarding = false;
        assert!(matches!(
            read_request(&mut reader, &mut pending, &mut discarding),
            ReadRequest::Invalid("RPC request is too large")
        ));
        assert!(discarding);
        assert!(matches!(
            read_request(&mut reader, &mut pending, &mut discarding),
            ReadRequest::Request(_)
        ));
        assert!(!discarding);
        assert!(matches!(
            read_request(&mut reader, &mut pending, &mut discarding),
            ReadRequest::Disconnected
        ));
    }
}
