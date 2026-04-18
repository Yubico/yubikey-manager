pub mod client;
mod connection;
mod ctap2;
pub(crate) mod device;
pub mod error;
#[allow(clippy::module_inception)]
pub mod rpc;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};

use rpc::{NodeHost, RpcNode};

/// Sender/receiver function types for the RPC loop.
pub type SendFn = Box<dyn Fn(Value) + Send + Sync>;
pub type RecvLine = Box<dyn FnMut() -> Option<String> + Send>;

/// Run the RPC server loop on stdin/stdout.
pub fn run(root: Box<dyn RpcNode>) {
    let stdout = Arc::new(Mutex::new(std::io::stdout()));

    let send: SendFn = {
        let stdout = stdout.clone();
        Box::new(move |data: Value| {
            let mut out = stdout.lock().unwrap();
            serde_json::to_writer(&mut *out, &data).unwrap();
            out.write_all(b"\n").unwrap();
            out.flush().unwrap();
        })
    };

    let recv: RecvLine = Box::new(|| {
        let stdin = std::io::stdin();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
        }
    });

    run_rpc_loop(root, send, recv);
}

/// Run the RPC server loop over TCP.
pub fn run_tcp(root: Box<dyn RpcNode>, port: u16, nonce: &str) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("Failed to connect to TCP port");
    // Send nonce for authentication
    sock.write_all(nonce.as_bytes()).unwrap();
    sock.write_all(b"\n").unwrap();
    sock.flush().unwrap();

    let write_sock = Arc::new(Mutex::new(sock.try_clone().unwrap()));

    let send: SendFn = {
        let write_sock = write_sock.clone();
        Box::new(move |data: Value| {
            let json_str = serde_json::to_string(&data).unwrap();
            let mut sock = write_sock.lock().unwrap();
            // "O" prefix for output messages
            sock.write_all(b"O").unwrap();
            sock.write_all(json_str.as_bytes()).unwrap();
            sock.write_all(b"\n").unwrap();
            sock.flush().unwrap();
        })
    };

    let reader = BufReader::new(sock);
    let reader = Arc::new(Mutex::new(reader));

    let recv: RecvLine = {
        let reader = reader.clone();
        Box::new(move || {
            let mut reader = reader.lock().unwrap();
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => None,
                Ok(_) => {
                    let trimmed = line.trim().to_string();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    }
                }
            }
        })
    };

    run_rpc_loop(root, send, recv);
}

/// Core RPC loop shared between stdio and TCP transports.
pub fn run_rpc_loop(root: Box<dyn RpcNode>, send: SendFn, mut recv: RecvLine) {
    let cancel = Arc::new(AtomicBool::new(false));
    let send = Arc::new(send);

    let send_err = {
        let send = send.clone();
        move |status: &str, message: &str, body: Value| {
            send(json!({
                "kind": "error",
                "status": status,
                "message": message,
                "body": body,
            }));
        }
    };

    let (cmd_tx, cmd_rx) = mpsc::sync_channel::<Option<Value>>(1);
    let cancel_reader = cancel.clone();

    // Reader thread: reads input, dispatches signals, queues commands
    let reader_handle = std::thread::spawn({
        let send_err = send_err.clone();
        move || {
            while let Some(line) = recv() {
                let request: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => {
                        send_err("invalid-command", "Invalid JSON", json!({}));
                        continue;
                    }
                };

                match request.get("kind").and_then(|v| v.as_str()) {
                    Some("signal") => {
                        if request.get("status").and_then(|v| v.as_str()) == Some("cancel") {
                            log::debug!("Got cancel signal!");
                            cancel_reader.store(true, Ordering::Relaxed);
                        } else {
                            log::error!("Unhandled signal: {request}");
                        }
                    }
                    Some("command") => {
                        cancel_reader.store(false, Ordering::Relaxed);
                        if cmd_tx.send(Some(request)).is_err() {
                            break;
                        }
                    }
                    _ => {
                        send_err("invalid-command", "Unsupported request type", json!({}));
                    }
                }
            }
            cancel_reader.store(true, Ordering::Relaxed);
            let _ = cmd_tx.send(None);
        }
    });

    // Main thread: process commands sequentially
    let mut host = NodeHost::new(root);

    while let Ok(Some(request)) = cmd_rx.recv() {
        let action = request
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target: Vec<String> = request
            .get("target")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let params = request.get("body").cloned().unwrap_or_else(|| json!({}));

        let signal_fn = {
            let send = send.clone();
            move |status: &str, body: Value| {
                send(json!({
                    "kind": "signal",
                    "status": status,
                    "body": body,
                }));
            }
        };

        match host.call(&action, &target, params, &signal_fn, &cancel) {
            Ok(response) => {
                send(json!({
                    "kind": "success",
                    "body": response.body,
                    "flags": response.flags,
                }));
            }
            Err(e) => {
                send_err(&e.status, &e.message, e.body);
            }
        }
    }

    reader_handle.join().unwrap();
}
