mod connection;
mod ctap2;
mod device;
pub mod error;
#[allow(clippy::module_inception)]
pub mod rpc;

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};

use yubikit::device::YubiKeyDevice;
use yubikit::smartcard::ScpKeyParams;

use rpc::NodeHost;

/// Run the RPC server loop on stdin/stdout for the given device.
pub fn run(device: YubiKeyDevice, scp_params: Option<ScpKeyParams>) {
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let cancel = Arc::new(AtomicBool::new(false));

    let send = {
        let stdout = stdout.clone();
        move |data: Value| {
            let mut out = stdout.lock().unwrap();
            serde_json::to_writer(&mut *out, &data).unwrap();
            out.write_all(b"\n").unwrap();
            out.flush().unwrap();
        }
    };

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

    // Reader thread: reads stdin, dispatches signals, queues commands
    let reader_handle = std::thread::spawn({
        let send_err = send_err.clone();
        move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let line = line.trim().to_string();
                if line.is_empty() {
                    break;
                }

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
    let root = device::DeviceNode::new(device, scp_params);
    let mut host = NodeHost::new(Box::new(root));

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
