//! Per-client session management.
//!
//! Each connected client gets a `ClientSession` with its own NodeHost tree
//! and multi_device setting. Device locks are released on disconnect.
//!
//! Named Pipe I/O on Windows is synchronous and serializes operations per
//! pipe endpoint within a process. Using `run_rpc_loop` (which spawns a
//! reader thread causing concurrent ReadFile + WriteFile on the same endpoint)
//! deadlocks because the pending ReadFile in the reader thread blocks the
//! server's WriteFile on the duplicate handle. We therefore use a simple
//! sequential request/response loop instead.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use ykman_cli::rpc::node::NodeHost;

use crate::device_manager::DeviceManager;
use crate::root_node::ServiceRootNode;

/// A session for a single connected client.
pub struct ClientSession {
    manager: Arc<DeviceManager>,
}

impl ClientSession {
    pub fn new(manager: Arc<DeviceManager>) -> Self {
        Self { manager }
    }

    /// Run the RPC loop for this client session using a sequential
    /// request/response model on a single `Read + Write` stream.
    ///
    /// Unlike `run_rpc_loop`, this never has a concurrent ReadFile + WriteFile
    /// pending on the same pipe endpoint, which avoids the Windows Named Pipe
    /// synchronous I/O serialization deadlock.
    pub fn run<T: Read + Write + Send + 'static>(self, io: T) {
        let root = Box::new(ServiceRootNode::new(self.manager.clone()));
        let mut host = NodeHost::new(root);
        let mut reader = BufReader::new(io);
        let cancel = Arc::new(AtomicBool::new(false));

        log::debug!("Client session started");

        loop {
            // Read next command (blocks until data arrives or client disconnects)
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }

            let line = line.trim().to_string();
            if line.is_empty() {
                break;
            }

            let request: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    let err = json!({"kind":"error","status":"invalid-command","message":"Invalid JSON","body":{}});
                    let _ = write_response(reader.get_mut(), &err);
                    continue;
                }
            };

            match request.get("kind").and_then(|v| v.as_str()) {
                Some("signal") => {
                    if request.get("status").and_then(|v| v.as_str()) == Some("cancel") {
                        log::debug!("Got cancel signal");
                        cancel.store(true, Ordering::Relaxed);
                    }
                    // Signals don't get a response
                    continue;
                }
                Some("command") => {}
                _ => {
                    let err = json!({"kind":"error","status":"invalid-command","message":"Unsupported request type","body":{}});
                    let _ = write_response(reader.get_mut(), &err);
                    continue;
                }
            }

            cancel.store(false, Ordering::Relaxed);

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

            // Signal callback — for sequential sessions, signals are sent inline.
            // We write them directly to the pipe before the final response.
            let signal_fn = {
                // We need a reference to the writer for signals, but since this
                // closure is called synchronously (not from another thread), we
                // can use a raw pointer to the writer through the BufReader.
                // SAFETY: signal_fn is only called synchronously within host.call
                // on the same thread, so the pointer is always valid.
                let writer_ptr = reader.get_mut() as *mut T;
                move |status: &str, body: Value| {
                    let signal = json!({"kind":"signal","status":status,"body":body});
                    // SAFETY: called synchronously, writer is alive
                    let _ = write_response(unsafe { &mut *writer_ptr }, &signal);
                }
            };

            let response_json = match host.call(&action, &target, params, &signal_fn, &cancel) {
                Ok(response) => {
                    log::debug!("RPC {action} [{}] → success", target.join("/"));
                    json!({"kind":"success","body":response.body,"flags":response.flags})
                }
                Err(e) => {
                    log::debug!(
                        "RPC {action} [{}] → error: {} {}",
                        target.join("/"),
                        e.status,
                        e.message
                    );
                    json!({"kind":"error","status":e.status,"message":e.message,"body":e.body})
                }
            };

            if write_response(reader.get_mut(), &response_json).is_err() {
                break;
            }
        }

        log::debug!("Client session ended");
    }
}

/// Serialize `data` as JSON followed by a newline and write it to `w`.
fn write_response<W: Write>(w: &mut W, data: &Value) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(data).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    w.write_all(&bytes)
}
