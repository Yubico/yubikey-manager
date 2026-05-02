//! Per-client session management.
//!
//! Each connected client gets a `ClientSession` with its own NodeHost tree
//! and multi_device setting. Device locks are released on disconnect.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;

use serde_json::Value;

use ykman_cli::rpc;

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

    /// Run the RPC loop for this client session.
    /// Takes ownership of read/write streams (pipe or socket).
    pub fn run<R: Read + Send + 'static, W: Write + Send + 'static>(self, read: R, write: W) {
        let root = Box::new(ServiceRootNode::new(self.manager.clone()));

        let write = std::sync::Arc::new(std::sync::Mutex::new(write));

        let send: rpc::SendFn = {
            let write = write.clone();
            Box::new(move |data: Value| {
                if let Ok(mut w) = write.lock() {
                    let _ = serde_json::to_writer(&mut *w, &data);
                    let _ = w.write_all(b"\n");
                    let _ = w.flush();
                }
            })
        };

        let recv: rpc::RecvLine = {
            let reader = std::sync::Mutex::new(BufReader::new(read));
            Box::new(move || {
                let mut r = reader.lock().unwrap();
                let mut line = String::new();
                match r.read_line(&mut line) {
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

        log::debug!("Client session started");
        rpc::run_rpc_loop(root, send, recv);
        log::debug!("Client session ended");

        // TODO: Release any device locks held by this session.
        // This requires tracking which devices this session opened,
        // which will be added when we integrate device locking into
        // the session's NodeHost lifecycle.
    }
}
