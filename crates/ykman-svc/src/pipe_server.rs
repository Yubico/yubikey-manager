//! Named Pipe server (Windows) / Unix socket server (dev fallback).
//!
//! Accepts client connections and spawns a session thread for each.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::device_manager::DeviceManager;
use crate::session::ClientSession;

/// Run the pipe server in standalone (foreground) mode.
pub fn run_standalone() {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    ctrlc::set_handler(move || {
        log::info!("Ctrl+C received, shutting down");
        stop_clone.store(true, Ordering::Relaxed);
    })
    .expect("Failed to set Ctrl+C handler");

    let manager = Arc::new(DeviceManager::new());
    run_server(manager, &stop);
}

/// Run the pipe server, blocking until `stop` is set.
pub fn run_server(manager: Arc<DeviceManager>, stop: &AtomicBool) {
    #[cfg(target_os = "windows")]
    {
        run_named_pipe_server(manager, stop);
    }
    #[cfg(not(target_os = "windows"))]
    {
        run_unix_socket_server(manager, stop);
    }
}

// ---------------------------------------------------------------------------
// Windows: Named Pipe server
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn run_named_pipe_server(manager: Arc<DeviceManager>, stop: &AtomicBool) {
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    let pipe_name = crate::PIPE_NAME;
    let pipe_name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    log::info!("Listening on {pipe_name}");

    while !stop.load(Ordering::Relaxed) {
        // Create a new pipe instance
        let handle = unsafe {
            CreateNamedPipeW(
                pipe_name_w.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            log::error!(
                "CreateNamedPipeW failed: {}",
                std::io::Error::last_os_error()
            );
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }

        // Wait for a client to connect
        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if connected == 0 {
            let err = std::io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED means client connected between Create and Connect
            if err.raw_os_error() != Some(535) {
                log::error!("ConnectNamedPipe failed: {err}");
                unsafe { CloseHandle(handle) };
                continue;
            }
        }

        if stop.load(Ordering::Relaxed) {
            unsafe { CloseHandle(handle) };
            break;
        }

        log::info!("Client connected");

        // Verify client signing if applicable
        if let Err(e) = crate::signing::verify_client(handle) {
            log::warn!("Client verification failed: {e}");
            unsafe { CloseHandle(handle) };
            continue;
        }

        let manager = manager.clone();
        // SAFETY: We own this handle exclusively; HANDLEs are safe to send across threads.
        let handle_addr = handle as usize;
        std::thread::spawn(move || {
            let handle = handle_addr as *mut core::ffi::c_void;
            // SAFETY: handle is a valid pipe handle that we own exclusively in this thread.
            // The sequential session loop never has concurrent ReadFile + WriteFile
            // pending on the same endpoint, so no synchronous I/O deadlock can occur.
            let file = unsafe { File::from_raw_handle(handle) };

            let session = ClientSession::new(manager);
            session.run(file);
        });
    }

    log::info!("Pipe server stopped");
}

// ---------------------------------------------------------------------------
// Unix: Unix domain socket server (development/testing fallback)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
fn run_unix_socket_server(manager: Arc<DeviceManager>, stop: &AtomicBool) {
    use std::os::unix::net::UnixListener;

    let socket_path = "/tmp/ykman-svc.sock";

    // Remove stale socket
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path).expect("Failed to bind Unix socket");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking failed");

    log::info!("Listening on {socket_path}");

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                log::info!("Client connected");
                let manager = manager.clone();
                std::thread::spawn(move || {
                    let session = ClientSession::new(manager);
                    session.run(stream);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                log::error!("Accept failed: {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    let _ = std::fs::remove_file(socket_path);
    log::info!("Socket server stopped");
}
