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
        poke_server();
    })
    .unwrap_or_else(|e| log::error!("Failed to set Ctrl+C handler: {e}"));

    let manager = DeviceManager::new();
    run_server(manager, &stop);
}

/// Wake a blocking server accept/connect operation after setting the stop flag.
pub fn poke_server() {
    #[cfg(target_os = "windows")]
    {
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(crate::PIPE_NAME);
    }
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

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, SetNamedPipeHandleState,
    };

    struct PipeHandle(windows_sys::Win32::Foundation::HANDLE);

    impl PipeHandle {
        fn as_raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
            self.0
        }

        fn into_raw_addr(mut self) -> usize {
            let handle = self.0 as usize;
            self.0 = std::ptr::null_mut();
            handle
        }
    }

    impl Drop for PipeHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct LocalSecurityDescriptor(*mut SECURITY_DESCRIPTOR);

    impl LocalSecurityDescriptor {
        fn as_security_attributes_ptr(
            &mut self,
            sa: &mut SECURITY_ATTRIBUTES,
        ) -> *mut SECURITY_ATTRIBUTES {
            if self.0.is_null() {
                std::ptr::null_mut()
            } else {
                sa.lpSecurityDescriptor = self.0 as *mut core::ffi::c_void;
                sa as *mut SECURITY_ATTRIBUTES
            }
        }
    }

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0 as *mut core::ffi::c_void) };
            }
        }
    }

    let pipe_name = crate::PIPE_NAME;
    let pipe_name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    // Build a security descriptor that allows Authenticated Users (AU) to
    // read and write the pipe.  Without an explicit DACL, a pipe created by
    // an elevated (admin) process gets the high-integrity default DACL, which
    // denies access to standard (medium-integrity) user processes.
    //
    // SDDL "D:(A;;GRGW;;;AU)":
    //   D:      = DACL
    //   A       = Allow
    //   GRGW    = GENERIC_READ | GENERIC_WRITE
    //   AU      = Authenticated Users
    let sddl: Vec<u16> = "D:(A;;GRGW;;;AU)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sd_ptr: *mut SECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr as *mut *mut SECURITY_DESCRIPTOR as *mut *mut core::ffi::c_void,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        log::error!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut sd = LocalSecurityDescriptor(sd_ptr);
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };
    let sa_ptr = sd.as_security_attributes_ptr(&mut sa);

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
                sa_ptr,
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
        let handle = PipeHandle(handle);

        // Wait for a client to connect
        let connected = unsafe { ConnectNamedPipe(handle.as_raw(), std::ptr::null_mut()) };
        if connected == 0 {
            let err = std::io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED means client connected between Create and Connect
            if err.raw_os_error() != Some(535) {
                log::error!("ConnectNamedPipe failed: {err}");
                continue;
            }
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }

        let mut pipe_mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        let mode_set = unsafe {
            SetNamedPipeHandleState(
                handle.as_raw(),
                &mut pipe_mode,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if mode_set == 0 {
            log::error!(
                "SetNamedPipeHandleState failed: {}",
                std::io::Error::last_os_error()
            );
            continue;
        }

        log::info!("Client connected");

        // Verify client signing if applicable
        if let Err(e) = crate::signing::verify_client(handle.as_raw()) {
            log::warn!("Client verification failed: {e}");
            continue;
        }

        let manager = manager.clone();
        // SAFETY: We own this handle exclusively; HANDLEs are safe to send across threads.
        let handle_addr = handle.into_raw_addr();
        std::thread::spawn(move || {
            let handle = handle_addr as *mut core::ffi::c_void;
            // SAFETY: handle is a valid pipe handle that we own exclusively in this thread.
            // ClientSession owns all I/O for the endpoint.
            let file = unsafe { File::from_raw_handle(handle) };

            if let Some(session) = ClientSession::new(manager) {
                session.run(file);
            }
        });
    }

    log::info!("Pipe server stopped");
}

// ---------------------------------------------------------------------------
// Unix: Unix domain socket server (development/testing fallback)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
fn run_unix_socket_server(manager: Arc<DeviceManager>, stop: &AtomicBool) {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let socket_path = match ykman::rpc::socket_path() {
        Ok(path) => path,
        Err(e) => {
            log::error!("{e}");
            return;
        }
    };

    // Remove stale socket
    let _ = std::fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("Failed to bind Unix socket {}: {e}", socket_path.display());
            return;
        }
    };
    if let Err(e) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)) {
        log::error!(
            "Failed to set socket permissions {}: {e}",
            socket_path.display()
        );
        let _ = std::fs::remove_file(&socket_path);
        return;
    }
    if let Err(e) = listener.set_nonblocking(true) {
        log::error!("Failed to set listener nonblocking: {e}");
        let _ = std::fs::remove_file(&socket_path);
        return;
    }

    log::info!("Listening on {}", socket_path.display());

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                log::info!("Client connected");
                if let Err(e) = stream.set_nonblocking(true) {
                    log::error!("Failed to set client socket nonblocking: {e}");
                    continue;
                }
                let manager = manager.clone();
                std::thread::spawn(move || {
                    if let Some(session) = ClientSession::new(manager) {
                        session.run(stream);
                    }
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

    let _ = std::fs::remove_file(&socket_path);
    log::info!("Socket server stopped");
}
