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
    .unwrap_or_else(|e| log::error!("Failed to set Ctrl+C handler: {e}"));

    let manager = DeviceManager::new();
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
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE,
        LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    // NOTE: buffers are advisory hints to the OS for internal pipe
    // sizing; RPC messages (especially large FIDO/CredentialManagement
    // responses) may exceed this size. Use a generous size to reduce
    // the odds of `WriteFile` needing to block/split on a full pipe
    // buffer, and keep the pipe in blocking (PIPE_WAIT) mode below.
    const PIPE_BUFFER_SIZE: u32 = 64 * 1024;

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

    fn wait_for_client_connect(
        handle: windows_sys::Win32::Foundation::HANDLE,
        stop: &AtomicBool,
    ) -> bool {
        struct EventHandle(windows_sys::Win32::Foundation::HANDLE);

        impl Drop for EventHandle {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { CloseHandle(self.0) };
                }
            }
        }

        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            log::error!("CreateEventW failed: {}", std::io::Error::last_os_error());
            return false;
        }
        let event = EventHandle(event);
        let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
        overlapped.hEvent = event.0;

        let connected = unsafe { ConnectNamedPipe(handle, &mut overlapped) };
        if connected != 0 {
            return true;
        }

        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => true,
            ERROR_IO_PENDING => {
                while !stop.load(Ordering::Relaxed) {
                    match unsafe { WaitForSingleObject(event.0, 100) } {
                        WAIT_OBJECT_0 => {
                            let mut transferred = 0;
                            let ok = unsafe {
                                GetOverlappedResult(handle, &mut overlapped, &mut transferred, 0)
                            };
                            if ok != 0 {
                                return true;
                            }
                            log::error!(
                                "ConnectNamedPipe completion failed: {}",
                                std::io::Error::last_os_error()
                            );
                            return false;
                        }
                        WAIT_TIMEOUT => {}
                        _ => {
                            log::error!(
                                "WaitForSingleObject failed: {}",
                                std::io::Error::last_os_error()
                            );
                            return false;
                        }
                    }
                }
                unsafe {
                    CancelIoEx(handle, &mut overlapped);
                    let mut transferred = 0;
                    GetOverlappedResult(handle, &mut overlapped, &mut transferred, 1);
                }
                false
            }
            _ => {
                log::error!(
                    "ConnectNamedPipe failed: {}",
                    std::io::Error::last_os_error()
                );
                false
            }
        }
    }

    let pipe_name = crate::windows_service().pipe();
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
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
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

        if !wait_for_client_connect(handle.as_raw(), stop) {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            continue;
        }
        if stop.load(Ordering::Relaxed) {
            break;
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
            let pipe = unsafe { OwnedHandle::from_raw_handle(handle) };
            let io = match named_pipe_io::NamedPipeIo::new(pipe) {
                Ok(io) => io,
                Err(e) => {
                    log::error!("Failed to set up client pipe I/O: {e}");
                    return;
                }
            };

            if let Some(session) = ClientSession::new(manager) {
                session.run(io);
            }
        });
    }

    log::info!("Pipe server stopped");
}

/// Client I/O on an overlapped server pipe handle.
///
/// The session reads and writes the pipe concurrently from different threads,
/// using separate overlapped endpoints so a pending read never blocks a write.
#[cfg(target_os = "windows")]
mod named_pipe_io {
    use std::io::{self, Write};
    use std::os::windows::io::{AsRawHandle, OwnedHandle};
    use std::sync::Arc;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::IO::CancelIoEx;
    use windows_sys::Win32::System::Pipes::DisconnectNamedPipe;
    use ykman::rpc::pipe::PipeEndpoint;

    use crate::session::SessionIo;

    pub struct NamedPipeIo {
        writer: PipeEndpoint,
    }

    impl NamedPipeIo {
        pub fn new(pipe: OwnedHandle) -> io::Result<Self> {
            Ok(Self {
                writer: PipeEndpoint::new(Arc::new(pipe))?,
            })
        }
    }

    impl Write for NamedPipeIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writer.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.writer.flush()
        }
    }

    impl SessionIo for NamedPipeIo {
        type Reader = PipeEndpoint;

        fn reader(&self) -> io::Result<PipeEndpoint> {
            PipeEndpoint::new(self.writer.pipe().clone())
        }

        fn shutdown(&self) {
            let handle = self.writer.pipe().as_raw_handle() as HANDLE;
            // Disconnecting makes any subsequent read fail immediately, and
            // cancelling aborts a read that is already pending.
            unsafe {
                DisconnectNamedPipe(handle);
                CancelIoEx(handle, std::ptr::null());
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl crate::session::SessionIo for std::os::unix::net::UnixStream {
    type Reader = std::os::unix::net::UnixStream;

    fn reader(&self) -> std::io::Result<Self::Reader> {
        self.try_clone()
    }

    fn shutdown(&self) {
        let _ = std::os::unix::net::UnixStream::shutdown(self, std::net::Shutdown::Both);
    }
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
                // Accepted sockets may inherit the listener's nonblocking mode.
                if let Err(e) = stream.set_nonblocking(false) {
                    log::error!("Failed to set client socket blocking: {e}");
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
