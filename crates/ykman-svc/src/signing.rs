//! Server-side client verification via named pipe handle.
//!
//! Extracts the client PID from the pipe handle and delegates to
//! the shared signing verification in ykman.

/// Verify that the client connected to the given pipe handle is signed
/// with the same certificate as this service.
///
/// Returns Ok(()) if verification passes or is skipped (unsigned service).
#[cfg(target_os = "windows")]
pub fn verify_client(
    pipe_handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), ykman::rpc::signing::SigningError> {
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use ykman::rpc::signing::{SigningError, verify_peer_by_pid};

    let mut client_pid: u32 = 0;
    let ok = unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut client_pid) };
    if ok == 0 {
        return Err(SigningError(format!(
            "GetNamedPipeClientProcessId failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    verify_peer_by_pid(client_pid)
}
