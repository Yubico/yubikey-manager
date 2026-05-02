//! Code signing verification for connecting clients.
//!
//! When the service binary is code-signed, verify that connecting clients
//! are signed with the same certificate. If the service is unsigned (dev mode),
//! verification is skipped.

#[cfg(target_os = "windows")]
use std::fmt;

/// Verify that the client connected to the given pipe handle is signed
/// with the same certificate as this service.
///
/// Returns Ok(()) if verification passes or is skipped (unsigned service).
#[cfg(target_os = "windows")]
pub fn verify_client(pipe_handle: windows_sys::Win32::Foundation::HANDLE) -> Result<(), SigningError> {
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    // Get the service's own certificate
    let service_exe = std::env::current_exe()
        .map_err(|e| SigningError(format!("Failed to get service exe path: {e}")))?;

    let service_cert = match get_signing_cert(&service_exe) {
        Ok(cert) => cert,
        Err(_) => {
            // Service is not signed — skip verification (dev mode)
            log::debug!("Service is unsigned, skipping client verification");
            return Ok(());
        }
    };

    // Get client PID from pipe
    let mut client_pid: u32 = 0;
    let ok = unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut client_pid) };
    if ok == 0 {
        return Err(SigningError(format!(
            "GetNamedPipeClientProcessId failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Get client executable path from PID
    let client_exe = get_process_image_path(client_pid)?;

    // Get client certificate
    let client_cert = get_signing_cert(&client_exe)
        .map_err(|e| SigningError(format!("Client exe is not signed: {e}")))?;

    // Compare certificates
    if service_cert != client_cert {
        return Err(SigningError(
            "Client certificate does not match service certificate".into(),
        ));
    }

    log::debug!("Client PID {client_pid} verified (same signing cert)");
    Ok(())
}

/// Get the executable path for a process by PID.
#[cfg(target_os = "windows")]
fn get_process_image_path(pid: u32) -> Result<std::path::PathBuf, SigningError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(SigningError(format!(
            "OpenProcess({pid}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        return Err(SigningError(format!(
            "QueryFullProcessImageNameW failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let path = String::from_utf16_lossy(&buf[..size as usize]);
    Ok(std::path::PathBuf::from(path))
}

/// Get the code signing certificate (DER-encoded) from an executable.
#[cfg(target_os = "windows")]
fn get_signing_cert(path: &std::path::Path) -> Result<Vec<u8>, SigningError> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Security::Cryptography::{
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CertFreeCertificateContext, CryptQueryObject,
    };

    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut cert_store = std::ptr::null_mut();
    let mut msg = std::ptr::null_mut();
    let mut context: *mut core::ffi::c_void = std::ptr::null_mut();

    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_w.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut cert_store,
            &mut msg,
            &mut context,
        )
    };

    if ok == 0 {
        return Err(SigningError(format!(
            "CryptQueryObject failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    // Get the signer certificate from the message
    // For now we extract the first certificate from the embedded signature
    use windows_sys::Win32::Security::Cryptography::CertEnumCertificatesInStore;

    let cert_ctx = unsafe { CertEnumCertificatesInStore(cert_store, std::ptr::null()) };
    if cert_ctx.is_null() {
        return Err(SigningError("No certificate in signed file".into()));
    }

    // Copy the DER-encoded certificate
    let cert_data = unsafe {
        let ctx = &*cert_ctx;
        std::slice::from_raw_parts(ctx.pbCertEncoded, ctx.cbCertEncoded as usize).to_vec()
    };

    unsafe { CertFreeCertificateContext(cert_ctx) };

    Ok(cert_data)
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct SigningError(String);

#[cfg(target_os = "windows")]
impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(target_os = "windows")]
impl std::error::Error for SigningError {}
