//! Code signing verification for peer processes.
//!
//! On Windows, verifies that a peer process is signed with the same certificate
//! as the current process. If the current process is unsigned (dev mode),
//! verification is skipped.

#[cfg(target_os = "windows")]
use std::fmt;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

/// Verify that a peer process (by PID) is signed with the same certificate
/// as the current process.
///
/// Returns `Ok(())` if verification passes, or if the current process is
/// unsigned (dev mode — verification is skipped).
#[cfg(target_os = "windows")]
pub fn verify_peer_by_pid(peer_pid: u32) -> Result<(), SigningError> {
    let own_exe = std::env::current_exe()
        .map_err(|e| SigningError(format!("Failed to get own exe path: {e}")))?;

    let own_cert = match get_signing_cert(&own_exe) {
        Ok(cert) => cert,
        Err(_) => {
            log::debug!("Process is unsigned, skipping peer verification");
            return Ok(());
        }
    };

    let peer_exe = get_process_image_path(peer_pid)?;

    let peer_cert = get_signing_cert(&peer_exe)
        .map_err(|e| SigningError(format!("Peer exe is not signed: {e}")))?;

    if own_cert != peer_cert {
        return Err(SigningError(
            "Peer certificate does not match own certificate".into(),
        ));
    }

    log::debug!("Peer PID {peer_pid} verified (same signing cert)");
    Ok(())
}

/// Get the executable path for a process by PID.
#[cfg(target_os = "windows")]
fn get_process_image_path(pid: u32) -> Result<PathBuf, SigningError> {
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
    Ok(PathBuf::from(path))
}

/// Get the code signing certificate (DER-encoded) from an executable.
#[cfg(target_os = "windows")]
fn get_signing_cert(path: &Path) -> Result<Vec<u8>, SigningError> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Security::Cryptography::{
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CertEnumCertificatesInStore, CertFreeCertificateContext,
        CryptQueryObject,
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

    let cert_ctx = unsafe { CertEnumCertificatesInStore(cert_store, std::ptr::null()) };
    if cert_ctx.is_null() {
        return Err(SigningError("No certificate in signed file".into()));
    }

    let cert_data = unsafe {
        let ctx = &*cert_ctx;
        std::slice::from_raw_parts(ctx.pbCertEncoded, ctx.cbCertEncoded as usize).to_vec()
    };

    unsafe { CertFreeCertificateContext(cert_ctx) };

    Ok(cert_data)
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct SigningError(pub String);

#[cfg(target_os = "windows")]
impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(target_os = "windows")]
impl std::error::Error for SigningError {}
