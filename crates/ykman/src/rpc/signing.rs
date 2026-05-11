//! Code signing verification for RPC peers.
//!
//! On Windows, verifies that a peer process's executable has a valid
//! Authenticode signature (via WinVerifyTrust) and is signed with the same
//! certificate as the current process. If the current process is unsigned
//! (dev mode), verification is skipped.

#[cfg(target_os = "windows")]
use std::fmt;
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

/// Verify that a peer process (by PID) has a valid Authenticode signature
/// signed with the same certificate as the current process.
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

    // Verify the peer's Authenticode signature is valid and trusted
    verify_authenticode(&peer_exe)?;

    let peer_cert = get_signing_cert(&peer_exe)
        .map_err(|e| SigningError(format!("Peer exe is not signed: {e}")))?;

    if own_cert != peer_cert {
        return Err(SigningError(
            "Peer certificate does not match own certificate".into(),
        ));
    }

    log::debug!("Peer PID {peer_pid} verified (valid signature, same signing cert)");
    Ok(())
}

/// Verify the Authenticode signature of an executable using WinVerifyTrust.
///
/// This checks that the signature is cryptographically valid, the certificate
/// chain is trusted, and the file has not been tampered with.
#[cfg(target_os = "windows")]
fn verify_authenticode(path: &Path) -> Result<(), SigningError> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrust,
    };

    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path_w.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: 0,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // INVALID_HANDLE_VALUE means "no parent window" — verification runs silently.
    let hwnd = -1isize as windows_sys::Win32::Foundation::HWND;
    let status =
        unsafe { WinVerifyTrust(hwnd, &mut action_id, &mut trust_data as *mut _ as *mut _) };

    if status != 0 {
        return Err(SigningError(format!(
            "WinVerifyTrust failed for {}: HRESULT 0x{:08X}",
            path.display(),
            status as u32,
        )));
    }

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
