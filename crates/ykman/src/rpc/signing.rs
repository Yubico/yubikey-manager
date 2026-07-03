//! Code signing verification for RPC peers.
//!
//! On Windows, verifies that a peer process's executable has a valid
//! Authenticode signature (via WinVerifyTrust) and is signed with the same
//! certificate as the current process. If the current process is unsigned
//! (dev mode), verification is skipped.

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
            if cfg!(debug_assertions) {
                log::debug!("Debug build is unsigned, skipping peer verification");
                return Ok(());
            }
            return Err(SigningError("Current process is unsigned!".into()));
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
        WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE, WinVerifyTrust,
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

    // Free the state data allocated by WTD_STATEACTION_VERIFY.
    if !trust_data.hWVTStateData.is_null() {
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe { WinVerifyTrust(hwnd, &mut action_id, &mut trust_data as *mut _ as *mut _) };
    }

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
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
        {
            return get_service_image_path_for_pid(pid).map_err(|fallback_error| {
                SigningError(format!(
                    "OpenProcess({pid}) failed: {error}; service image lookup failed: {fallback_error}"
                ))
            });
        }
        return Err(SigningError(format!("OpenProcess({pid}) failed: {error}")));
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

/// Get the configured service executable when the service process cannot be
/// opened directly by a non-elevated client.
#[cfg(target_os = "windows")]
fn get_service_image_path_for_pid(pid: u32) -> Result<PathBuf, SigningError> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
        QueryServiceConfigW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    };

    const SERVICE_NAME: &str = "ykman-svc";

    struct ServiceHandle(windows_sys::Win32::System::Services::SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseServiceHandle(self.0) };
            }
        }
    }

    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(SigningError(format!(
            "OpenSCManagerW failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let manager = ServiceHandle(manager);

    let service_name_w: Vec<u16> = SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let service = unsafe {
        OpenServiceW(
            manager.0,
            service_name_w.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    };
    if service.is_null() {
        return Err(SigningError(format!(
            "OpenServiceW({SERVICE_NAME}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let service = ServiceHandle(service);

    let mut status = unsafe { std::mem::zeroed::<SERVICE_STATUS_PROCESS>() };
    let mut bytes_needed = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        return Err(SigningError(format!(
            "QueryServiceStatusEx({SERVICE_NAME}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if status.dwProcessId != pid {
        return Err(SigningError(format!(
            "{SERVICE_NAME} PID {} does not match pipe server PID {pid}",
            status.dwProcessId
        )));
    }

    let mut config_bytes_needed = 0;
    let ok = unsafe {
        QueryServiceConfigW(service.0, std::ptr::null_mut(), 0, &mut config_bytes_needed)
    };
    if ok != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(SigningError(format!(
            "QueryServiceConfigW({SERVICE_NAME}) sizing failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut config = vec![0u8; config_bytes_needed as usize];
    let ok = unsafe {
        QueryServiceConfigW(
            service.0,
            config.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
            config_bytes_needed,
            &mut config_bytes_needed,
        )
    };
    if ok == 0 {
        return Err(SigningError(format!(
            "QueryServiceConfigW({SERVICE_NAME}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let binary_path = unsafe {
        let ptr = (*(config.as_ptr() as *const QUERY_SERVICE_CONFIGW)).lpBinaryPathName;
        if ptr.is_null() {
            return Err(SigningError(format!(
                "{SERVICE_NAME} has no configured binary path"
            )));
        }
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    };

    executable_path_from_command_line(&binary_path)
}

#[cfg(target_os = "windows")]
fn executable_path_from_command_line(command_line: &str) -> Result<PathBuf, SigningError> {
    let command_line = command_line.trim();
    if command_line.is_empty() {
        return Err(SigningError("Service binary path is empty".into()));
    }

    if let Some(rest) = command_line.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return Ok(PathBuf::from(&rest[..end]));
        }
        return Err(SigningError(format!(
            "Service binary path has unmatched quote: {command_line}"
        )));
    }

    let lower = command_line.to_ascii_lowercase();
    if let Some(end) = lower.find(".exe") {
        return Ok(PathBuf::from(&command_line[..end + 4]));
    }

    command_line
        .split_whitespace()
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| SigningError("Service binary path is empty".into()))
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
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SigningError(pub String);
