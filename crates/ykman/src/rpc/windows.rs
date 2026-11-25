//! Windows service identities shared by the server and its clients.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsService {
    Shared,
    AuthenticatorMsix,
}

impl WindowsService {
    pub fn name(self) -> &'static str {
        match self {
            Self::Shared => "ykman-svc",
            Self::AuthenticatorMsix => "yubico-authenticator-svc",
        }
    }

    pub fn pipe(self) -> &'static str {
        match self {
            Self::Shared => r"\\.\pipe\ykman-svc",
            Self::AuthenticatorMsix => r"\\.\pipe\yubico-authenticator-svc",
        }
    }
}

fn service_for_package(full_name: &str) -> WindowsService {
    if full_name.starts_with("YubicoAB.YubicoAuthenticator_") {
        WindowsService::AuthenticatorMsix
    } else {
        WindowsService::Shared
    }
}

/// Select the isolated service only for processes in the Authenticator package.
#[cfg(target_os = "windows")]
pub fn client_service() -> Result<WindowsService, std::io::Error> {
    use windows_sys::Win32::Foundation::{APPMODEL_ERROR_NO_PACKAGE, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;

    let mut length = 0;
    // SAFETY: With a null buffer and length 0, the call only writes the
    // required length to `length`.
    let status = unsafe { GetCurrentPackageFullName(&mut length, std::ptr::null_mut()) };
    if status == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(WindowsService::Shared);
    }
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let mut name = vec![0u16; length as usize];
    // SAFETY: `name` is a writable buffer of `length` UTF-16 units.
    let status = unsafe { GetCurrentPackageFullName(&mut length, name.as_mut_ptr()) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let name = String::from_utf16(&name[..length as usize - 1])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(service_for_package(&name))
}

/// Whether the current process runs in a remote (RDP or Citrix HDX) session.
///
/// ykman-svc runs in session 0, which cannot use smart card readers
/// redirected into a remote session (Citrix ignores impersonation entirely),
/// so clients in remote sessions bypass the service and access devices
/// directly.
#[cfg(target_os = "windows")]
pub fn is_remote_session() -> bool {
    let protocol = wts_client_protocol();
    log::debug!("Session client protocol: {protocol:?}");
    if matches!(protocol, Some(p) if p != 0) {
        return true;
    }
    // Single-session Citrix VDAs present HDX sessions as the console (protocol 0).
    let citrix = citrix_active_protocol();
    log::debug!("Citrix protocol: {citrix:?}");
    citrix == Some(1)
}

#[cfg(target_os = "windows")]
fn wts_client_protocol() -> Option<u16> {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientProtocolType, WTSFreeMemory,
        WTSQuerySessionInformationW,
    };

    let mut buffer = std::ptr::null_mut();
    let mut size = 0;
    // SAFETY: The out-pointers are valid for writes; the returned buffer is
    // freed below with `WTSFreeMemory`.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSClientProtocolType,
            &mut buffer,
            &mut size,
        )
    };
    if ok == 0 || buffer.is_null() {
        return None;
    }
    // SAFETY: `buffer` holds `size` bytes, which is checked to fit a u16.
    let protocol = (size as usize >= size_of::<u16>())
        .then(|| unsafe { std::ptr::read_unaligned(buffer as *const u16) });
    // SAFETY: `buffer` was allocated by `WTSQuerySessionInformationW`.
    unsafe { WTSFreeMemory(buffer.cast()) };
    protocol
}

/// The Citrix protocol of the current session (0 = console, 1 = ICA), or
/// `None` if the Citrix VDA API is not installed.
#[cfg(target_os = "windows")]
fn citrix_active_protocol() -> Option<u32> {
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };

    const WF_CURRENT_SESSION: u32 = u32::MAX;
    type WfGetActiveProtocol = unsafe extern "system" fn(u32) -> u32;

    let dll = if cfg!(target_pointer_width = "64") {
        "wfapi64.dll"
    } else {
        "wfapi.dll"
    };
    let name: Vec<u16> = dll.encode_utf16().chain(Some(0)).collect();
    // SAFETY: `name` is NUL-terminated and the search is restricted to
    // System32.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return None;
    }
    // SAFETY: `module` is a valid module handle and the name is NUL-terminated.
    let protocol =
        unsafe { GetProcAddress(module, c"WFGetActiveProtocol".as_ptr().cast()) }.map(|proc| {
            // SAFETY: WFGetActiveProtocol is documented as
            // `DWORD WINAPI WFGetActiveProtocol(DWORD SessionId)`, which
            // matches `WfGetActiveProtocol`.
            let get_active_protocol: WfGetActiveProtocol = unsafe { std::mem::transmute(proc) };
            // SAFETY: The function takes a session id and has no other
            // preconditions. `module` is still loaded.
            unsafe { get_active_protocol(WF_CURRENT_SESSION) }
        });
    // SAFETY: `module` was returned by `LoadLibraryExW` and is not used again.
    unsafe { FreeLibrary(module) };
    protocol
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn client_identity_lookup_succeeds() {
        assert!(client_service().is_ok());
    }

    #[test]
    fn authenticator_package_has_a_separate_service_and_pipe() {
        let service = service_for_package("YubicoAB.YubicoAuthenticator_7.5.0.0_arm64__test");
        assert_eq!(service, WindowsService::AuthenticatorMsix);
        assert_ne!(service.name(), WindowsService::Shared.name());
        assert_ne!(service.pipe(), WindowsService::Shared.pipe());
        assert_eq!(
            service_for_package("Other.Package_1.0.0.0_x64__test"),
            WindowsService::Shared
        );
        assert_eq!(
            service_for_package("YubicoAB.YubicoAuthenticatorOther_1.0.0.0_x64__test"),
            WindowsService::Shared
        );
    }
}
