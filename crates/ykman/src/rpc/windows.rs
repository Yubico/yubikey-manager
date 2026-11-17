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
    let status = unsafe { GetCurrentPackageFullName(&mut length, std::ptr::null_mut()) };
    if status == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(WindowsService::Shared);
    }
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let mut name = vec![0u16; length as usize];
    let status = unsafe { GetCurrentPackageFullName(&mut length, name.as_mut_ptr()) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let name = String::from_utf16(&name[..length as usize - 1])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(service_for_package(&name))
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
