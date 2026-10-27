const WINDOWS_BUILD: u16 = 0;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set("CompanyName", "Yubico");
        resource.set("FileDescription", "YubiKey Manager Service");
        resource.set("OriginalFilename", "ykman-svc.exe");
        resource.set("ProductName", "YubiKey Manager Service");
        let major = env!("CARGO_PKG_VERSION_MAJOR")
            .parse::<u8>()
            .expect("Cargo major version must fit MSI's 0..=255 range");
        let minor = env!("CARGO_PKG_VERSION_MINOR")
            .parse::<u8>()
            .expect("Cargo minor version must fit MSI's 0..=255 range");
        let version =
            (u64::from(major) << 48) | (u64::from(minor) << 32) | (u64::from(WINDOWS_BUILD) << 16);
        resource.set_version_info(winresource::VersionInfo::FILEVERSION, version);
        resource.set_version_info(winresource::VersionInfo::PRODUCTVERSION, version);
        resource
            .compile()
            .expect("Failed to compile service version resources");
    }
}
