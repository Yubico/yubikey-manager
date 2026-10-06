fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set("CompanyName", "Yubico");
        resource.set("FileDescription", "YubiKey Manager Service");
        resource.set("OriginalFilename", "ykman-svc.exe");
        resource.set("ProductName", "YubiKey Manager Service");
        resource
            .compile()
            .expect("Failed to compile service version resources");
    }
}
