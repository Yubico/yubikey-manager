fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set("CompanyName", "Yubico");
        res.set("FileDescription", "YubiKey Manager CLI");
        res.set("LegalCopyright", "Copyright (c) 2024 Yubico AB");
        res.set("OriginalFilename", "ykman.exe");
        res.set("ProductName", "YubiKey Manager");
        res.set_manifest_file("ykman.exe.manifest");
        res.compile().expect("Failed to compile Windows resources");
    }
}
