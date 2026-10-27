use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::DeflateEncoder;

fn main() {
    embed_licenses();

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set("CompanyName", "Yubico");
        res.set("FileDescription", "YubiKey Manager CLI");
        res.set("LegalCopyright", "Copyright 2024 Yubico AB. Apache-2.0");
        res.set("OriginalFilename", "ykman.exe");
        res.set("ProductName", "YubiKey Manager");
        res.set_manifest_file("ykman.exe.manifest");
        res.compile().expect("Failed to compile Windows resources");
    }
}

fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).expect("Failed to compress");
    encoder.finish().expect("Failed to finish compression")
}

fn embed_licenses() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("licenses.deflate");
    println!("cargo:rerun-if-changed=licenses.txt");
    fs::write(&dest, compress(include_bytes!("licenses.txt")))
        .expect("Failed to write licenses.deflate");
}
