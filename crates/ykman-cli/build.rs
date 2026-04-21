use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use flate2::Compression;
use flate2::write::DeflateEncoder;

fn main() {
    generate_licenses();

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

fn generate_licenses() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("licenses.deflate");

    // Find workspace root (where about.toml and about-cli.hbs live)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("cannot find workspace root");

    let template = workspace_root.join("about-cli.hbs");
    let config = workspace_root.join("about.toml");
    let lockfile = workspace_root.join("Cargo.lock");

    println!("cargo:rerun-if-changed={}", template.display());
    println!("cargo:rerun-if-changed={}", config.display());
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let output = Command::new("cargo")
        .args(["about", "generate"])
        .arg(&template)
        .arg("--config")
        .arg(&config)
        .arg("--manifest-path")
        .arg(workspace_root.join("Cargo.toml"))
        .output();

    let raw = match output {
        Ok(result) if result.status.success() => result.stdout,
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            eprintln!("cargo:warning=cargo-about failed: {stderr}");
            b"License information unavailable (cargo-about failed).\n".to_vec()
        }
        Err(e) => {
            eprintln!("cargo:warning=cargo-about not found: {e}");
            b"License information unavailable (cargo-about not installed).\n".to_vec()
        }
    };

    fs::write(&dest, compress(&raw)).expect("Failed to write licenses.deflate");
}
