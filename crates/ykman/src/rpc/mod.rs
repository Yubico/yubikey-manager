pub mod client;
pub mod error;
pub mod node;
pub mod proxy;
pub mod signing;

#[cfg(not(target_os = "windows"))]
pub fn socket_path() -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "XDG_RUNTIME_DIR is not set!".to_string())?;
    if !dir.is_absolute() {
        return Err("XDG_RUNTIME_DIR must be an absolute path".into());
    }
    let metadata = std::fs::metadata(&dir)
        .map_err(|e| format!("Failed to inspect XDG_RUNTIME_DIR {}: {e}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "XDG_RUNTIME_DIR is not a directory: {}",
            dir.display()
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "XDG_RUNTIME_DIR must not be accessible by group/other users: {}",
            dir.display()
        ));
    }
    Ok(dir.join("ykman-svc.sock"))
}
