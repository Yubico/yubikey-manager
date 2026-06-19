pub mod client;
pub mod error;
pub mod node;
pub mod proxy;
pub mod signing;

#[cfg(not(target_os = "windows"))]
#[derive(Debug, thiserror::Error)]
pub enum SocketPathError {
    #[error("XDG_RUNTIME_DIR is not set!")]
    NotSet,
    #[error("XDG_RUNTIME_DIR must be an absolute path")]
    NotAbsolute,
    #[error("Failed to inspect XDG_RUNTIME_DIR {path}: {source}")]
    Inspect {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("XDG_RUNTIME_DIR is not a directory: {0}")]
    NotDirectory(std::path::PathBuf),
    #[error("XDG_RUNTIME_DIR must not be accessible by group/other users: {0}")]
    InsecurePermissions(std::path::PathBuf),
}

#[cfg(not(target_os = "windows"))]
pub fn socket_path() -> Result<std::path::PathBuf, SocketPathError> {
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or(SocketPathError::NotSet)?;
    if !dir.is_absolute() {
        return Err(SocketPathError::NotAbsolute);
    }
    let metadata = std::fs::metadata(&dir).map_err(|source| SocketPathError::Inspect {
        path: dir.clone(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(SocketPathError::NotDirectory(dir));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(SocketPathError::InsecurePermissions(dir));
    }
    Ok(dir.join("ykman-svc.sock"))
}
