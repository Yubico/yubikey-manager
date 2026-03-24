use std::io::{self, Read, Write};

/// CLI error type for user-facing error messages.
pub struct CliError(pub String);

/// Read from a file, or from stdin if path is "-".
pub fn read_file_or_stdin(path: &str) -> Result<Vec<u8>, CliError> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError(format!("Failed to read from stdin: {e}")))?;
        Ok(buf)
    } else {
        std::fs::read(path).map_err(|e| CliError(format!("Failed to read file '{path}': {e}")))
    }
}

/// Write to a file, or to stdout if path is "-".
pub fn write_file_or_stdout(path: &str, data: &[u8]) -> Result<(), CliError> {
    if path == "-" {
        io::stdout()
            .write_all(data)
            .map_err(|e| CliError(format!("Failed to write to stdout: {e}")))?;
        io::stdout()
            .flush()
            .map_err(|e| CliError(format!("Failed to flush stdout: {e}")))?;
        Ok(())
    } else {
        std::fs::write(path, data)
            .map_err(|e| CliError(format!("Failed to write file '{path}': {e}")))
    }
}
