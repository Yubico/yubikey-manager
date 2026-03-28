use std::io::{self, Read, Write};

/// CLI error type for user-facing error messages.
pub struct CliError(pub String);

/// Prompt for a secret value with hidden input.
pub fn prompt_secret(prompt: &str) -> Result<String, CliError> {
    rpassword::prompt_password(format!("{prompt}: "))
        .map_err(|e| CliError(format!("Failed to read input: {e}")))
}

/// Prompt for a new secret value with confirmation. Re-prompts on mismatch.
pub fn prompt_new_secret(prompt: &str) -> Result<String, CliError> {
    loop {
        let first = prompt_secret(prompt)?;
        let confirm = prompt_secret(&format!("Confirm {}", prompt.to_ascii_lowercase()))?;
        if first == confirm {
            return Ok(first);
        }
        eprintln!("Values do not match, try again.");
    }
}

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
