use std::io::{self, Read, Write};

/// CLI error type for user-facing error messages.
pub struct CliError(pub String);

/// Prompt for a secret value with hidden input.
pub fn prompt_secret(prompt: &str) -> Result<String, CliError> {
    rpassword::prompt_password(format!("{prompt}: "))
        .map_err(|e| CliError(format!("Failed to read input: {e}")))
}

/// Prompt for a non-secret value (visible input).
#[expect(dead_code)]
pub fn prompt_line(prompt: &str) -> Result<String, CliError> {
    eprint!("{prompt}: ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| CliError(format!("Failed to read input: {e}")))?;
    Ok(input
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string())
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
