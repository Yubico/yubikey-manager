use std::fmt;
use std::io::{self, Read, Write};

use ykman::rpc::client::RpcCallError;
use yubikit::device::DeviceError;
use yubikit::smartcard::{SmartCardError, Sw};

/// CLI error type for user-facing error messages.
#[derive(Debug)]
pub struct CliError(pub String);

impl From<RpcCallError> for CliError {
    fn from(e: RpcCallError) -> Self {
        CliError(format!("{e}"))
    }
}

/// Format a failed CCID connection in a way that points at the selected application.
pub fn format_smartcard_connection_error(app: &str, e: DeviceError) -> CliError {
    match e {
        DeviceError::NoDeviceFound => CliError("No YubiKey detected!".into()),
        DeviceError::NotYubiKey => CliError("Connected smart card is not a YubiKey.".into()),
        DeviceError::Cancelled => CliError("Operation cancelled.".into()),
        DeviceError::WrongDevice => {
            CliError("Inserted YubiKey does not match the one removed.".into())
        }
        DeviceError::SmartCard(SmartCardError::ApplicationNotAvailable) => {
            CliError(format!("{app} is not available on this YubiKey."))
        }
        DeviceError::SmartCard(SmartCardError::Apdu { sw, .. }) => CliError(format!(
            "{app} is not available on this YubiKey: {}",
            sw_message(sw)
        )),
        DeviceError::Transport(e) => CliError(format!(
            "Failed to connect to {app} over CCID: {e}. Make sure the CCID interface is enabled and the YubiKey is accessible."
        )),
        other => CliError(format!("Failed to connect to {app} over CCID: {other}")),
    }
}

/// Format a failed application session open.
pub fn format_session_error(app: &str, e: impl fmt::Display) -> CliError {
    CliError(format!("Failed to open {app} session: {e}"))
}

fn sw_message(sw: u16) -> String {
    match Sw::from_u16(sw) {
        Some(Sw::FileNotFound | Sw::AppletSelectFailed) => {
            format!("application not found (SW=0x{sw:04X})")
        }
        Some(Sw::SecurityConditionNotSatisfied) => {
            format!("security condition not satisfied (SW=0x{sw:04X})")
        }
        Some(Sw::ConditionsNotSatisfied) => {
            format!("conditions of use not satisfied (SW=0x{sw:04X})")
        }
        Some(Sw::CommandNotAllowed) => format!("command not allowed (SW=0x{sw:04X})"),
        Some(Sw::FunctionNotSupported) => format!("function not supported (SW=0x{sw:04X})"),
        _ => format!("APDU error SW=0x{sw:04X}"),
    }
}

/// Prompt the user for visible text input.
pub fn prompt(prompt: &str) -> Result<String, CliError> {
    eprint!("{prompt}: ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| CliError(format!("Failed to read input: {e}")))?;
    Ok(input.trim().to_string())
}

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

/// Parse a one-byte hexadecimal value, accepting an optional 0x prefix.
pub fn parse_hex_u8(s: &str) -> Result<u8, CliError> {
    u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|_| CliError(format!("Invalid hex value: {s}")))
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
