use anyhow::{Error, Result, anyhow};
use std::fmt;
use std::io::{self, Read, Write};

use yubikit::device::{DeviceError, YubiKeyDevice};
use yubikit::management::Capability;
use yubikit::otp::modhex_decode;
use yubikit::smartcard::{ScpKeyParams, SmartCardConnection, SmartCardError, Sw};

use crate::scp::{self, ScpParams};

/// Format a failed CCID connection in a way that points at the selected application.
pub fn format_smartcard_connection_error(app: &str, e: DeviceError) -> Error {
    match e {
        DeviceError::NoDeviceFound => anyhow!("No YubiKey detected!"),
        DeviceError::NotYubiKey => anyhow!("Connected smart card is not a YubiKey."),
        DeviceError::Cancelled => anyhow!("Operation cancelled."),
        DeviceError::WrongDevice => {
            anyhow!("Inserted YubiKey does not match the one removed.")
        }
        DeviceError::SmartCard(SmartCardError::ApplicationNotAvailable) => {
            anyhow!("{app} is not available on this YubiKey.")
        }
        DeviceError::SmartCard(SmartCardError::Apdu { sw, .. }) => {
            anyhow!("{app} is not available on this YubiKey: {}", sw_message(sw))
        }
        DeviceError::Transport(e) => anyhow!(
            "Failed to connect to {app} over CCID: {e}. Make sure the CCID interface is enabled and the YubiKey is accessible."
        ),
        other => anyhow!("Failed to connect to {app} over CCID: {other}"),
    }
}

/// Format a failed application session open.
pub fn format_session_error(app: &str, e: impl fmt::Display) -> Error {
    anyhow!("Failed to open {app} session: {e}")
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
pub fn prompt(prompt: &str) -> Result<String> {
    eprint!("{prompt}: ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| anyhow!("Failed to read input: {e}"))?;
    Ok(input.trim().to_string())
}

/// Prompt for a secret value with hidden input.
pub fn prompt_secret(prompt: &str) -> Result<String> {
    rpassword::prompt_password(format!("{prompt}: "))
        .map_err(|e| anyhow!("Failed to read input: {e}"))
}

/// Prompt for a new secret value with confirmation. Re-prompts on mismatch.
pub fn prompt_new_secret(prompt: &str) -> Result<String> {
    loop {
        let first = prompt_secret(prompt)?;
        let confirm = prompt_secret(&format!("Confirm {}", prompt.to_ascii_lowercase()))?;
        if first == confirm {
            return Ok(first);
        }
        eprintln!("Values do not match, try again.");
    }
}

/// Encoding of a binary value entered on the command line.
#[derive(Clone, Copy)]
pub enum ByteEncoding {
    Hex,
    Modhex,
}

impl ByteEncoding {
    fn label(self) -> &'static str {
        match self {
            ByteEncoding::Hex => "hex",
            ByteEncoding::Modhex => "modhex",
        }
    }

    fn decode(self, input: &str) -> Result<Vec<u8>> {
        let input = input.trim();
        match self {
            ByteEncoding::Hex => {
                hex::decode(input).map_err(|_| anyhow!("Value must be hex-encoded."))
            }
            ByteEncoding::Modhex => {
                modhex_decode(input).map_err(|_| anyhow!("Value must be modhex-encoded."))
            }
        }
    }
}

/// Expected length, in bytes, of a binary value.
#[derive(Clone, Copy)]
pub enum ByteLen {
    /// Any length is accepted.
    Any,
    /// Exactly `n` bytes.
    Exact(usize),
    /// Between `min` and `max` bytes, inclusive.
    Range(usize, usize),
}

/// Describes an expected hex/modhex byte value for prompts, help text and parsing.
#[derive(Clone, Copy)]
pub struct ByteFormat {
    encoding: ByteEncoding,
    len: ByteLen,
}

impl ByteFormat {
    pub fn hex(len: ByteLen) -> Self {
        Self {
            encoding: ByteEncoding::Hex,
            len,
        }
    }

    pub fn modhex(len: ByteLen) -> Self {
        Self {
            encoding: ByteEncoding::Modhex,
            len,
        }
    }

    /// A human-readable description, e.g. "modhex, 0-16 bytes" or "hex, 6 bytes".
    pub fn describe(&self) -> String {
        let label = self.encoding.label();
        match self.len {
            ByteLen::Any => label.to_string(),
            ByteLen::Exact(n) => format!("{label}, {n} bytes"),
            ByteLen::Range(min, max) => format!("{label}, {min}-{max} bytes"),
        }
    }

    /// Decode and length-validate a user-entered value.
    pub fn parse(&self, input: &str) -> Result<Vec<u8>> {
        let bytes = self.encoding.decode(input)?;
        let ok = match self.len {
            ByteLen::Any => true,
            ByteLen::Exact(n) => bytes.len() == n,
            ByteLen::Range(min, max) => (min..=max).contains(&bytes.len()),
        };
        if !ok {
            return Err(anyhow!(
                "Expected {} but got {} bytes.",
                self.describe(),
                bytes.len()
            ));
        }
        Ok(bytes)
    }
}

/// Prompt for a hex/modhex value, showing its expected format, and return the
/// decoded bytes. Errors if the input is not valid for the given format.
pub fn prompt_bytes(label: &str, spec: &ByteFormat) -> Result<Vec<u8>> {
    let input = prompt(&format!("{label} ({})", spec.describe()))?;
    spec.parse(&input)
}

/// Read from a file, or from stdin if path is "-".
pub fn read_file_or_stdin(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| anyhow!("Failed to read from stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read(path).map_err(|e| anyhow!("Failed to read file '{path}': {e}"))
    }
}

/// Parse a one-byte hexadecimal value, accepting an optional 0x prefix.
pub fn parse_hex_u8(s: &str) -> Result<u8> {
    u8::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|_| anyhow!("Invalid hex value: {s}"))
}

/// Encode bytes as Base32 (RFC 4648, no padding).
pub fn b32_encode(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, data)
}

/// Prompt the user with a yes/no confirmation.
pub fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub(crate) trait TableRow {
    fn into_table_row(self) -> Vec<String>;
}

impl<L, V> TableRow for (L, V)
where
    L: Into<String>,
    V: Into<String>,
{
    fn into_table_row(self) -> Vec<String> {
        vec![format!("{}:", self.0.into()), self.1.into()]
    }
}

impl<T, const N: usize> TableRow for [T; N]
where
    T: Into<String>,
{
    fn into_table_row(self) -> Vec<String> {
        self.into_iter().map(Into::into).collect()
    }
}

impl<T> TableRow for Vec<T>
where
    T: Into<String>,
{
    fn into_table_row(self) -> Vec<String> {
        self.into_iter().map(Into::into).collect()
    }
}

/// Print rows with columns aligned to the widest cell in each column.
pub(crate) fn print_table<R>(rows: impl IntoIterator<Item = R>)
where
    R: TableRow,
{
    let rows: Vec<Vec<String>> = rows.into_iter().map(TableRow::into_table_row).collect();
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; columns];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    for row in rows {
        print_table_row(&row, &widths);
    }
}

fn print_table_row(row: &[String], widths: &[usize]) {
    for (i, width) in widths.iter().enumerate() {
        if i > 0 {
            print!(" ");
        }
        let cell = row.get(i).map(String::as_str).unwrap_or("");
        print!("{cell:<width$}");
    }
    println!();
}

/// Write to a file, or to stdout if path is "-".
pub fn write_file_or_stdout(path: &str, data: &[u8]) -> Result<()> {
    if path == "-" {
        io::stdout()
            .write_all(data)
            .map_err(|e| anyhow!("Failed to write to stdout: {e}"))?;
        io::stdout()
            .flush()
            .map_err(|e| anyhow!("Failed to flush stdout: {e}"))?;
        Ok(())
    } else {
        std::fs::write(path, data).map_err(|e| anyhow!("Failed to write file '{path}': {e}"))
    }
}

/// Open a smartcard session with optional SCP, handling connection and error mapping.
///
/// Resolves SCP configuration, opens the smartcard connection, and creates a session
/// using the provided constructors. This eliminates the repetitive open-session boilerplate
/// across application modules.
pub fn open_smartcard_session<S, E>(
    dev: &dyn YubiKeyDevice,
    scp_params: &ScpParams,
    capability: Capability,
    app_name: &str,
    new_session: impl FnOnce(
        Box<dyn SmartCardConnection + Send>,
    ) -> Result<S, (E, Box<dyn SmartCardConnection + Send>)>,
    new_session_with_scp: impl FnOnce(
        Box<dyn SmartCardConnection + Send>,
        &ScpKeyParams,
    ) -> Result<S, (E, Box<dyn SmartCardConnection + Send>)>,
) -> Result<S>
where
    E: fmt::Display,
{
    let scp_config = scp::resolve_scp_for_app(dev, scp_params, capability, app_name)?;
    let conn = dev
        .open_smartcard()
        .map_err(|e| format_smartcard_connection_error(app_name, e))?;
    match scp_config {
        None => new_session(conn).map_err(|(e, _)| format_session_error(app_name, e)),
        Some(params) => {
            new_session_with_scp(conn, &params).map_err(|(e, _)| format_session_error(app_name, e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_formats() {
        assert_eq!(
            ByteFormat::modhex(ByteLen::Range(0, 16)).describe(),
            "modhex, 0-16 bytes"
        );
        assert_eq!(
            ByteFormat::hex(ByteLen::Exact(6)).describe(),
            "hex, 6 bytes"
        );
        assert_eq!(ByteFormat::hex(ByteLen::Any).describe(), "hex");
    }

    #[test]
    fn parse_validates_length_and_encoding() {
        let spec = ByteFormat::hex(ByteLen::Exact(6));
        assert_eq!(spec.parse("aabbccddeeff").unwrap().len(), 6);
        assert!(spec.parse("aabbcc").is_err()); // too short
        assert!(spec.parse("zz").is_err()); // not hex

        let modhex = ByteFormat::modhex(ByteLen::Range(0, 16));
        assert!(modhex.parse("").unwrap().is_empty()); // empty allowed
        assert!(modhex.parse("vvincredible").is_ok());

        let any = ByteFormat::hex(ByteLen::Any);
        assert_eq!(any.parse("00112233").unwrap().len(), 4);
    }
}
