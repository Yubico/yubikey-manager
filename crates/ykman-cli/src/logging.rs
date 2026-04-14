//! Logging setup for the ykman CLI.
//!
//! Provides a custom logger that matches Python ykman's log format:
//! `LEVEL HH:MM:SS.ms [module.function:line] message`
//!
//! Supports custom TRAFFIC level (maps to Trace with "traffic::" target prefix).

use std::fs::File;
use std::io::Write;
use std::sync::Mutex;

use chrono::Local;
use log::{Level, LevelFilter, Log, Metadata, Record};

use yubikit::logging::TRAFFIC_TARGET_PREFIX;

/// Log levels matching Python's ykman logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
    Traffic,
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "ERROR" => Ok(Self::Error),
            "WARNING" => Ok(Self::Warning),
            "INFO" => Ok(Self::Info),
            "DEBUG" => Ok(Self::Debug),
            "TRAFFIC" => Ok(Self::Traffic),
            _ => Err(format!("Unknown log level: {s}")),
        }
    }
}

impl LogLevel {
    pub fn name(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Traffic => "TRAFFIC",
        }
    }

    fn to_level_filter(self) -> LevelFilter {
        match self {
            Self::Error => LevelFilter::Error,
            Self::Warning => LevelFilter::Warn,
            Self::Info => LevelFilter::Info,
            Self::Debug => LevelFilter::Debug,
            Self::Traffic => LevelFilter::Trace,
        }
    }
}

const DEBUG_WARNING: &[&str] = &[
    "WARNING: Sensitive data may be logged!",
    "Some personally identifying information may be logged, such as usernames!",
];

const TRAFFIC_WARNING: &[&str] = &[
    "WARNING: All data sent to/from the YubiKey will be logged!",
    "This data may contain sensitive values, such as secret keys, PINs or passwords!",
];

fn print_box(lines: &[&str]) -> String {
    let w = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let bar = "#".repeat(w + 4);
    let mut out = vec![String::new(), bar.clone()];
    // Empty line, content lines, empty line
    for line in std::iter::once(&"")
        .chain(lines.iter())
        .chain(std::iter::once(&""))
    {
        out.push(format!("# {:<w$} #", line));
    }
    out.push(bar);
    out.join("\n")
}

enum Output {
    Stderr,
    File(Mutex<File>),
}

struct YkmanLogger {
    level: LogLevel,
    output: Output,
}

impl Log for YkmanLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // For TRAFFIC (Trace), only enable if target starts with "traffic::"
        if metadata.level() == Level::Trace {
            metadata.target().starts_with(TRAFFIC_TARGET_PREFIX) && self.level == LogLevel::Traffic
        } else {
            metadata.level() <= self.level.to_level_filter()
        }
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = Local::now();
        let timestamp = now.format("%H:%M:%S");
        let millis = now.timestamp_subsec_millis();

        // Map level name: Trace with traffic target → "TRAFFIC", Warn → "WARNING"
        let level_name = if record.level() == Level::Trace
            && record.target().starts_with(TRAFFIC_TARGET_PREFIX)
        {
            "TRAFFIC"
        } else {
            match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARNING",
                Level::Info => "INFO",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            }
        };

        // Module path: strip the traffic:: prefix if present
        let module = if let Some(stripped) = record.target().strip_prefix(TRAFFIC_TARGET_PREFIX) {
            stripped
        } else {
            record.target()
        };

        let line = record.line().unwrap_or(0);

        let msg = format!(
            "{level_name} {timestamp}.{millis} [{module}:{line}] {}\n",
            record.args()
        );

        match &self.output {
            Output::Stderr => {
                eprint!("{msg}");
            }
            Output::File(file) => {
                if let Ok(mut f) = file.lock() {
                    let _ = f.write_all(msg.as_bytes());
                }
            }
        }
    }

    fn flush(&self) {
        match &self.output {
            Output::Stderr => {
                let _ = std::io::stderr().flush();
            }
            Output::File(file) => {
                if let Ok(mut f) = file.lock() {
                    let _ = f.flush();
                }
            }
        }
    }
}

/// Initialize logging with the given level and optional log file.
pub fn init_logging(level: LogLevel, log_file: Option<&str>) -> Result<(), String> {
    let output = if let Some(path) = log_file {
        let file =
            File::create(path).map_err(|e| format!("Failed to open log file '{path}': {e}"))?;
        Output::File(Mutex::new(file))
    } else {
        Output::Stderr
    };

    let logger = YkmanLogger { level, output };
    log::set_boxed_logger(Box::new(logger)).map_err(|e| format!("Failed to set logger: {e}"))?;
    log::set_max_level(level.to_level_filter());

    if let Some(file) = &log_file {
        log::warn!("Logging to file: {file}");
    }
    set_log_level(level);

    Ok(())
}

/// Set the active log level, logging a warning if sensitive data may be captured.
pub fn set_log_level(level: LogLevel) {
    log::set_max_level(level.to_level_filter());
    log::info!("Logging at level: {}", level.name());
    if level == LogLevel::Traffic {
        log::warn!("{}", print_box(TRAFFIC_WARNING));
    } else if level == LogLevel::Debug {
        log::warn!("{}", print_box(DEBUG_WARNING));
    }
}
