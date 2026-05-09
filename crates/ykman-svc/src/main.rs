use clap::{Parser, Subcommand};

mod device_manager;
mod pipe_server;
mod root_node;
#[cfg(target_os = "windows")]
mod service;
mod session;
#[cfg(target_os = "windows")]
mod signing;

pub const SERVICE_NAME: &str = "ykman-svc";
#[cfg(target_os = "windows")]
pub const PIPE_NAME: &str = r"\\.\pipe\ykman-svc";

#[derive(Parser)]
#[command(name = "ykman-svc", about = "YubiKey Manager Service")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the Windows service
    Install,
    /// Uninstall the Windows service
    Uninstall,
    /// Run as a Windows service (called by SCM)
    Run,
    /// Run in standalone mode (foreground, for testing)
    Standalone {
        /// Enable logging at given verbosity level (ERROR, WARNING, INFO, DEBUG, TRAFFIC)
        #[arg(short = 'l', long = "log-level")]
        log_level: Option<ykman::logging::LogLevel>,

        /// Write log to FILE instead of stderr (requires --log-level)
        #[arg(long = "log-file", value_name = "FILE")]
        log_file: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Standalone {
            log_level,
            log_file,
        } => {
            let level = log_level.unwrap_or(ykman::logging::LogLevel::Info);
            if let Some(path) = log_file {
                let _ = ykman::logging::init_logging(level, Some(path.as_str()));
            } else {
                let _ = ykman::logging::init_logging_stdout(level);
            }
        }
        _ => {
            let _ = ykman::logging::init_logging(ykman::logging::LogLevel::Warning, None);
        }
    }

    match cli.command {
        Commands::Install => {
            #[cfg(target_os = "windows")]
            service::install().unwrap_or_else(|e| {
                eprintln!("Failed to install service: {e}");
                std::process::exit(1);
            });
            #[cfg(not(target_os = "windows"))]
            {
                eprintln!("Service install is only supported on Windows");
                std::process::exit(1);
            }
        }
        Commands::Uninstall => {
            #[cfg(target_os = "windows")]
            service::uninstall().unwrap_or_else(|e| {
                eprintln!("Failed to uninstall service: {e}");
                std::process::exit(1);
            });
            #[cfg(not(target_os = "windows"))]
            {
                eprintln!("Service uninstall is only supported on Windows");
                std::process::exit(1);
            }
        }
        Commands::Run => {
            #[cfg(target_os = "windows")]
            service::run_service().unwrap_or_else(|e| {
                eprintln!("Service failed: {e}");
                std::process::exit(1);
            });
            #[cfg(not(target_os = "windows"))]
            {
                eprintln!("Service mode is only supported on Windows");
                std::process::exit(1);
            }
        }
        Commands::Standalone { .. } => {
            log::info!("Running in standalone mode");
            pipe_server::run_standalone();
        }
    }
}
