use anyhow::Result;
#[cfg(not(target_os = "windows"))]
use anyhow::bail;
use clap::{Parser, Subcommand};

mod connection;
mod device;
mod device_manager;
mod pipe_server;
mod root_node;
#[cfg(target_os = "windows")]
mod service;
mod session;
#[cfg(target_os = "windows")]
mod signing;

#[cfg(target_os = "windows")]
static WINDOWS_SERVICE: std::sync::OnceLock<ykman::rpc::windows::WindowsService> =
    std::sync::OnceLock::new();

#[cfg(target_os = "windows")]
pub fn windows_service() -> ykman::rpc::windows::WindowsService {
    *WINDOWS_SERVICE.get().expect("service identity initialized")
}

#[derive(Parser)]
#[command(name = "ykman-svc", about = "YubiKey Manager Service")]
struct Cli {
    /// Use the isolated Yubico Authenticator MSIX service and named pipe
    #[cfg(target_os = "windows")]
    #[arg(long, global = true)]
    authenticator_msix: bool,

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

fn run() -> Result<()> {
    let cli = Cli::parse();
    #[cfg(target_os = "windows")]
    WINDOWS_SERVICE
        .set(if cli.authenticator_msix {
            ykman::rpc::windows::WindowsService::AuthenticatorMsix
        } else {
            ykman::rpc::windows::WindowsService::Shared
        })
        .expect("service identity initialized only once");

    match &cli.command {
        Commands::Standalone {
            log_level,
            log_file,
        } => {
            let level = log_level.unwrap_or(ykman::logging::LogLevel::Info);
            let result = if let Some(path) = log_file {
                ykman::logging::init_logging(level, Some(path.as_str()))
            } else {
                ykman::logging::init_logging_stdout(level)
            };
            result?;
        }
        _ => {
            ykman::logging::init_logging(ykman::logging::LogLevel::Warning, None)?;
        }
    }

    match cli.command {
        Commands::Install => {
            #[cfg(target_os = "windows")]
            service::install()?;
            #[cfg(not(target_os = "windows"))]
            bail!("Service install is only supported on Windows");
        }
        Commands::Uninstall => {
            #[cfg(target_os = "windows")]
            service::uninstall()?;
            #[cfg(not(target_os = "windows"))]
            bail!("Service uninstall is only supported on Windows");
        }
        Commands::Run => {
            #[cfg(target_os = "windows")]
            service::run_service()?;
            #[cfg(not(target_os = "windows"))]
            bail!("Service mode is only supported on Windows");
        }
        Commands::Standalone { .. } => {
            log::info!("Running in standalone mode");
            pipe_server::run_standalone();
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
