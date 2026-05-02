//! Windows Service integration.
//!
//! Uses the `windows-service` crate for SCM registration and lifecycle.

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(target_os = "windows")]
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
#[cfg(target_os = "windows")]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
#[cfg(target_os = "windows")]
use windows_service::{define_windows_service, service_dispatcher};

#[cfg(target_os = "windows")]
const SERVICE_NAME: &str = crate::SERVICE_NAME;
#[cfg(target_os = "windows")]
const DISPLAY_NAME: &str = "YubiKey Manager Service";

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, service_main);

/// Install the service.
#[cfg(target_os = "windows")]
pub fn install() -> Result<(), Box<dyn std::error::Error>> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let exe_path = std::env::current_exe()?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let _service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    log::info!("Service '{SERVICE_NAME}' installed");
    println!("Service installed successfully.");
    Ok(())
}

/// Uninstall the service.
#[cfg(target_os = "windows")]
pub fn uninstall() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;

    // Stop the service if running
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            // Wait briefly for stop
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    service.delete()?;
    log::info!("Service '{SERVICE_NAME}' uninstalled");
    println!("Service uninstalled successfully.");
    Ok(())
}

/// Entry point called by the service dispatcher.
#[cfg(target_os = "windows")]
pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

/// The actual service main function.
#[cfg(target_os = "windows")]
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service_inner() {
        log::error!("Service error: {e}");
    }
}

#[cfg(target_os = "windows")]
fn run_service_inner() -> Result<(), Box<dyn std::error::Error>> {
    ykman_cli::logging::init_logging();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_clone.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    // Report running
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    log::info!("Service started");

    let manager = Arc::new(crate::device_manager::DeviceManager::new());
    crate::pipe_server::run_server(manager, &stop);

    // Report stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    log::info!("Service stopped");
    Ok(())
}
