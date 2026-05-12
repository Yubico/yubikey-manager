//! Device source abstraction for YubiKey enumeration.
//!
//! Provides a [`DeviceSource`] trait that abstracts over local USB/NFC
//! enumeration and remote access via the ykman-svc service. Use
//! [`get_device_source`] to get the best available source for the platform.

use std::cell::RefCell;
use std::rc::Rc;

use serde_json::json;

use yubikit::device::{DeviceError, YubiKeyDevice, list_devices, select_fido};
use yubikit::management::UsbInterface;

use crate::rpc::client::{RpcCallError, RpcClient};
use crate::rpc::proxy::RpcDevice;

/// A source of YubiKey devices.
///
/// Abstracts over local enumeration (USB/NFC) and remote access via the
/// ykman-svc service, allowing callers to enumerate devices without caring
/// about the underlying transport.
pub trait DeviceSource {
    /// List all currently connected YubiKey devices.
    ///
    /// Returns devices across all transports (USB and NFC) and connection
    /// types (CCID, FIDO, OTP). Callers should filter the returned list
    /// as needed.
    fn list_devices(&mut self) -> Result<Vec<Box<dyn YubiKeyDevice>>, DeviceError>;

    /// Select a YubiKey by touch via CTAP2 authenticator selection.
    ///
    /// Waits for the user to touch a connected YubiKey and returns it.
    /// Polls for newly inserted devices until one is selected or cancelled.
    fn select_fido(
        &mut self,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Box<dyn YubiKeyDevice>, DeviceError>;

    /// Whether this source is backed by the ykman-svc service.
    fn is_service(&self) -> bool {
        false
    }
}

/// Device source using direct local access (USB HID, PC/SC).
pub struct LocalDeviceSource;

impl DeviceSource for LocalDeviceSource {
    fn list_devices(&mut self) -> Result<Vec<Box<dyn YubiKeyDevice>>, DeviceError> {
        let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
        let devices = list_devices(all)?;
        Ok(devices.into_iter().map(|d| Box::new(d) as _).collect())
    }

    fn select_fido(
        &mut self,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Box<dyn YubiKeyDevice>, DeviceError> {
        let dev = select_fido(cancel)?;
        Ok(Box::new(dev))
    }
}

/// Device source using the ykman-svc service (Named Pipe on Windows, Unix
/// socket in debug builds).
pub struct RpcDeviceSource {
    client: Rc<RefCell<RpcClient>>,
}

impl RpcDeviceSource {
    fn new(client: RpcClient) -> Self {
        Self {
            client: Rc::new(RefCell::new(client)),
        }
    }

    /// Get a shared reference to the underlying RPC client.
    ///
    /// Useful for callers that need to perform additional operations on the
    /// same connection (e.g., opening a specific device by name).
    pub fn client(&self) -> Rc<RefCell<RpcClient>> {
        self.client.clone()
    }
}

impl DeviceSource for RpcDeviceSource {
    fn list_devices(&mut self) -> Result<Vec<Box<dyn YubiKeyDevice>>, DeviceError> {
        let root = self
            .client
            .borrow_mut()
            .get(&[] as &[&str])
            .map_err(rpc_to_device_error)?;

        let children = root
            .body
            .get("children")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let mut devices: Vec<Box<dyn YubiKeyDevice>> = Vec::new();
        for (name, _info) in &children {
            match RpcDevice::from_shared_at(self.client.clone(), name) {
                Ok(dev) => devices.push(Box::new(dev)),
                Err(e) => log::warn!("Failed to open service device '{name}': {e}"),
            }
        }

        Ok(devices)
    }

    fn select_fido(
        &mut self,
        _cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Box<dyn YubiKeyDevice>, DeviceError> {
        let result = self
            .client
            .borrow_mut()
            .call("select_fido", &[] as &[&str], json!({}), None, true)
            .map_err(rpc_to_device_error)?;

        let name = result
            .body
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or(DeviceError::NoDeviceFound)?;

        let dev =
            RpcDevice::from_shared_at(self.client.clone(), name).map_err(rpc_to_device_error)?;
        Ok(Box::new(dev))
    }

    fn is_service(&self) -> bool {
        true
    }
}

fn rpc_to_device_error(e: RpcCallError) -> DeviceError {
    log::warn!("Service error: {e}");
    DeviceError::NoDeviceFound
}

/// Get the best available device source for the current platform.
///
/// On Windows, attempts to connect to the ykman-svc Named Pipe service.
/// On other platforms in debug builds, attempts a Unix socket connection.
/// Falls back to direct local device access on failure or when the service
/// is unavailable.
pub fn get_device_source() -> Box<dyn DeviceSource> {
    #[cfg(target_os = "windows")]
    {
        match RpcClient::connect_pipe() {
            Ok(client) => {
                log::debug!("Connected to ykman-svc service");
                return Box::new(RpcDeviceSource::new(client));
            }
            Err(e) => {
                log::debug!("ykman-svc not available ({e}), using direct access");
            }
        }
    }

    #[cfg(all(debug_assertions, not(target_os = "windows")))]
    {
        match RpcClient::connect_pipe() {
            Ok(client) => {
                log::debug!("Connected to ykman-svc socket (dev mode)");
                return Box::new(RpcDeviceSource::new(client));
            }
            Err(e) => {
                log::debug!("ykman-svc socket not available ({e}), using direct access");
            }
        }
    }

    Box::new(LocalDeviceSource)
}
