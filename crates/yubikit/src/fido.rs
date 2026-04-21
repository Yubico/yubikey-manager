// Copyright 2026 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! FIDO connection trait.

use crate::transport::ctaphid::FidoError;

/// Abstract FIDO connection — send CTAP HID commands.
pub trait FidoConnection: crate::core::Connection<Error = FidoError> {
    /// Send a CTAP HID command and receive the response.
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError>;
    /// Return the firmware version as `(major, minor, patch)`.
    fn device_version(&self) -> (u8, u8, u8);
    /// Return the CTAP HID capability flags reported by the device.
    fn capabilities(&self) -> crate::transport::ctaphid::CtapHidCapability;
}

impl crate::core::Connection for Box<dyn FidoConnection + Send> {
    type Error = FidoError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl FidoConnection for Box<dyn FidoConnection + Send> {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        (**self).call(cmd, data, on_keepalive, cancel)
    }
    fn device_version(&self) -> (u8, u8, u8) {
        (**self).device_version()
    }
    fn capabilities(&self) -> crate::transport::ctaphid::CtapHidCapability {
        (**self).capabilities()
    }
}

impl crate::core::Connection for Box<dyn FidoConnection + Send + Sync> {
    type Error = FidoError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl FidoConnection for Box<dyn FidoConnection + Send + Sync> {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        (**self).call(cmd, data, on_keepalive, cancel)
    }
    fn device_version(&self) -> (u8, u8, u8) {
        (**self).device_version()
    }
    fn capabilities(&self) -> crate::transport::ctaphid::CtapHidCapability {
        (**self).capabilities()
    }
}
