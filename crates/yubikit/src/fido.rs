// Copyright (c) 2026 Yubico AB
// All rights reserved.
//
//   Redistribution and use in source and binary forms, with or
//   without modification, are permitted provided that the following
//   conditions are met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//    2. Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! FIDO connection trait.

use crate::transport::ctaphid::FidoError;

/// Abstract FIDO connection — send CTAP HID commands.
pub trait FidoConnection: crate::core::Connection<Error = FidoError> {
    fn call(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>, FidoError>;
    fn call_with_keepalive(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError>;
    fn device_version(&self) -> (u8, u8, u8);
    fn capabilities(&self) -> crate::transport::ctaphid::CtapHidCapability;
}

impl crate::core::Connection for Box<dyn FidoConnection + Send> {
    type Error = FidoError;
    fn close(&mut self) {
        (**self).close();
    }
}

impl FidoConnection for Box<dyn FidoConnection + Send> {
    fn call(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>, FidoError> {
        (**self).call(cmd, data)
    }
    fn call_with_keepalive(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        (**self).call_with_keepalive(cmd, data, on_keepalive, cancel)
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
    fn call(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>, FidoError> {
        (**self).call(cmd, data)
    }
    fn call_with_keepalive(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        (**self).call_with_keepalive(cmd, data, on_keepalive, cancel)
    }
    fn device_version(&self) -> (u8, u8, u8) {
        (**self).device_version()
    }
    fn capabilities(&self) -> crate::transport::ctaphid::CtapHidCapability {
        (**self).capabilities()
    }
}
