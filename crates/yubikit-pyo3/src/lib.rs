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

mod py_bridge;
mod py_core;
mod py_device;
mod py_hid;
mod py_hsmauth;
mod py_logging;
mod py_management;
mod py_oath;
mod py_openpgp;
mod py_otp;
mod py_pcsc;
mod py_piv;
mod py_scp;
mod py_securitydomain;
mod py_smartcard;
mod py_yubiotp;

use pyo3::prelude::*;

#[pymodule]
fn _yubikit_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    py_logging::init();
    py_pcsc::register(m)?;
    py_hid::register(m)?;
    py_core::register(m)?;
    py_scp::register(m)?;
    py_oath::register(m)?;
    py_device::register(m)?;
    register_sessions(m)?;
    Ok(())
}

fn register_sessions(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "sessions")?;
    m.add_class::<py_oath::OathSession>()?;
    m.add_class::<py_piv::PivSession>()?;
    m.add_class::<py_openpgp::OpenPgpSession>()?;
    m.add_class::<py_hsmauth::HsmAuthSession>()?;
    m.add_class::<py_management::ManagementSession>()?;
    m.add_class::<py_management::ManagementOtpSession>()?;
    m.add_class::<py_management::ManagementFidoSession>()?;
    m.add_function(wrap_pyfunction!(py_management::py_list_fido_devices, &m)?)?;
    m.add_class::<py_securitydomain::SecurityDomainSession>()?;
    m.add_class::<py_yubiotp::PyYubiOtpSession>()?;
    m.add_class::<py_yubiotp::PyYubiOtpOtpSession>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.sessions", &m)?;

    Ok(())
}
