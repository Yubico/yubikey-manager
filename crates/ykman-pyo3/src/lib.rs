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
mod py_hsmauth_session;
mod py_management_session;
mod py_oath;
mod py_oath_session;
mod py_openpgp_session;
mod py_pcsc;
mod py_piv_session;
mod py_scp;
mod py_securitydomain_session;
mod py_yubiotp_session;

use pyo3::prelude::*;

#[pymodule]
fn _ykman_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    m.add_class::<py_oath_session::OathSession>()?;
    m.add_class::<py_piv_session::PivSession>()?;
    m.add_class::<py_openpgp_session::OpenPgpSession>()?;
    m.add_class::<py_hsmauth_session::HsmAuthSession>()?;
    m.add_class::<py_management_session::ManagementSession>()?;
    m.add_class::<py_management_session::ManagementOtpSession>()?;
    m.add_class::<py_securitydomain_session::SecurityDomainSession>()?;
    m.add_class::<py_yubiotp_session::PyYubiOtpSession>()?;
    m.add_class::<py_yubiotp_session::PyYubiOtpOtpSession>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.sessions", &m)?;

    Ok(())
}
