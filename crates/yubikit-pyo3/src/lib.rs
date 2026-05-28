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

mod py_bridge;
mod py_core;
mod py_ctap;
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
mod py_securitydomain;
mod py_smartcard;
mod py_webauthn;
mod py_yubiotp;

use pyo3::prelude::*;

#[pymodule(gil_used = true)]
fn _yubikit_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    py_logging::init();
    py_pcsc::register(m)?;
    py_hid::register(m)?;
    py_core::register(m)?;
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
    m.add_class::<py_management::ManagementSessionCcid>()?;
    m.add_class::<py_management::ManagementSessionOtp>()?;
    m.add_class::<py_management::ManagementSessionFido>()?;
    m.add_function(wrap_pyfunction!(py_management::py_list_fido_devices, &m)?)?;
    m.add_class::<py_securitydomain::SecurityDomainSession>()?;
    m.add_class::<py_yubiotp::PyYubiOtpSessionCcid>()?;
    m.add_class::<py_yubiotp::PyYubiOtpSessionOtp>()?;
    m.add_class::<py_ctap::PyCtap2SessionCcid>()?;
    m.add_class::<py_ctap::PyCtap2SessionFido>()?;
    m.add_class::<py_ctap::PyPinProtocol>()?;
    m.add_class::<py_ctap::PyClientPinCcid>()?;
    m.add_class::<py_ctap::PyClientPinFido>()?;
    m.add_class::<py_ctap::PyCredentialManagementCcid>()?;
    m.add_class::<py_ctap::PyCredentialManagementFido>()?;
    m.add_class::<py_ctap::PyConfigCcid>()?;
    m.add_class::<py_ctap::PyConfigFido>()?;
    m.add_class::<py_ctap::PyBioEnrollmentCcid>()?;
    m.add_class::<py_ctap::PyBioEnrollmentFido>()?;
    m.add_class::<py_ctap::PyLargeBlobsCcid>()?;
    m.add_class::<py_ctap::PyLargeBlobsFido>()?;
    m.add_class::<py_webauthn::PyWebAuthnClientFido>()?;
    m.add_class::<py_webauthn::PyWebAuthnClientCcid>()?;
    parent.add_submodule(&m)?;

    let sys = parent.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_yubikit_native.sessions", &m)?;

    Ok(())
}
