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

//! PyO3 wrapper for Rust SmartCardProtocol.
//!
//! Exposes `SmartCardProtocol` as a Python class that wraps the Rust
//! implementation, delegating `select()`, `send_apdu()`, `configure()`,
//! `init_scp()`, and `close()` to native code.

use pyo3::prelude::*;
use yubikit_rs::core_types::Version;
use yubikit_rs::smartcard::SmartCardProtocol as RustSmartCardProtocol;

use crate::py_bridge::{init_scp_from_py, smartcard_err, PySmartCardConnection};

#[pyclass]
pub struct SmartCardProtocol {
    inner: RustSmartCardProtocol<PySmartCardConnection>,
    /// Keep a reference to the Python connection so it can be accessed.
    connection: PyObject,
}

#[pymethods]
impl SmartCardProtocol {
    #[new]
    #[pyo3(signature = (connection, ins_send_remaining=0xC0))]
    fn new(connection: &Bound<'_, PyAny>, ins_send_remaining: u8) -> PyResult<Self> {
        let py_conn = PySmartCardConnection::from_py(connection)?;
        let protocol =
            RustSmartCardProtocol::new(py_conn).with_ins_send_remaining(ins_send_remaining);
        Ok(Self {
            inner: protocol,
            connection: connection.clone().unbind(),
        })
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let conn = self.connection.bind(py);
        conn.call_method0("close")?;
        Ok(())
    }

    fn configure(&mut self, version: (u8, u8, u8), force_short: Option<bool>) {
        let v = Version(version.0, version.1, version.2);
        self.inner
            .configure_force_short(v, force_short.unwrap_or(false));
    }

    #[pyo3(signature = (cla, ins, p1, p2, data=None, le=0))]
    fn send_apdu(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Option<&[u8]>,
        le: u16,
    ) -> PyResult<Vec<u8>> {
        let data = data.unwrap_or(&[]);
        if le > 0 {
            self.inner
                .send_apdu_with_le(cla, ins, p1, p2, data, le)
                .map_err(smartcard_err)
        } else {
            self.inner
                .send_apdu(cla, ins, p1, p2, data)
                .map_err(smartcard_err)
        }
    }

    fn select(&mut self, aid: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.select(aid).map_err(smartcard_err)
    }

    fn init_scp(&mut self, key_params: &Bound<'_, PyAny>) -> PyResult<()> {
        init_scp_from_py(&mut self.inner, key_params)
    }
}
