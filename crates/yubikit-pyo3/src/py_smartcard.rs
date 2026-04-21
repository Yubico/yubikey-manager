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

//! PyO3 wrapper for Rust SmartCardProtocol.
//!
//! Exposes `SmartCardProtocol` as a Python class that wraps the Rust
//! implementation, delegating `select()`, `send_apdu()`, `configure()`,
//! `init_scp()`, and `close()` to native code.

use pyo3::prelude::*;
use yubikit::core::Version;
use yubikit::smartcard::SmartCardProtocol as RustSmartCardProtocol;

use crate::py_bridge::{
    BoxedSmartCardConnection, extract_smartcard_connection, init_scp_from_py,
    restore_smartcard_connection, smartcard_err,
};

#[pyclass]
pub struct SmartCardProtocol {
    inner: Option<RustSmartCardProtocol<BoxedSmartCardConnection>>,
    py_connection: PyObject,
}

impl SmartCardProtocol {
    fn protocol_mut(&mut self) -> PyResult<&mut RustSmartCardProtocol<BoxedSmartCardConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("SmartCardProtocol is closed"))
    }
}

#[pymethods]
impl SmartCardProtocol {
    #[new]
    #[pyo3(signature = (connection, ins_send_remaining=0xC0))]
    fn new(connection: &Bound<'_, PyAny>, ins_send_remaining: u8) -> PyResult<Self> {
        let py_conn = extract_smartcard_connection(connection)?;
        let protocol =
            RustSmartCardProtocol::new(py_conn).with_ins_send_remaining(ins_send_remaining);
        Ok(Self {
            inner: Some(protocol),
            py_connection: connection.clone().unbind(),
        })
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(protocol) = self.inner.take() {
            let conn = protocol.into_connection();
            restore_smartcard_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }

    fn configure(&mut self, version: (u8, u8, u8), force_short: Option<bool>) -> PyResult<()> {
        let v = Version(version.0, version.1, version.2);
        self.protocol_mut()?
            .configure_force_short(v, force_short.unwrap_or(false));
        Ok(())
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
            self.protocol_mut()?
                .send_apdu_with_le(cla, ins, p1, p2, data, le)
                .map_err(smartcard_err)
        } else {
            self.protocol_mut()?
                .send_apdu(cla, ins, p1, p2, data)
                .map_err(smartcard_err)
        }
    }

    fn select(&mut self, aid: &[u8]) -> PyResult<Vec<u8>> {
        self.protocol_mut()?.select(aid).map_err(smartcard_err)
    }

    fn init_scp(&mut self, key_params: &Bound<'_, PyAny>) -> PyResult<()> {
        init_scp_from_py(self.protocol_mut()?, key_params)
    }
}
