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

//! PyO3 wrapper for Rust OtpProtocol.
//!
//! Exposes `OtpProtocol` as a Python class that wraps the Rust
//! implementation. Supports both native `HidOtpConnection` (fast path)
//! and arbitrary Python OTP connections (slow path via bridge).

use pyo3::prelude::*;
use yubikit::otp::{OtpError, OtpProtocol as RustOtpProtocol};

use crate::py_bridge::{BoxedOtpConnection, extract_otp_connection, restore_otp_connection};

#[pyclass(unsendable)]
pub struct OtpProtocol {
    inner: Option<RustOtpProtocol<BoxedOtpConnection>>,
    py_connection: PyObject,
}

impl OtpProtocol {
    fn protocol(&self) -> PyResult<&RustOtpProtocol<BoxedOtpConnection>> {
        self.inner
            .as_ref()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("OtpProtocol is closed"))
    }

    fn protocol_mut(&mut self) -> PyResult<&mut RustOtpProtocol<BoxedOtpConnection>> {
        self.inner
            .as_mut()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("OtpProtocol is closed"))
    }
}

#[pymethods]
impl OtpProtocol {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let otp_conn = extract_otp_connection(connection)?;
        let protocol = RustOtpProtocol::new(otp_conn)
            .map_err(|(e, _)| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self {
            inner: Some(protocol),
            py_connection: connection.clone().unbind(),
        })
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(protocol) = self.inner.take() {
            let conn = protocol.into_connection();
            restore_otp_connection(self.py_connection.bind(py), conn)?;
        }
        Ok(())
    }

    #[getter]
    fn version(&self) -> PyResult<(u8, u8, u8)> {
        let p = self.protocol()?;
        Ok((p.version.0, p.version.1, p.version.2))
    }

    #[pyo3(signature = (slot, data=None, expected_len=None, event=None, on_keepalive=None))]
    fn send_and_receive(
        &mut self,
        slot: u8,
        data: Option<&[u8]>,
        expected_len: Option<i32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Option<Vec<u8>>> {
        // Bridge Python Event to cancel closure
        let cancel_fn = || {
            Python::with_gil(|py| {
                if let Some(ref evt) = event
                    && let Ok(is_set) = evt.call_method0(py, "is_set")
                    && is_set.extract::<bool>(py).unwrap_or(false)
                {
                    return true;
                }
                false
            })
        };
        let cancel_ref: Option<&dyn Fn() -> bool> = if event.is_some() {
            Some(&cancel_fn)
        } else {
            None
        };

        // Build keepalive callback
        let keepalive_fn = |status: u8| {
            if let Some(ref cb) = on_keepalive {
                Python::with_gil(|py| {
                    let _ = cb.call1(py, (status,));
                });
            }
        };
        let keepalive_ref: Option<&dyn Fn(u8)> = if on_keepalive.is_some() {
            Some(&keepalive_fn)
        } else {
            None
        };

        self.protocol_mut()?
            .send_and_receive_with_cancel(slot, data, expected_len, cancel_ref, keepalive_ref)
            .map_err(|e| match e {
                OtpError::CommandRejected(msg) => {
                    Python::with_gil(|py| match py.import("yubikit.core.otp") {
                        Ok(module) => match module.getattr("CommandRejectedError") {
                            Ok(cls) => match cls.call1((msg.clone(),)) {
                                Ok(exc) => PyErr::from_value(exc),
                                Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                            },
                            Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                        },
                        Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                    })
                }
                OtpError::Timeout(msg) => Python::with_gil(|py| match py.import("yubikit.core") {
                    Ok(module) => match module.getattr("TimeoutError") {
                        Ok(cls) => match cls.call1((msg.clone(),)) {
                            Ok(exc) => PyErr::from_value(exc),
                            Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                        },
                        Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                    },
                    Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                }),
                _ => pyo3::exceptions::PyRuntimeError::new_err(e.to_string()),
            })
    }

    fn read_status(&mut self) -> PyResult<Vec<u8>> {
        self.protocol_mut()?
            .read_status()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }
}
