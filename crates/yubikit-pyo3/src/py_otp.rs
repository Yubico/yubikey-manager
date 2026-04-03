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
//! implementation, bridging a Python OTP connection to the Rust
//! `OtpTransport` trait.

use std::sync::atomic::{AtomicBool, Ordering};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit::otp::{OtpConnection, OtpProtocol as RustOtpProtocol, YubiOtpError};

/// Bridges a Python OtpConnection object to the Rust OtpTransport trait.
pub struct PyOtpConnection {
    receive_fn: PyObject,
    send_fn: PyObject,
}

impl PyOtpConnection {
    pub fn from_py(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let receive_fn = connection.getattr("receive")?.unbind();
        let send_fn = connection.getattr("send")?.unbind();
        Ok(Self {
            receive_fn,
            send_fn,
        })
    }
}

impl OtpConnection for PyOtpConnection {
    fn otp_receive(&self) -> Result<Vec<u8>, YubiOtpError> {
        Python::with_gil(|py| {
            let result = self
                .receive_fn
                .call0(py)
                .map_err(|e| YubiOtpError::BadResponse(e.to_string()))?;
            let bytes: Vec<u8> = result
                .extract(py)
                .map_err(|e| YubiOtpError::BadResponse(e.to_string()))?;
            Ok(bytes)
        })
    }

    fn otp_send(&self, data: &[u8]) -> Result<(), YubiOtpError> {
        Python::with_gil(|py| {
            let py_bytes = PyBytes::new(py, data);
            self.send_fn
                .call1(py, (py_bytes,))
                .map_err(|e| YubiOtpError::BadResponse(e.to_string()))?;
            Ok(())
        })
    }
}

#[pyclass(unsendable)]
pub struct OtpProtocol {
    inner: RustOtpProtocol<PyOtpConnection>,
    connection: PyObject,
}

#[pymethods]
impl OtpProtocol {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let py_conn = PyOtpConnection::from_py(connection)?;
        let protocol = RustOtpProtocol::new(py_conn)
            .map_err(|(e, _)| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
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

    #[getter]
    fn version(&self) -> (u8, u8, u8) {
        (
            self.inner.version.0,
            self.inner.version.1,
            self.inner.version.2,
        )
    }

    #[pyo3(signature = (slot, data=None, expected_len=None, event=None, on_keepalive=None))]
    fn send_and_receive(
        &self,
        slot: u8,
        data: Option<&[u8]>,
        expected_len: Option<i32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Option<Vec<u8>>> {
        // Bridge Python Event to AtomicBool cancel flag
        let cancel = AtomicBool::new(false);
        let cancel_ref = if event.is_some() { Some(&cancel) } else { None };

        // Build keepalive callback that checks event.is_set() and calls on_keepalive
        let keepalive_fn = |status: u8| {
            Python::with_gil(|py| {
                if let Some(ref evt) = event
                    && let Ok(is_set) = evt.call_method0(py, "is_set")
                    && is_set.extract::<bool>(py).unwrap_or(false)
                {
                    cancel.store(true, Ordering::Relaxed);
                }
                if let Some(ref cb) = on_keepalive {
                    let _ = cb.call1(py, (status,));
                }
            });
        };

        let keepalive_ref: Option<&dyn Fn(u8)> = if event.is_some() || on_keepalive.is_some() {
            Some(&keepalive_fn)
        } else {
            None
        };

        self.inner
            .send_and_receive_with_cancel(slot, data, expected_len, cancel_ref, keepalive_ref)
            .map_err(|e| match e {
                YubiOtpError::CommandRejected(msg) => {
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
                YubiOtpError::Timeout(msg) => {
                    Python::with_gil(|py| match py.import("yubikit.core") {
                        Ok(module) => match module.getattr("TimeoutError") {
                            Ok(cls) => match cls.call1((msg.clone(),)) {
                                Ok(exc) => PyErr::from_value(exc),
                                Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                            },
                            Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                        },
                        Err(_) => pyo3::exceptions::PyRuntimeError::new_err(msg),
                    })
                }
                _ => pyo3::exceptions::PyRuntimeError::new_err(e.to_string()),
            })
    }

    fn read_status(&self) -> PyResult<Vec<u8>> {
        self.inner
            .read_status()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }
}
