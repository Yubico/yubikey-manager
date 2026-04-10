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
use pyo3::types::PyBytes;
use yubikit::otp::{OtpConnection, OtpError, OtpProtocol as RustOtpProtocol};

use crate::py_hid;

/// Type alias for a boxed OTP connection.
pub type BoxedOtpConnection = Box<dyn OtpConnection + Send>;

/// Bridges an arbitrary Python OtpConnection to the Rust OtpConnection trait.
struct PythonOtpConnection {
    receive_fn: PyObject,
    send_fn: PyObject,
}

unsafe impl Send for PythonOtpConnection {}
unsafe impl Sync for PythonOtpConnection {}

impl PythonOtpConnection {
    fn from_py(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let receive_fn = connection.getattr("receive")?.unbind();
        let send_fn = connection.getattr("send")?.unbind();
        Ok(Self {
            receive_fn,
            send_fn,
        })
    }
}

impl yubikit::core::Connection for PythonOtpConnection {
    type Error = OtpError;

    fn close(&mut self) {}
}

impl OtpConnection for PythonOtpConnection {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError> {
        Python::with_gil(|py| {
            let result = self
                .receive_fn
                .call0(py)
                .map_err(|e| OtpError::BadResponse(e.to_string()))?;
            let bytes: Vec<u8> = result
                .extract(py)
                .map_err(|e| OtpError::BadResponse(e.to_string()))?;
            Ok(bytes)
        })
    }

    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        Python::with_gil(|py| {
            let py_bytes = PyBytes::new(py, data);
            self.send_fn
                .call1(py, (py_bytes,))
                .map_err(|e| OtpError::BadResponse(e.to_string()))?;
            Ok(())
        })
    }
}

/// Extract a `BoxedOtpConnection` from a Python connection argument.
///
/// **Fast path**: if `obj` is a native `OtpConnection` pyclass, take the inner
/// `HidOtpConnection` directly.
///
/// **Slow path**: wrap the Python object in a `PythonOtpConnection` bridge.
fn extract_otp_connection(obj: &Bound<'_, PyAny>) -> PyResult<BoxedOtpConnection> {
    if let Ok(hid_conn) = obj.downcast::<py_hid::OtpConnection>() {
        let conn = hid_conn.borrow_mut().take_inner()?;
        return Ok(Box::new(conn));
    }
    Ok(Box::new(PythonOtpConnection::from_py(obj)?))
}

#[pyclass(unsendable)]
pub struct OtpProtocol {
    inner: RustOtpProtocol<BoxedOtpConnection>,
    connection: PyObject,
}

#[pymethods]
impl OtpProtocol {
    #[new]
    fn new(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let otp_conn = extract_otp_connection(connection)?;
        let protocol = RustOtpProtocol::new(otp_conn)
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

        self.inner
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
        self.inner
            .read_status()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }
}
