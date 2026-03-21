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

//! Bridge between Python SmartCardConnection and Rust SmartCardConnection trait.
//!
//! This module provides `PySmartCardConnection`, which implements the Rust
//! `SmartCardConnection` trait by calling back to a Python connection object's
//! `send_and_receive` method. This allows Rust sessions to work with any
//! Python connection type (PCSC, NFC, etc.) transparently.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit_rs::iso7816::{SmartCardConnection, SmartCardError, Transport};

/// A Rust `SmartCardConnection` backed by a Python connection object.
///
/// Calls the Python object's `send_and_receive(apdu)` method for each APDU,
/// and reads `transport` property to determine USB vs NFC.
pub struct PySmartCardConnection {
    /// The Python connection's `send_and_receive` bound method.
    send_fn: PyObject,
    transport: Transport,
}

impl PySmartCardConnection {
    /// Create from a Python SmartCardConnection object.
    ///
    /// Extracts the `send_and_receive` method and `transport` property.
    pub fn from_py(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let send_fn = connection.getattr("send_and_receive")?.unbind();

        // Read transport: Python TRANSPORT enum has string values "usb"/"nfc"
        let transport_str: String = connection
            .getattr("transport")?
            .getattr("value")?
            .extract()?;
        let transport = if transport_str == "nfc" {
            Transport::Nfc
        } else {
            Transport::Usb
        };

        Ok(Self { send_fn, transport })
    }
}

impl SmartCardConnection for PySmartCardConnection {
    fn send_and_receive(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        Python::with_gil(|py| {
            let apdu_bytes = PyBytes::new(py, apdu);
            let result = self
                .send_fn
                .call1(py, (apdu_bytes,))
                .map_err(|e| SmartCardError::Transport(Box::new(e)))?;

            let tuple = result
                .extract::<(Vec<u8>, u16)>(py)
                .map_err(|e| SmartCardError::Transport(Box::new(e)))?;

            Ok(tuple)
        })
    }

    fn transport(&self) -> Transport {
        self.transport
    }
}

/// Convert a `SmartCardError` to the appropriate Python exception.
///
/// Maps Rust error variants to the corresponding `yubikit` Python exceptions:
/// - `SmartCardError::Apdu` → `yubikit.core.smartcard.ApduError(data, sw)`
/// - `SmartCardError::NotSupported` → `yubikit.core.NotSupportedError`
/// - `SmartCardError::BadResponse` → `yubikit.core.BadResponseError`
/// - Others → `RuntimeError`
pub fn smartcard_err(e: SmartCardError) -> PyErr {
    use pyo3::exceptions::*;
    Python::with_gil(|py| match &e {
        SmartCardError::Apdu { data, sw } => {
            match py.import("yubikit.core.smartcard") {
                Ok(module) => match module.getattr("ApduError") {
                    Ok(cls) => {
                        let data_bytes = PyBytes::new(py, data);
                        match cls.call1((data_bytes, *sw)) {
                            Ok(exc) => PyErr::from_value(exc),
                            Err(_) => PyRuntimeError::new_err(e.to_string()),
                        }
                    }
                    Err(_) => PyRuntimeError::new_err(e.to_string()),
                },
                Err(_) => PyRuntimeError::new_err(e.to_string()),
            }
        }
        SmartCardError::NotSupported(msg) => {
            match py.import("yubikit.core") {
                Ok(module) => match module.getattr("NotSupportedError") {
                    Ok(cls) => match cls.call1((msg.clone(),)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyValueError::new_err(msg.clone()),
                    },
                    Err(_) => PyValueError::new_err(msg.clone()),
                },
                Err(_) => PyValueError::new_err(msg.clone()),
            }
        }
        SmartCardError::BadResponse(msg) => {
            match py.import("yubikit.core") {
                Ok(module) => match module.getattr("BadResponseError") {
                    Ok(cls) => match cls.call1((msg.clone(),)) {
                        Ok(exc) => PyErr::from_value(exc),
                        Err(_) => PyRuntimeError::new_err(msg.clone()),
                    },
                    Err(_) => PyRuntimeError::new_err(msg.clone()),
                },
                Err(_) => PyRuntimeError::new_err(msg.clone()),
            }
        }
        SmartCardError::InvalidPin(retries) => {
            PyValueError::new_err(format!("Invalid PIN, {} attempts remaining", retries))
        }
        SmartCardError::ApplicationNotAvailable => {
            PyRuntimeError::new_err("Application not available")
        }
        _ => PyRuntimeError::new_err(e.to_string()),
    })
}
