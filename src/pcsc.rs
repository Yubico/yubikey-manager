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

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn pcsc_err(e: pcsc::Error) -> PyErr {
    PyOSError::new_err(format!("PC/SC error: {e}"))
}

/// List available PC/SC reader names.
#[pyfunction]
fn list_readers() -> PyResult<Vec<String>> {
    let ctx = Context::establish(Scope::User).map_err(pcsc_err)?;
    let len = ctx.list_readers_len().map_err(pcsc_err)?;
    let mut buf = vec![0u8; len];
    let names: Vec<String> = ctx
        .list_readers(&mut buf)
        .map_err(pcsc_err)?
        .map(|r| r.to_string_lossy().into_owned())
        .collect();
    Ok(names)
}

#[pyclass]
struct PcscConnection {
    card: Option<Card>,
    reader_name: String,
}

#[pymethods]
impl PcscConnection {
    /// Connect to a reader, optionally using exclusive mode.
    #[new]
    #[pyo3(signature = (reader_name, exclusive=true))]
    fn new(reader_name: &str, exclusive: bool) -> PyResult<Self> {
        let ctx = Context::establish(Scope::User).map_err(pcsc_err)?;
        let reader = std::ffi::CString::new(reader_name)
            .map_err(|_| PyValueError::new_err("Invalid reader name"))?;
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        let card = ctx
            .connect(&reader, share_mode, Protocols::ANY)
            .map_err(pcsc_err)?;
        Ok(Self {
            card: Some(card),
            reader_name: reader_name.to_owned(),
        })
    }

    /// Get the ATR (Answer-To-Reset) of the connected card.
    fn get_atr<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let card = self.card.as_ref().ok_or_else(|| {
            PyOSError::new_err("Connection is closed")
        })?;
        let atr = card.get_attribute_owned(pcsc::Attribute::AtrString).map_err(pcsc_err)?;
        Ok(PyBytes::new(py, &atr))
    }

    /// Transmit an APDU command and return the response bytes.
    fn transmit<'py>(&self, py: Python<'py>, apdu: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let card = self.card.as_ref().ok_or_else(|| {
            PyOSError::new_err("Connection is closed")
        })?;
        // Max response: 64KB + 2 status bytes
        let mut resp_buf = vec![0u8; 65538];
        let resp = card.transmit(apdu, &mut resp_buf).map_err(pcsc_err)?;
        Ok(PyBytes::new(py, resp))
    }

    /// Disconnect from the card.
    fn disconnect(&mut self) -> PyResult<()> {
        if let Some(card) = self.card.take() {
            card.disconnect(pcsc::Disposition::LeaveCard)
                .map_err(|(_, e)| pcsc_err(e))?;
        }
        Ok(())
    }

    /// Reconnect to the card (useful after exclusive access fails).
    #[pyo3(signature = (exclusive=true))]
    fn reconnect(&mut self, exclusive: bool) -> PyResult<()> {
        let card = self.card.as_mut().ok_or_else(|| {
            PyOSError::new_err("Connection is closed")
        })?;
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        card.reconnect(share_mode, Protocols::ANY, pcsc::Disposition::ResetCard)
            .map_err(pcsc_err)?;
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.disconnect()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "pcsc")?;
    sub.add_function(wrap_pyfunction!(list_readers, &sub)?)?;
    sub.add_class::<PcscConnection>()?;
    m.add_submodule(&sub)?;

    // Register in sys.modules so `from _ykman_native.pcsc import ...` works
    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_ykman_native.pcsc", &sub)?;

    Ok(())
}
