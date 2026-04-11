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

//! Bridge between Python connection types and Rust connection traits.
//!
//! This module provides extraction functions that convert Python connection
//! objects into their Rust trait counterparts:
//!
//! - [`extract_smartcard_connection`]: `SmartCardConnection` from Python
//! - [`extract_fido_connection`]: `FidoConnection` from Python
//!
//! Each supports a **fast path** (unwrapping a native pyclass) and a
//! **slow path** (bridging an arbitrary Python object via the GIL).

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use yubikit::core::Transport;
use yubikit::fido::FidoConnection as FidoConnectionTrait;
use yubikit::smartcard::{SmartCardConnection, SmartCardError, SmartCardProtocol};
use yubikit::transport::ctaphid::{CtapHidCapability, FidoError, HidFidoConnection};
use yubikit::transport::pcsc::PcscSmartCardConnection;

use crate::py_pcsc::PcscConnection;

// ---------------------------------------------------------------------------
// SmartCard connection enum
// ---------------------------------------------------------------------------

/// Enum over the two concrete SmartCard connection types used in the PyO3 layer.
///
/// Replaces `Box<dyn SmartCardConnection>` to allow type-safe restoration
/// without downcasting when a session is closed.
pub enum PySmartCardConn {
    Native(PcscSmartCardConnection),
    Bridge(PythonSmartCardConnection),
}

impl yubikit::core::Connection for PySmartCardConn {
    type Error = SmartCardError;
    fn close(&mut self) {
        match self {
            Self::Native(c) => c.close(),
            Self::Bridge(c) => c.close(),
        }
    }
}

impl SmartCardConnection for PySmartCardConn {
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        match self {
            Self::Native(c) => c.send_and_receive(apdu),
            Self::Bridge(c) => c.send_and_receive(apdu),
        }
    }
    fn transport(&self) -> Transport {
        match self {
            Self::Native(c) => c.transport(),
            Self::Bridge(c) => c.transport(),
        }
    }
}

/// Type alias used as the generic parameter for sessions in the PyO3 layer.
pub type BoxedSmartCardConnection = PySmartCardConn;

/// A Rust `SmartCardConnection` backed by a Python connection object.
///
/// Calls the Python object's `send_and_receive(apdu)` method for each APDU,
/// and reads `transport` property to determine USB vs NFC. Used as the
/// slow-path bridge when the connection is implemented in Python rather than
/// being a native Rust connection.
pub struct PythonSmartCardConnection {
    /// The Python connection's `send_and_receive` bound method.
    send_fn: PyObject,
    transport: Transport,
}

/// `Py<PyAny>` / `PyObject` is Send+Sync by design in pyo3 ≥0.21 — it's a
/// GIL-independent handle. We only touch the Python object while holding the GIL.
unsafe impl Send for PythonSmartCardConnection {}
unsafe impl Sync for PythonSmartCardConnection {}

impl PythonSmartCardConnection {
    fn from_py(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
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

impl yubikit::core::Connection for PythonSmartCardConnection {
    type Error = SmartCardError;

    fn close(&mut self) {}
}

impl SmartCardConnection for PythonSmartCardConnection {
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
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

/// Extract a `BoxedSmartCardConnection` from a Python connection argument.
///
/// **Fast path**: if `obj` is a native `PcscConnection`, take the inner
/// `PcscSmartCardConnection` directly (no Python call overhead per APDU).
///
/// **Slow path**: wrap the Python object in a `PythonSmartCardConnection`
/// bridge that calls `send_and_receive()` via the GIL.
pub fn extract_smartcard_connection(obj: &Bound<'_, PyAny>) -> PyResult<BoxedSmartCardConnection> {
    // Fast path: native PcscConnection
    if let Ok(pcsc) = obj.downcast::<PcscConnection>() {
        let conn = pcsc.borrow_mut().take_inner()?;
        return Ok(PySmartCardConn::Native(conn));
    }

    // Slow path: arbitrary Python connection
    Ok(PySmartCardConn::Bridge(PythonSmartCardConnection::from_py(
        obj,
    )?))
}

// ---------------------------------------------------------------------------
// FidoConnection enum
// ---------------------------------------------------------------------------

/// Enum over the two concrete FIDO connection types used in the PyO3 layer.
pub enum PyFidoConn {
    Native(HidFidoConnection),
    Bridge(PythonFidoConnection),
}

impl yubikit::core::Connection for PyFidoConn {
    type Error = FidoError;
    fn close(&mut self) {
        match self {
            Self::Native(c) => c.close(),
            Self::Bridge(c) => c.close(),
        }
    }
}

impl FidoConnectionTrait for PyFidoConn {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        match self {
            Self::Native(c) => c.call(cmd, data, on_keepalive, cancel),
            Self::Bridge(c) => c.call(cmd, data, on_keepalive, cancel),
        }
    }
    fn device_version(&self) -> (u8, u8, u8) {
        match self {
            Self::Native(c) => c.device_version(),
            Self::Bridge(c) => c.device_version(),
        }
    }
    fn capabilities(&self) -> CtapHidCapability {
        match self {
            Self::Native(c) => c.capabilities(),
            Self::Bridge(c) => c.capabilities(),
        }
    }
}

/// Type alias used as the generic parameter for FIDO sessions in the PyO3 layer.
pub type BoxedFidoConnection = PyFidoConn;

/// A Rust `FidoConnection` backed by a Python connection object.
///
/// Calls the Python object's `call(cmd, data)` method for each CTAP HID
/// command. Reads `device_version` and `capabilities` properties once at
/// construction time. Used as the slow-path bridge when the connection is
/// implemented in Python rather than being a native Rust connection.
pub struct PythonFidoConnection {
    call_fn: PyObject,
    device_version: (u8, u8, u8),
    capabilities: CtapHidCapability,
}

unsafe impl Send for PythonFidoConnection {}

impl PythonFidoConnection {
    fn from_py(connection: &Bound<'_, PyAny>) -> PyResult<Self> {
        let call_fn = connection.getattr("call")?.unbind();
        let device_version: (u8, u8, u8) = connection.getattr("device_version")?.extract()?;
        let caps_raw: u8 = connection.getattr("capabilities")?.extract()?;

        Ok(Self {
            call_fn,
            device_version,
            capabilities: CtapHidCapability::from_raw(caps_raw),
        })
    }
}

impl yubikit::core::Connection for PythonFidoConnection {
    type Error = FidoError;
    fn close(&mut self) {}
}

impl FidoConnectionTrait for PythonFidoConnection {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        _on_keepalive: Option<&mut dyn FnMut(u8)>,
        _cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        Python::with_gil(|py| {
            let data_bytes = PyBytes::new(py, data);
            let result = self
                .call_fn
                .call1(py, (cmd, data_bytes))
                .map_err(|e| FidoError::Other(e.to_string()))?;
            result
                .extract::<Vec<u8>>(py)
                .map_err(|e| FidoError::Other(e.to_string()))
        })
    }

    fn device_version(&self) -> (u8, u8, u8) {
        self.device_version
    }

    fn capabilities(&self) -> CtapHidCapability {
        self.capabilities
    }
}

/// Extract a `BoxedFidoConnection` from a Python connection argument.
///
/// **Fast path**: if `obj` is a native `FidoConnection` pyclass, take the
/// inner `HidFidoConnection` directly (no Python call overhead per command).
///
/// **Slow path**: wrap the Python object in a `PythonFidoConnection` bridge
/// that calls `call(cmd, data)` via the GIL.
pub fn extract_fido_connection(obj: &Bound<'_, PyAny>) -> PyResult<BoxedFidoConnection> {
    // Fast path: native FidoConnection
    if let Ok(fido) = obj.downcast::<crate::py_hid::FidoConnection>() {
        let conn = fido.borrow_mut().take_inner()?;
        return Ok(PyFidoConn::Native(conn));
    }

    // Slow path: arbitrary Python connection
    Ok(PyFidoConn::Bridge(PythonFidoConnection::from_py(obj)?))
}

/// Restore a `BoxedSmartCardConnection` back to the Python connection wrapper.
///
/// **Native variant**: restore the `PcscSmartCardConnection` into the pyclass.
/// **Bridge variant**: just drop — the Python object was never modified.
pub fn restore_smartcard_connection(
    py_conn: &Bound<'_, PyAny>,
    conn: BoxedSmartCardConnection,
) -> PyResult<()> {
    match conn {
        PySmartCardConn::Native(inner) => {
            let pcsc = py_conn.downcast::<PcscConnection>().map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err(
                    "Native SmartCard connection but Python object is not PcscConnection",
                )
            })?;
            pcsc.borrow_mut().restore_inner(inner);
        }
        PySmartCardConn::Bridge(_) => {
            // Nothing to restore — the Python connection object is unchanged
        }
    }
    Ok(())
}

/// Restore a `BoxedFidoConnection` back to the Python connection wrapper.
///
/// **Native variant**: restore the `HidFidoConnection` into the pyclass.
/// **Bridge variant**: just drop.
pub fn restore_fido_connection(
    py_conn: &Bound<'_, PyAny>,
    conn: BoxedFidoConnection,
) -> PyResult<()> {
    match conn {
        PyFidoConn::Native(inner) => {
            let fido = py_conn
                .downcast::<crate::py_hid::FidoConnection>()
                .map_err(|_| {
                    pyo3::exceptions::PyRuntimeError::new_err(
                        "Native FIDO connection but Python object is not FidoConnection",
                    )
                })?;
            fido.borrow_mut().restore_inner(inner);
        }
        PyFidoConn::Bridge(_) => {
            // Nothing to restore
        }
    }
    Ok(())
}

/// Convert a `FidoError` to a Python exception.
#[expect(dead_code)]
pub fn fido_err(e: FidoError) -> PyErr {
    pyo3::exceptions::PyOSError::new_err(e.to_string())
}

/// Convert a `SmartCardError` to the appropriate Python exception.
///
/// Maps Rust error variants to the corresponding `yubikit` Python exceptions:
/// - `SmartCardError::Apdu` → `yubikit.core.smartcard.ApduError(data, sw)`
/// - `SmartCardError::NotSupported` → `yubikit.core.NotSupportedError`
/// - `SmartCardError::InvalidData` → `yubikit.core.BadResponseError`
/// - `SmartCardError::ApplicationNotAvailable` → `yubikit.core.ApplicationNotAvailableError`
/// - Others → `RuntimeError`
pub fn smartcard_err(e: SmartCardError) -> PyErr {
    use pyo3::exceptions::*;
    Python::with_gil(|py| match &e {
        SmartCardError::Apdu { data, sw } => match py.import("yubikit.core.smartcard") {
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
        },
        SmartCardError::NotSupported(msg) => match py.import("yubikit.core") {
            Ok(module) => match module.getattr("NotSupportedError") {
                Ok(cls) => match cls.call1((msg.clone(),)) {
                    Ok(exc) => PyErr::from_value(exc),
                    Err(_) => PyRuntimeError::new_err(msg.clone()),
                },
                Err(_) => PyRuntimeError::new_err(msg.clone()),
            },
            Err(_) => PyRuntimeError::new_err(msg.clone()),
        },
        SmartCardError::InvalidData(msg) => match py.import("yubikit.core") {
            Ok(module) => match module.getattr("BadResponseError") {
                Ok(cls) => match cls.call1((msg.clone(),)) {
                    Ok(exc) => PyErr::from_value(exc),
                    Err(_) => PyRuntimeError::new_err(msg.clone()),
                },
                Err(_) => PyRuntimeError::new_err(msg.clone()),
            },
            Err(_) => PyRuntimeError::new_err(msg.clone()),
        },
        SmartCardError::InvalidState(msg) => match py.import("yubikit.core") {
            Ok(module) => match module.getattr("BadResponseError") {
                Ok(cls) => match cls.call1((msg.clone(),)) {
                    Ok(exc) => PyErr::from_value(exc),
                    Err(_) => PyRuntimeError::new_err(msg.clone()),
                },
                Err(_) => PyRuntimeError::new_err(msg.clone()),
            },
            Err(_) => PyRuntimeError::new_err(msg.clone()),
        },
        SmartCardError::ApplicationNotAvailable => match py.import("yubikit.core") {
            Ok(module) => match module.getattr("ApplicationNotAvailableError") {
                Ok(cls) => match cls.call0() {
                    Ok(exc) => PyErr::from_value(exc),
                    Err(_) => PyRuntimeError::new_err("Application not available"),
                },
                Err(_) => PyRuntimeError::new_err("Application not available"),
            },
            Err(_) => PyRuntimeError::new_err("Application not available"),
        },
        _ => PyRuntimeError::new_err(e.to_string()),
    })
}

/// Initialize SCP on a `SmartCardProtocol` from Python `ScpKeyParams`.
///
/// Inspects the Python object's class name to determine whether to use SCP03
/// or SCP11, then extracts the necessary fields and calls the Rust init method.
pub fn scp_key_params_from_py(params: &Bound<'_, PyAny>) -> PyResult<yubikit::scp::ScpKeyParams> {
    let class_name = params.get_type().name()?.to_string();

    if class_name.contains("Scp03KeyParams") {
        scp03_key_params_from_py(params)
    } else if class_name.contains("Scp11KeyParams") {
        scp11_key_params_from_py(params)
    } else {
        Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unsupported SCP key params type: {class_name}"
        )))
    }
}

fn scp03_key_params_from_py(params: &Bound<'_, PyAny>) -> PyResult<yubikit::scp::ScpKeyParams> {
    let key_ref = params.getattr("ref")?;
    let kvn: u8 = key_ref.getattr("kvn")?.extract()?;
    let keys = params.getattr("keys")?;
    let key_enc: Vec<u8> = keys
        .getattr("key_enc")?
        .call_method0("__bytes__")?
        .extract()?;
    let key_mac: Vec<u8> = keys
        .getattr("key_mac")?
        .call_method0("__bytes__")?
        .extract()?;
    let key_dek_obj = keys.getattr("key_dek")?;
    let key_dek: Option<Vec<u8>> = if key_dek_obj.is_none() {
        None
    } else {
        Some(key_dek_obj.call_method0("__bytes__")?.extract()?)
    };

    let key_enc: [u8; 16] = key_enc
        .as_slice()
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_enc must be 16 bytes"))?;
    let key_mac: [u8; 16] = key_mac
        .as_slice()
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_mac must be 16 bytes"))?;
    let key_dek: Option<[u8; 16]> = key_dek
        .map(|v| {
            v.as_slice()
                .try_into()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("key_dek must be 16 bytes"))
        })
        .transpose()?;

    Ok(yubikit::scp::ScpKeyParams::Scp03 {
        kvn,
        key_enc,
        key_mac,
        key_dek,
    })
}

fn scp11_key_params_from_py(params: &Bound<'_, PyAny>) -> PyResult<yubikit::scp::ScpKeyParams> {
    let key_ref = params.getattr("ref")?;
    let kid: u8 = key_ref.getattr("kid")?.extract()?;
    let kvn: u8 = key_ref.getattr("kvn")?.extract()?;

    let pk = params.getattr("pk_sd_ecka")?;
    let serialization = pk
        .py()
        .import("cryptography.hazmat.primitives.serialization")?;
    let encoding_x962 = serialization.getattr("Encoding")?.getattr("X962")?;
    let format_uncompressed = serialization
        .getattr("PublicFormat")?
        .getattr("UncompressedPoint")?;
    let pk_bytes: Vec<u8> = pk
        .call_method1("public_bytes", (encoding_x962, format_uncompressed))?
        .extract()?;

    let sk_oce_obj = params.getattr("sk_oce_ecka")?;
    let sk_oce: Option<Vec<u8>> = if sk_oce_obj.is_none() {
        None
    } else {
        let numbers = sk_oce_obj.call_method0("private_numbers")?;
        let private_value = numbers.getattr("private_value")?;
        let bytes: Vec<u8> = private_value
            .call_method1("to_bytes", (32usize, "big"))?
            .extract()?;
        Some(bytes)
    };

    let certs_list = params.getattr("certificates")?;
    let certs_len: usize = certs_list.len()?;
    let encoding_der = serialization.getattr("Encoding")?.getattr("DER")?;
    let mut cert_ders: Vec<Vec<u8>> = Vec::with_capacity(certs_len);
    for i in 0..certs_len {
        let cert = certs_list.get_item(i)?;
        let der: Vec<u8> = cert
            .call_method1("public_bytes", (encoding_der.clone(),))?
            .extract()?;
        cert_ders.push(der);
    }

    let oce_ref_obj = params.getattr("oce_ref")?;
    let oce_ref: Option<(u8, u8)> = if oce_ref_obj.is_none() {
        None
    } else {
        let oce_kid: u8 = oce_ref_obj.getattr("kid")?.extract()?;
        let oce_kvn: u8 = oce_ref_obj.getattr("kvn")?.extract()?;
        Some((oce_kid, oce_kvn))
    };

    match sk_oce {
        Some(sk) => {
            let sk_arr: [u8; 32] = sk.as_slice().try_into().map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("sk_oce_ecka must be 32 bytes")
            })?;
            Ok(yubikit::scp::ScpKeyParams::Scp11ac {
                kid,
                kvn,
                pk_sd_ecka: pk_bytes,
                sk_oce_ecka: sk_arr,
                certificates: cert_ders,
                oce_ref,
            })
        }
        None => Ok(yubikit::scp::ScpKeyParams::Scp11b {
            kid,
            kvn,
            pk_sd_ecka: pk_bytes,
        }),
    }
}

pub fn init_scp_from_py<C: SmartCardConnection>(
    protocol: &mut SmartCardProtocol<C>,
    params: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let class_name = params.get_type().name()?.to_string();

    if class_name.contains("Scp03KeyParams") {
        init_scp03_from_py(protocol, params)
    } else if class_name.contains("Scp11KeyParams") {
        init_scp11_from_py(protocol, params)
    } else {
        Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unsupported SCP key params type: {class_name}"
        )))
    }
}

fn init_scp03_from_py<C: SmartCardConnection>(
    protocol: &mut SmartCardProtocol<C>,
    params: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let key_ref = params.getattr("ref")?;
    let kvn: u8 = key_ref.getattr("kvn")?.extract()?;
    let keys = params.getattr("keys")?;
    let key_enc: Vec<u8> = keys
        .getattr("key_enc")?
        .call_method0("__bytes__")?
        .extract()?;
    let key_mac: Vec<u8> = keys
        .getattr("key_mac")?
        .call_method0("__bytes__")?
        .extract()?;
    let key_dek_obj = keys.getattr("key_dek")?;
    let key_dek: Option<Vec<u8>> = if key_dek_obj.is_none() {
        None
    } else {
        Some(key_dek_obj.call_method0("__bytes__")?.extract()?)
    };

    protocol
        .init_scp03(kvn, &key_enc, &key_mac, key_dek.as_deref())
        .map_err(smartcard_err)?;
    Ok(())
}

fn init_scp11_from_py<C: SmartCardConnection>(
    protocol: &mut SmartCardProtocol<C>,
    params: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let key_ref = params.getattr("ref")?;
    let kid: u8 = key_ref.getattr("kid")?.extract()?;
    let kvn: u8 = key_ref.getattr("kvn")?.extract()?;

    // pk_sd_ecka: ec.EllipticCurvePublicKey → uncompressed point bytes
    let pk = params.getattr("pk_sd_ecka")?;
    let serialization = pk
        .py()
        .import("cryptography.hazmat.primitives.serialization")?;
    let encoding_x962 = serialization.getattr("Encoding")?.getattr("X962")?;
    let format_uncompressed = serialization
        .getattr("PublicFormat")?
        .getattr("UncompressedPoint")?;
    let pk_bytes: Vec<u8> = pk
        .call_method1("public_bytes", (encoding_x962, format_uncompressed))?
        .extract()?;

    // sk_oce_ecka: optional ec.EllipticCurvePrivateKey → raw scalar bytes
    let sk_oce_obj = params.getattr("sk_oce_ecka")?;
    let sk_oce: Option<Vec<u8>> = if sk_oce_obj.is_none() {
        None
    } else {
        let numbers = sk_oce_obj.call_method0("private_numbers")?;
        let private_value = numbers.getattr("private_value")?;
        let bytes: Vec<u8> = private_value
            .call_method1("to_bytes", (32usize, "big"))?
            .extract()?;
        Some(bytes)
    };

    // certificates: list[x509.Certificate] → Vec<DER bytes>
    let certs_list = params.getattr("certificates")?;
    let certs_len: usize = certs_list.len()?;
    let encoding_der = serialization.getattr("Encoding")?.getattr("DER")?;
    let mut cert_ders: Vec<Vec<u8>> = Vec::with_capacity(certs_len);
    for i in 0..certs_len {
        let cert = certs_list.get_item(i)?;
        let der: Vec<u8> = cert
            .call_method1("public_bytes", (encoding_der.clone(),))?
            .extract()?;
        cert_ders.push(der);
    }
    let cert_refs: Vec<&[u8]> = cert_ders.iter().map(|c| c.as_slice()).collect();

    // oce_ref: optional KeyRef → (kid, kvn)
    let oce_ref_obj = params.getattr("oce_ref")?;
    let oce_ref: Option<(u8, u8)> = if oce_ref_obj.is_none() {
        None
    } else {
        let oce_kid: u8 = oce_ref_obj.getattr("kid")?.extract()?;
        let oce_kvn: u8 = oce_ref_obj.getattr("kvn")?.extract()?;
        Some((oce_kid, oce_kvn))
    };

    protocol
        .init_scp11(kid, kvn, &pk_bytes, sk_oce.as_deref(), &cert_refs, oce_ref)
        .map_err(smartcard_err)?;
    Ok(())
}
