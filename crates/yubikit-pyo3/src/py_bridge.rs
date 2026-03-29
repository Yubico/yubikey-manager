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
use yubikit::smartcard::{SmartCardConnection, SmartCardError, SmartCardProtocol, Transport};

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
                    Err(_) => PyValueError::new_err(msg.clone()),
                },
                Err(_) => PyValueError::new_err(msg.clone()),
            },
            Err(_) => PyValueError::new_err(msg.clone()),
        },
        SmartCardError::BadResponse(msg) => match py.import("yubikit.core") {
            Ok(module) => match module.getattr("BadResponseError") {
                Ok(cls) => match cls.call1((msg.clone(),)) {
                    Ok(exc) => PyErr::from_value(exc),
                    Err(_) => PyRuntimeError::new_err(msg.clone()),
                },
                Err(_) => PyRuntimeError::new_err(msg.clone()),
            },
            Err(_) => PyRuntimeError::new_err(msg.clone()),
        },
        SmartCardError::InvalidPin(retries) => {
            PyValueError::new_err(format!("Invalid PIN, {} attempts remaining", retries))
        }
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
        Some(sk) => Ok(yubikit::scp::ScpKeyParams::Scp11ac {
            kid,
            kvn,
            pk_sd_ecka: pk_bytes,
            sk_oce_ecka: sk,
            certificates: cert_ders,
            oce_ref,
        }),
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
