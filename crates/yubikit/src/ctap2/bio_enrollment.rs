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

//! CTAP2 Bio Enrollment — manage fingerprint templates.

use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::core::Connection;

use super::pin_protocol::PinProtocol;
use super::session::Ctap2Session;
use super::types::{EnrollSampleResult, FingerprintSensorInfo, FingerprintTemplate};
use super::{Ctap2Error, build_args_map, ctap2_cmd};

/// Fingerprint bio-enrollment sub-command identifiers (§6.7).
mod bio_cmd {
    /// Begin a new fingerprint enrollment.
    pub const ENROLL_BEGIN: u8 = 0x01;
    /// Capture the next fingerprint sample during enrollment.
    pub const ENROLL_CAPTURE_NEXT: u8 = 0x02;
    /// Cancel an in-progress fingerprint enrollment.
    pub const ENROLL_CANCEL: u8 = 0x03;
    /// Enumerate all enrolled fingerprint templates.
    pub const ENUMERATE_ENROLLMENTS: u8 = 0x04;
    /// Set a friendly name for a fingerprint template.
    pub const SET_NAME: u8 = 0x05;
    /// Remove a fingerprint enrollment.
    pub const REMOVE_ENROLLMENT: u8 = 0x06;
    /// Query fingerprint sensor information.
    pub const GET_SENSOR_INFO: u8 = 0x07;
}

/// Response map key constants for internal parsing.
mod bio_result_key {
    /// Array of fingerprint template info entries.
    pub const TEMPLATE_INFOS: i64 = 0x07;
}

/// CTAP2 BioEnrollment operations (§6.7).
///
/// Provides fingerprint enrollment, enumeration, naming, and removal.
/// Owns a [`Ctap2Session`] and a [`PinProtocol`] for authenticated commands.
pub struct BioEnrollment<C: Connection> {
    session: Ctap2Session<C>,
    protocol: PinProtocol,
    pin_token: Zeroizing<Vec<u8>>,
    use_legacy: bool,
}

impl<C: Connection + 'static> BioEnrollment<C> {
    /// Whether the authenticator supports bio enrollment.
    ///
    /// Returns `true` if the standard `bioEnroll` option is present, or if the
    /// device supports the `userVerificationMgmtPreview` prototype.
    pub fn is_supported(info: &super::Info) -> bool {
        if info.options.contains_key("bioEnroll") {
            return true;
        }
        info.versions.contains(&"FIDO_2_1_PRE".to_string())
            && info.options.contains_key("userVerificationMgmtPreview")
    }

    /// Create a new `BioEnrollment` from a `Ctap2Session` and a PIN token.
    ///
    /// The PIN token must have the `BIO_ENROLL` permission.
    /// On failure, returns the session alongside the error.
    #[allow(clippy::result_large_err)]
    pub fn new(
        session: Ctap2Session<C>,
        protocol: PinProtocol,
        pin_token: Vec<u8>,
    ) -> Result<Self, (Ctap2Error<C::Error>, Ctap2Session<C>)> {
        let info = &session.cached_info;
        if !Self::is_supported(info) {
            return Err((
                Ctap2Error::InvalidResponse("Authenticator does not support bioEnrollment".into()),
                session,
            ));
        }

        let has_bio = info.options.contains_key("bioEnroll");
        let use_legacy = !has_bio;

        Ok(Self {
            session,
            protocol,
            pin_token: Zeroizing::new(pin_token),
            use_legacy,
        })
    }

    /// Consume this `BioEnrollment`, returning the underlying `Ctap2Session`.
    pub fn into_session(self) -> Ctap2Session<C> {
        self.session
    }

    fn cmd_byte(&self) -> u8 {
        if self.use_legacy {
            ctap2_cmd::BIO_ENROLLMENT_PRE
        } else {
            ctap2_cmd::BIO_ENROLLMENT
        }
    }

    fn call(
        &mut self,
        modality: Option<u8>,
        sub_cmd: Option<u8>,
        sub_cmd_params: Option<&Value>,
        auth: bool,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, Ctap2Error<C::Error>> {
        let (protocol_ver, pin_uv_param) = if auth {
            let mut msg: Vec<u8> = Vec::new();
            if let Some(m) = modality {
                msg.push(m);
            }
            if let Some(sc) = sub_cmd {
                msg.push(sc);
            }
            if let Some(p) = sub_cmd_params {
                msg.extend_from_slice(&cbor::encode(p));
            }
            let param = self.protocol.authenticate(&self.pin_token, &msg);
            (
                Some(Value::Int(self.protocol.version() as i64)),
                Some(Value::Bytes(param)),
            )
        } else {
            (None, None)
        };

        let data = build_args_map(&[
            modality.map(|m| Value::Int(m as i64)),  // 0x01
            sub_cmd.map(|sc| Value::Int(sc as i64)), // 0x02
            sub_cmd_params.cloned(),                 // 0x03
            protocol_ver,                            // 0x04
            pin_uv_param,                            // 0x05
        ]);
        self.session
            .send_cbor(self.cmd_byte(), Some(&data), on_keepalive, cancel)
    }

    /// Get fingerprint sensor info (type and max samples).
    pub fn get_fingerprint_sensor_info(
        &mut self,
    ) -> Result<FingerprintSensorInfo, Ctap2Error<C::Error>> {
        let resp = self.call(
            Some(0x01),
            Some(bio_cmd::GET_SENSOR_INFO),
            None,
            false,
            None,
            None,
        )?;
        FingerprintSensorInfo::from_cbor(&resp)
            .ok_or_else(|| Ctap2Error::InvalidResponse("invalid fingerprint sensor info".into()))
    }

    /// Begin a new fingerprint enrollment.
    ///
    /// Returns the enrollment sample result containing template ID,
    /// last sample status, and remaining samples.
    pub fn enroll_begin(
        &mut self,
        timeout: Option<u32>,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<EnrollSampleResult, Ctap2Error<C::Error>> {
        let sub_params =
            timeout.map(|t| Value::Map(vec![(Value::Int(0x03), Value::Int(t as i64))]));
        let resp = self.call(
            Some(0x01),
            Some(bio_cmd::ENROLL_BEGIN),
            sub_params.as_ref(),
            true,
            on_keepalive,
            cancel,
        )?;
        EnrollSampleResult::from_cbor(&resp)
            .ok_or_else(|| Ctap2Error::InvalidResponse("invalid enroll result".into()))
    }

    /// Capture next fingerprint sample during enrollment.
    pub fn enroll_capture_next(
        &mut self,
        template_id: &[u8],
        timeout: Option<u32>,
        on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<EnrollSampleResult, Ctap2Error<C::Error>> {
        let mut sub_entries = vec![(Value::Int(0x01), Value::Bytes(template_id.to_vec()))];
        if let Some(t) = timeout {
            sub_entries.push((Value::Int(0x03), Value::Int(t as i64)));
        }
        let sub_params = Value::Map(sub_entries);
        let resp = self.call(
            Some(0x01),
            Some(bio_cmd::ENROLL_CAPTURE_NEXT),
            Some(&sub_params),
            true,
            on_keepalive,
            cancel,
        )?;
        EnrollSampleResult::from_cbor(&resp)
            .ok_or_else(|| Ctap2Error::InvalidResponse("invalid enroll result".into()))
    }

    /// Cancel an ongoing enrollment.
    pub fn enroll_cancel(&mut self) -> Result<(), Ctap2Error<C::Error>> {
        self.call(
            Some(0x01),
            Some(bio_cmd::ENROLL_CANCEL),
            None,
            false,
            None,
            None,
        )?;
        Ok(())
    }

    /// Enumerate all enrolled fingerprints.
    pub fn enumerate_enrollments(
        &mut self,
    ) -> Result<Vec<FingerprintTemplate>, Ctap2Error<C::Error>> {
        let resp = self.call(
            Some(0x01),
            Some(bio_cmd::ENUMERATE_ENROLLMENTS),
            None,
            true,
            None,
            None,
        )?;
        let infos = resp
            .map_get_int(bio_result_key::TEMPLATE_INFOS)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(FingerprintTemplate::from_cbor)
                    .collect()
            })
            .unwrap_or_default();
        Ok(infos)
    }

    /// Set a friendly name for a fingerprint template.
    pub fn set_name(&mut self, template_id: &[u8], name: &str) -> Result<(), Ctap2Error<C::Error>> {
        let sub_params = Value::Map(vec![
            (Value::Int(0x01), Value::Bytes(template_id.to_vec())),
            (Value::Int(0x02), Value::Text(name.to_string())),
        ]);
        self.call(
            Some(0x01),
            Some(bio_cmd::SET_NAME),
            Some(&sub_params),
            true,
            None,
            None,
        )?;
        Ok(())
    }

    /// Remove a fingerprint enrollment.
    pub fn remove_enrollment(&mut self, template_id: &[u8]) -> Result<(), Ctap2Error<C::Error>> {
        let sub_params = Value::Map(vec![(Value::Int(0x01), Value::Bytes(template_id.to_vec()))]);
        self.call(
            Some(0x01),
            Some(bio_cmd::REMOVE_ENROLLMENT),
            Some(&sub_params),
            true,
            None,
            None,
        )?;
        Ok(())
    }
}
