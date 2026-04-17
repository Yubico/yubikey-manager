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

//! USB HID and PC/SC transport implementations.
//!
//! This module provides low-level transport drivers for communicating with
//! YubiKeys over different USB interfaces:
//!
//! - [`ctaphid`] — FIDO CTAP HID protocol (used by FIDO2/WebAuthn)
//! - [`otphid`] — OTP HID protocol (used by YubiOTP challenge-response)
//! - [`pcsc`] — PC/SC smart card reader access (used by CCID applications)
//!
//! Most users don't need to interact with transports directly — use
//! [`crate::device::list_devices`] to discover YubiKeys and open
//! connections through the device handle.

/// CTAP HID transport for FIDO2 security keys.
pub mod ctaphid;
/// OTP HID transport for YubiKey OTP protocol.
pub mod otphid;
/// PC/SC smart card transport.
pub mod pcsc;
#[cfg(windows)]
/// Windows SetupDI device enumeration.
pub mod setupdi;
