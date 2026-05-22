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

//! Platform-specific transport implementations.
//!
//! This module provides low-level transport drivers for communicating with
//! YubiKeys over different interfaces:
//!
//! - [`hidapi`] — HID transport (CTAP HID for FIDO2, OTP HID for YubiOTP)
//! - [`pcsc`] — PC/SC smart card reader access (used by CCID applications)
//! - [`device`] — Local device enumeration and connection management
//!
//! Most users don't need to interact with these directly — use
//! [`device::list_devices`] to discover YubiKeys and open connections through
//! the device handle.

/// Local device enumeration and connection management.
pub mod device;
/// HID transport for FIDO (CTAP HID) and OTP (feature reports).
pub mod hidapi;
/// PC/SC smart card transport.
pub mod pcsc;
#[cfg(windows)]
/// Windows SetupDI device enumeration.
pub mod setupdi;
