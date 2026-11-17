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

//! Fundamental types shared across the crate.

use std::fmt;
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// 3-digit firmware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u8, pub u8, pub u8);

impl Version {
    /// Parse a version from a byte slice (major, minor, patch).
    ///
    /// Missing bytes default to `0`. Only the first three bytes are used.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(
            data.first().copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
        )
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// Development devices report version 0.0.1.
const DEV_VERSION: Version = Version(0, 0, 1);

static OVERRIDE_VERSION: RwLock<Option<Version>> = RwLock::new(None);

/// Set the global version override for development devices.
///
/// When set, any session detecting version 0.0.1 will use this instead.
pub fn set_override_version(version: Version) {
    if let Ok(mut guard) = OVERRIDE_VERSION.write() {
        *guard = Some(version);
    }
}

/// If `version` is the development placeholder (0.0.1) and an override has been
/// set, return the override; otherwise return `version` unchanged.
pub(crate) fn patch_version(version: Version) -> Version {
    if version == DEV_VERSION {
        OVERRIDE_VERSION
            .read()
            .ok()
            .and_then(|guard| *guard)
            .unwrap_or(version)
    } else {
        version
    }
}

/// Check that a firmware version meets a minimum requirement.
/// Returns `Err` with a descriptive message if the version is too low.
pub fn require_version(version: Version, required: Version, feature: &str) -> Result<(), String> {
    if version < required {
        Err(format!(
            "{feature} requires version {required} or later (device has {version})"
        ))
    } else {
        Ok(())
    }
}

/// Decode big-endian bytes into an integer.
///
/// Only the last 8 bytes are used; longer inputs silently lose high-order bytes.
pub fn bytes2int(data: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &b in data {
        v = (v << 8) | b as u64;
    }
    v
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Common supertrait for all YubiKey connection types.
pub trait Connection {
    /// The transport-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Close the connection.
    fn close(&mut self);
}

/// Physical transport used for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    /// USB (wired) connection.
    Usb,
    /// NFC (contactless) connection.
    Nfc,
}

/// Encode an integer as big-endian bytes with no leading zeros.
pub fn int2bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let byte_len = ((64 - value.leading_zeros()) as usize).div_ceil(8);
    value.to_be_bytes()[8 - byte_len..].to_vec()
}
