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
pub fn patch_version(version: Version) -> Version {
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

/// Transport type for a smart card connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    Usb,
    Nfc,
}
