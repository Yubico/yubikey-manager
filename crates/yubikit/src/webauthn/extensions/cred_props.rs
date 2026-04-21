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

//! Credential Properties extension (credProps).
//!
//! Client-side extension that reports whether a created credential is
//! discoverable (resident key). No CTAP2 extension is sent to the
//! authenticator — the result is computed by the client.

use serde::{Deserialize, Serialize};

/// Registration output for credProps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOutput {
    /// Whether the created credential is discoverable (resident).
    pub rk: bool,
}
