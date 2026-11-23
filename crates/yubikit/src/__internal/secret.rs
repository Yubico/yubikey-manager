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

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue<T: Zeroize>(T);

impl<T: Zeroize> SecretValue<T> {
    /// Create a new `SecretValue` wrapping the given value.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Access the inner secret value.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Mutably access the inner secret value.
    #[allow(dead_code)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> fmt::Debug for SecretValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> fmt::Display for SecretValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Non-constant-time comparison. This is intentional — `PartialEq` is used only for
/// non-security-critical comparisons (e.g. checking if an access code matches for slot
/// configuration updates). Cryptographic comparisons use `subtle::ConstantTimeEq` directly.
impl<T: Zeroize + PartialEq> PartialEq for SecretValue<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Zeroize + Eq> Eq for SecretValue<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redacted() {
        let secret = SecretValue::new(vec![1, 2, 3]);
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn test_display_redacted() {
        let secret = SecretValue::new(vec![1, 2, 3]);
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn test_expose_secret() {
        let secret = SecretValue::new(vec![1, 2, 3]);
        assert_eq!(secret.expose_secret(), &vec![1, 2, 3]);
    }

    #[test]
    fn test_clone() {
        let secret = SecretValue::new(vec![7, 8, 9]);
        let cloned = secret.clone();
        assert_eq!(cloned.expose_secret(), secret.expose_secret());
    }
}
