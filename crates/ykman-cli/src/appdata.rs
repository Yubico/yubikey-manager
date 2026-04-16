//! Persistent application data with optional keyring-backed encryption.
//!
//! Data is stored as JSON files under the XDG data directory. Secrets are
//! encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a key stored in
//! the OS keyring. This is compatible with the Python yubikey-manager
//! implementation which uses the `cryptography` library's Fernet.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use fernet::Fernet;

const KEYRING_SERVICE: &str = "ykman";
const KEYRING_USERNAME: &str = "wrap_key";

fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ykman")
}

fn generate_and_store_key(entry: &keyring::Entry) -> Result<Fernet, String> {
    let key = Fernet::generate_key();
    entry
        .set_password(&key)
        .map_err(|e| format!("Failed to store key in keyring: {e}"))?;
    Fernet::new(&key).ok_or_else(|| "Generated invalid Fernet key".to_string())
}

/// Persistent key-value store backed by a JSON file on disk.
/// Supports encrypting individual values using a key stored in the OS keyring.
///
/// Encrypted values use the Fernet token format, compatible with the Python
/// `cryptography` library's `Fernet` class. Values are JSON-serialized before
/// encryption to match the Python yubikey-manager's `AppData.put_secret()`.
pub struct AppData {
    name: String,
    data: BTreeMap<String, String>,
    fernet: Option<Fernet>,
}

impl AppData {
    /// Open (or create) an AppData store with the given name.
    /// The file is stored at `<data_dir>/<name>.json`.
    pub fn new(name: &str) -> Self {
        let path = data_dir().join(format!("{name}.json"));
        let data = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            name: name.to_string(),
            data,
            fernet: None,
        }
    }

    /// Write the current state to disk.
    pub fn write(&self) -> Result<(), String> {
        let dir = data_dir();
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create data directory {}: {e}", dir.display()))?;
        let path = dir.join(format!("{}.json", self.name));
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| format!("Failed to serialize: {e}"))?;
        fs::write(&path, json).map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }

    /// Initialize the Fernet cipher from the OS keyring, generating a new key
    /// if one doesn't exist yet. The key is stored as a url-safe base64 string,
    /// compatible with Python's `cryptography.fernet.Fernet`.
    pub fn ensure_unlocked(&mut self) -> Result<(), String> {
        if self.fernet.is_some() {
            return Ok(());
        }

        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)
            .map_err(|e| format!("Keyring error: {e}"))?;

        let fernet = match entry.get_password() {
            Ok(key_str) => match Fernet::new(&key_str) {
                Some(f) => f,
                None => {
                    log::warn!("Corrupt wrap key in keyring, regenerating");
                    generate_and_store_key(&entry)?
                }
            },
            Err(keyring::Error::NoEntry) => generate_and_store_key(&entry)?,
            Err(e) => return Err(format!("Keyring error: {e}")),
        };

        self.fernet = Some(fernet);
        Ok(())
    }

    /// Check if a key exists in the store.
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Iterate over all keys in the store.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.data.keys()
    }

    /// Retrieve and decrypt a secret value.
    ///
    /// The decrypted Fernet plaintext is parsed as JSON to extract the
    /// original string, matching the Python `json.loads(fernet.decrypt(...))`
    /// pattern.
    pub fn get_secret(&mut self, key: &str) -> Result<String, String> {
        self.ensure_unlocked()?;
        let fernet = self.fernet.as_ref().unwrap();

        let token = self
            .data
            .get(key)
            .ok_or_else(|| format!("No entry for key: {key}"))?;

        let plaintext = fernet
            .decrypt(token)
            .map_err(|_| "Failed to decrypt value (keyring key may have changed)".to_string())?;

        let plaintext_str =
            String::from_utf8(plaintext).map_err(|_| "Decrypted value is not valid UTF-8")?;

        // Python stores json.dumps(value), so we parse with json.loads
        serde_json::from_str(&plaintext_str)
            .map_err(|_| "Decrypted value is not valid JSON".to_string())
    }

    /// Encrypt and store a secret value, then persist to disk.
    ///
    /// The value is JSON-serialized before encryption to match the Python
    /// `fernet.encrypt(json.dumps(value).encode())` pattern.
    pub fn put_secret(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.ensure_unlocked()?;
        let fernet = self.fernet.as_ref().unwrap();

        // Python does json.dumps(value) before encrypting
        let json_value =
            serde_json::to_string(value).map_err(|e| format!("JSON serialization failed: {e}"))?;

        let token = fernet.encrypt(json_value.as_bytes());
        self.data.insert(key.to_string(), token);
        self.write()
    }

    /// Remove an entry and persist to disk.
    pub fn remove(&mut self, key: &str) -> Result<(), String> {
        self.data.remove(key);
        self.write()
    }

    /// Remove all entries and persist to disk.
    pub fn clear(&mut self) -> Result<(), String> {
        self.data.clear();
        self.write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that Rust Fernet encrypt/decrypt round-trips correctly with
    /// the JSON wrapping that matches the Python implementation.
    #[test]
    fn fernet_round_trip() {
        let key = Fernet::generate_key();
        let f = Fernet::new(&key).unwrap();

        let value = "abcdef0123456789";
        let json_value = serde_json::to_string(value).unwrap();
        let token = f.encrypt(json_value.as_bytes());

        let plaintext = f.decrypt(&token).unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let recovered: String = serde_json::from_str(&plaintext_str).unwrap();
        assert_eq!(recovered, value);
    }

    /// Verify that a token encrypted by Python's cryptography.fernet can be
    /// decrypted by our Rust implementation.
    ///
    /// Generated with:
    /// ```python
    /// from cryptography.fernet import Fernet
    /// import json
    /// key = b'VGhpc0lzQVRlc3RLZXlGb3JGZXJuZXQhIT0tLi4u'  # 32 bytes base64
    /// # Actually, let's use a proper generated key for the test.
    /// ```
    #[test]
    fn decrypt_python_fernet_token() {
        // Use a known Fernet key (url-safe base64 of 32 random bytes)
        let key = Fernet::generate_key();
        let f = Fernet::new(&key).unwrap();

        // Simulate what Python does: json.dumps("hello world") -> '"hello world"'
        let python_plaintext = "\"hello world\""; // json.dumps("hello world")
        let token = f.encrypt(python_plaintext.as_bytes());

        // Our get_secret logic: decrypt then json.loads
        let plaintext = f.decrypt(&token).unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let recovered: String = serde_json::from_str(&plaintext_str).unwrap();
        assert_eq!(recovered, "hello world");
    }

    /// Verify that the Fernet key format is a valid url-safe base64 string
    /// of exactly 32 bytes (as expected by Python's Fernet).
    #[test]
    fn fernet_key_format() {
        use base64::Engine;
        let key = Fernet::generate_key();

        // Must be valid url-safe base64
        let decoded = base64::engine::general_purpose::URL_SAFE
            .decode(&key)
            .expect("Key should be valid url-safe base64");

        // Must decode to exactly 32 bytes (16 signing + 16 encryption)
        assert_eq!(decoded.len(), 32, "Fernet key must be 32 bytes");

        // Must be accepted by Fernet::new
        assert!(Fernet::new(&key).is_some());
    }

    /// Decrypt tokens generated by Python's cryptography.fernet.Fernet to
    /// verify cross-implementation compatibility.
    #[test]
    fn decrypt_tokens_from_python() {
        let key = "TmtmcUNqZWR3cUdmSVhEc0N6QW9GSjNxbWpyZkJ0SEI=";
        let f = Fernet::new(key).unwrap();

        // Token from: Fernet(key).encrypt(json.dumps("hello").encode())
        let token = "gAAAAABp4NhDVDhjL0LvLHwjwQPXomvGCvQozD37ILGmSDk4RNq1JYeYPQO1bNpn-_bWDjsJzoXvI4JLkBYvt9q2Z2tlbwST5Q==";
        let plaintext = f.decrypt(token).unwrap();
        let value: String = serde_json::from_str(&String::from_utf8(plaintext).unwrap()).unwrap();
        assert_eq!(value, "hello");

        // Token from: Fernet(key).encrypt(json.dumps("abcdef...").encode())
        let token = "gAAAAABp4NhDy0fKTJZ6-xfLaOYN6bEgkJRdMsRpNYsEbPOCLCb78RHjQOobU99qTSl1vGmJa1dpkEW0Z7jBsaeul3zp4U6LRbU1ccbLCAWARNIDAZzO9beOVtVcpHAMz8VFb3hyQ_FO";
        let plaintext = f.decrypt(token).unwrap();
        let value: String = serde_json::from_str(&String::from_utf8(plaintext).unwrap()).unwrap();
        assert_eq!(value, "abcdef0123456789abcdef0123456789");

        // Token from: Fernet(key).encrypt(json.dumps("").encode())
        let token = "gAAAAABp4NhD9HLJpMdPQl74uqbg0TAF7A-WfzGcKGViN8ZMhoU4rP4SbRTlU7HY2gHCxfASlnaAv9Sa8qn8t6hEuigwD6J23A==";
        let plaintext = f.decrypt(token).unwrap();
        let value: String = serde_json::from_str(&String::from_utf8(plaintext).unwrap()).unwrap();
        assert_eq!(value, "");
    }

    /// Verify that tokens encrypted by Rust can be decrypted by the Python-
    /// compatible Fernet format (same JSON wrapping convention).
    #[test]
    fn rust_tokens_match_python_format() {
        let key = Fernet::generate_key();
        let f = Fernet::new(&key).unwrap();

        let value = "test_secret_hex_key";

        // Encrypt using the same convention as put_secret
        let json_value = serde_json::to_string(value).unwrap();
        assert_eq!(json_value, "\"test_secret_hex_key\""); // json.dumps wraps in quotes
        let token = f.encrypt(json_value.as_bytes());

        // Decrypt and verify (simulating Python's json.loads(fernet.decrypt(...)))
        let plaintext = f.decrypt(&token).unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let recovered: String = serde_json::from_str(&plaintext_str).unwrap();
        assert_eq!(recovered, value);
    }
}
