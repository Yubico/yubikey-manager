//! Persistent application data with optional keyring-backed encryption.
//!
//! Data is stored as JSON files under the XDG data directory. Secrets are
//! encrypted with AES-256-GCM using a key stored in the OS keyring.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};

const KEYRING_SERVICE: &str = "ykman";
const KEYRING_USERNAME: &str = "wrap_key";

fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ykman")
}

fn generate_and_store_key(entry: &keyring::Entry) -> Result<Vec<u8>, String> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| format!("Failed to generate key: {e}"))?;
    entry
        .set_password(&hex::encode(key))
        .map_err(|e| format!("Failed to store key in keyring: {e}"))?;
    Ok(key.to_vec())
}

/// Persistent key-value store backed by a JSON file on disk.
/// Supports encrypting individual values using a key stored in the OS keyring.
pub struct AppData {
    name: String,
    data: BTreeMap<String, String>,
    cipher: Option<Aes256Gcm>,
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
            cipher: None,
        }
    }

    /// Write the current state to disk.
    fn write(&self) -> Result<(), String> {
        let dir = data_dir();
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create data directory {}: {e}", dir.display()))?;
        let path = dir.join(format!("{}.json", self.name));
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| format!("Failed to serialize: {e}"))?;
        fs::write(&path, json).map_err(|e| format!("Failed to write {}: {e}", path.display()))
    }

    /// Initialize the AES-256-GCM cipher from the OS keyring, generating a
    /// new key if one doesn't exist yet.
    fn ensure_unlocked(&mut self) -> Result<(), String> {
        if self.cipher.is_some() {
            return Ok(());
        }

        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)
            .map_err(|e| format!("Keyring error: {e}"))?;

        let key_bytes = match entry.get_password() {
            Ok(hex_key) => match hex::decode(&hex_key) {
                Ok(bytes) if bytes.len() == 32 => bytes,
                _ => {
                    log::warn!("Corrupt wrap key in keyring, regenerating");
                    generate_and_store_key(&entry)?
                }
            },
            Err(keyring::Error::NoEntry) => generate_and_store_key(&entry)?,
            Err(e) => return Err(format!("Keyring error: {e}")),
        };

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        self.cipher = Some(Aes256Gcm::new(key));
        Ok(())
    }

    /// Check if a key exists in the store.
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Retrieve and decrypt a secret value.
    pub fn get_secret(&mut self, key: &str) -> Result<String, String> {
        self.ensure_unlocked()?;
        let cipher = self.cipher.as_ref().unwrap();

        let encrypted = self
            .data
            .get(key)
            .ok_or_else(|| format!("No entry for key: {key}"))?;

        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted)
            .map_err(|_| "Corrupt encrypted value".to_string())?;

        if raw.len() < 12 {
            return Err("Corrupt encrypted value (too short)".to_string());
        }
        let (nonce_bytes, ciphertext) = raw.split_at(12);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Failed to decrypt value (keyring key may have changed)".to_string())?;

        String::from_utf8(plaintext).map_err(|_| "Decrypted value is not valid UTF-8".to_string())
    }

    /// Encrypt and store a secret value, then persist to disk.
    pub fn put_secret(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.ensure_unlocked()?;
        let cipher = self.cipher.as_ref().unwrap();

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, value.as_bytes())
            .map_err(|e| format!("Encryption failed: {e}"))?;

        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);

        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob);
        self.data.insert(key.to_string(), encoded);
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
