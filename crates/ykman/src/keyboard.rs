//! USB HID keyboard scancode tables for YubiKey OTP configuration.
//!
//! A YubiKey stores a static password as a sequence of USB HID keyboard scan
//! codes, each optionally OR-ed with the [`SHIFT`] bit. Which character a scan
//! code produces depends on the keyboard layout active on the host receiving
//! the keystrokes, so we ship a table mapping characters to scan codes for a
//! wide range of layouts.
//!
//! The layout tables are generated from the system's XKB data by
//! `scripts/gen_keyboard_layouts.py` and embedded as a compact binary blob
//! (`keyboard_layouts.bin`) that is parsed on first use. The blob does *not*
//! contain modhex: modhex is a YubiKey-specific, layout-invariant encoding
//! using a fixed subset of characters, so it is defined directly in code.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Modifier flag indicating the Shift key is held.
pub const SHIFT: u8 = 0x80;

/// The 16 characters used in modhex encoding.
pub const MODHEX_CHARS: &str = "cbdefghijklnrtuv";

/// Canonical name of the modhex pseudo-layout.
const MODHEX_NAME: &str = "MODHEX";

/// Embedded layout blob produced by `scripts/gen_keyboard_layouts.py`.
const LAYOUT_BLOB: &[u8] = include_bytes!("keyboard_layouts.bin");

/// Backing data for a single keyboard layout.
struct LayoutData {
    name: String,
    scancodes: HashMap<char, u8>,
}

/// A keyboard layout mapping characters to YubiKey scan codes.
///
/// Values are lightweight handles into a process-wide registry loaded from the
/// embedded layout blob, so they are cheap to copy and live for the whole
/// program.
#[derive(Clone, Copy)]
pub struct KeyboardLayout {
    data: &'static LayoutData,
}

/// Returns the process-wide layout registry, parsing the blob on first use.
///
/// The modhex pseudo-layout is always first, followed by the generated layouts
/// in the order they appear in the blob (sorted by name at generation time).
fn registry() -> &'static Vec<LayoutData> {
    static REG: OnceLock<Vec<LayoutData>> = OnceLock::new();
    REG.get_or_init(|| {
        let mut layouts = Vec::new();
        layouts.push(LayoutData {
            name: MODHEX_NAME.to_string(),
            scancodes: modhex_scancodes(),
        });
        parse_blob(LAYOUT_BLOB, &mut layouts);
        layouts
    })
}

/// Parses the embedded layout blob, appending each layout to `out`.
///
/// Format (little-endian):
///   magic `b"YKL1"`, `u16` layout count, then per layout: `u8` name length,
///   name (UTF-8), `u16` entry count, then entries of `u32` codepoint + `u8`
///   scancode.
fn parse_blob(data: &[u8], out: &mut Vec<LayoutData>) {
    assert!(
        data.len() >= 6 && &data[0..4] == b"YKL1",
        "invalid keyboard layout blob header"
    );
    let count = u16::from_le_bytes([data[4], data[5]]) as usize;
    let mut off = 6;
    for _ in 0..count {
        let name_len = data[off] as usize;
        off += 1;
        let name = std::str::from_utf8(&data[off..off + name_len])
            .expect("invalid UTF-8 in layout name")
            .to_string();
        off += name_len;
        let entries = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let mut scancodes = HashMap::with_capacity(entries);
        for _ in 0..entries {
            let cp = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            let sc = data[off + 4];
            off += 5;
            if let Some(c) = char::from_u32(cp) {
                scancodes.insert(c, sc);
            }
        }
        out.push(LayoutData { name, scancodes });
    }
}

/// Resolves user-facing layout aliases to the names used in the blob.
///
/// Keeps the historical short names working now that layouts follow XKB naming
/// (e.g. `UK` is XKB `gb`, `BEPO` is the `fr:bepo` variant).
fn resolve_alias(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "modhex" => MODHEX_NAME.to_string(),
        "uk" => "gb".to_string(),
        "bepo" => "fr:bepo".to_string(),
        "norman" => "us:norman".to_string(),
        other => other.to_string(),
    }
}

impl KeyboardLayout {
    /// The modhex pseudo-layout.
    pub fn modhex() -> KeyboardLayout {
        KeyboardLayout {
            data: &registry()[0],
        }
    }

    /// All available layouts, modhex first.
    pub fn all() -> Vec<KeyboardLayout> {
        registry()
            .iter()
            .map(|data| KeyboardLayout { data })
            .collect()
    }

    /// Looks up a layout by name (case-insensitive), honoring aliases.
    pub fn from_name(name: &str) -> Option<KeyboardLayout> {
        let target = resolve_alias(name);
        registry()
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(&target))
            .map(|data| KeyboardLayout { data })
    }

    /// The layout's canonical name.
    pub fn name(&self) -> &'static str {
        self.data.name.as_str()
    }

    /// The character-to-scancode map for this layout.
    pub fn scancodes(&self) -> &'static HashMap<char, u8> {
        &self.data.scancodes
    }

    /// Whether this is the modhex pseudo-layout.
    pub fn is_modhex(&self) -> bool {
        self.data.name == MODHEX_NAME
    }
}

impl std::str::FromStr for KeyboardLayout {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyboardLayout::from_name(s).ok_or_else(|| format!("Unknown keyboard layout: {s}"))
    }
}

impl std::fmt::Display for KeyboardLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::fmt::Debug for KeyboardLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("KeyboardLayout").field(&self.name()).finish()
    }
}

impl PartialEq for KeyboardLayout {
    fn eq(&self, other: &Self) -> bool {
        self.data.name == other.data.name
    }
}

impl Eq for KeyboardLayout {}

/// The modhex scancode map, defined in code since modhex is not a real layout.
fn modhex_scancodes() -> HashMap<char, u8> {
    let mut m = HashMap::new();
    for c in MODHEX_CHARS.chars() {
        let idx = "abcdefghijklmnopqrstuvwxyz".find(c).unwrap();
        m.insert(c, 0x04 + idx as u8);
        m.insert(c.to_ascii_uppercase(), (0x04 + idx as u8) | SHIFT);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_parses_and_has_common_layouts() {
        for name in ["us", "gb", "de", "fr", "it", "fr:bepo", "us:norman"] {
            let layout =
                KeyboardLayout::from_name(name).unwrap_or_else(|| panic!("missing layout {name}"));
            assert!(!layout.scancodes().is_empty());
        }
    }

    #[test]
    fn modhex_is_special() {
        let modhex = KeyboardLayout::modhex();
        assert!(modhex.is_modhex());
        assert_eq!(modhex.name(), MODHEX_NAME);
        // 16 modhex chars, each in lower and upper case.
        assert_eq!(modhex.scancodes().len(), MODHEX_CHARS.chars().count() * 2);
        assert_eq!(modhex.scancodes().get(&'c'), Some(&0x06));
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!(KeyboardLayout::from_name("uk").unwrap().name(), "gb");
        assert_eq!(KeyboardLayout::from_name("BEPO").unwrap().name(), "fr:bepo");
        assert_eq!(
            KeyboardLayout::from_name("norman").unwrap().name(),
            "us:norman"
        );
        assert!(KeyboardLayout::from_name("modhex").unwrap().is_modhex());
    }

    #[test]
    fn us_layout_basics() {
        let us = KeyboardLayout::from_name("us").unwrap();
        assert_eq!(us.scancodes().get(&'a'), Some(&0x04));
        assert_eq!(us.scancodes().get(&'A'), Some(&(0x04 | SHIFT)));
        assert_eq!(us.scancodes().get(&'1'), Some(&0x1E));
        assert_eq!(us.scancodes().get(&' '), Some(&0x2C));
    }
}
