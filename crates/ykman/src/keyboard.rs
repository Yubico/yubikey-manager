//! USB HID keyboard scancode tables for YubiKey OTP configuration.
//!
//! A YubiKey stores a static password as a sequence of USB HID keyboard scan
//! codes, each optionally OR-ed with the [`SHIFT`] bit. Which character a scan
//! code produces depends on the keyboard layout active on the host receiving
//! the keystrokes, so we ship a table mapping characters to scan codes for a
//! wide range of layouts.
//!
//! Layouts are organized as a [`KeyboardLayout`] family (a base layout plus
//! zero or more named [`Variant`]s). A specific mapping is selected with a
//! `layout` or `layout:variant` string, resolved into a [`LayoutSelection`].
//!
//! The tables are generated from the system's XKB data by
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
const MODHEX_NAME: &str = "modhex";

/// Embedded layout blob produced by `scripts/gen_keyboard_layouts.py`.
const LAYOUT_BLOB: &[u8] = include_bytes!("keyboard_layouts.bin");

/// A named variant of a [`KeyboardLayout`], with its own scancode mapping.
pub struct Variant {
    name: String,
    /// Fully-qualified `layout:variant` selector, e.g. `de:dvorak`.
    full_name: String,
    scancodes: HashMap<char, u8>,
}

impl Variant {
    /// The variant's short name, e.g. `dvorak`.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A keyboard layout family: a base layout plus zero or more [`Variant`]s.
///
/// Values live in a process-wide registry loaded from the embedded blob.
pub struct KeyboardLayout {
    name: String,
    description: String,
    scancodes: HashMap<char, u8>,
    variants: Vec<Variant>,
}

impl KeyboardLayout {
    /// The layout's canonical name, e.g. `de` or `modhex`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A human-readable description, e.g. `German`.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The layout's variants, if any.
    pub fn variants(&self) -> &[Variant] {
        &self.variants
    }

    /// All available layouts, modhex first.
    pub fn all() -> &'static [KeyboardLayout] {
        registry()
    }

    /// Whether this is the modhex pseudo-layout.
    fn is_modhex(&self) -> bool {
        self.name == MODHEX_NAME
    }
}

/// A resolved selection of a specific scancode mapping (base layout or variant).
///
/// This is a lightweight handle into the registry, cheap to copy and valid for
/// the whole program.
#[derive(Clone, Copy)]
pub struct LayoutSelection {
    name: &'static str,
    scancodes: &'static HashMap<char, u8>,
    is_modhex: bool,
}

impl LayoutSelection {
    /// The modhex pseudo-layout selection.
    pub fn modhex() -> LayoutSelection {
        resolve(MODHEX_NAME).expect("modhex layout is always present")
    }

    /// The fully-qualified name of the selection, e.g. `de` or `de:dvorak`.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The character-to-scancode map for this selection.
    pub fn scancodes(&self) -> &'static HashMap<char, u8> {
        self.scancodes
    }

    /// Whether this selection is the modhex pseudo-layout.
    pub fn is_modhex(&self) -> bool {
        self.is_modhex
    }
}

/// Returns the process-wide layout registry, parsing the blob on first use.
///
/// The modhex pseudo-layout is always first, followed by the generated layouts
/// in the order they appear in the blob (sorted by name at generation time).
fn registry() -> &'static Vec<KeyboardLayout> {
    static REG: OnceLock<Vec<KeyboardLayout>> = OnceLock::new();
    REG.get_or_init(|| {
        let mut layouts = Vec::new();
        layouts.push(KeyboardLayout {
            name: MODHEX_NAME.to_string(),
            description: "Modhex".to_string(),
            scancodes: modhex_scancodes(),
            variants: Vec::new(),
        });
        parse_blob(LAYOUT_BLOB, &mut layouts);
        layouts
    })
}

/// Cursor over the embedded blob.
struct Reader<'a> {
    data: &'a [u8],
    off: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> u8 {
        let v = self.data[self.off];
        self.off += 1;
        v
    }

    fn u16(&mut self) -> usize {
        let v = u16::from_le_bytes([self.data[self.off], self.data[self.off + 1]]);
        self.off += 2;
        v as usize
    }

    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes([
            self.data[self.off],
            self.data[self.off + 1],
            self.data[self.off + 2],
            self.data[self.off + 3],
        ]);
        self.off += 4;
        v
    }

    fn string(&mut self) -> String {
        let len = self.u8() as usize;
        let s = std::str::from_utf8(&self.data[self.off..self.off + len])
            .expect("invalid UTF-8 in layout blob")
            .to_string();
        self.off += len;
        s
    }

    fn scancodes(&mut self) -> HashMap<char, u8> {
        let entries = self.u16();
        let mut map = HashMap::with_capacity(entries);
        for _ in 0..entries {
            let cp = self.u32();
            let sc = self.u8();
            if let Some(c) = char::from_u32(cp) {
                map.insert(c, sc);
            }
        }
        map
    }
}

/// Parses the embedded layout blob, appending each layout family to `out`.
///
/// See `scripts/gen_keyboard_layouts.py` for the format specification.
fn parse_blob(data: &[u8], out: &mut Vec<KeyboardLayout>) {
    assert!(
        data.len() >= 6 && &data[0..4] == b"YKL2",
        "invalid keyboard layout blob header"
    );
    let mut r = Reader { data, off: 4 };
    let count = r.u16();
    for _ in 0..count {
        let name = r.string();
        let description = r.string();
        let scancodes = r.scancodes();
        let variant_count = r.u16();
        let mut variants = Vec::with_capacity(variant_count);
        for _ in 0..variant_count {
            let vname = r.string();
            let vscancodes = r.scancodes();
            variants.push(Variant {
                full_name: format!("{name}:{vname}"),
                name: vname,
                scancodes: vscancodes,
            });
        }
        out.push(KeyboardLayout {
            name,
            description,
            scancodes,
            variants,
        });
    }
}

/// Resolves a `layout` or `layout:variant` selector into a [`LayoutSelection`].
fn resolve(input: &str) -> Result<LayoutSelection, String> {
    let (layout_name, variant_name) = match input.split_once(':') {
        Some((l, v)) => (l, Some(v)),
        None => (input, None),
    };
    let layout = registry()
        .iter()
        .find(|l| l.name.eq_ignore_ascii_case(layout_name))
        .ok_or_else(|| format!("Unknown keyboard layout: {input}"))?;
    match variant_name {
        None => Ok(LayoutSelection {
            name: layout.name.as_str(),
            scancodes: &layout.scancodes,
            is_modhex: layout.is_modhex(),
        }),
        Some(variant) => {
            let variant = layout
                .variants
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(variant))
                .ok_or_else(|| {
                    format!(
                        "Unknown variant '{variant}' for keyboard layout '{}'",
                        layout.name
                    )
                })?;
            Ok(LayoutSelection {
                name: variant.full_name.as_str(),
                scancodes: &variant.scancodes,
                is_modhex: false,
            })
        }
    }
}

impl std::str::FromStr for LayoutSelection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        resolve(s)
    }
}

impl std::fmt::Display for LayoutSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

impl std::fmt::Debug for LayoutSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LayoutSelection").field(&self.name).finish()
    }
}

impl PartialEq for LayoutSelection {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for LayoutSelection {}

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
    use std::str::FromStr;

    #[test]
    fn blob_parses_and_has_common_layouts() {
        for name in ["us", "gb", "de", "fr", "it"] {
            let selection = LayoutSelection::from_str(name)
                .unwrap_or_else(|e| panic!("missing layout {name}: {e}"));
            assert!(!selection.scancodes().is_empty());
        }
    }

    #[test]
    fn layouts_have_descriptions_and_variants() {
        let de = KeyboardLayout::all()
            .iter()
            .find(|l| l.name() == "de")
            .expect("de layout present");
        assert_eq!(de.description(), "German");
        assert!(de.variants().iter().any(|v| v.name() == "dvorak"));
    }

    #[test]
    fn modhex_is_special() {
        let modhex = LayoutSelection::modhex();
        assert!(modhex.is_modhex());
        assert_eq!(modhex.name(), MODHEX_NAME);
        assert_eq!(modhex.scancodes().len(), MODHEX_CHARS.chars().count() * 2);
        assert_eq!(modhex.scancodes().get(&'c'), Some(&0x06));
        // Modhex is listed first and carries no variants.
        let first = &KeyboardLayout::all()[0];
        assert_eq!(first.name(), MODHEX_NAME);
        assert!(first.variants().is_empty());
    }

    #[test]
    fn resolves_variants() {
        assert_eq!(
            LayoutSelection::from_str("de:dvorak").unwrap().name(),
            "de:dvorak"
        );
        assert_eq!(
            LayoutSelection::from_str("fr:bepo").unwrap().name(),
            "fr:bepo"
        );
        assert_eq!(
            LayoutSelection::from_str("us:norman").unwrap().name(),
            "us:norman"
        );
        assert!(LayoutSelection::from_str("modhex").unwrap().is_modhex());
    }

    #[test]
    fn rejects_unknown_layout_and_variant() {
        assert!(LayoutSelection::from_str("nonesuch").is_err());
        let err = LayoutSelection::from_str("de:nope").unwrap_err();
        assert!(err.contains("Unknown variant"), "{err}");
    }

    #[test]
    fn us_layout_basics() {
        let us = LayoutSelection::from_str("us").unwrap();
        assert_eq!(us.scancodes().get(&'a'), Some(&0x04));
        assert_eq!(us.scancodes().get(&'A'), Some(&(0x04 | SHIFT)));
        assert_eq!(us.scancodes().get(&'1'), Some(&0x1E));
        assert_eq!(us.scancodes().get(&' '), Some(&0x2C));
    }
}
