#!/usr/bin/env python3
"""Generate the YubiKey static-password keyboard layout table.

A YubiKey stores a static password as a sequence of USB HID keyboard scan
codes, each optionally OR-ed with a "shift" bit (0x80).  Which character a
given scan code produces depends on the keyboard layout active on the host
that receives the keystrokes, so ``ykman`` ships a table mapping characters to
scan codes for a range of layouts.

This script derives those mappings directly from the system's XKB data using
``libxkbcommon``.  For every requested layout it compiles a keymap (without
touching the running keyboard), then for each scan code the YubiKey can emit it
records the character produced at the base level and, separately, with Shift
held.  The result is written as a compact binary blob that ``keyboard.rs`` loads
at runtime with ``include_bytes!``.

This is a reproducible re-implementation of the idea behind
https://github.com/dholth/yubikey.git, which probed keycodes for many layouts
by mutating the live X11 keyboard.  Here we use ``libxkbcommon`` so no X server
is required and the running keyboard is never changed.

The 16 "modhex" scan codes are *not* generated here: modhex is a
YubiKey-specific, layout-invariant encoding handled directly in ``keyboard.rs``.

Usage::

    # Generate every layout advertised by the system's evdev rules:
    ./gen_keyboard_layouts.py

    # Restrict to specific layouts / variants (layout or layout:variant):
    ./gen_keyboard_layouts.py us gb de fr:bepo us:norman

    # List which layouts would be generated, without writing the blob:
    ./gen_keyboard_layouts.py --list

Requires ``libxkbcommon`` and the XKB layout database (``xkb-data``).
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Output blob, relative to this script (crates/ykman/scripts/).
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "src" / "keyboard_layouts.bin"

# XKB rules database describing all available layouts and their variants.
EVDEV_XML = "/usr/share/X11/xkb/rules/evdev.xml"

# Keyboard model to compile keymaps against.  pc105 exposes the ISO 102nd key
# (LSGT), which several European layouts rely on.
XKB_MODEL = "pc105"

SHIFT = 0x80

# Blob format:
#   magic   : b"YKL1"
#   count   : u16 little-endian (number of layouts)
#   layouts : repeated
#       name_len : u8
#       name     : name_len UTF-8 bytes  (e.g. "us" or "fr:bepo")
#       entries  : u16 little-endian
#       entry    : char (u32 LE) + scancode (u8)   -- repeated `entries` times
MAGIC = b"YKL1"

# Map each YubiKey-producible HID keyboard usage id to the XKB key name for its
# physical position.  These are exactly the scan codes referenced by
# keyboard.rs (minus the control/whitespace keys handled as constants below).
# The mapping is layout-independent: it identifies a physical key, and XKB tells
# us which character that key produces in each layout.
HID_TO_XKB = {
    # Letter block (positions, not the letters themselves).
    0x04: "AC01",
    0x05: "AB05",
    0x06: "AB03",
    0x07: "AC03",
    0x08: "AD03",
    0x09: "AC04",
    0x0A: "AC05",
    0x0B: "AC06",
    0x0C: "AD08",
    0x0D: "AC07",
    0x0E: "AC08",
    0x0F: "AC09",
    0x10: "AB07",
    0x11: "AB06",
    0x12: "AD09",
    0x13: "AD10",
    0x14: "AD01",
    0x15: "AD04",
    0x16: "AC02",
    0x17: "AD05",
    0x18: "AD07",
    0x19: "AB04",
    0x1A: "AD02",
    0x1B: "AB02",
    0x1C: "AD06",
    0x1D: "AB01",
    # Number row.
    0x1E: "AE01",
    0x1F: "AE02",
    0x20: "AE03",
    0x21: "AE04",
    0x22: "AE05",
    0x23: "AE06",
    0x24: "AE07",
    0x25: "AE08",
    0x26: "AE09",
    0x27: "AE10",
    # Symbol / punctuation keys.
    0x2D: "AE11",
    0x2E: "AE12",
    0x2F: "AD11",
    0x30: "AD12",
    0x31: "BKSL",
    0x33: "AC10",
    0x34: "AC11",
    0x35: "TLDE",
    0x36: "AB08",
    0x37: "AB09",
    0x38: "AB10",
    # ISO 102nd key (between Left Shift and Z on ISO keyboards).
    0x64: "LSGT",
}

# Layout-invariant keys, added verbatim to every layout.
CONSTANT_KEYS = {
    "\t": 0x2B,  # Tab
    "\n": 0x28,  # Enter / Return
    " ": 0x2C,  # Space
}


class RuleNames(ctypes.Structure):
    _fields_ = [
        ("rules", ctypes.c_char_p),
        ("model", ctypes.c_char_p),
        ("layout", ctypes.c_char_p),
        ("variant", ctypes.c_char_p),
        ("options", ctypes.c_char_p),
    ]


class Xkb:
    """Thin ctypes wrapper around the bits of libxkbcommon we need."""

    def __init__(self) -> None:
        lib_path = ctypes.util.find_library("xkbcommon") or "libxkbcommon.so.0"
        lib = ctypes.CDLL(lib_path)
        self._lib = lib

        lib.xkb_context_new.restype = ctypes.c_void_p
        lib.xkb_context_new.argtypes = [ctypes.c_int]
        lib.xkb_keymap_new_from_names.restype = ctypes.c_void_p
        lib.xkb_keymap_new_from_names.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(RuleNames),
            ctypes.c_int,
        ]
        lib.xkb_keymap_unref.argtypes = [ctypes.c_void_p]
        lib.xkb_keymap_key_by_name.restype = ctypes.c_uint32
        lib.xkb_keymap_key_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.xkb_keymap_mod_get_index.restype = ctypes.c_uint32
        lib.xkb_keymap_mod_get_index.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.xkb_state_new.restype = ctypes.c_void_p
        lib.xkb_state_new.argtypes = [ctypes.c_void_p]
        lib.xkb_state_unref.argtypes = [ctypes.c_void_p]
        lib.xkb_state_update_mask.argtypes = [ctypes.c_void_p] + [ctypes.c_uint32] * 6
        lib.xkb_state_key_get_utf32.restype = ctypes.c_uint32
        lib.xkb_state_key_get_utf32.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

        self._ctx = lib.xkb_context_new(0)
        if not self._ctx:
            raise RuntimeError("failed to create xkb context")

    def layout_map(self, layout: str, variant: str) -> dict[str, int] | None:
        """Return {char: scancode} for a layout, or None if it won't compile."""
        lib = self._lib
        names = RuleNames(
            b"evdev",
            XKB_MODEL.encode(),
            layout.encode(),
            variant.encode(),
            b"",
        )
        keymap = lib.xkb_keymap_new_from_names(self._ctx, ctypes.byref(names), 0)
        if not keymap:
            return None
        try:
            shift_idx = lib.xkb_keymap_mod_get_index(keymap, b"Shift")
            shift_mask = 0 if shift_idx == 0xFFFFFFFF else (1 << shift_idx)
            state = lib.xkb_state_new(keymap)
            if not state:
                return None
            try:
                result: dict[str, int] = {}
                for char, scancode in CONSTANT_KEYS.items():
                    result[char] = scancode
                for hid, key_name in HID_TO_XKB.items():
                    keycode = lib.xkb_keymap_key_by_name(keymap, key_name.encode())
                    if keycode == 0:
                        continue
                    # Base level (no modifiers).
                    lib.xkb_state_update_mask(state, 0, 0, 0, 0, 0, 0)
                    base = lib.xkb_state_key_get_utf32(state, keycode)
                    self._record(result, base, hid)
                    # Shifted level.
                    if shift_mask:
                        lib.xkb_state_update_mask(state, shift_mask, 0, 0, 0, 0, 0)
                        shifted = lib.xkb_state_key_get_utf32(state, keycode)
                        self._record(result, shifted, hid | SHIFT)
                return result
            finally:
                lib.xkb_state_unref(state)
        finally:
            lib.xkb_keymap_unref(keymap)

    @staticmethod
    def _record(result: dict[str, int], codepoint: int, scancode: int) -> None:
        # 0 means "no symbol" (also returned for dead keys). Skip control chars
        # and anything already provided by an earlier/lower scancode so the
        # mapping stays deterministic and first-wins.
        if codepoint == 0 or codepoint < 0x20 or codepoint == 0x7F:
            return
        char = chr(codepoint)
        result.setdefault(char, scancode)


def enumerate_layouts(xml_path: str) -> list[tuple[str, str]]:
    """Return (layout, variant) pairs from the evdev rules database."""
    # evdev.xml ships with the system's xkb-data package and is trusted input.
    tree = ET.parse(xml_path)  # noqa: S314
    pairs: list[tuple[str, str]] = []
    for layout in tree.findall(".//layout"):
        name_el = layout.find("./configItem/name")
        if name_el is None or not name_el.text:
            continue
        name = name_el.text
        pairs.append((name, ""))
        for variant in layout.findall("./variantList/variant/configItem/name"):
            if variant.text:
                pairs.append((name, variant.text))
    return pairs


def parse_selection(tokens: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for token in tokens:
        layout, _, variant = token.partition(":")
        pairs.append((layout, variant))
    return pairs


def layout_key(layout: str, variant: str) -> str:
    return f"{layout}:{variant}" if variant else layout


def build_blob(layouts: dict[str, dict[str, int]]) -> bytes:
    out = bytearray(MAGIC)
    out += struct.pack("<H", len(layouts))
    for name in sorted(layouts):
        mapping = layouts[name]
        name_bytes = name.encode("utf-8")
        out += struct.pack("<B", len(name_bytes))
        out += name_bytes
        out += struct.pack("<H", len(mapping))
        for char in sorted(mapping):
            out += struct.pack("<IB", ord(char), mapping[char])
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "layouts",
        nargs="*",
        help="Layouts to generate as 'layout' or 'layout:variant'. "
        "Defaults to every layout in the evdev rules database.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output blob path (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--rules",
        default=EVDEV_XML,
        help=f"Path to the evdev rules XML (default: {EVDEV_XML}).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the layouts that would be generated and exit.",
    )
    args = parser.parse_args()

    if args.layouts:
        selection = parse_selection(args.layouts)
    else:
        selection = enumerate_layouts(args.rules)

    if args.list:
        for layout, variant in selection:
            print(layout_key(layout, variant))
        return 0

    xkb = Xkb()
    layouts: dict[str, dict[str, int]] = {}
    skipped = 0
    for layout, variant in selection:
        mapping = xkb.layout_map(layout, variant)
        key = layout_key(layout, variant)
        # A useful layout must produce at least the ASCII letters; skip
        # non-Latin-only or unmappable layouts that yield nothing typable.
        if mapping is None or len(mapping) <= len(CONSTANT_KEYS):
            skipped += 1
            print(f"skip  {key}", file=sys.stderr)
            continue
        layouts[key] = mapping

    if not layouts:
        print("error: no layouts generated", file=sys.stderr)
        return 1

    blob = build_blob(layouts)
    args.output.write_bytes(blob)
    print(
        f"wrote {len(layouts)} layouts ({skipped} skipped) "
        f"= {len(blob)} bytes to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
