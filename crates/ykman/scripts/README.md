# Keyboard layout table generation

`../src/keyboard.rs` maps characters to USB HID scan codes so a YubiKey can
emit static passwords. Those per-layout tables are generated from the system's
XKB data and embedded as `../src/keyboard_layouts.bin`.

## Regenerating

Requires `libxkbcommon` and the XKB layout database (`xkb-data` on Debian/Ubuntu):

```sh
sudo apt install libxkbcommon0 xkb-data
```

Then, from anywhere in the repo:

```sh
# Every layout advertised by the system's evdev rules:
crates/ykman/scripts/gen_keyboard_layouts.py

# A specific subset (layout or layout:variant):
crates/ykman/scripts/gen_keyboard_layouts.py us gb de fr:bepo us:norman

# List the layouts that would be generated, without writing the blob:
crates/ykman/scripts/gen_keyboard_layouts.py --list
```

For each layout the script compiles an XKB keymap (without touching the running
keyboard) and records the character produced by each YubiKey-emittable scan
code at the base and Shift levels. The YubiKey only has a Shift modifier for
static passwords, so AltGr-only characters are intentionally not represented.
Each layout also stores its human-readable description (e.g. `German`) and its
variants (e.g. `dvorak`, `neo`) grouped under it.

## Modhex

Modhex is **not** generated here. It is a YubiKey-specific, layout-invariant
encoding using a fixed 16-character subset, so it is defined directly in
`keyboard.rs`.

## Blob format

Little-endian:

```
magic    : b"YKL2"
count    : u16                      number of layout families
families : repeated `count` times
    name_len : u8
    name     : name_len UTF-8 bytes        e.g. "de"
    desc_len : u8
    desc     : desc_len UTF-8 bytes         e.g. "German"
    base     : scancode map                 the layout's default mapping
    variants : u16                          number of variants
        vname_len : u8
        vname     : vname_len UTF-8 bytes    e.g. "dvorak"
        map       : scancode map
scancode map:
    entries : u16
    entry   : u32 codepoint + u8 scancode   repeated `entries` times
```
