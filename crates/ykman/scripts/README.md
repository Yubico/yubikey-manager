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

## Modhex

Modhex is **not** generated here. It is a YubiKey-specific, layout-invariant
encoding using a fixed 16-character subset, so it is defined directly in
`keyboard.rs`.

## Blob format

Little-endian:

```
magic   : b"YKL1"
count   : u16                      number of layouts
layouts : repeated `count` times
    name_len : u8
    name     : name_len UTF-8 bytes   e.g. "us" or "fr:bepo"
    entries  : u16
    entry    : u32 codepoint + u8 scancode   repeated `entries` times
```
