# ykman-cli

Command-line interface for configuring and managing YubiKeys.

## Commands

```
ykman list      List connected YubiKeys
ykman info      Show general information
ykman config    Enable or disable applications and settings
ykman oath      Manage the OATH application
ykman otp       Manage the YubiKey OTP application
ykman piv       Manage the PIV application
ykman fido      Manage the FIDO applications
ykman openpgp   Manage the OpenPGP application
ykman hsmauth   Manage the YubiHSM Auth application
ykman sd        Manage the Security Domain
ykman apdu      Send raw APDUs to the YubiKey
```

## Installation

### Prerequisites

Building requires Rust 1.88 or later and a native linker/toolchain.
On Debian/Ubuntu:

```sh
sudo apt install build-essential pkg-config libpcsclite-dev libudev-dev libdbus-1-dev pcscd
```

On Fedora:

```sh
sudo dnf install gcc pkgconf-pkg-config pcsc-lite-devel systemd-devel dbus-devel pcsc-lite
```

On macOS, install the Xcode Command Line Tools (`xcode-select --install`).
On Windows, use the Rust MSVC toolchain with Visual Studio Build Tools,
including the Desktop development with C++ workload and Windows SDK.
Neither platform requires separately installed PC/SC or HID development libraries.

On Linux, ensure `pcscd` is running or socket-activated for smart-card and NFC
commands. HID access requires appropriate udev permissions; install your
distribution's YubiKey udev rules and reconnect the device after changing them.
Saving credentials requires a session D-Bus and a Secret Service provider,
such as GNOME Keyring.

### Alpha release

The crates.io installation command selects the beta explicitly:

```sh
cargo install ykman-cli --version 6.0.0-beta.0 --locked
```

To install from a repository checkout instead:

```sh
cargo install --path crates/ykman-cli --locked
```

The installed executable is named `ykman`. Ensure Cargo's binary directory
(`$HOME/.cargo/bin` by default, or `%USERPROFILE%\.cargo\bin` on Windows) is on
`PATH`. It can conflict with an existing Python installation of `ykman`; check
which executable your shell resolves.

Third-party licence notices are bundled with the crate and can be displayed
with `ykman licenses`. Building does not require `cargo-about`.

Pre-built binaries are also available from the
[releases page](https://github.com/Yubico/yubikey-manager/releases).

## Documentation

See the [YubiKey Manager CLI User Manual](https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html)
for detailed usage information and examples.

## CCID access and GnuPG

If `ykman list` detects a YubiKey but a smart-card command reports that its
reader is unavailable, GnuPG's scdaemon may be claiming the USB CCID interface
directly. Add `disable-ccid` to `~/.gnupg/scdaemon.conf` so scdaemon uses PC/SC
instead, then restart scdaemon. If PC/SC still does not show the reader, reconnect
the YubiKey so the reader can be discovered again.

## License

Apache-2.0; see the bundled `LICENSE` file.
