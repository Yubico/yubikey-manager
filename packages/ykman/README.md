# YubiKey Manager CLI

YubiKey Manager provides the `ykman` command-line tool for configuring and
managing YubiKeys. It supports device configuration and the OATH, Yubico OTP,
PIV, FIDO, OpenPGP, YubiHSM Auth, and Security Domain applications.

The CLI is written in Rust and distributed through this Python package as a
native executable. **This Python package exists only to ease migration from
earlier Python-based versions of YubiKey Manager. Installing the Rust CLI
directly is the preferred approach.**

**This is an alpha release.** Commands and behavior may change before the
stable release.

## Installation

### Preferred: install the Rust CLI directly

Install the native CLI through Cargo:

```sh
cargo install ykman-cli --version 6.0.0-alpha.0 --locked
```

Building requires Rust 1.88 or later and the platform prerequisites listed in
the [`ykman-cli` crate documentation](https://crates.io/crates/ykman-cli).
The directly installed CLI does not require Python.

### Python package (migration only)

The migration package requires Python 3.11 or later:

```sh
python -m pip install --pre yubikey-manager
```

This installs only the CLI. The Python SDK is distributed separately as
[`yubikit`](https://pypi.org/project/yubikit/); neither package installs the
other. To use the Python API, install it explicitly:

```sh
python -m pip install --pre yubikit
```

When migrating from `yubikey-manager` 5.x, use a new virtual environment or
uninstall the old distribution before installing either new package. The old
distribution contains files now owned by the separate SDK, and uninstalling
it afterward can remove those shared files.

### Linux prerequisites

Install the system PC/SC client library (`libpcsclite.so.1`) and ensure `pcscd`
is running or socket-activated for smart card and NFC access. Linux wheels use
the system PC/SC library rather than bundling a potentially incompatible copy.

HID access may require your distribution's YubiKey udev rules and suitable
device permissions. Saving credentials requires a session D-Bus and a Secret
Service provider, such as GNOME Keyring.

## Usage

```sh
ykman --help
ykman list
ykman info
ykman oath --help
```

See the [YubiKey Manager CLI User Manual](https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html)
for command details and examples. Source code and migration documentation are
available in the [YubiKey Manager repository](https://github.com/Yubico/yubikey-manager).

## License

The Python package is licensed under BSD-2-Clause. The native Rust executable
is licensed under Apache-2.0. Bundled third-party license notices are available
with `ykman licenses`.
