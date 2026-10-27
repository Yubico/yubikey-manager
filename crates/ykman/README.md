# ykman

YubiKey Manager library — high-level device management and application logic
built on top of [`yubikit`](https://crates.io/crates/yubikit).

This crate provides shared functionality mainly used by other Yubico
applications, such as the [YubiKey Manager
CLI](https://crates.io/crates/ykman-cli).

## Getting started

Requires Rust 1.88 or later. Add the alpha explicitly to your `Cargo.toml`:

```toml
[dependencies]
ykman = "1.0.0-alpha.0"
```

## Features

- `hardware` *(default)* — Enables physical YubiKey transports (passed
  through to `yubikit/pcsc` and `yubikit/hid`).

## Native prerequisites

With `hardware` enabled, install the transport prerequisites described in the
[`yubikit` README](https://crates.io/crates/yubikit).

On Linux, the keyring backend also requires D-Bus development libraries:
`libdbus-1-dev` on Debian/Ubuntu or `dbus-devel` on Fedora. Both D-Bus and
libudev remain build dependencies with `hardware` disabled. Saving credentials
requires a running session D-Bus and a Secret Service provider, such as GNOME
Keyring.

## License

Apache-2.0; see the bundled `LICENSE` file.
