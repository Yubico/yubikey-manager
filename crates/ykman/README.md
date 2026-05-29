# ykman

YubiKey Manager library — high-level device management and application logic
built on top of [`yubikit`](https://crates.io/crates/yubikit).

This crate provides shared functionality mainly used by other Yubico
applications, such as the [YubiKey Manager
CLI](https://crates.io/crates/ykman-cli).

## Features

- `hardware` *(default)* — Enables physical YubiKey transports (passed
  through to `yubikit/hardware`).

## License

Apache-2.0
