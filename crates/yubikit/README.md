# yubikit

Rust SDK for interacting with YubiKey devices.

**yubikit** provides a complete API for communicating with YubiKeys over USB
(CCID/SmartCard, FIDO HID, OTP HID) and NFC. It covers the full range of
YubiKey applications:

- **OATH** — TOTP/HOTP credential management
- **PIV** — Smart card certificates, key management, signing
- **OpenPGP** — PGP key operations
- **FIDO2/CTAP2** — WebAuthn credential creation and assertion
- **YubiOTP** — Yubico OTP configuration
- **HSM Auth** — YubiHSM authentication credentials
- **Management** — Device configuration, firmware info, interfaces

## Getting started

Requires Rust 1.88 or later. Add the beta explicitly to your `Cargo.toml`:

```toml
[dependencies]
yubikit = "1.0.0-beta.0"
```

Install the native prerequisites below before building with the default features.

```rust
use yubikit::platform::device::list_devices;
use yubikit::management::UsbInterface;
use yubikit::oath::OathSession;

// 1. Discover connected YubiKeys
let all = UsbInterface::CCID | UsbInterface::OTP | UsbInterface::FIDO;
let devices = list_devices(all).expect("enumeration failed");
let dev = devices.first().expect("no YubiKey found");

// 2. Open a SmartCard (CCID) connection
let conn = dev.open_smartcard().expect("connection failed");

// 3. Create an OATH session and list accounts
let mut session = OathSession::new(conn).expect("OATH init failed");
let creds = session.list_credentials().expect("list failed");
for cred in &creds {
    println!("{cred:?}");
}
```

## Features

The default feature set enables both physical-device transport backends:

- `pcsc` *(default)* — Enables PC/SC smart card transport for CCID over USB and
  NFC readers.
- `hid` *(default)* — Enables HID transport for FIDO and OTP over USB.

Disable default features for environments where only custom transports are
needed, or enable only the transport backend required by your application.

## Platform support

| Platform | Transport |
|----------|-----------|
| Linux | PC/SC (pcsclite), HID (hidraw) |
| macOS | PC/SC (CryptoTokenKit), HID |
| Windows | PC/SC (WinSCard), HID |

### Native prerequisites

On Debian/Ubuntu, install a C toolchain, `pkg-config`, and the development
libraries for the enabled transports:

```sh
sudo apt install build-essential pkg-config libpcsclite-dev libudev-dev pcscd
```

On Fedora:

```sh
sudo dnf install gcc pkgconf-pkg-config pcsc-lite-devel systemd-devel pcsc-lite
```

`pcsc` requires PC/SC development libraries; `hid` uses libudev on Linux.
At runtime, CCID and NFC access require `pcscd` to be running or socket-activated.
HID access requires suitable udev permissions. Install your distribution's
YubiKey udev rules and reconnect the device after changing the rules.

On macOS, install the Xcode Command Line Tools (`xcode-select --install`).
On Windows, use the Rust MSVC toolchain with Visual Studio Build Tools,
including the Desktop development with C++ workload and Windows SDK.
PC/SC and HID support use system libraries on both platforms.

With `default-features = false`, device discovery and platform transport
modules are unavailable; provide your own connection implementations instead.
On Linux, libudev remains a build dependency even with both transport features
disabled.

## License

Apache-2.0; see the bundled `LICENSE` file.
