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

## License

Apache-2.0
