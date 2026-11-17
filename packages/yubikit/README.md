# YubiKit for Python

YubiKit is a Python SDK for communicating with and configuring YubiKey devices.
It provides APIs for OATH (TOTP/HOTP), PIV, OpenPGP, FIDO2/CTAP2, Yubico OTP,
YubiHSM Auth, and device management over USB and NFC.

The protocol implementations and device transports are written in Rust and
exposed through Python bindings.

**This is a beta release.** APIs may change before the stable release.

## Installation

Requires Python 3.11 or later:

```sh
python -m pip install --pre yubikit
```

The command-line tool is distributed separately as
[`yubikey-manager`](https://pypi.org/project/yubikey-manager/).

When migrating from `yubikey-manager` 5.x, use a new virtual environment or
uninstall the old distribution before installing YubiKit. The old distribution
contains Python files that now belong to this package, and uninstalling it
afterward can remove those shared files.

### Linux prerequisites

Install the system PC/SC client library (`libpcsclite.so.1`) and ensure `pcscd`
is running or socket-activated for smart card and NFC access. The client library
must match the host daemon; Linux wheels do not bundle it.

HID access may also require your distribution's YubiKey udev rules and suitable
device permissions.

## Getting started

List connected YubiKeys and read their device information:

```python
from yubikit.device import list_all_devices

for device in list_all_devices():
    print(device.name, device.info.serial, device.info.version)
```

Source code, examples, and migration documentation are available in the
[YubiKey Manager repository](https://github.com/Yubico/yubikey-manager).

## License

The Python package is licensed under BSD-2-Clause. The native Rust components
are licensed under Apache-2.0.
