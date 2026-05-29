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

From crates.io:

```sh
cargo install ykman-cli
```

Pre-built binaries are also available from the
[releases page](https://github.com/Yubico/yubikey-manager/releases).

## Documentation

See the [YubiKey Manager CLI User Manual](https://docs.yubico.com/software/yubikey/tools/ykman/Using_the_ykman_CLI.html)
for detailed usage information and examples.

## License

Apache-2.0
