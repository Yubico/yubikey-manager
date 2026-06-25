//! Integration tests for the ykman CLI.
//!
//! Hardware tests require a YubiKey to be connected and `YUBIKEY_SERIAL` to be
//! set to the device serial number. For devices without a serial number, use
//! `YUBIKEY_SERIAL=-1`. Tests that require hardware skip themselves when no
//! test device is configured.
//!
//! ```sh
//! YUBIKEY_SERIAL=12345678 cargo test -p ykman-cli --test cli_tests
//! YUBIKEY_SERIAL=-1 cargo test -p ykman-cli --test cli_tests
//! ```
//!
//! **WARNING**: Some tests are destructive and reset or reconfigure
//! applications. Only run against a test/development YubiKey.

#[macro_use]
#[path = "cli_tests/common.rs"]
mod common;

#[path = "cli_tests/apdu.rs"]
mod apdu;
#[path = "cli_tests/config.rs"]
mod config;
#[path = "cli_tests/fido.rs"]
mod fido;
#[path = "cli_tests/help.rs"]
mod help;
#[path = "cli_tests/hsmauth.rs"]
mod hsmauth;
#[path = "cli_tests/info.rs"]
mod info;
#[path = "cli_tests/oath.rs"]
mod oath;
#[path = "cli_tests/openpgp.rs"]
mod openpgp;
#[path = "cli_tests/otp.rs"]
mod otp;
#[path = "cli_tests/piv.rs"]
mod piv;
#[path = "cli_tests/securitydomain.rs"]
mod securitydomain;
