mod common;

use common::{DEFAULT_HSMAUTH_MANAGEMENT_KEY, hsmauth_reset, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_hsmauth_info() {
    hsmauth_reset();
    ykman_dev()
        .args(["hsmauth", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("version:").or(predicate::str::contains("Version:")));
}

#[test]
#[ignore]
#[serial]
fn test_hsmauth_reset() {
    ykman_dev()
        .args(["hsmauth", "reset", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_hsmauth_add_symmetric_and_list() {
    hsmauth_reset();

    // Add a symmetric credential with generated keys
    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "symmetric",
            "test-cred",
            "--generate",
            "-c",
            "12345679",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();

    // List credentials
    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-cred"));

    // Delete the credential
    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "delete",
            "test-cred",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
            "-f",
        ])
        .assert()
        .success();

    // Verify it is gone
    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-cred").not());

    hsmauth_reset();
}

#[test]
#[ignore]
#[serial]
fn test_hsmauth_add_derive_and_list() {
    hsmauth_reset();

    // Derive a credential from a password
    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "derive",
            "derive-cred",
            "p4ssw0rd",
            "-c",
            "12345679",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();

    // List credentials
    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("derive-cred"));

    hsmauth_reset();
}
