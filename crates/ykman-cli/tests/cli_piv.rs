mod common;

use common::{
    DEFAULT_MANAGEMENT_KEY, DEFAULT_PIN, DEFAULT_PUK, NON_DEFAULT_MANAGEMENT_KEY, NON_DEFAULT_PIN,
    NON_DEFAULT_PUK, piv_reset, ykman_dev,
};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_piv_info() {
    piv_reset();
    ykman_dev().args(["piv", "info"]).assert().success().stdout(
        predicate::str::contains("PIV version:")
            .or(predicate::str::contains("PIN tries remaining:")),
    );
}

#[test]
#[ignore]
#[serial]
fn test_piv_reset() {
    ykman_dev().args(["piv", "reset", "-f"]).assert().success();
}

#[test]
#[ignore]
#[serial]
fn test_piv_change_pin() {
    piv_reset();

    // Change PIN from default to non-default
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-pin",
            "--pin",
            DEFAULT_PIN,
            "--new-pin",
            NON_DEFAULT_PIN,
        ])
        .assert()
        .success();

    // Change back
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-pin",
            "--pin",
            NON_DEFAULT_PIN,
            "--new-pin",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_change_puk() {
    piv_reset();

    // Change PUK from default to non-default
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-puk",
            "--puk",
            DEFAULT_PUK,
            "--new-puk",
            NON_DEFAULT_PUK,
        ])
        .assert()
        .success();

    // Change back
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-puk",
            "--puk",
            NON_DEFAULT_PUK,
            "--new-puk",
            DEFAULT_PUK,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_change_management_key() {
    piv_reset();

    // Change management key
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-management-key",
            "--management-key",
            DEFAULT_MANAGEMENT_KEY,
            "--new-management-key",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-f",
        ])
        .assert()
        .success();

    // Change back
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-management-key",
            "--management-key",
            NON_DEFAULT_MANAGEMENT_KEY,
            "--new-management-key",
            DEFAULT_MANAGEMENT_KEY,
            "-f",
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_generate_self_signed() {
    piv_reset();

    // Generate key in slot 9a, output public key to stdout
    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    // Generate self-signed certificate for that key
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=test",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    // Verify certificate appears in info
    ykman_dev()
        .args(["piv", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("9A"));

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_export_certificate() {
    piv_reset();

    // Generate key
    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    // Generate self-signed cert
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=export-test",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    // Export certificate to stdout
    ykman_dev()
        .args(["piv", "certificates", "export", "9a", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN CERTIFICATE"));

    piv_reset();
}
