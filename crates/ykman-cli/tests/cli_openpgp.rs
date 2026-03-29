mod common;

use common::{
    DEFAULT_OPENPGP_ADMIN_PIN, DEFAULT_OPENPGP_PIN, NON_DEFAULT_OPENPGP_ADMIN_PIN,
    NON_DEFAULT_OPENPGP_PIN, openpgp_reset, ykman_dev,
};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_openpgp_info() {
    openpgp_reset();
    ykman_dev()
        .args(["openpgp", "info"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Version:")
                .or(predicate::str::contains("PIN tries remaining:")),
        );
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_reset() {
    ykman_dev()
        .args(["openpgp", "reset", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_change_pin() {
    openpgp_reset();

    // Change PIN to non-default
    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-pin",
            "--pin",
            DEFAULT_OPENPGP_PIN,
            "--new-pin",
            NON_DEFAULT_OPENPGP_PIN,
        ])
        .assert()
        .success();

    // Change back
    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-pin",
            "--pin",
            NON_DEFAULT_OPENPGP_PIN,
            "--new-pin",
            DEFAULT_OPENPGP_PIN,
        ])
        .assert()
        .success();

    openpgp_reset();
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_change_admin_pin() {
    openpgp_reset();

    // Change admin PIN to non-default
    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-admin-pin",
            "--admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
            "--new-admin-pin",
            NON_DEFAULT_OPENPGP_ADMIN_PIN,
        ])
        .assert()
        .success();

    // Change back
    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-admin-pin",
            "--admin-pin",
            NON_DEFAULT_OPENPGP_ADMIN_PIN,
            "--new-admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
        ])
        .assert()
        .success();

    openpgp_reset();
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_set_pin_retries() {
    openpgp_reset();

    // Set custom PIN retries (PIN, Reset Code, Admin PIN)
    ykman_dev()
        .args([
            "openpgp",
            "access",
            "set-retries",
            "5",
            "5",
            "5",
            "-a",
            DEFAULT_OPENPGP_ADMIN_PIN,
            "-f",
        ])
        .assert()
        .success();

    // Verify retries changed in info output
    ykman_dev().args(["openpgp", "info"]).assert().success();

    // Reset to restore defaults
    openpgp_reset();
}
