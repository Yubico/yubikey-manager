mod common;

use common::{OATH_PASSWORD, oath_reset, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_oath_info() {
    oath_reset();
    ykman_dev()
        .args(["oath", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("version:").or(predicate::str::contains("Version:")));
}

#[test]
#[ignore]
#[serial]
fn test_oath_reset() {
    ykman_dev().args(["oath", "reset", "-f"]).assert().success();
}

#[test]
#[ignore]
#[serial]
fn test_oath_add_and_list() {
    oath_reset();

    // Add a TOTP credential
    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "-f",
            "test-issuer:test-account",
            "abba",
        ])
        .assert()
        .success();

    // List and verify it appears
    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-issuer:test-account"));

    // Delete it
    ykman_dev()
        .args([
            "oath",
            "accounts",
            "delete",
            "test-issuer:test-account",
            "-f",
        ])
        .assert()
        .success();

    // Verify it is gone
    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-issuer:test-account").not());

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_add_totp_and_code() {
    oath_reset();

    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "-f",
            "totp-test",
            "abba",
        ])
        .assert()
        .success();

    // Get a code – should output digits
    ykman_dev()
        .args(["oath", "accounts", "code", "totp-test", "-s"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d{6}").unwrap());

    ykman_dev()
        .args(["oath", "accounts", "delete", "totp-test", "-f"])
        .assert()
        .success();

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_add_hotp_and_code() {
    oath_reset();

    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "hotp",
            "-f",
            "hotp-test",
            "abba",
        ])
        .assert()
        .success();

    // Get a code
    ykman_dev()
        .args(["oath", "accounts", "code", "hotp-test", "-s"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d{6}").unwrap());

    ykman_dev()
        .args(["oath", "accounts", "delete", "hotp-test", "-f"])
        .assert()
        .success();

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_rename() {
    oath_reset();

    // Add credential
    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "-f",
            "rename-me",
            "abba",
        ])
        .assert()
        .success();

    // Rename it
    ykman_dev()
        .args([
            "oath",
            "accounts",
            "rename",
            "rename-me",
            "renamed-acct",
            "-f",
        ])
        .assert()
        .success();

    // Verify new name exists, old name gone
    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("renamed-acct")
                .and(predicate::str::contains("rename-me").not()),
        );

    // Cleanup
    ykman_dev()
        .args(["oath", "accounts", "delete", "renamed-acct", "-f"])
        .assert()
        .success();

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_password_set_and_clear() {
    oath_reset();

    // Set password
    ykman_dev()
        .args(["oath", "access", "change", "-n", OATH_PASSWORD])
        .assert()
        .success();

    // List with password should work
    ykman_dev()
        .args(["oath", "accounts", "list", "-p", OATH_PASSWORD])
        .assert()
        .success();

    // Clear password
    ykman_dev()
        .args(["oath", "access", "change", "-p", OATH_PASSWORD, "-c"])
        .assert()
        .success();

    // List without password should work again
    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success();

    oath_reset();
}
