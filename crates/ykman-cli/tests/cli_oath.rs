mod common;

use common::{OATH_PASSWORD, fixture_path, oath_reset, ykman_dev};
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

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-issuer:test-account"));

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

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("renamed-acct")
                .and(predicate::str::contains("rename-me").not()),
        );

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

    ykman_dev()
        .args(["oath", "access", "change", "-n", OATH_PASSWORD])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list", "-p", OATH_PASSWORD])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "access", "change", "-p", OATH_PASSWORD, "-c"])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success();

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_add_totp_sha256_7digits() {
    oath_reset();

    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "--algorithm",
            "sha256",
            "--digits",
            "7",
            "-f",
            "sha256-7d",
            "abba",
        ])
        .assert()
        .success();

    // Code should be 7 digits
    ykman_dev()
        .args(["oath", "accounts", "code", "sha256-7d", "-s"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{7}\n?$").unwrap());

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_add_with_issuer() {
    oath_reset();

    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "--issuer",
            "MyIssuer",
            "-f",
            "issuer-test",
            "abba",
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MyIssuer"));

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_add_totp_touch() {
    oath_reset();

    // Just verify the --touch flag is accepted
    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "--touch",
            "-f",
            "touch-test",
            "abba",
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("touch-test"));

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_import_pskc() {
    oath_reset();

    let pskc = fixture_path("pskc_totp.xml");
    ykman_dev()
        .args(["oath", "accounts", "import", pskc.to_str().unwrap(), "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pskc-test"));

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_import_pskc_multi() {
    oath_reset();

    let pskc = fixture_path("pskc_multi.xml");
    ykman_dev()
        .args(["oath", "accounts", "import", pskc.to_str().unwrap(), "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("multi-1").and(predicate::str::contains("multi-2")));

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_list_oath_type() {
    oath_reset();

    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "-f",
            "type-test",
            "abba",
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list", "--oath-type"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOTP"));

    oath_reset();
}

#[test]
#[ignore]
#[serial]
fn test_oath_accounts_code_totp_single() {
    oath_reset();

    ykman_dev()
        .args([
            "oath",
            "accounts",
            "add",
            "-o",
            "totp",
            "-f",
            "single-test",
            "abba",
        ])
        .assert()
        .success();

    // -s / --single should output just the code
    ykman_dev()
        .args(["oath", "accounts", "code", "single-test", "-s"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{6}\n?$").unwrap());

    oath_reset();
}
