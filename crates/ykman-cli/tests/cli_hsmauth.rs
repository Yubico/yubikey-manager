mod common;

use common::{DEFAULT_HSMAUTH_MANAGEMENT_KEY, fixture_path, hsmauth_reset, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;

const NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY: &str = "01020304050607080102030405060708";

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

    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-cred"));

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

    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("derive-cred"));

    hsmauth_reset();
}

#[test]
#[ignore]
#[serial]
fn test_hsmauth_credential_import() {
    hsmauth_reset();

    let key_file = fixture_path("ec_p256_key.pem");
    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "import",
            "import-cred",
            key_file.to_str().unwrap(),
            "-c",
            "12345679",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("import-cred"));

    hsmauth_reset();
}

// NOTE: hsmauth credential import with --password for encrypted keys
// is not currently supported by the CLI. Test would be:
// test_hsmauth_credential_import_encrypted

#[test]
#[ignore]
#[serial]
fn test_hsmauth_change_management_password() {
    hsmauth_reset();

    // Change management password to non-default
    ykman_dev()
        .args([
            "hsmauth",
            "access",
            "change-management-password",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
            "-n",
            NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();

    // Verify the new key works by using it to add a credential
    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "derive",
            "verify-key",
            "p4ssw0rd",
            "-c",
            "12345679",
            "-m",
            NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();

    // Reset to restore default key (PIN complexity may prevent changing
    // back to the all-zeros default directly)
    hsmauth_reset();
}
