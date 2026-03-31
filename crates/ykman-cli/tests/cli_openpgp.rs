mod common;

use common::{
    DEFAULT_OPENPGP_ADMIN_PIN, DEFAULT_OPENPGP_PIN, NON_DEFAULT_OPENPGP_ADMIN_PIN,
    NON_DEFAULT_OPENPGP_PIN, fixture_path, openpgp_reset, ykman_dev,
};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_openpgp_info() {
    require_interface!("CCID");
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
    require_interface!("CCID");
    ykman_dev()
        .args(["openpgp", "reset", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_change_pin() {
    require_interface!("CCID");
    openpgp_reset();

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
    require_interface!("CCID");
    openpgp_reset();

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
    require_interface!("CCID");
    openpgp_reset();

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

    ykman_dev().args(["openpgp", "info"]).assert().success();

    openpgp_reset();
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_keys_set_touch() {
    require_interface!("CCID");
    openpgp_reset();

    // Set touch on aut key to "on"
    ykman_dev()
        .args([
            "openpgp",
            "keys",
            "set-touch",
            "aut",
            "on",
            "--admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
            "-f",
        ])
        .assert()
        .success();

    // Set touch back to "off"
    ykman_dev()
        .args([
            "openpgp",
            "keys",
            "set-touch",
            "aut",
            "off",
            "--admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
            "-f",
        ])
        .assert()
        .success();

    openpgp_reset();
}

// NOTE: openpgp keys import is not yet implemented in the CLI.
// test_openpgp_keys_import would test this when available.

#[test]
#[ignore]
#[serial]
fn test_openpgp_certificates_import_export() {
    require_interface!("CCID");
    openpgp_reset();

    let cert_file = fixture_path("ec_p256_cert.pem");
    ykman_dev()
        .args([
            "openpgp",
            "certificates",
            "import",
            "att",
            cert_file.to_str().unwrap(),
            "--admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
        ])
        .assert()
        .success();

    // Export and verify content
    ykman_dev()
        .args(["openpgp", "certificates", "export", "att", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN CERTIFICATE"));

    openpgp_reset();
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_certificates_delete() {
    require_interface!("CCID");
    openpgp_reset();

    let cert_file = fixture_path("ec_p256_cert.pem");
    ykman_dev()
        .args([
            "openpgp",
            "certificates",
            "import",
            "att",
            cert_file.to_str().unwrap(),
            "--admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "openpgp",
            "certificates",
            "delete",
            "att",
            "--admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
        ])
        .assert()
        .success();

    openpgp_reset();
}

#[test]
#[ignore]
#[serial]
fn test_openpgp_change_reset_code() {
    require_interface!("CCID");
    openpgp_reset();

    let new_reset_code = "12345679";

    // Set a reset code (requires admin PIN)
    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-reset-code",
            "--admin-pin",
            DEFAULT_OPENPGP_ADMIN_PIN,
            "--reset-code",
            new_reset_code,
        ])
        .assert()
        .success();

    openpgp_reset();
}
