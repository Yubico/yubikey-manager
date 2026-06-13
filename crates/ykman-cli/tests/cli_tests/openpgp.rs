use super::common::{
    fixture_path, openpgp_admin_pin, openpgp_new_admin_pin, openpgp_new_pin, openpgp_pin,
    openpgp_reset, openpgp_reset_code, ykman_dev,
};
use predicates::prelude::*;

struct OpenPgpResetGuard;

impl OpenPgpResetGuard {
    fn reset() -> Self {
        openpgp_reset();
        Self
    }
}

impl Drop for OpenPgpResetGuard {
    fn drop(&mut self) {
        openpgp_reset();
    }
}

#[test]
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
fn test_openpgp_reset() {
    require_interface!("CCID");
    ykman_dev()
        .args(["openpgp", "reset", "-f"])
        .assert()
        .success();
    openpgp_reset();
}

#[test]
fn test_openpgp_change_pin() {
    require_interface!("CCID");
    let _guard = OpenPgpResetGuard::reset();

    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-pin",
            "--pin",
            openpgp_pin(),
            "--new-pin",
            openpgp_new_pin(),
        ])
        .assert()
        .success();
}

#[test]
fn test_openpgp_change_admin_pin() {
    require_interface!("CCID");
    let _guard = OpenPgpResetGuard::reset();

    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-admin-pin",
            "--admin-pin",
            openpgp_admin_pin(),
            "--new-admin-pin",
            openpgp_new_admin_pin(),
        ])
        .assert()
        .success();
}

#[test]
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
            openpgp_admin_pin(),
            "-f",
        ])
        .assert()
        .success();

    ykman_dev().args(["openpgp", "info"]).assert().success();

    openpgp_reset();
}

#[test]
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
            openpgp_admin_pin(),
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
            openpgp_admin_pin(),
            "-f",
        ])
        .assert()
        .success();

    openpgp_reset();
}

// NOTE: openpgp keys import is not yet implemented in the CLI.
// test_openpgp_keys_import would test this when available.

#[test]
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
            openpgp_admin_pin(),
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
            openpgp_admin_pin(),
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
            openpgp_admin_pin(),
        ])
        .assert()
        .success();

    openpgp_reset();
}

#[test]
fn test_openpgp_change_reset_code() {
    require_interface!("CCID");
    openpgp_reset();

    // Set a reset code (requires admin PIN)
    ykman_dev()
        .args([
            "openpgp",
            "access",
            "change-reset-code",
            "--admin-pin",
            openpgp_admin_pin(),
            "--reset-code",
            openpgp_reset_code(),
        ])
        .assert()
        .success();

    openpgp_reset();
}
