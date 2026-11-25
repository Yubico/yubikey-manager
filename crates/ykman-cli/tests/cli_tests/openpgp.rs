use super::common::{
    InputMode, fixture_path, openpgp_admin_pin, openpgp_new_admin_pin, openpgp_new_pin,
    openpgp_pin, openpgp_reset, openpgp_reset_code, skip_before_version, ykman_dev, ykman_dev_tty,
};
use predicates::prelude::*;
use rstest::rstest;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

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
    require_capability!("OpenPGP");
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
    require_capability!("OpenPGP");
    ykman_dev()
        .args(["openpgp", "reset", "-f"])
        .assert()
        .success();
    openpgp_reset();
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_change_pin(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    let _guard = OpenPgpResetGuard::reset();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "access", "change-pin"],
            &format!(
                "{}\n{}\n{}\n",
                openpgp_pin(),
                openpgp_new_pin(),
                openpgp_new_pin()
            ),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_change_admin_pin(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    let _guard = OpenPgpResetGuard::reset();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "access", "change-admin-pin"],
            &format!(
                "{}\n{}\n{}\n",
                openpgp_admin_pin(),
                openpgp_new_admin_pin(),
                openpgp_new_admin_pin()
            ),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_set_pin_retries(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    openpgp_reset();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "access", "set-retries", "5", "5", "5", "-f"],
            &format!("{}\n", openpgp_admin_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
    }

    ykman_dev().args(["openpgp", "info"]).assert().success();

    openpgp_reset();
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_keys_set_touch(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    if skip_before_version((4, 2, 0), "OpenPGP touch policy") {
        return;
    }
    openpgp_reset();

    // Set touch on aut key to "on"
    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "keys", "set-touch", "aut", "on", "-f"],
            &format!("{}\n", openpgp_admin_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
    }

    // Set touch back to "off"
    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "keys", "set-touch", "aut", "off", "-f"],
            &format!("{}\n", openpgp_admin_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
    }

    openpgp_reset();
}

#[test]
fn test_openpgp_keys_import_requires_att() {
    require_capability!("OpenPGP");
    let key_file = fixture_path("ec_p256_key.pem");
    ykman_dev()
        .args([
            "openpgp",
            "keys",
            "import",
            "sig",
            key_file.to_str().unwrap(),
            "--admin-pin",
            openpgp_admin_pin(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "only supported for the attestation key",
        ));
}

/// Subject of the certificate written alongside the test attestation key.
const TEST_ATT_SUBJECT: &str = "CN=Test EC P256";

/// Returns true if the attestation key and certificate may be overwritten by
/// tests.
///
/// The factory-provisioned attestation key and certificate cannot be restored,
/// so the slot is only considered safe if it has no key, or if it holds a key
/// previously imported by a test, identified by the test certificate (matched
/// by subject) whose public key matches the stored key. Tests must leave the
/// test certificate in place while the test key is present.
fn att_slot_is_test_owned() -> bool {
    let key = ykman_dev()
        .args(["openpgp", "keys", "export", "att", "-F", "der", "-"])
        .output()
        .expect("failed to run ykman");
    if !key.status.success() {
        return String::from_utf8_lossy(&key.stderr).contains("No key stored");
    }
    let cert = ykman_dev()
        .args(["openpgp", "certificates", "export", "att", "-F", "der", "-"])
        .output()
        .expect("failed to run ykman");
    if !cert.status.success() {
        return false;
    }
    let Ok(cert) = Certificate::from_der(&cert.stdout) else {
        return false;
    };
    let tbs = &cert.tbs_certificate;
    tbs.subject.to_string() == TEST_ATT_SUBJECT
        && tbs
            .subject_public_key_info
            .to_der()
            .is_ok_and(|spki| spki == key.stdout)
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_keys_import_export_delete(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    if skip_before_version((5, 2, 0), "OpenPGP attestation key") {
        return;
    }
    let _guard = OpenPgpResetGuard::reset();
    if !att_slot_is_test_owned() {
        skip!("attestation key slot holds a non-test key, refusing to overwrite it");
    }

    // Write the test certificate first, marking the slot as test-owned.
    ykman_dev()
        .args([
            "openpgp",
            "certificates",
            "import",
            "att",
            fixture_path("ec_p256_cert.pem").to_str().unwrap(),
            "--admin-pin",
            openpgp_admin_pin(),
        ])
        .assert()
        .success();

    let key_file = fixture_path("ec_p256_key.pem");
    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &[
                "openpgp",
                "keys",
                "import",
                "att",
                key_file.to_str().unwrap(),
            ],
            &format!("{}\n", openpgp_admin_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
        ykman_dev()
            .args([
                "openpgp",
                "keys",
                "import",
                "att",
                key_file.to_str().unwrap(),
                "--admin-pin",
                openpgp_admin_pin(),
            ])
            .assert()
            .success();
    }

    ykman_dev()
        .args(["openpgp", "keys", "export", "att", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "keys", "delete", "att"],
            &format!("y\n{}\n", openpgp_admin_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
        ykman_dev()
            .args([
                "openpgp",
                "keys",
                "delete",
                "att",
                "--admin-pin",
                openpgp_admin_pin(),
                "-f",
            ])
            .assert()
            .success();
    }

    ykman_dev()
        .args(["openpgp", "keys", "export", "att", "-"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("No key stored"));
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_certificates_import_export(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    if skip_before_version((5, 2, 0), "OpenPGP ATT certificate") {
        return;
    }
    openpgp_reset();
    if !att_slot_is_test_owned() {
        skip!("attestation slot holds a non-test key, refusing to overwrite its certificate");
    }

    let cert_file = fixture_path("ec_p256_cert.pem");
    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &[
                "openpgp",
                "certificates",
                "import",
                "att",
                cert_file.to_str().unwrap(),
            ],
            &format!("{}\n", openpgp_admin_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
    }

    // Export and verify content
    ykman_dev()
        .args(["openpgp", "certificates", "export", "att", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN CERTIFICATE"));

    openpgp_reset();
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_certificates_delete(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    if skip_before_version((5, 2, 0), "OpenPGP ATT certificate") {
        return;
    }
    openpgp_reset();
    if !att_slot_is_test_owned() {
        skip!("attestation slot holds a non-test key, refusing to overwrite its certificate");
    }

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

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "certificates", "delete", "att"],
            &format!("{}\n", openpgp_admin_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
    }

    // Restore the test certificate, which marks the slot as test-owned.
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

    openpgp_reset();
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_change_reset_code(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    openpgp_reset();

    // Set a reset code (requires admin PIN)
    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["openpgp", "access", "change-reset-code"],
            &format!(
                "{}\n{}\n{}\n",
                openpgp_reset_code(),
                openpgp_reset_code(),
                openpgp_admin_pin()
            ),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
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
    }

    openpgp_reset();
}
