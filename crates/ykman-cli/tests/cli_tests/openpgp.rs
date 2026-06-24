use super::common::{
    InputMode, fixture_path, openpgp_admin_pin, openpgp_new_admin_pin, openpgp_new_pin,
    openpgp_pin, openpgp_reset, openpgp_reset_code, ykman_dev, ykman_dev_tty,
};
use predicates::prelude::*;
use rstest::rstest;

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

// NOTE: openpgp keys import is not yet implemented in the CLI.
// test_openpgp_keys_import would test this when available.

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_openpgp_certificates_import_export(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("OpenPGP");
    openpgp_reset();

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
