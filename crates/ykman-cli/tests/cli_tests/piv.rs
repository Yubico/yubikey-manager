use super::common::{
    InputMode, fixture_path, piv_has_puk, piv_management_key, piv_management_key_algorithm,
    piv_new_management_key, piv_new_pin, piv_new_puk, piv_pin, piv_puk, piv_reset, reset_blocked,
    skip_before_version, ykman_dev, ykman_dev_tty,
};
use predicates::prelude::*;
use rstest::rstest;

struct PivResetGuard;

impl PivResetGuard {
    fn reset() -> Self {
        piv_reset();
        Self
    }
}

impl Drop for PivResetGuard {
    fn drop(&mut self) {
        piv_reset();
    }
}

#[test]
fn test_piv_info() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();
    ykman_dev().args(["piv", "info"]).assert().success().stdout(
        predicate::str::contains("PIV version:")
            .or(predicate::str::contains("PIN tries remaining:")),
    );
}

#[test]
fn test_piv_reset() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    if reset_blocked("PIV") {
        ykman_dev()
            .args(["piv", "reset", "-f"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Cannot perform PIV reset when FIDO is configured, use 'ykman config reset' for full factory reset.",
            ));
        return;
    }
    ykman_dev().args(["piv", "reset", "-f"]).assert().success();
    piv_reset();
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_piv_change_pin(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    let _guard = PivResetGuard::reset();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["piv", "access", "change-pin"],
            &format!("{}\n{}\n{}\n", piv_pin(), piv_new_pin(), piv_new_pin()),
        );
        assert!(output.status.success(), "{output:?}");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(combined.contains("Enter the current PIN"), "{combined}");
        assert!(combined.contains("New PIN"), "{combined}");
    } else {
        ykman_dev()
            .args([
                "piv",
                "access",
                "change-pin",
                "--pin",
                piv_pin(),
                "--new-pin",
                piv_new_pin(),
            ])
            .assert()
            .success();
    }
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_piv_change_puk(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    if !piv_has_puk() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m PUK is not supported on this device");
        return;
    }
    let _guard = PivResetGuard::reset();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["piv", "access", "change-puk"],
            &format!("{}\n{}\n{}\n", piv_puk(), piv_new_puk(), piv_new_puk()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
        ykman_dev()
            .args([
                "piv",
                "access",
                "change-puk",
                "--puk",
                piv_puk(),
                "--new-puk",
                piv_new_puk(),
            ])
            .assert()
            .success();
    }
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_piv_change_management_key(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &[
                "piv",
                "access",
                "change-management-key",
                "--algorithm",
                piv_management_key_algorithm(),
                "-f",
            ],
            &format!(
                "{}\n{}\n{}\n",
                piv_new_management_key(),
                piv_new_management_key(),
                piv_management_key()
            ),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
        ykman_dev()
            .args([
                "piv",
                "access",
                "change-management-key",
                "--management-key",
                piv_management_key(),
                "--new-management-key",
                piv_new_management_key(),
                "--algorithm",
                piv_management_key_algorithm(),
                "-f",
            ])
            .assert()
            .success();
    }

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &[
                "piv",
                "access",
                "change-management-key",
                "--algorithm",
                piv_management_key_algorithm(),
                "-f",
            ],
            &format!(
                "{}\n{}\n{}\n",
                piv_management_key(),
                piv_management_key(),
                piv_new_management_key()
            ),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
        ykman_dev()
            .args([
                "piv",
                "access",
                "change-management-key",
                "--management-key",
                piv_new_management_key(),
                "--new-management-key",
                piv_management_key(),
                "--algorithm",
                piv_management_key_algorithm(),
                "-f",
            ])
            .assert()
            .success();
    }

    piv_reset();
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_piv_generate_self_signed(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &[
                "piv",
                "keys",
                "generate",
                "9a",
                "-",
                "-m",
                piv_management_key(),
            ],
            &format!("{}\n", piv_pin()),
        );
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("BEGIN PUBLIC KEY"),
            "{output:?}"
        );
    } else {
        ykman_dev()
            .args([
                "piv",
                "keys",
                "generate",
                "9a",
                "-",
                "-m",
                piv_management_key(),
                "-P",
                piv_pin(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));
    }

    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &[
                "piv",
                "certificates",
                "generate",
                "9a",
                "-s",
                "CN=test",
                "-m",
                piv_management_key(),
            ],
            &format!("{}\n", piv_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
        ykman_dev()
            .args([
                "piv",
                "certificates",
                "generate",
                "9a",
                "-s",
                "CN=test",
                "-m",
                piv_management_key(),
                "-P",
                piv_pin(),
            ])
            .assert()
            .success();
    }

    ykman_dev()
        .args(["piv", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("9A"));

    piv_reset();
}

#[test]
fn test_piv_export_certificate() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=export-test",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["piv", "certificates", "export", "9a", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN CERTIFICATE"));

    piv_reset();
}

#[test]
fn test_piv_import_key_ec() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p256_key.pem");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

// NOTE: PIV encrypted key import (--password) does not decrypt EC PKCS#8 keys
// in-process. test_piv_import_key_encrypted would test this when supported.

#[test]
fn test_piv_import_key_rsa() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("rsa_2048_key.pem");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_certificate() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("ec_p256_cert.pem");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["piv", "certificates", "export", "9a", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN CERTIFICATE"));

    piv_reset();
}

#[test]
fn test_piv_import_certificate_der() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("ec_p256_cert.der");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_delete_certificate() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    // Generate a key and self-signed cert
    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=delete-test",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    // Delete the certificate
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "delete",
            "9a",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_export_key() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    // Generate a key and self-signed cert (cert needed for export)
    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=export-key-test",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    // Export the public key
    ykman_dev()
        .args(["piv", "keys", "export", "9a", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
fn test_piv_export_key_der() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=der-test",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    // Export in DER format — binary output, just check non-empty
    let output = ykman_dev()
        .args(["piv", "keys", "export", "9a", "-", "--format", "der"])
        .output()
        .expect("failed to run command");
    assert!(output.status.success());
    assert!(!output.stdout.is_empty(), "DER export should produce data");

    piv_reset();
}

#[test]
fn test_piv_export_key_verify() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    // Generate key and cert so --verify can match them
    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=verify-test",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "export",
            "9a",
            "-",
            "--verify",
            "-P",
            piv_pin(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
fn test_piv_key_move() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    // Generate key in 9a
    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    // Move key from 9a to 9c
    ykman_dev()
        .args([
            "piv",
            "keys",
            "move",
            "9a",
            "9c",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_objects_generate_chuid() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "objects",
            "generate",
            "chuid",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_objects_generate_ccc() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "objects",
            "generate",
            "ccc",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_objects_export_chuid() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    // Generate CHUID first
    ykman_dev()
        .args([
            "piv",
            "objects",
            "generate",
            "chuid",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    // Export CHUID to stdout (binary data — just check success and non-empty output)
    let output = ykman_dev()
        .args(["piv", "objects", "export", "CHUID", "-"])
        .output()
        .expect("failed to run command");
    assert!(output.status.success());
    assert!(
        !output.stdout.is_empty(),
        "CHUID export should produce data"
    );

    piv_reset();
}

#[rstest]
#[case::arguments(InputMode::Arguments)]
#[case::interactive(InputMode::Interactive)]
fn test_piv_unblock_pin(#[case] mode: InputMode) {
    if mode.skip_if_windows() {
        return;
    }
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    if !piv_has_puk() {
        eprintln!("\x1b[1;33mSKIP:\x1b[0m PUK is not supported on this device");
        return;
    }
    let _guard = PivResetGuard::reset();

    // Exhaust PIN tries to lock the PIN
    for _ in 0..4 {
        let _ = ykman_dev()
            .args([
                "piv",
                "access",
                "change-pin",
                "--pin",
                "91827364",
                "--new-pin",
                "82736495",
            ])
            .ok();
    }

    // Unblock PIN using PUK
    if mode.is_interactive() {
        let output = ykman_dev_tty(
            &["piv", "access", "unblock-pin"],
            &format!("{}\n{}\n{}\n", piv_puk(), piv_new_pin(), piv_new_pin()),
        );
        assert!(output.status.success(), "{output:?}");
    } else {
        ykman_dev()
            .args([
                "piv",
                "access",
                "unblock-pin",
                "--puk",
                piv_puk(),
                "--new-pin",
                piv_new_pin(),
            ])
            .assert()
            .success();
    }
}

#[test]
fn test_piv_generate_rsa2048() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "--algorithm",
            "rsa2048",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
fn test_piv_generate_eccp384() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "--algorithm",
            "eccp384",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
fn test_piv_key_pin_policy() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "--pin-policy",
            "once",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
fn test_piv_key_touch_policy() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "--touch-policy",
            "cached",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

// ── key import (additional formats) ──────────────────────────────────

#[test]
fn test_piv_import_key_ec_der() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p256_key.der");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_ec_p384() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p384_key.pem");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_ec_p384_der() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p384_key.der");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_rsa_der() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("rsa_2048_key.der");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_ec_pkcs12() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p256.p12");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_ec_pkcs12_encrypted() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p256_enc.p12");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_rsa_pkcs12() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("rsa_2048.p12");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_rsa_pkcs12_encrypted() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("rsa_2048_enc.p12");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_ec_p384_pkcs12() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p384.p12");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_ec_p256_pkcs12_modern() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p256_modern.p12");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

// ── certificate import (additional formats) ──────────────────────────

#[test]
fn test_piv_import_certificate_rsa_pem() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("rsa_2048_cert.pem");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_certificate_rsa_der() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("rsa_2048_cert.der");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_certificate_ec_pkcs12() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("ec_p256.p12");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "--password",
            "",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    // Verify the certificate was imported
    ykman_dev()
        .args(["piv", "certificates", "export", "9a", "-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN CERTIFICATE"));

    piv_reset();
}

#[test]
fn test_piv_import_certificate_ec_pkcs12_encrypted() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("ec_p256_enc.p12");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_certificate_rsa_pkcs12() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("rsa_2048.p12");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "--password",
            "",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_certificate_rsa_pkcs12_encrypted() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("rsa_2048_enc.p12");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_certificate_ec_pkcs12_modern() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let cert_file = fixture_path("ec_p256_modern.p12");
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            cert_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_and_cert_pkcs12_verify() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let p12_file = fixture_path("ec_p256_enc.p12");

    // Import key from PKCS#12
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            p12_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    // Import cert from the same PKCS#12 with --verify to confirm key match
    ykman_dev()
        .args([
            "piv",
            "certificates",
            "import",
            "9a",
            p12_file.to_str().unwrap(),
            "--password",
            "test123",
            "--verify",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_ec_encrypted_pem() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p256_key_enc.pem");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_key_rsa_encrypted_pem() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("rsa_2048_key_enc.pem");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "test123",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
fn test_piv_import_pkcs12_wrong_password() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let key_file = fixture_path("ec_p256_enc.p12");
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9a",
            key_file.to_str().unwrap(),
            "--password",
            "wrongpassword",
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("MAC")
                .and(predicate::str::contains("fail").or(predicate::str::contains("mismatch"))),
        );

    piv_reset();
}
