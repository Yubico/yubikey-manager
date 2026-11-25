use super::common::{
    InputMode, app_is_fips_capable, device_version, fixture_path, piv_has_puk, piv_management_key,
    piv_management_key_algorithm, piv_new_management_key, piv_new_pin, piv_new_puk, piv_pin,
    piv_puk, piv_reset, reset_blocked, skip_before_version, ykman_dev, ykman_dev_tty,
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

fn generate_key_and_certificate(subject: &str, mode: InputMode) {
    let dir = tempfile::tempdir().expect("public key temp dir");
    let public_key = dir.path().join("public.pem");
    let public_key = public_key.to_str().expect("public key file path");
    let mut generate = vec![
        "piv",
        "keys",
        "generate",
        "9a",
        public_key,
        "-m",
        piv_management_key(),
    ];
    let mut certificate = vec!["piv", "certificates", "generate", "9a"];
    if device_version().is_some_and(|version| version < (5, 3, 0)) {
        certificate.push(public_key);
    }
    certificate.extend(["-s", subject, "-m", piv_management_key()]);
    for args in [&mut generate, &mut certificate] {
        if mode.is_interactive() {
            let output = ykman_dev_tty(args, &format!("{}\n", piv_pin()));
            assert!(output.status.success(), "{output:?}");
        } else {
            ykman_dev()
                .args(args.iter().copied())
                .args(["-P", piv_pin()])
                .assert()
                .success();
        }
    }
    assert!(
        std::fs::read_to_string(public_key)
            .unwrap()
            .contains("BEGIN PUBLIC KEY")
    );
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
        skip!("PUK is not supported on this device");
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
        let input = if app_is_fips_capable("PIV") {
            format!(
                "{}\n{}\n{}\n",
                piv_management_key(),
                piv_new_management_key(),
                piv_new_management_key()
            )
        } else {
            format!(
                "{}\n{}\n",
                piv_new_management_key(),
                piv_new_management_key()
            )
        };
        let output = ykman_dev_tty(
            &[
                "piv",
                "access",
                "change-management-key",
                "--algorithm",
                piv_management_key_algorithm(),
            ],
            &input,
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
            ],
            &format!(
                "{}\n{}\n{}\n",
                piv_new_management_key(),
                piv_management_key(),
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
                piv_new_management_key(),
                "--new-management-key",
                piv_management_key(),
                "--algorithm",
                piv_management_key_algorithm(),
            ])
            .assert()
            .success();
    }

    piv_reset();
}

fn change_management_key(current: &str, new: &str, extra: &[&str]) -> assert_cmd::assert::Assert {
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-management-key",
            "-m",
            current,
            "-n",
            new,
            "-a",
            piv_management_key_algorithm(),
        ])
        .args(extra)
        .assert()
        .success()
}

#[test]
fn test_piv_change_management_key_clears_stored_key() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    if app_is_fips_capable("PIV") {
        eprintln!("SKIP: --protect requires FIPS approved mode");
        return;
    }
    piv_reset();
    let (key, new_key) = (piv_management_key(), piv_new_management_key());
    let warning = "previous management key stored on the YubiKey was not cleared";

    change_management_key(key, new_key, &["--protect", "-P", piv_pin()]);
    change_management_key(new_key, key, &["-P", piv_pin()])
        .stderr(predicate::str::contains(warning).not());

    change_management_key(key, new_key, &["--protect", "-P", piv_pin()]);
    change_management_key(new_key, key, &[]).stderr(predicate::str::contains(warning));

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

    generate_key_and_certificate("CN=test", mode);

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

    generate_key_and_certificate("CN=export-test", InputMode::Arguments);

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

    generate_key_and_certificate("CN=delete-test", InputMode::Arguments);

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

    generate_key_and_certificate("CN=export-key-test", InputMode::Arguments);

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

    generate_key_and_certificate("CN=der-test", InputMode::Arguments);

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

    generate_key_and_certificate("CN=verify-test", InputMode::Arguments);

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
    if skip_before_version((5, 7, 0), "PIV key move") {
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

#[test]
fn test_piv_objects_export_hex_object_id() {
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

    // Export using the raw hex object ID instead of the "CHUID" alias.
    let output = ykman_dev()
        .args(["piv", "objects", "export", "5fc102", "-"])
        .output()
        .expect("failed to run command");
    assert!(output.status.success());
    assert!(
        !output.stdout.is_empty(),
        "CHUID export via hex object ID should produce data"
    );

    piv_reset();
}

#[test]
fn test_piv_objects_import_too_large_error() {
    require_capability!("PIV");
    if skip_before_version((4, 1, 0), "PIV management") {
        return;
    }
    piv_reset();

    let temp_dir = tempfile::tempdir().expect("failed to create temporary directory");
    let data_path = temp_dir.path().join("piv_large_object.bin");
    std::fs::write(&data_path, vec![0u8; 20000]).expect("failed to write fixture");

    ykman_dev()
        .args([
            "piv",
            "objects",
            "import",
            "5fc10d",
            data_path.to_str().unwrap(),
            "-m",
            piv_management_key(),
            "-P",
            piv_pin(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("too large to import"));

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
        skip!("PUK is not supported on this device");
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
        .stderr(predicate::str::contains("Wrong password."));

    piv_reset();
}
