mod common;

use common::{
    DEFAULT_MANAGEMENT_KEY, DEFAULT_PIN, DEFAULT_PUK, NON_DEFAULT_MANAGEMENT_KEY, NON_DEFAULT_PIN,
    NON_DEFAULT_PUK, fixture_path, piv_reset, ykman_dev,
};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_piv_info() {
    piv_reset();
    ykman_dev().args(["piv", "info"]).assert().success().stdout(
        predicate::str::contains("PIV version:")
            .or(predicate::str::contains("PIN tries remaining:")),
    );
}

#[test]
#[ignore]
#[serial]
fn test_piv_reset() {
    ykman_dev().args(["piv", "reset", "-f"]).assert().success();
}

#[test]
#[ignore]
#[serial]
fn test_piv_change_pin() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "access",
            "change-pin",
            "--pin",
            DEFAULT_PIN,
            "--new-pin",
            NON_DEFAULT_PIN,
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "access",
            "change-pin",
            "--pin",
            NON_DEFAULT_PIN,
            "--new-pin",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_change_puk() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "access",
            "change-puk",
            "--puk",
            DEFAULT_PUK,
            "--new-puk",
            NON_DEFAULT_PUK,
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "access",
            "change-puk",
            "--puk",
            NON_DEFAULT_PUK,
            "--new-puk",
            DEFAULT_PUK,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_change_management_key() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "access",
            "change-management-key",
            "--management-key",
            DEFAULT_MANAGEMENT_KEY,
            "--new-management-key",
            NON_DEFAULT_MANAGEMENT_KEY,
            "-f",
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "piv",
            "access",
            "change-management-key",
            "--management-key",
            NON_DEFAULT_MANAGEMENT_KEY,
            "--new-management-key",
            DEFAULT_MANAGEMENT_KEY,
            "-f",
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_generate_self_signed() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    ykman_dev()
        .args([
            "piv",
            "certificates",
            "generate",
            "9a",
            "-s",
            "CN=test",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["piv", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("9A"));

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_export_certificate() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
#[ignore]
#[serial]
fn test_piv_import_key_ec() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

// NOTE: PIV encrypted key import (--password) does not decrypt EC PKCS#8 keys
// in-process. test_piv_import_key_encrypted would test this when supported.

#[test]
#[ignore]
#[serial]
fn test_piv_import_key_rsa() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_import_certificate() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
#[ignore]
#[serial]
fn test_piv_import_certificate_der() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_delete_certificate() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_export_key() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
#[ignore]
#[serial]
fn test_piv_export_key_der() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
#[ignore]
#[serial]
fn test_piv_export_key_verify() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_key_move() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_objects_generate_chuid() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "objects",
            "generate",
            "chuid",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_objects_generate_ccc() {
    piv_reset();

    ykman_dev()
        .args([
            "piv",
            "objects",
            "generate",
            "ccc",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_objects_export_chuid() {
    piv_reset();

    // Generate CHUID first
    ykman_dev()
        .args([
            "piv",
            "objects",
            "generate",
            "chuid",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
#[ignore]
#[serial]
fn test_piv_unblock_pin() {
    piv_reset();

    // Exhaust PIN tries to lock the PIN
    for _ in 0..4 {
        let _ = ykman_dev()
            .args([
                "piv",
                "access",
                "change-pin",
                "--pin",
                "00000000",
                "--new-pin",
                "00000000",
            ])
            .ok();
    }

    // Unblock PIN using PUK
    ykman_dev()
        .args([
            "piv",
            "access",
            "unblock-pin",
            "--puk",
            DEFAULT_PUK,
            "--new-pin",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_generate_rsa2048() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_generate_eccp384() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_key_pin_policy() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}

#[test]
#[ignore]
#[serial]
fn test_piv_key_touch_policy() {
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BEGIN PUBLIC KEY"));

    piv_reset();
}
