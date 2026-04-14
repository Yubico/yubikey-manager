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
    require_interface!("CCID");
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
    require_interface!("CCID");
    ykman_dev().args(["piv", "reset", "-f"]).assert().success();
}

#[test]
#[ignore]
#[serial]
fn test_piv_change_pin() {
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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
    require_interface!("CCID");
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

// ── key import (additional formats) ──────────────────────────────────

#[test]
#[ignore]
#[serial]
fn test_piv_import_key_ec_der() {
    require_interface!("CCID");
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
fn test_piv_import_key_ec_p384() {
    require_interface!("CCID");
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
fn test_piv_import_key_ec_p384_der() {
    require_interface!("CCID");
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
fn test_piv_import_key_rsa_der() {
    require_interface!("CCID");
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
fn test_piv_import_key_ec_pkcs12() {
    require_interface!("CCID");
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
fn test_piv_import_key_ec_pkcs12_encrypted() {
    require_interface!("CCID");
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
fn test_piv_import_key_rsa_pkcs12() {
    require_interface!("CCID");
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
fn test_piv_import_key_rsa_pkcs12_encrypted() {
    require_interface!("CCID");
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
fn test_piv_import_key_ec_p384_pkcs12() {
    require_interface!("CCID");
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
fn test_piv_import_key_ec_p256_pkcs12_modern() {
    require_interface!("CCID");
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .success();

    piv_reset();
}

// ── certificate import (additional formats) ──────────────────────────

#[test]
#[ignore]
#[serial]
fn test_piv_import_certificate_rsa_pem() {
    require_interface!("CCID");
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
fn test_piv_import_certificate_rsa_der() {
    require_interface!("CCID");
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
fn test_piv_import_certificate_ec_pkcs12() {
    require_interface!("CCID");
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
#[ignore]
#[serial]
fn test_piv_import_certificate_ec_pkcs12_encrypted() {
    require_interface!("CCID");
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
fn test_piv_import_certificate_rsa_pkcs12() {
    require_interface!("CCID");
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
fn test_piv_import_certificate_rsa_pkcs12_encrypted() {
    require_interface!("CCID");
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
fn test_piv_import_certificate_ec_pkcs12_modern() {
    require_interface!("CCID");
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
fn test_piv_import_key_and_cert_pkcs12_verify() {
    require_interface!("CCID");
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
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
fn test_piv_import_key_ec_encrypted_pem() {
    require_interface!("CCID");
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
fn test_piv_import_key_rsa_encrypted_pem() {
    require_interface!("CCID");
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
fn test_piv_import_pkcs12_wrong_password() {
    require_interface!("CCID");
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
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("MAC")
                .and(predicate::str::contains("fail").or(predicate::str::contains("mismatch"))),
        );

    piv_reset();
}
