//! OpenSSL interoperability tests. Overwrites the key in retired slot 95.

use super::common::{piv_management_key, piv_pin, skip_before_version, ykman_dev};
use predicates::prelude::*;
use rstest::rstest;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn openssl(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run OpenSSL");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn openssl_supports(algorithm: &str) -> bool {
    let output = match Command::new("openssl")
        .args(["list", "-public-key-algorithms"])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => panic!("Cannot execute OpenSSL: {e}"),
    };
    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout)
        .to_ascii_lowercase()
        .contains(algorithm)
}

struct KeySlotGuard;

impl KeySlotGuard {
    fn generate(dir: &Path, algorithm: &str) -> Self {
        Self::generate_with_pin_policy(dir, algorithm, "always")
    }

    fn generate_with_pin_policy(dir: &Path, algorithm: &str, pin_policy: &str) -> Self {
        let guard = Self;
        ykman_dev()
            .current_dir(dir)
            .args([
                "piv",
                "keys",
                "generate",
                "95",
                "public.pem",
                "--algorithm",
                algorithm,
                "--pin-policy",
                pin_policy,
                "--touch-policy",
                "never",
                "-m",
                piv_management_key(),
                "-P",
                piv_pin(),
            ])
            .assert()
            .success()
            .stdout("");
        guard
    }
}

#[test]
fn test_piv_crypto_pin_never() {
    require_capability!("PIV");
    if skip_before_version((5, 3, 0), "slot metadata") {
        return;
    }
    if super::common::app_is_fips_capable("PIV") {
        skip!("PIN-never signing is not supported in FIPS approved mode");
    }
    if !openssl_supports("ec") {
        skip!("OpenSSL is required");
    }
    let dir = tempfile::tempdir().unwrap();
    let _guard = KeySlotGuard::generate_with_pin_policy(dir.path(), "eccp256", "never");
    fs::write(dir.path().join("message"), b"PIN-never signing").unwrap();
    ykman_dev()
        .current_dir(dir.path())
        .args(["piv", "keys", "sign", "95", "message", "signature"])
        .assert()
        .success()
        .stdout("");
    openssl(
        dir.path(),
        &[
            "dgst",
            "-sha256",
            "-verify",
            "public.pem",
            "-signature",
            "signature",
            "message",
        ],
    );
    ykman_dev()
        .current_dir(dir.path())
        .args([
            "piv",
            "keys",
            "sign",
            "95",
            "message",
            "invalid",
            "--pin",
            "too-long-to-be-a-pin",
        ])
        .assert()
        .failure();
    ykman_dev()
        .current_dir(dir.path())
        .args([
            "piv",
            "keys",
            "sign",
            "95",
            "message",
            "invalid",
            "--algorithm",
            "eccp384",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not match"));
    assert!(!dir.path().join("invalid").exists());
}

#[test]
fn test_piv_crypto_pin_prompt() {
    require_capability!("PIV");
    if super::common::skip_interactive_on_windows()
        || skip_before_version((5, 3, 0), "slot metadata")
    {
        return;
    }
    if !openssl_supports("ec") {
        skip!("OpenSSL is required");
    }
    let dir = tempfile::tempdir().unwrap();
    let _guard = KeySlotGuard::generate_with_pin_policy(dir.path(), "eccp256", "once");
    let message = dir.path().join("message");
    let signature = dir.path().join("signature");
    fs::write(&message, b"Interactive PIN signing").unwrap();
    let output = super::common::ykman_dev_tty(
        &[
            "piv",
            "keys",
            "sign",
            "95",
            message.to_str().unwrap(),
            signature.to_str().unwrap(),
        ],
        &format!("{}\n", piv_pin()),
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Enter PIN")
            || String::from_utf8_lossy(&output.stderr).contains("Enter PIN")
    );
    openssl(
        dir.path(),
        &[
            "dgst",
            "-sha256",
            "-verify",
            "public.pem",
            "-signature",
            "signature",
            "message",
        ],
    );
}

impl Drop for KeySlotGuard {
    fn drop(&mut self) {
        let output = ykman_dev()
            .args([
                "piv",
                "keys",
                "delete",
                "95",
                "-m",
                piv_management_key(),
                "-P",
                piv_pin(),
            ])
            .output()
            .expect("delete test key");
        if !output.status.success() {
            assert!(
                std::thread::panicking(),
                "Failed to delete test key: {output:?}"
            );
            eprintln!("Failed to delete test key during unwinding: {output:?}");
        }
    }
}

#[rstest]
#[case::rsa("rsa2048", "rsa", (5, 3, 0))]
#[case::p256("eccp256", "ec", (5, 3, 0))]
#[case::p384("eccp384", "ec", (5, 3, 0))]
#[case::ed25519("ed25519", "ed25519", (5, 7, 0))]
#[case::mldsa44("ml-dsa-44", "ml-dsa-44", (6, 0, 0))]
#[case::mldsa65("ml-dsa-65", "ml-dsa-65", (6, 0, 0))]
#[case::mldsa87("ml-dsa-87", "ml-dsa-87", (6, 0, 0))]
fn test_piv_crypto_sign(
    #[case] algorithm: &str,
    #[case] openssl_algorithm: &str,
    #[case] version: (u8, u8, u8),
) {
    require_capability!("PIV");
    if skip_before_version(version, algorithm) {
        return;
    }
    if !openssl_supports(openssl_algorithm) {
        skip!("OpenSSL with {openssl_algorithm} is required");
    }
    let dir = tempfile::tempdir().unwrap();
    let _guard = KeySlotGuard::generate(dir.path(), algorithm);
    fs::write(
        dir.path().join("message"),
        b"OpenSSL PIV signature interoperability",
    )
    .unwrap();
    let direct = algorithm == "ed25519" || algorithm.starts_with("ml-dsa");
    let hashes: &[&str] = if direct {
        &[""]
    } else {
        &["sha256", "sha384", "sha512"]
    };
    for hash in hashes {
        let paddings: &[&str] = if algorithm == "rsa2048" {
            &["pkcs1v15", "pss"]
        } else {
            &[""]
        };
        for padding in paddings {
            for prehashed in [false, true] {
                if direct && prehashed {
                    continue;
                }
                let input = if prehashed {
                    openssl(
                        dir.path(),
                        &[
                            "dgst",
                            &format!("-{hash}"),
                            "-binary",
                            "-out",
                            "digest",
                            "message",
                        ],
                    );
                    "digest"
                } else {
                    "message"
                };
                let mut command = ykman_dev();
                command
                    .current_dir(dir.path())
                    .args(["piv", "keys", "sign", "95", "-", "-", "-P", piv_pin()])
                    .write_stdin(fs::read(dir.path().join(input)).unwrap());
                if !hash.is_empty() {
                    command.args(["--hash-algorithm", hash]);
                }
                if !padding.is_empty() {
                    command.args(["--padding", padding]);
                }
                if prehashed {
                    command.arg("--prehashed");
                }
                let output = command.assert().success().get_output().stdout.clone();
                assert!(!output.is_empty());
                fs::write(dir.path().join("signature"), output).unwrap();
                if direct {
                    openssl(
                        dir.path(),
                        &[
                            "pkeyutl",
                            "-verify",
                            "-rawin",
                            "-pubin",
                            "-inkey",
                            "public.pem",
                            "-in",
                            "message",
                            "-sigfile",
                            "signature",
                        ],
                    );
                } else {
                    let hash = format!("-{hash}");
                    let mut args = vec![
                        "dgst",
                        hash.as_str(),
                        "-verify",
                        "public.pem",
                        "-signature",
                        "signature",
                    ];
                    if *padding == "pss" {
                        args.extend([
                            "-sigopt",
                            "rsa_padding_mode:pss",
                            "-sigopt",
                            "rsa_pss_saltlen:digest",
                        ]);
                    }
                    args.push("message");
                    openssl(dir.path(), &args);
                }
            }
        }
    }
    if direct {
        ykman_dev()
            .current_dir(dir.path())
            .args([
                "piv",
                "keys",
                "sign",
                "95",
                "message",
                "invalid",
                "--hash-algorithm",
                "sha256",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("signs messages directly"));
    } else {
        ykman_dev()
            .current_dir(dir.path())
            .args([
                "piv",
                "keys",
                "sign",
                "95",
                "message",
                "invalid",
                "--prehashed",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("exactly 32 bytes"));
    }
    assert!(!dir.path().join("invalid").exists());
}

#[test]
fn test_piv_crypto_decrypt() {
    require_capability!("PIV");
    if skip_before_version((5, 3, 0), "slot metadata") {
        return;
    }
    if !openssl_supports("rsa") {
        skip!("OpenSSL is required");
    }
    let dir = tempfile::tempdir().unwrap();
    let _guard = KeySlotGuard::generate(dir.path(), "rsa2048");
    let message = b"RSA plaintext\0with binary data";
    fs::write(dir.path().join("message"), message).unwrap();
    for hash in ["sha256", "sha384", "sha512", "pkcs1"] {
        let mut args = vec![
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            "public.pem",
            "-in",
            "message",
            "-out",
            "ciphertext",
            "-pkeyopt",
        ];
        let oaep_md = format!("rsa_oaep_md:{hash}");
        let mgf_md = format!("rsa_mgf1_md:{hash}");
        if hash == "pkcs1" {
            args.push("rsa_padding_mode:pkcs1");
        } else {
            args.extend([
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                &oaep_md,
                "-pkeyopt",
                &mgf_md,
            ]);
        }
        openssl(dir.path(), &args);
        let mut command = ykman_dev();
        command.current_dir(dir.path()).args([
            "piv",
            "keys",
            "decrypt",
            "95",
            "ciphertext",
            "plaintext",
            "-P",
            piv_pin(),
        ]);
        if hash == "pkcs1" {
            command.args(["--padding", "pkcs1v15"]);
        } else {
            command.args(["--hash-algorithm", hash]);
        }
        command.assert().success().stdout("");
        assert_eq!(fs::read(dir.path().join("plaintext")).unwrap(), message);
        fs::remove_file(dir.path().join("plaintext")).unwrap();
    }
    // The last ciphertext uses PKCS#1 v1.5, so OAEP decoding must reject it.
    fs::copy(dir.path().join("ciphertext"), dir.path().join("bad")).unwrap();
    ykman_dev()
        .current_dir(dir.path())
        .args([
            "piv",
            "keys",
            "decrypt",
            "95",
            "bad",
            "invalid",
            "-P",
            piv_pin(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid ciphertext"));
    assert!(!dir.path().join("invalid").exists());
}

#[rstest]
#[case::mlkem512("ml-kem-512")]
#[case::mlkem768("ml-kem-768")]
#[case::mlkem1024("ml-kem-1024")]
fn test_piv_crypto_decapsulate(#[case] algorithm: &str) {
    require_capability!("PIV");
    if skip_before_version((6, 0, 0), algorithm) {
        return;
    }
    if !openssl_supports(algorithm) {
        skip!("OpenSSL with {algorithm} is required");
    }
    let dir = tempfile::tempdir().unwrap();
    let _guard = KeySlotGuard::generate(dir.path(), algorithm);
    openssl(
        dir.path(),
        &[
            "pkeyutl",
            "-encap",
            "-pubin",
            "-inkey",
            "public.pem",
            "-secret",
            "original",
            "-out",
            "ciphertext",
        ],
    );
    let original = fs::read(dir.path().join("original")).unwrap();
    assert_eq!(original.len(), 32);
    let expected_hash = Sha256::digest(original);
    fs::remove_file(dir.path().join("original")).unwrap();
    ykman_dev()
        .current_dir(dir.path())
        .args([
            "piv",
            "keys",
            "decapsulate",
            "95",
            "ciphertext",
            "recovered",
            "-P",
            piv_pin(),
        ])
        .assert()
        .success()
        .stdout("");
    let recovered = fs::read(dir.path().join("recovered")).unwrap();
    assert_eq!(recovered.len(), 32);
    assert_eq!(Sha256::digest(recovered), expected_hash);
    ykman_dev()
        .current_dir(dir.path())
        .args([
            "piv",
            "keys",
            "decapsulate",
            "95",
            "ciphertext",
            "recovered",
            "-P",
            piv_pin(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("must not already exist"));
    fs::write(dir.path().join("bad"), b"short").unwrap();
    ykman_dev()
        .current_dir(dir.path())
        .args(["piv", "keys", "decapsulate", "95", "bad", "invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("bytes of ML-KEM ciphertext"));
    ykman_dev()
        .current_dir(dir.path())
        .args(["piv", "keys", "sign", "95", "ciphertext", "invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used for signing"));
    assert!(!dir.path().join("invalid").exists());
}

#[rstest]
#[case::p256("eccp256", "P-256", (5, 3, 0))]
#[case::p384("eccp384", "P-384", (5, 3, 0))]
#[case::x25519("x25519", "", (5, 7, 0))]
fn test_piv_crypto_derive(
    #[case] algorithm: &str,
    #[case] curve: &str,
    #[case] version: (u8, u8, u8),
) {
    require_capability!("PIV");
    if skip_before_version(version, algorithm) {
        return;
    }
    if algorithm == "x25519" && super::common::app_is_fips_capable("PIV") {
        skip!("X25519 is not supported in FIPS approved mode");
    }
    if !openssl_supports(if curve.is_empty() { "x25519" } else { "ec" }) {
        skip!("OpenSSL with {algorithm} is required");
    }
    let dir = tempfile::tempdir().unwrap();
    let _guard = KeySlotGuard::generate(dir.path(), algorithm);
    if curve.is_empty() {
        openssl(
            dir.path(),
            &["genpkey", "-algorithm", "X25519", "-out", "peer.pem"],
        );
    } else {
        openssl(
            dir.path(),
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                &format!("ec_paramgen_curve:{curve}"),
                "-out",
                "peer.pem",
            ],
        );
    }
    openssl(
        dir.path(),
        &[
            "pkeyutl",
            "-derive",
            "-inkey",
            "peer.pem",
            "-peerkey",
            "public.pem",
            "-out",
            "expected",
        ],
    );
    for format in ["PEM", "DER"] {
        openssl(
            dir.path(),
            &[
                "pkey",
                "-in",
                "peer.pem",
                "-pubout",
                "-outform",
                format,
                "-out",
                "peer.public",
            ],
        );
        let output = ykman_dev()
            .current_dir(dir.path())
            .args([
                "piv",
                "keys",
                "derive",
                "95",
                "peer.public",
                "-",
                "-P",
                piv_pin(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        assert_eq!(output, fs::read(dir.path().join("expected")).unwrap());
    }
    ykman_dev()
        .current_dir(dir.path())
        .args(["piv", "keys", "decrypt", "95", "peer.public", "invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires an RSA key"));
    assert!(!dir.path().join("invalid").exists());
}

#[rstest]
#[case::p256("eccp256")]
#[case::p384("eccp384")]
fn test_piv_crypto_ec_hashes(#[case] algorithm: &str) {
    require_capability!("PIV");
    if skip_before_version((5, 3, 0), "slot metadata") {
        return;
    }
    if !openssl_supports("ec") {
        skip!("OpenSSL is required");
    }
    let dir = tempfile::tempdir().unwrap();
    let _guard = KeySlotGuard::generate(dir.path(), algorithm);
    fs::write(dir.path().join("message"), b"ECDSA hash truncation").unwrap();
    for hash in ["sha256", "sha384", "sha512"] {
        // Certificate requests are signed through yubikit's PivSigner.
        let _ = fs::remove_file(dir.path().join("csr.pem"));
        ykman_dev()
            .current_dir(dir.path())
            .args([
                "piv",
                "certificates",
                "request",
                "95",
                "public.pem",
                "csr.pem",
                "-s",
                "CN=hash-test",
                "-a",
                hash,
                "-P",
                piv_pin(),
            ])
            .assert()
            .success();
        openssl(dir.path(), &["req", "-in", "csr.pem", "-verify", "-noout"]);

        let signature = ykman_dev()
            .current_dir(dir.path())
            .args([
                "piv",
                "keys",
                "sign",
                "95",
                "message",
                "-",
                "-a",
                hash,
                "-P",
                piv_pin(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        fs::write(dir.path().join("signature"), signature).unwrap();
        openssl(
            dir.path(),
            &[
                "dgst",
                &format!("-{hash}"),
                "-verify",
                "public.pem",
                "-signature",
                "signature",
                "message",
            ],
        );
    }
}
