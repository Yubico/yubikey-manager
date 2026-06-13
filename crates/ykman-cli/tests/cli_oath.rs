mod common;

use common::{OATH_PASSWORD, fixture_path, is_fips, oath_reset, ykman_dev, ykman_dev_tty};
use predicates::prelude::*;
use serial_test::serial;

const OATH_ACCOUNT_SECRET: &str = "KE4CG4SUGIQW2VRXER5EYNJFNY";

fn prepare_oath_for_credentials() -> Option<&'static str> {
    oath_reset();
    if is_fips() {
        ykman_dev()
            .args(["oath", "access", "change", "-n", OATH_PASSWORD])
            .assert()
            .success();
        Some(OATH_PASSWORD)
    } else {
        None
    }
}

fn add_password<'a>(args: &mut Vec<&'a str>, password: Option<&'a str>) {
    if let Some(password) = password {
        args.extend(["-p", password]);
    }
}

#[test]
#[serial]
fn test_oath_info() {
    require_interface!("CCID");
    oath_reset();
    ykman_dev()
        .args(["oath", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("version:").or(predicate::str::contains("Version:")));
}

#[test]
#[serial]
fn test_oath_reset() {
    require_interface!("CCID");
    ykman_dev().args(["oath", "reset", "-f"]).assert().success();
}

#[test]
#[serial]
fn test_oath_add_and_list() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "-f",
        "test-issuer:test-account",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("test-issuer:test-account"));

    let mut args = vec![
        "oath",
        "accounts",
        "delete",
        "test-issuer:test-account",
        "-f",
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("test-issuer:test-account").not());

    oath_reset();
}

#[test]
#[serial]
fn test_oath_add_totp_and_code() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "-f",
        "totp-test",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "code", "totp-test", "-s"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d{6}").unwrap());

    let mut args = vec!["oath", "accounts", "delete", "totp-test", "-f"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    oath_reset();
}

#[test]
#[serial]
fn test_oath_add_hotp_and_code() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "hotp",
        "-f",
        "hotp-test",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "code", "hotp-test", "-s"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d{6}").unwrap());

    let mut args = vec!["oath", "accounts", "delete", "hotp-test", "-f"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    oath_reset();
}

#[test]
#[serial]
fn test_oath_rename() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "-f",
        "rename-me",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec![
        "oath",
        "accounts",
        "rename",
        "rename-me",
        "renamed-acct",
        "-f",
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success().stdout(
        predicate::str::contains("renamed-acct").and(predicate::str::contains("rename-me").not()),
    );

    let mut args = vec!["oath", "accounts", "delete", "renamed-acct", "-f"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    oath_reset();
}

#[test]
#[serial]
fn test_oath_password_set_and_clear() {
    require_interface!("CCID");
    oath_reset();

    ykman_dev()
        .args(["oath", "access", "change", "-n", OATH_PASSWORD])
        .assert()
        .success();

    ykman_dev()
        .args(["oath", "accounts", "list", "-p", OATH_PASSWORD])
        .assert()
        .success();

    if is_fips() {
        oath_reset();
    } else {
        ykman_dev()
            .args(["oath", "access", "change", "-p", OATH_PASSWORD, "-c"])
            .assert()
            .success();
    }

    ykman_dev()
        .args(["oath", "accounts", "list"])
        .assert()
        .success();

    if !is_fips() {
        oath_reset();
    }
}

#[test]
#[serial]
fn test_oath_password_change_prompts_for_new_password() {
    require_interface!("CCID");
    oath_reset();

    let output = ykman_dev_tty(
        &["oath", "access", "change"],
        &format!("{OATH_PASSWORD}\n{OATH_PASSWORD}\n"),
    );
    assert!(output.status.success(), "{output:?}");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("New OATH password"), "{combined}");

    ykman_dev()
        .args(["oath", "accounts", "list", "-p", OATH_PASSWORD])
        .assert()
        .success();

    if is_fips() {
        oath_reset();
    } else {
        ykman_dev()
            .args(["oath", "access", "change", "-p", OATH_PASSWORD, "-c"])
            .assert()
            .success();
    }

    if !is_fips() {
        oath_reset();
    }
}

#[test]
#[serial]
fn test_oath_add_totp_sha256_7digits() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "--algorithm",
        "sha256",
        "--digits",
        "7",
        "-f",
        "sha256-7d",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    // Code should be 7 digits
    let mut args = vec!["oath", "accounts", "code", "sha256-7d", "-s"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{7}\n?$").unwrap());

    oath_reset();
}

#[test]
#[serial]
fn test_oath_add_with_issuer() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "--issuer",
        "MyIssuer",
        "-f",
        "issuer-test",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("MyIssuer"));

    oath_reset();
}

#[test]
#[serial]
fn test_oath_add_totp_touch() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    // Just verify the --touch flag is accepted
    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "--touch",
        "-f",
        "touch-test",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("touch-test"));

    oath_reset();
}

#[test]
#[serial]
fn test_oath_import_pskc() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let pskc = fixture_path("pskc_totp.xml");
    let mut args = vec!["oath", "accounts", "import", pskc.to_str().unwrap(), "-f"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("pskc-test"));

    oath_reset();
}

#[test]
#[serial]
fn test_oath_import_pskc_multi() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let pskc = fixture_path("pskc_multi.xml");
    let mut args = vec!["oath", "accounts", "import", pskc.to_str().unwrap(), "-f"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("multi-1").and(predicate::str::contains("multi-2")));

    oath_reset();
}

#[test]
#[serial]
fn test_oath_list_oath_type() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "-f",
        "type-test",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list", "--oath-type"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("TOTP"));

    oath_reset();
}

#[test]
#[serial]
fn test_oath_accounts_code_totp_single() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let mut args = vec![
        "oath",
        "accounts",
        "add",
        "-o",
        "totp",
        "-f",
        "single-test",
        OATH_ACCOUNT_SECRET,
    ];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    // -s / --single should output just the code
    let mut args = vec!["oath", "accounts", "code", "single-test", "-s"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{6}\n?$").unwrap());

    oath_reset();
}

// ── PSKC import (additional formats) ─────────────────────────────────

#[test]
#[serial]
fn test_oath_import_pskc_hotp() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let pskc = fixture_path("pskc_hotp.xml");
    let mut args = vec!["oath", "accounts", "import", pskc.to_str().unwrap(), "-f"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("pskc-hotp-test"));

    // Verify it produces a code (HOTP)
    let mut args = vec!["oath", "accounts", "code", "pskc-hotp-test", "-s"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d{6}").unwrap());

    oath_reset();
}

#[test]
#[serial]
fn test_oath_import_pskc_sha256() {
    require_interface!("CCID");
    let password = prepare_oath_for_credentials();

    let pskc = fixture_path("pskc_sha256.xml");
    let mut args = vec!["oath", "accounts", "import", pskc.to_str().unwrap(), "-f"];
    add_password(&mut args, password);
    ykman_dev().args(args).assert().success();

    let mut args = vec!["oath", "accounts", "list"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("pskc-sha256-test"));

    // SHA-256 TOTP with 8 digits
    let mut args = vec!["oath", "accounts", "code", "pskc-sha256-test", "-s"];
    add_password(&mut args, password);
    ykman_dev()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{8}\n?$").unwrap());

    oath_reset();
}
