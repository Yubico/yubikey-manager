use super::common::{DEFAULT_HSMAUTH_MANAGEMENT_KEY, fixture_path, hsmauth_reset, ykman_dev};
use predicates::prelude::*;

const NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY: &str = "Ru7!vN2$qL9#zX5%";
const HSMAUTH_CREDENTIAL_PASSWORD: &str = "T8#qZ2!mV7$rB4n%";
const HSMAUTH_DERIVATION_PASSWORD: &str = "K9$wQ3#nR6!tM2x%";

fn prepare_hsmauth_for_credentials() -> &'static str {
    hsmauth_reset();
    ykman_dev()
        .args([
            "hsmauth",
            "access",
            "change-management-password",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
            "-n",
            NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();
    NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY
}

#[test]
fn test_hsmauth_info() {
    require_capability!("YubiHSM Auth");
    hsmauth_reset();
    ykman_dev()
        .args(["hsmauth", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("version:").or(predicate::str::contains("Version:")));
}

#[test]
fn test_hsmauth_reset() {
    require_capability!("YubiHSM Auth");
    ykman_dev()
        .args(["hsmauth", "reset", "-f"])
        .assert()
        .success();
}

#[test]
fn test_hsmauth_add_symmetric_and_list() {
    require_capability!("YubiHSM Auth");
    let management_key = prepare_hsmauth_for_credentials();

    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "symmetric",
            "test-cred",
            "--generate",
            "-c",
            HSMAUTH_CREDENTIAL_PASSWORD,
            "-m",
            management_key,
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-cred"));

    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "delete",
            "test-cred",
            "-m",
            management_key,
            "-f",
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-cred").not());

    hsmauth_reset();
}

#[test]
fn test_hsmauth_add_derive_and_list() {
    require_capability!("YubiHSM Auth");
    let management_key = prepare_hsmauth_for_credentials();

    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "derive",
            "derive-cred",
            HSMAUTH_DERIVATION_PASSWORD,
            "-c",
            HSMAUTH_CREDENTIAL_PASSWORD,
            "-m",
            management_key,
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("derive-cred"));

    hsmauth_reset();
}

#[test]
fn test_hsmauth_credential_import() {
    require_capability!("YubiHSM Auth");
    let management_key = prepare_hsmauth_for_credentials();

    let key_file = fixture_path("ec_p256_key.pem");
    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "import",
            "import-cred",
            key_file.to_str().unwrap(),
            "-c",
            HSMAUTH_CREDENTIAL_PASSWORD,
            "-m",
            management_key,
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["hsmauth", "credentials", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("import-cred"));

    hsmauth_reset();
}

// NOTE: hsmauth credential import with --password for encrypted keys
// is not currently supported by the CLI. Test would be:
// test_hsmauth_credential_import_encrypted

#[test]
fn test_hsmauth_change_management_password() {
    require_capability!("YubiHSM Auth");
    hsmauth_reset();

    // Change management password to non-default
    ykman_dev()
        .args([
            "hsmauth",
            "access",
            "change-management-password",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
            "-n",
            NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();

    // Verify the new key works by using it to add a credential
    ykman_dev()
        .args([
            "hsmauth",
            "credentials",
            "derive",
            "verify-key",
            HSMAUTH_DERIVATION_PASSWORD,
            "-c",
            HSMAUTH_CREDENTIAL_PASSWORD,
            "-m",
            NON_DEFAULT_HSMAUTH_MANAGEMENT_KEY,
        ])
        .assert()
        .success();

    // Reset to restore default key (PIN complexity may prevent changing
    // back to the all-zeros default directly)
    hsmauth_reset();
}
