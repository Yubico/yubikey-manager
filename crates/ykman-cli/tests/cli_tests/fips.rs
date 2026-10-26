use super::common::{
    DEFAULT_HSMAUTH_MANAGEMENT_KEY, DEFAULT_MANAGEMENT_KEY, DEFAULT_PIN, DEFAULT_PUK,
    FIPS_PIV_MANAGEMENT_KEY, FIPS_PIV_PIN, FIPS_PIV_PUK, OATH_PASSWORD, app_is_fips_capable,
    device_info, fixture_path, hsmauth_reset_raw, oath_reset_raw, openpgp_reset_raw, piv_reset,
    piv_reset_raw, ykman_dev,
};
use predicates::prelude::*;
use std::time::Duration;

const APPROVAL_ERROR: &str = "YubiKey FIPS must be in FIPS approved mode";
const HSM_PASSWORD: &str = "Ru7!vN2$qL9#zX5%";
const CREDENTIAL_PASSWORD: &str = "T8#qZ2!mV7$rB4n%";

fn reject(args: &[&str], message: &str) {
    ykman_dev()
        .args(args)
        .timeout(Duration::from_secs(15))
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains(message));
}

#[test]
fn oath_requires_approval_for_all_account_import_paths() {
    require_capability!("OATH");
    if !app_is_fips_capable("OATH") {
        skip!("OATH is not FIPS capable");
    }
    oath_reset_raw();
    let uri = "otpauth://totp/FIPS:uri?secret=JBSWY3DPEHPK3PXP";
    for args in [
        vec![
            "oath",
            "accounts",
            "add",
            "fips-add",
            "JBSWY3DPEHPK3PXP",
            "-f",
        ],
        vec!["oath", "accounts", "uri", uri, "-f"],
        vec!["oath", "accounts", "import", "missing.pskc", "-f"],
    ] {
        reject(
            &args,
            &format!("{APPROVAL_ERROR} prior to adding accounts."),
        );
    }
    reject(
        &["oath", "access", "change", "--clear"],
        "Removing the password is not allowed on YubiKey FIPS.",
    );
    ykman_dev()
        .args(["oath", "access", "change", "-n", OATH_PASSWORD])
        .assert()
        .success();
    let pskc = fixture_path("pskc_totp.xml");
    for args in [
        vec![
            "oath",
            "accounts",
            "add",
            "fips-add",
            "JBSWY3DPEHPK3PXP",
            "-f",
        ],
        vec!["oath", "accounts", "uri", uri, "-f"],
        vec!["oath", "accounts", "import", pskc.to_str().unwrap(), "-f"],
    ] {
        ykman_dev()
            .args(args)
            .args(["-p", OATH_PASSWORD])
            .assert()
            .success();
    }
    reject(
        &["oath", "access", "change", "--clear", "-p", OATH_PASSWORD],
        "Removing the password is not allowed on YubiKey FIPS.",
    );
    oath_reset_raw();
}

#[test]
fn hsmauth_requires_approval_and_names_password_policy_errors() {
    require_capability!("YubiHSM Auth");
    if !app_is_fips_capable("YubiHSM Auth") {
        skip!("YubiHSM Auth is not FIPS capable");
    }
    hsmauth_reset_raw();
    for args in [
        vec!["generate", "fips-generate"],
        vec!["import", "fips-import", "missing.pem"],
        vec!["symmetric", "fips-symmetric", "--generate"],
        vec!["derive", "fips-derive", "derivation-password"],
    ] {
        let mut command = vec!["hsmauth", "credentials"];
        command.extend(args);
        reject(
            &command,
            &format!("{APPROVAL_ERROR} prior to adding credentials."),
        );
    }
    reject(
        &[
            "hsmauth",
            "access",
            "change-management-password",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
            "-n",
            "11111111",
        ],
        "Management password does not meet complexity requirement.",
    );
    ykman_dev()
        .args([
            "hsmauth",
            "access",
            "change-management-password",
            "-m",
            DEFAULT_HSMAUTH_MANAGEMENT_KEY,
            "-n",
            HSM_PASSWORD,
        ])
        .assert()
        .success();
    reject(
        &[
            "hsmauth",
            "credentials",
            "symmetric",
            "bad-password",
            "--generate",
            "-m",
            HSM_PASSWORD,
            "-c",
            "11111111",
        ],
        "Credential password does not meet complexity requirement.",
    );
    let key = fixture_path("ec_p256_key.pem");
    for args in [
        vec!["generate", "fips-generate"],
        vec!["import", "fips-import", key.to_str().unwrap()],
        vec!["symmetric", "fips-symmetric", "--generate"],
        vec!["derive", "fips-derive", "derivation-password"],
    ] {
        ykman_dev()
            .args(["hsmauth", "credentials"])
            .args(args)
            .args(["-m", HSM_PASSWORD, "-c", CREDENTIAL_PASSWORD])
            .assert()
            .success();
    }
    reject(
        &[
            "hsmauth",
            "credentials",
            "symmetric",
            "bad-authentication",
            "--generate",
            "-m",
            "wrong-password",
            "-c",
            CREDENTIAL_PASSWORD,
        ],
        "Wrong management password,",
    );
    hsmauth_reset_raw();
}

#[test]
fn piv_requires_approval_and_enforces_fips_key_policies() {
    require_capability!("PIV");
    if !app_is_fips_capable("PIV") {
        skip!("PIV is not FIPS capable");
    }
    let complexity = device_info().contains("PIN complexity is enforced");
    let length_unit = if complexity { "characters" } else { "bytes" };
    piv_reset_raw();
    reject(
        &["piv", "keys", "generate", "9a", "-"],
        &format!("{APPROVAL_ERROR} prior to key generation."),
    );
    reject(
        &["piv", "keys", "import", "9a", "missing.pem"],
        &format!("{APPROVAL_ERROR} prior to key import."),
    );
    reject(
        &["piv", "access", "change-management-key", "--protect"],
        &format!("{APPROVAL_ERROR} prior to using --protect."),
    );
    for object in ["PRINTED", "FINGERPRINTS", "FACIAL", "IRIS", "5fc109"] {
        reject(
            &["piv", "objects", "export", object, "-"],
            &format!("{APPROVAL_ERROR} to export this object."),
        );
    }
    for (action, option, old, label) in [
        ("change-pin", "--pin", DEFAULT_PIN, "New PIN"),
        ("change-puk", "--puk", DEFAULT_PUK, "New PUK"),
        ("unblock-pin", "--puk", DEFAULT_PUK, "New PIN"),
    ] {
        reject(
            &["piv", "access", action, option, old, "-n", "123456"],
            &format!("{label} must be exactly 8 {length_unit} long."),
        );
        if complexity {
            let label = if action == "change-puk" { "PUK" } else { "PIN" };
            reject(
                &["piv", "access", action, option, old, "-n", "11111111"],
                &format!("{label} does not meet complexity requirement."),
            );
        }
    }
    ykman_dev()
        .args([
            "piv",
            "access",
            "set-retries",
            "3",
            "3",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            "-f",
        ])
        .assert()
        .success();
    for (action, option, old, new) in [
        ("change-pin", "--pin", DEFAULT_PIN, FIPS_PIV_PIN),
        ("change-puk", "--puk", DEFAULT_PUK, FIPS_PIV_PUK),
    ] {
        piv_reset_raw();
        ykman_dev()
            .args(["piv", "access", action, option, old, "-n", new])
            .assert()
            .success();
        reject(
            &["piv", "access", "set-retries", "3", "3", "-f"],
            "Retry attempts must be set before PIN/PUK have been changed.",
        );
    }
    piv_reset();
    reject(
        &["piv", "access", "set-retries", "3", "3", "-f"],
        "Retry attempts must be set before PIN/PUK have been changed.",
    );
    reject(
        &["piv", "access", "change-management-key", "-a", "tdes"],
        "TDES not supported on YubiKey FIPS.",
    );
    for algorithm in ["rsa1024", "x25519"] {
        reject(
            &["piv", "keys", "generate", "9a", "-", "-a", algorithm],
            &format!(
                "Key type {} not supported on YubiKey FIPS.",
                algorithm.to_uppercase()
            ),
        );
    }
    reject(
        &[
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "--pin-policy",
            "never",
        ],
        "PIN policy NEVER not supported on YubiKey FIPS.",
    );
    let key = fixture_path("ec_p256_key.pem");
    reject(
        &[
            "piv",
            "keys",
            "import",
            "9a",
            key.to_str().unwrap(),
            "--pin-policy",
            "never",
        ],
        "PIN policy NEVER not supported on YubiKey FIPS.",
    );
    ykman_dev()
        .args([
            "piv",
            "keys",
            "generate",
            "9a",
            "-",
            "-m",
            FIPS_PIV_MANAGEMENT_KEY,
            "-P",
            FIPS_PIV_PIN,
        ])
        .assert()
        .success();
    ykman_dev()
        .args([
            "piv",
            "keys",
            "import",
            "9c",
            key.to_str().unwrap(),
            "-m",
            FIPS_PIV_MANAGEMENT_KEY,
            "-P",
            FIPS_PIV_PIN,
        ])
        .assert()
        .success();
    ykman_dev()
        .args([
            "piv",
            "access",
            "change-management-key",
            "--protect",
            "--generate",
            "-m",
            FIPS_PIV_MANAGEMENT_KEY,
            "-P",
            FIPS_PIV_PIN,
        ])
        .assert()
        .success();
    piv_reset_raw();
}

#[test]
fn openpgp_reports_complexity_errors_for_each_credential() {
    require_capability!("OpenPGP");
    if !app_is_fips_capable("OpenPGP") {
        skip!("OpenPGP is not FIPS capable");
    }
    if !device_info().contains("PIN complexity is enforced") {
        skip!("PIN complexity is not enforced");
    }
    openpgp_reset_raw();
    for (args, credential) in [
        (vec!["change-pin", "-P", "123456", "-n", "11111111"], "PIN"),
        (
            vec!["change-admin-pin", "-a", "12345678", "-n", "11111111"],
            "Admin PIN",
        ),
        (
            vec![
                "change-reset-code",
                "-a",
                "12345678",
                "--reset-code",
                "11111111",
            ],
            "Reset Code",
        ),
        (
            vec!["unblock-pin", "-a", "12345678", "-n", "11111111"],
            "New PIN",
        ),
    ] {
        let mut command = vec!["openpgp", "access"];
        command.extend(args);
        reject(
            &command,
            &format!("{credential} does not meet complexity requirement."),
        );
    }
    openpgp_reset_raw();
}
