use assert_cmd::Command;
use predicates::prelude::*;

fn ykman() -> Command {
    super::common::validate_device_if_configured();
    Command::cargo_bin("ykman").expect("binary 'ykman' not found")
}

fn assert_help(path: &[&str]) {
    let mut cmd = ykman();
    cmd.args(path).arg("--help");
    let output = cmd.output().expect("failed to run help command");
    assert!(
        output.status.success(),
        "help command failed for {:?}: {}",
        path,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "missing Usage for {path:?}");
    assert!(stdout.contains("--help"), "missing --help for {path:?}");
    assert_no_missing_arg_descriptions(path, &stdout);
}

fn assert_no_missing_arg_descriptions(path: &[&str], help: &str) {
    let lines: Vec<_> = help.lines().collect();
    let mut in_arg_section = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if line.ends_with(':') && !line.starts_with(' ') {
            in_arg_section = matches!(trimmed, "Arguments:" | "Options:");
            continue;
        }

        if !in_arg_section
            || !line.starts_with("  ")
            || !(trimmed.starts_with('-') || trimmed.starts_with('<'))
        {
            continue;
        }

        if let Some((_, description)) = trimmed.rsplit_once("  ")
            && !description.trim_start().starts_with('[')
        {
            continue;
        }

        let next = lines.get(i + 1).map(|line| line.trim()).unwrap_or("");
        assert!(
            lines
                .get(i + 1)
                .is_some_and(|line| line.starts_with("          "))
                && !next.starts_with("[possible values:")
                && !next.starts_with("[default:"),
            "missing help description for {:?}: {}",
            path,
            trimmed
        );
    }
}

#[test]
fn test_all_command_help_pages() {
    let command_paths: &[&[&str]] = &[
        &[],
        &["list"],
        &["info"],
        &["config"],
        &["config", "usb"],
        &["config", "nfc"],
        &["config", "set-lock-code"],
        &["config", "mode"],
        &["config", "reset"],
        &["oath"],
        &["oath", "info"],
        &["oath", "reset"],
        &["oath", "accounts"],
        &["oath", "accounts", "list"],
        &["oath", "accounts", "code"],
        &["oath", "accounts", "add"],
        &["oath", "accounts", "import"],
        &["oath", "accounts", "delete"],
        &["oath", "accounts", "rename"],
        &["oath", "accounts", "uri"],
        &["oath", "access"],
        &["oath", "access", "change"],
        &["oath", "access", "remember"],
        &["oath", "access", "forget"],
        &["otp"],
        &["otp", "info"],
        &["otp", "swap"],
        &["otp", "delete"],
        &["otp", "ndef"],
        &["otp", "yubiotp"],
        &["otp", "static"],
        &["otp", "chalresp"],
        &["otp", "calculate"],
        &["otp", "hotp"],
        &["otp", "settings"],
        &["piv"],
        &["piv", "info"],
        &["piv", "reset"],
        &["piv", "access"],
        &["piv", "access", "change-pin"],
        &["piv", "access", "change-puk"],
        &["piv", "access", "unblock-pin"],
        &["piv", "access", "set-retries"],
        &["piv", "access", "change-management-key"],
        &["piv", "keys"],
        &["piv", "keys", "generate"],
        &["piv", "keys", "import"],
        &["piv", "keys", "info"],
        &["piv", "keys", "attest"],
        &["piv", "keys", "export"],
        &["piv", "keys", "move"],
        &["piv", "keys", "delete"],
        &["piv", "certificates"],
        &["piv", "certificates", "export"],
        &["piv", "certificates", "import"],
        &["piv", "certificates", "delete"],
        &["piv", "certificates", "generate"],
        &["piv", "certificates", "request"],
        &["piv", "objects"],
        &["piv", "objects", "export"],
        &["piv", "objects", "import"],
        &["piv", "objects", "generate"],
        &["fido"],
        &["fido", "info"],
        &["fido", "reset"],
        &["fido", "access"],
        &["fido", "access", "change-pin"],
        &["fido", "access", "verify-pin"],
        &["fido", "access", "force-change"],
        &["fido", "access", "set-min-length"],
        &["fido", "credentials"],
        &["fido", "credentials", "list"],
        &["fido", "credentials", "delete"],
        &["fido", "credentials", "update"],
        &["fido", "fingerprints"],
        &["fido", "fingerprints", "list"],
        &["fido", "fingerprints", "add"],
        &["fido", "fingerprints", "rename"],
        &["fido", "fingerprints", "delete"],
        &["fido", "config"],
        &["fido", "config", "toggle-always-uv"],
        &["fido", "config", "enable-ep-attestation"],
        &["openpgp"],
        &["openpgp", "info"],
        &["openpgp", "reset"],
        &["openpgp", "access"],
        &["openpgp", "access", "set-retries"],
        &["openpgp", "access", "change-pin"],
        &["openpgp", "access", "change-admin-pin"],
        &["openpgp", "access", "change-reset-code"],
        &["openpgp", "access", "unblock-pin"],
        &["openpgp", "access", "set-signature-policy"],
        &["openpgp", "keys"],
        &["openpgp", "keys", "info"],
        &["openpgp", "keys", "set-touch"],
        &["openpgp", "keys", "import"],
        &["openpgp", "keys", "attest"],
        &["openpgp", "certificates"],
        &["openpgp", "certificates", "export"],
        &["openpgp", "certificates", "import"],
        &["openpgp", "certificates", "delete"],
        &["hsmauth"],
        &["hsmauth", "info"],
        &["hsmauth", "reset"],
        &["hsmauth", "credentials"],
        &["hsmauth", "credentials", "list"],
        &["hsmauth", "credentials", "generate"],
        &["hsmauth", "credentials", "symmetric"],
        &["hsmauth", "credentials", "derive"],
        &["hsmauth", "credentials", "delete"],
        &["hsmauth", "credentials", "change-password"],
        &["hsmauth", "credentials", "import"],
        &["hsmauth", "credentials", "export"],
        &["hsmauth", "access"],
        &["hsmauth", "access", "change-management-password"],
        &["sd"],
        &["sd", "info"],
        &["sd", "reset"],
        &["sd", "keys"],
        &["sd", "keys", "generate"],
        &["sd", "keys", "export"],
        &["sd", "keys", "delete"],
        &["sd", "keys", "import"],
        &["sd", "keys", "set-allowlist"],
        &["apdu"],
    ];

    for path in command_paths {
        assert_help(path);
    }
}

#[test]
fn test_parser_rejects_common_invalid_arguments_without_device() {
    let invalid: &[&[&str]] = &[
        &["--device", "not-a-number", "info"],
        &["config", "usb", "--enable", "not-an-app"],
        &[
            "config",
            "set-lock-code",
            "--new-lock-code",
            "01020304050607080102030405060708",
            "--generate",
        ],
        &[
            "config",
            "set-lock-code",
            "--clear",
            "--new-lock-code",
            "01020304050607080102030405060708",
        ],
        &["otp", "yubiotp", "1", "--enter", "--no-enter"],
        &["otp", "static", "1", "--enter", "--no-enter"],
        &[
            "otp",
            "hotp",
            "1",
            "3132333435363738393031323334353637383930",
            "--enter",
            "--no-enter",
        ],
        &["otp", "settings", "1", "--enter", "--no-enter"],
        &["piv", "keys", "generate", "9a", "-", "--algorithm", "nope"],
        &["openpgp", "keys", "info", "bad-key-ref"],
        &[
            "sd", "keys", "import", "01", "02", "--type", "bad-type", "file.pem",
        ],
    ];

    for args in invalid {
        ykman()
            .args(*args)
            .assert()
            .failure()
            .stderr(predicate::str::is_empty().not());
    }
}
