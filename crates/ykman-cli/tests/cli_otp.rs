mod common;

use common::{otp_delete_slot2, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_otp_info() {
    require_interface!("OTP");
    ykman_dev()
        .args(["otp", "info"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Slot 1:").and(predicate::str::contains("Slot 2:")));
}

#[test]
#[ignore]
#[serial]
fn test_otp_static() {
    require_interface!("OTP");
    otp_delete_slot2();

    ykman_dev()
        .args(["otp", "static", "2", "--generate", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["otp", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"Slot 2:\s+\S+").unwrap());

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_chalresp() {
    require_interface!("OTP");
    otp_delete_slot2();

    ykman_dev()
        .args(["otp", "chalresp", "2", "--generate", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["otp", "calculate", "2", "--totp"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_swap() {
    require_interface!("OTP");
    otp_delete_slot2();

    ykman_dev()
        .args(["otp", "static", "2", "--generate", "-f"])
        .assert()
        .success();

    ykman_dev().args(["otp", "swap", "-f"]).assert().success();

    ykman_dev().args(["otp", "swap", "-f"]).assert().success();

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_hotp() {
    require_interface!("OTP");
    otp_delete_slot2();

    ykman_dev()
        .args([
            "otp",
            "hotp",
            "2",
            "3132333435363738393031323334353637383930",
            "-f",
        ])
        .assert()
        .success();

    ykman_dev().args(["otp", "info"]).assert().success();

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_yubiotp() {
    require_interface!("OTP");
    otp_delete_slot2();

    // Program Yubico OTP in slot 2 with auto-generated IDs and key
    ykman_dev()
        .args([
            "otp",
            "yubiotp",
            "2",
            "--serial-public-id",
            "-g",
            "-G",
            "-f",
        ])
        .assert()
        .success();

    ykman_dev()
        .args(["otp", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"Slot 2:\s+\S+").unwrap());

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_calculate_standalone() {
    require_interface!("OTP");
    otp_delete_slot2();

    // Program challenge-response in slot 2
    ykman_dev()
        .args(["otp", "chalresp", "2", "--generate", "-f"])
        .assert()
        .success();

    // Calculate with a hex challenge
    ykman_dev()
        .args(["otp", "calculate", "2", "aabbccdd"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_calculate_totp_8digits() {
    require_interface!("OTP");
    otp_delete_slot2();

    ykman_dev()
        .args(["otp", "chalresp", "2", "--generate", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["otp", "calculate", "2", "--totp", "--digits", "8"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d{8}").unwrap());

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_delete() {
    require_interface!("OTP");
    otp_delete_slot2();

    // Program slot 2
    ykman_dev()
        .args(["otp", "static", "2", "--generate", "-f"])
        .assert()
        .success();

    // Verify slot 2 is programmed
    ykman_dev()
        .args(["otp", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"Slot 2:\s+\S+").unwrap());

    // Delete slot 2
    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();

    // Verify slot 2 is empty
    ykman_dev().args(["otp", "info"]).assert().success().stdout(
        predicate::str::contains("Slot 2: empty").or(predicate::str::contains("Slot 2: Empty")),
    );
}

#[test]
#[ignore]
#[serial]
fn test_otp_static_length() {
    require_interface!("OTP");
    otp_delete_slot2();

    ykman_dev()
        .args(["otp", "static", "2", "--generate", "--length", "20", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["otp", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"Slot 2:\s+\S+").unwrap());

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_hotp_8digits() {
    require_interface!("OTP");
    otp_delete_slot2();

    ykman_dev()
        .args([
            "otp",
            "hotp",
            "2",
            "3132333435363738393031323334353637383930",
            "--digits",
            "8",
            "-f",
        ])
        .assert()
        .success();

    ykman_dev().args(["otp", "info"]).assert().success();

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_settings_enter() {
    require_interface!("OTP");
    otp_delete_slot2();

    // Program a static password first
    ykman_dev()
        .args(["otp", "static", "2", "--generate", "-f"])
        .assert()
        .success();

    // Update settings to append Enter
    ykman_dev()
        .args(["otp", "settings", "2", "--enter", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_ndef() {
    require_interface!("OTP");
    otp_delete_slot2();

    // Program slot 2
    ykman_dev()
        .args(["otp", "static", "2", "--generate", "-f"])
        .assert()
        .success();

    // Configure NDEF for slot 2
    ykman_dev()
        .args(["otp", "ndef", "2", "-f"])
        .assert()
        .success();

    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}
