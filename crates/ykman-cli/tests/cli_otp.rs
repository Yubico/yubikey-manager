mod common;

use common::{otp_delete_slot2, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_otp_info() {
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
    otp_delete_slot2();

    // Program a static password in slot 2
    ykman_dev()
        .args(["otp", "static", "2", "--generate", "-f"])
        .assert()
        .success();

    // Verify slot 2 is now programmed
    ykman_dev()
        .args(["otp", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"Slot 2:\s+\S+").unwrap());

    // Cleanup
    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_chalresp() {
    otp_delete_slot2();

    // Program challenge-response in slot 2
    ykman_dev()
        .args(["otp", "chalresp", "2", "--generate", "-f"])
        .assert()
        .success();

    // Calculate a challenge
    ykman_dev()
        .args(["otp", "calculate", "2", "--totp"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());

    // Cleanup
    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_swap() {
    otp_delete_slot2();

    // Program slot 2 so we have something to swap
    ykman_dev()
        .args(["otp", "static", "2", "--generate", "-f"])
        .assert()
        .success();

    // Swap slots
    ykman_dev().args(["otp", "swap", "-f"]).assert().success();

    // Swap back to restore
    ykman_dev().args(["otp", "swap", "-f"]).assert().success();

    // Cleanup
    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_otp_hotp() {
    otp_delete_slot2();

    // Program HOTP in slot 2
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

    // Verify slot 2 is programmed
    ykman_dev().args(["otp", "info"]).assert().success();

    // Cleanup
    ykman_dev()
        .args(["otp", "delete", "2", "-f"])
        .assert()
        .success();
}
