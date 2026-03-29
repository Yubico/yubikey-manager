mod common;

use common::{DEVICE_SERIAL, ykman, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_list_devices() {
    ykman()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
#[ignore]
#[serial]
fn test_list_devices_serial() {
    ykman()
        .args(["list", "--serials"])
        .assert()
        .success()
        .stdout(predicate::str::contains(DEVICE_SERIAL));
}

#[test]
#[ignore]
#[serial]
fn test_info() {
    ykman_dev().arg("info").assert().success().stdout(
        predicate::str::contains("Serial number:")
            .and(predicate::str::contains("Firmware version:")),
    );
}

#[test]
#[ignore]
#[serial]
fn test_info_check_fips() {
    ykman_dev()
        .args(["info", "--check-fips"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_diagnose() {
    ykman().arg("--diagnose").assert().success();
}
