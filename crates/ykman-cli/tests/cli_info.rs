mod common;

use common::{device_serial, ykman, ykman_dev};
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
    let serial = match device_serial() {
        Some(s) => s,
        None => return,
    };
    ykman()
        .args(["list", "--serials"])
        .assert()
        .success()
        .stdout(predicate::str::contains(serial));
}

#[test]
#[ignore]
#[serial]
fn test_list_readers() {
    ykman()
        .args(["list", "--readers"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
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
