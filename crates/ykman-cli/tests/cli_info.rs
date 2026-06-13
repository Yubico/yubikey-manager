mod common;

use common::{device_serial, ykman, ykman_dev};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[serial]
fn test_list_devices() {
    require_device_configured!();
    ykman()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
#[serial]
fn test_list_devices_serial() {
    require_device_configured!();
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
#[serial]
fn test_list_readers() {
    require_device_configured!();
    ykman()
        .args(["list", "--readers"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
#[serial]
fn test_info() {
    require_device_configured!();
    let assert = ykman_dev()
        .arg("info")
        .assert()
        .success()
        .stdout(predicate::str::contains("Firmware version:"));
    if device_serial().is_some() {
        assert.stdout(predicate::str::contains("Serial number:"));
    }
}

#[test]
#[serial]
fn test_info_check_fips() {
    require_device_configured!();
    ykman_dev()
        .args(["info", "--check-fips"])
        .assert()
        .success();
}

#[test]
#[serial]
fn test_diagnose() {
    require_device_configured!();
    ykman().arg("--diagnose").assert().success();
}
