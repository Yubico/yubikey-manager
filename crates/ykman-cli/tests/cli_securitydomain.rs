mod common;

use common::ykman_dev;
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_sd_info() {
    ykman_dev()
        .args(["sd", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
#[ignore]
#[serial]
fn test_sd_reset() {
    ykman_dev().args(["sd", "reset", "-f"]).assert().success();
}
