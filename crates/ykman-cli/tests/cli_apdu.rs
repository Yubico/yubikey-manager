mod common;

use common::ykman_dev;
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_apdu_select_oath() {
    // Send a LIST instruction (0xa1) to the OATH applet
    ykman_dev()
        .args(["apdu", "-a", "oath", "a1"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_apdu_hex_format() {
    // Send LIST instruction with hex-only output
    ykman_dev()
        .args(["apdu", "-x", "-a", "oath", "a1"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
#[ignore]
#[serial]
fn test_apdu_send_flag() {
    // Send a raw SELECT APDU via the -s flag (SELECT OATH AID)
    ykman_dev()
        .args(["apdu", "-s", "00a4040008a000000527210101"])
        .assert()
        .success();
}

#[test]
#[ignore]
#[serial]
fn test_apdu_expected_sw() {
    // Send LIST with expected SW=9000
    ykman_dev()
        .args(["apdu", "-a", "oath", "a1=9000"])
        .assert()
        .success();
}
