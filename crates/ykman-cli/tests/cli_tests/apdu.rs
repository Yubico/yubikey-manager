use super::common::ykman_dev;
use predicates::prelude::*;

#[test]
fn test_apdu_select_oath() {
    require_capability!("OATH");
    // Send a LIST instruction (0xa1) to the OATH applet
    ykman_dev()
        .args(["apdu", "-a", "oath", "a1"])
        .assert()
        .success();
}

#[test]
fn test_apdu_hex_format() {
    require_capability!("OATH");
    // Send LIST instruction with hex-only output
    ykman_dev()
        .args(["apdu", "-x", "-a", "oath", "a1"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn test_apdu_send_flag() {
    require_capability!("OATH");
    // Send a raw SELECT APDU via the -s flag (SELECT OATH AID)
    ykman_dev()
        .args(["apdu", "-s", "00a4040008a000000527210101"])
        .assert()
        .success();
}

#[test]
fn test_apdu_expected_sw() {
    require_capability!("OATH");
    // SELECT works regardless of whether the applet is password-protected.
    ykman_dev()
        .args(["apdu", "00a40400:a000000527210101=9000"])
        .assert()
        .success();
}
