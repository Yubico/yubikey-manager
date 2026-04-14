mod common;

use common::{DEFAULT_SCP03_KEYS, sd_reset, ykman_dev, ykman_dev_scp};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[ignore]
#[serial]
fn test_sd_info() {
    require_interface!("CCID");
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
    require_interface!("CCID");
    ykman_dev().args(["sd", "reset", "-f"]).assert().success();
}

#[test]
#[ignore]
#[serial]
fn test_sd_keys_generate() {
    require_interface!("CCID");
    sd_reset();

    // Generate an EC key pair at KID=0x13 (SCP11b range), KVN=0x7F.
    // Must use --replace-kvn to replace the pre-installed SCP11b key at KVN=0x01,
    // otherwise the card removes the default SCP03 key set.
    ykman_dev_scp()
        .args([
            "sd",
            "keys",
            "generate",
            "13",
            "7f",
            "-",
            "--replace-kvn",
            "01",
        ])
        .assert()
        .success();

    sd_reset();
}

#[test]
#[ignore]
#[serial]
fn test_sd_keys_import_scp03() {
    require_interface!("CCID");
    sd_reset();

    // Import a new SCP03 key set at KVN=0x02 (default is KVN=0xFF)
    ykman_dev_scp()
        .args([
            "sd",
            "keys",
            "import",
            "01",
            "02",
            DEFAULT_SCP03_KEYS,
            "-t",
            "scp03",
        ])
        .assert()
        .success();

    sd_reset();
}

#[test]
#[ignore]
#[serial]
fn test_sd_keys_delete() {
    require_interface!("CCID");
    sd_reset();

    // Generate a key (replace pre-installed KVN=0x01 with KVN=0x7F)
    ykman_dev_scp()
        .args([
            "sd",
            "keys",
            "generate",
            "13",
            "7f",
            "/dev/null",
            "--replace-kvn",
            "01",
        ])
        .assert()
        .success();

    // Delete it
    ykman_dev_scp()
        .args(["sd", "keys", "delete", "13", "7f", "-f"])
        .assert()
        .success();

    sd_reset();
}

#[test]
#[ignore]
#[serial]
fn test_sd_keys_import_scp11() {
    require_interface!("CCID");
    sd_reset();

    // Import a CA certificate as SCP11 OCE CA key (KID=0x10).
    let ca_file = common::fixture_path("ec_p256_cert.pem");

    ykman_dev_scp()
        .args([
            "sd",
            "keys",
            "import",
            "10",
            "01",
            ca_file.to_str().unwrap(),
            "-t",
            "scp11",
        ])
        .assert()
        .success();

    sd_reset();
}
