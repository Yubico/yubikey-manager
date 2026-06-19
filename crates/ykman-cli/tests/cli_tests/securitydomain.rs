use super::common::{
    DEFAULT_SCP03_KEYS, device_info, fixture_path, is_fips, sd_reset, ykman_dev, ykman_dev_scp,
};
use predicates::prelude::*;

fn selected_over_nfc() -> bool {
    !device_info()
        .lines()
        .any(|line| line.starts_with("Enabled USB interfaces:"))
}

fn skip_if_fips_over_nfc(feature: &str) -> bool {
    if is_fips() && selected_over_nfc() {
        eprintln!("SKIP: {feature} is not safe on FIPS YubiKeys over NFC");
        true
    } else {
        false
    }
}

#[test]
fn test_sd_info() {
    require_interface!("CCID");
    ykman_dev()
        .args(["sd", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn test_sd_reset() {
    require_interface!("CCID");
    if is_fips() && selected_over_nfc() {
        ykman_dev()
            .args(["sd", "reset", "-f"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Security Domain reset is not supported for FIPS YubiKeys over NFC. \
                 Connect the YubiKey over USB and try again.",
            ));
        return;
    }

    ykman_dev().args(["sd", "reset", "-f"]).assert().success();
}

#[test]
fn test_sd_keys_generate() {
    require_interface!("CCID");
    if skip_if_fips_over_nfc("Security Domain key generation") {
        return;
    }
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
fn test_sd_keys_import_scp03() {
    require_interface!("CCID");
    if skip_if_fips_over_nfc("Security Domain SCP03 import") {
        return;
    }
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
fn test_sd_keys_delete() {
    require_interface!("CCID");
    if skip_if_fips_over_nfc("Security Domain key deletion") {
        return;
    }
    sd_reset();

    let output_dir = tempfile::tempdir().expect("failed to create temporary output directory");
    let output_path = output_dir.path().join("scp11b.pem");
    let output_path = output_path
        .to_str()
        .expect("temporary output path is not UTF-8");

    // Generate a key (replace pre-installed KVN=0x01 with KVN=0x7F)
    ykman_dev_scp()
        .args([
            "sd",
            "keys",
            "generate",
            "13",
            "7f",
            output_path,
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
fn test_sd_keys_import_scp11() {
    require_interface!("CCID");
    if skip_if_fips_over_nfc("Security Domain SCP11 import") {
        return;
    }
    sd_reset();

    // Import a CA certificate as SCP11 OCE CA key (KID=0x10).
    let ca_file = fixture_path("ec_p256_cert.pem");

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
