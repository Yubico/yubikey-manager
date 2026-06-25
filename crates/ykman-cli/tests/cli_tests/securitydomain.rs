use super::common::{
    DEFAULT_SCP03_KEYS, device_info, fixture_path, is_fips, sd_reset, skip_before_version,
    ykman_dev, ykman_dev_scp,
};
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;

const TEST_SCP03_KEYS: &str = "000102030405060708090a0b0c0d0e0f:101112131415161718191a1b1c1d1e1f:202122232425262728292a2b2c2d2e2f";

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

fn scp_fixture_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/files/scp")
        .join(name);
    assert!(path.exists(), "SCP fixture not found: {}", path.display());
    path
}

#[test]
fn test_sd_info() {
    require_capability!("CCID");
    if skip_before_version((5, 7, 2), "Security Domain") {
        return;
    }
    ykman_dev()
        .args(["sd", "info"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn test_sd_reset() {
    require_capability!("CCID");
    if skip_before_version((5, 7, 2), "Security Domain") {
        return;
    }
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
    require_capability!("CCID");
    if skip_before_version((5, 7, 2), "Security Domain") {
        return;
    }
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
    require_capability!("CCID");
    if skip_before_version((5, 7, 2), "Security Domain") {
        return;
    }
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
    require_capability!("CCID");
    if skip_before_version((5, 7, 2), "Security Domain") {
        return;
    }
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
    require_capability!("CCID");
    if skip_before_version((5, 7, 2), "Security Domain") {
        return;
    }
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

#[test]
fn test_sd_scp11a_with_encrypted_scp_key() {
    require_capability!("CCID");
    if skip_before_version((5, 7, 2), "Security Domain") {
        return;
    }
    if skip_if_fips_over_nfc("Security Domain SCP11a import") {
        return;
    }
    sd_reset();

    let temp_dir = tempfile::tempdir().expect("failed to create temporary SCP directory");
    let import_scp11a_path = temp_dir.path().join("scp11a-import.pem");
    let encrypted_scp_path = temp_dir.path().join("scp11a-encrypted.pem");
    let encrypted_key = fs::read_to_string(fixture_path("ec_p256_key_enc.pem"))
        .expect("failed to read encrypted key");
    let card_cert =
        fs::read_to_string(fixture_path("ec_p256_cert.pem")).expect("failed to read card cert");
    let encrypted_oce_key = fs::read_to_string(fixture_path("sk_oce_ecka_enc.pem"))
        .expect("failed to read encrypted OCE key");
    let ka_cert = fs::read_to_string(scp_fixture_path("cert.ka-kloc.ecdsa.pem"))
        .expect("failed to read OCE intermediate cert");
    let oce_cert = fs::read_to_string(scp_fixture_path("cert.oce.ecka.pem"))
        .expect("failed to read OCE leaf cert");

    fs::write(&import_scp11a_path, format!("{encrypted_key}\n{card_cert}"))
        .expect("failed to write SCP11a import PEM");
    fs::write(
        &encrypted_scp_path,
        format!("{encrypted_oce_key}\n{ka_cert}\n{oce_cert}"),
    )
    .expect("failed to write encrypted SCP PEM");

    ykman_dev_scp()
        .args([
            "sd",
            "keys",
            "import",
            "01",
            "02",
            TEST_SCP03_KEYS,
            "-t",
            "scp03",
        ])
        .assert()
        .success();

    let mut delete_scp11b = ykman_dev();
    delete_scp11b
        .args(["--scp", TEST_SCP03_KEYS, "--scp-sd", "01", "02"])
        .args(["sd", "keys", "delete", "13", "01", "-f"])
        .assert()
        .success();

    let mut import_scp11a = ykman_dev();
    import_scp11a
        .args(["--scp", TEST_SCP03_KEYS, "--scp-sd", "01", "02"])
        .args([
            "sd",
            "keys",
            "import",
            "11",
            "7f",
            import_scp11a_path.to_str().unwrap(),
            "-t",
            "scp11",
            "--password",
            "test123",
        ])
        .assert()
        .success();

    let mut import_ca = ykman_dev();
    import_ca
        .args(["--scp", TEST_SCP03_KEYS, "--scp-sd", "01", "02"])
        .args([
            "sd",
            "keys",
            "import",
            "10",
            "03",
            scp_fixture_path("cert.ca-kloc.ecdsa.pem").to_str().unwrap(),
            "-t",
            "scp11",
        ])
        .assert()
        .success();

    ykman_dev()
        .args([
            "--scp",
            encrypted_scp_path.to_str().unwrap(),
            "--scp-password",
            "test123",
            "--scp-sd",
            "11",
            "7f",
            "--scp-oce",
            "10",
            "03",
            "sd",
            "info",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("SCP11a"));

    sd_reset();
}
