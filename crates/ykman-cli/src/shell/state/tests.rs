use super::*;

#[test]
fn parses_a_listed_key() {
    let devices = parse_devices("YubiKey 5C Nano (5.7.1) [FIDO+CCID] Serial: 29654997\n");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].serial, 29654997);
    assert_eq!(devices[0].name, "YubiKey 5C Nano");
    assert_eq!(devices[0].version, "5.7.1");
}

#[test]
fn keys_without_a_serial_are_kept() {
    let devices = parse_devices("FIDO U2F Security Key (1.2.3) [FIDO]\n");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].serial, NO_SERIAL);
    assert_eq!(devices[0].name, "FIDO U2F Security Key");
}

#[test]
fn highest_serial_first_and_serial_less_last() {
    let out = "\
FIDO U2F Security Key (1.2.3) [FIDO]
YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 100
YubiKey 5C Nano (5.7.1) [FIDO+CCID] Serial: 300
YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 200
";
    let serials: Vec<u32> = parse_devices(out).iter().map(|d| d.serial).collect();
    assert_eq!(serials, [300, 200, 100, NO_SERIAL]);
}

#[test]
fn skips_lines_it_cannot_read() {
    assert!(parse_devices("").is_empty());
    assert!(parse_devices("\n\n").is_empty());
    assert!(parse_devices("not a device line\n").is_empty());
    assert!(parse_devices("YubiKey (5.7.1) [FIDO] Serial: notanumber\n").is_empty());
    assert!(parse_devices("YubiKey 5 [FIDO] Serial: 1\n").is_empty());
}

#[test]
fn state_file_is_under_a_ykman_folder() {
    if let Some(path) = state_file() {
        assert_eq!(path.file_name().unwrap(), "shell-state");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "ykman");
    }
}
