use super::*;
use yubikit::yubiotp::{HmacKey, Slot, SlotConfiguration, YubiOtpSession};

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_yubiotp_session_version(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OTP);
    match tc {
        TestConnection::UsbHid => {
            require_transport!(Transport::Usb);
            let conn = get_device().open_otp().expect("open OTP");
            let session = YubiOtpSession::new_otp(conn).expect("YubiOtpSession::new_otp");
            let _v = session.version();
        }
        _ => {
            let conn = open_smartcard_connection(&tc);
            let session = if let Some((kid, kvn, ref pk)) = scp_params(&tc) {
                let params = make_scp_key_params(kid, kvn, pk);
                YubiOtpSession::new_with_scp(conn, &params).expect("YubiOtpSession with SCP")
            } else {
                YubiOtpSession::new(conn).expect("YubiOtpSession::new")
            };
            let _v = session.version();
        }
    }
}

#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_yubiotp_slot_configuration(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OTP);

    let conn = open_smartcard_connection(&tc);
    let mut session = YubiOtpSession::new(conn).expect("YubiOtpSession");

    // Check initial state
    let state = session.get_config_state();
    let _slot2_was_configured = state.is_configured(Slot::Two).unwrap_or(false);

    // Program slot 2 with HMAC-SHA1 (no touch)
    let hmac_key = HmacKey::new(&[0x42; 20]).unwrap();
    let config = SlotConfiguration::hmac_sha1(&hmac_key)
        .expect("hmac config")
        .require_touch(false);
    session
        .put_configuration(Slot::Two, &config, None, None)
        .expect("put hmac config");

    // Verify slot 2 is now configured
    let state = session.get_config_state();
    assert!(
        state.is_configured(Slot::Two).unwrap_or(false),
        "Slot 2 should be configured"
    );

    // Swap slots
    session.swap_slots().expect("swap_slots");

    // Slot 1 should now be configured (was slot 2)
    let state = session.get_config_state();
    assert!(
        state.is_configured(Slot::One).unwrap_or(false),
        "Slot 1 should be configured after swap"
    );

    // Swap back
    session.swap_slots().expect("swap_slots back");

    // Delete slot 2
    session.delete_slot(Slot::Two, None).expect("delete slot 2");

    // Verify slot 2 is no longer configured
    let state = session.get_config_state();
    assert!(
        !state.is_configured(Slot::Two).unwrap_or(true),
        "Slot 2 should be empty after delete"
    );
}

/// Test that cancelling an OTP HMAC challenge-response with touch works.
///
/// Programs slot 2 with HMAC-SHA1 + require_touch, starts a
/// calculate_hmac_sha1 and immediately cancels it, verifying
/// that it returns a Timeout error promptly.
#[rstest]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_calculate_hmac_sha1_cancel(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OTP);
    require_transport!(Transport::Usb);

    let dev = get_device();

    // Program slot 2 with HMAC-SHA1 requiring touch (use CCID)
    {
        let conn = dev.open_smartcard().expect("open smartcard");
        let mut session = YubiOtpSession::new(conn).expect("YubiOtpSession");
        let hmac_key = HmacKey::new(&[0x0b; 20]).unwrap();
        let config = SlotConfiguration::hmac_sha1(&hmac_key)
            .expect("hmac config")
            .require_touch(true);
        session
            .put_configuration(Slot::Two, &config, None, None)
            .expect("put_configuration");
    }

    // Open OTP session and attempt calculate, cancel after first keepalive
    let conn = dev.open_otp().expect("open OTP");
    let mut session = YubiOtpSession::new_otp(conn).expect("YubiOtpSession");

    let got_keepalive = std::sync::atomic::AtomicBool::new(false);
    let start = std::time::Instant::now();
    let result = session.calculate_hmac_sha1_with_cancel(
        Slot::Two,
        b"test challenge",
        Some(&|| got_keepalive.load(std::sync::atomic::Ordering::Relaxed)),
        Some(&|_status| {
            got_keepalive.store(true, std::sync::atomic::Ordering::Relaxed);
        }),
    );
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Expected error from cancelled operation");
    let err_msg = result.unwrap_err().to_string();
    if err_msg.contains("No data") {
        skip!("HMAC challenge-response not supported over OTP HID on this key");
    }
    assert!(
        err_msg.contains("cancelled") || err_msg.contains("Timeout"),
        "Expected cancel/timeout error, got: {err_msg}"
    );
    assert!(
        elapsed.as_secs() < 10,
        "Cancel took too long: {elapsed:?} (expected < 10s)"
    );

    // Clean up: delete slot 2
    {
        let conn = dev.open_smartcard().expect("open smartcard");
        let mut session = YubiOtpSession::new(conn).expect("YubiOtpSession");
        session.delete_slot(Slot::Two, None).expect("delete slot");
    }
}

/// Test HMAC-SHA1 challenge-response with a known test vector.
/// Key: 0x0b repeated 20 times. Challenge: "Hi There"
/// Expected HMAC-SHA1: b617318655057264e28bc0b6fb378c8ef146be00
///
/// HMAC challenge-response works over OTP HID (USB) or CCID (NFC only).
#[rstest]
#[case::usb_hid(TestConnection::UsbHid)]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_hmac_sha1_known_vector(#[case] tc: TestConnection) {
    skip_if_needed!(tc);
    require_capability!(Capability::OTP);

    match tc {
        TestConnection::UsbHid => {
            require_transport!(Transport::Usb);
        }
        _ => {
            // HMAC challenge-response over CCID only works on NFC
            require_transport!(Transport::Nfc);
        }
    }

    let dev = get_device();
    let hmac_key = HmacKey::new(&[0x0b; 20]).unwrap();

    // Program slot 2 with the test key via CCID (no touch required)
    {
        let conn = dev.open_smartcard().expect("open smartcard");
        let mut session = YubiOtpSession::new(conn).expect("YubiOtpSession");
        let config = SlotConfiguration::hmac_sha1(&hmac_key)
            .expect("hmac config")
            .require_touch(false);
        session
            .put_configuration(Slot::Two, &config, None, None)
            .expect("put_configuration");
    }

    let expected: [u8; 20] = [
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c,
        0x8e, 0xf1, 0x46, 0xbe, 0x00,
    ];

    match tc {
        TestConnection::UsbHid => {
            let conn = dev.open_otp().expect("open OTP");
            let mut session = YubiOtpSession::new_otp(conn).expect("YubiOtpSession OTP");
            let result = session.calculate_hmac_sha1(Slot::Two, b"Hi There");
            match result {
                Err(ref e) if e.to_string().contains("No data") => {
                    skip!("HMAC challenge-response not supported over OTP HID on this key");
                }
                _ => {}
            }
            let result = result.expect("calculate_hmac_sha1");
            assert_eq!(result, expected, "HMAC-SHA1 test vector mismatch");
        }
        _ => {
            let conn = open_smartcard_connection(&tc);
            let mut session = if let Some((kid, kvn, ref pk)) = scp_params(&tc) {
                let params = make_scp_key_params(kid, kvn, pk);
                YubiOtpSession::new_with_scp(conn, &params).expect("YubiOtpSession with SCP")
            } else {
                YubiOtpSession::new(conn).expect("YubiOtpSession")
            };
            let result = session
                .calculate_hmac_sha1(Slot::Two, b"Hi There")
                .expect("calculate_hmac_sha1");
            assert_eq!(result, expected, "HMAC-SHA1 test vector mismatch");
        }
    }

    // Clean up via CCID
    {
        let conn = dev.open_smartcard().expect("open smartcard");
        let mut session = YubiOtpSession::new(conn).expect("YubiOtpSession");
        session.delete_slot(Slot::Two, None).expect("delete slot");
    }
}
