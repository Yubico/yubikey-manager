use super::*;
use crate::controller::Controller;
use std::sync::Arc;
use yubikit::ctap::CtapSession;
use yubikit::ctap2::{
    Aaguid, ClientPin, CredentialManagement, Ctap2Error, Ctap2Pin, Ctap2Session, CtapStatus,
    LargeBlobs, Permissions, PinProtocol, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialUserEntity,
};

const TEST_PIN: &str = "12345679";
const TEST_RP_ID: &str = "test.rs.yubikey.example";

fn ctap2_pin(pin: &str) -> Ctap2Pin {
    Ctap2Pin::new(pin).unwrap()
}

/// Get the appropriate controller for the current device transport.
/// Returns None if USB and no CONTROLLER env var is set (test should skip).
fn get_controller() -> Option<Arc<dyn Controller>> {
    let dev = get_device();
    controller::get_controller(dev.transport(), dev.reader_name.as_deref()).map(Arc::from)
}

/// Reinsert (power-cycle) the device using `YubiKeyDevice::reinsert`,
/// delegating the physical remove/insert to the Controller.
///
/// For USB, uses the library's polling-based reinsert (detects device
/// removal/reinsertion on the bus) with the Controller triggering the
/// physical power cycle. For NFC, calls remove+insert directly since
/// the card stays physically on the reader (no removal to detect).
fn reinsert_device() {
    let transport = get_device().transport();
    let ctrl = {
        let dev = get_device();
        controller::get_controller(dev.transport(), dev.reader_name.as_deref())
            .expect("reinsert_device requires a controller")
    };

    match transport {
        Transport::Nfc => {
            // NFC: card is physically on reader; controller handles the
            // full power cycle (unpower field + reset). No bus-level
            // removal to detect.
            ctrl.remove();
            ctrl.insert();
        }
        Transport::Usb => {
            let mut dev = DEVICE.get().unwrap().write().unwrap();
            dev.reinsert(
                &|status| match status {
                    ReinsertStatus::Remove => ctrl.remove(),
                    ReinsertStatus::Reinsert => ctrl.insert(),
                },
                &|| false,
            )
            .expect("reinsert failed");

            set_touch_threshold(&dev);
        }
    }
}

/// Get the controller, skipping the test if unavailable.
macro_rules! require_controller {
    () => {
        match get_controller() {
            Some(c) => c,
            None => {
                skip!("no controller available (set CONTROLLER env var for USB)");
            }
        }
    };
}

/// Reset the UP budget before an operation that requires user presence.
///
/// On NFC this power-cycles the card (reinsert) so the "recently powered
/// up" window is refreshed. On USB this is a no-op because UP is satisfied
/// by physical touch via the controller's keepalive callback on HID.
fn reset_up_budget() {
    if get_device().transport() == Transport::Nfc {
        reinsert_device();
    }
}

/// Check PIN state and determine if a reset is needed.
/// Returns `Ok(true)` if PIN is already TEST_PIN (no action needed),
/// `Ok(false)` if reset is needed,
/// or `Err(false)` if reset is not allowed on this transport.
fn check_pin_state<C: yubikit::core::Connection + 'static>(
    mut session: Ctap2Session<C>,
) -> Result<bool, bool> {
    let info = session
        .get_info()
        .unwrap_or_else(|e| panic!("FIDO setup: get_info: {e}"));
    let pin_set = info.options.get("clientPin").copied().unwrap_or(false);
    if !pin_set {
        return Ok(false);
    }
    // PIN is set — try to verify it's already TEST_PIN.
    let mut cp = ClientPin::new(session)
        .map_err(|(e, _)| panic!("FIDO setup: ClientPin::new failed: {e}"))
        .unwrap();
    match cp.get_pin_token(&ctap2_pin(TEST_PIN), None, None) {
        Ok(_) => Ok(true),
        Err(Ctap2Error::StatusError(CtapStatus::PinInvalid))
        | Err(Ctap2Error::StatusError(CtapStatus::PinAuthBlocked))
        | Err(Ctap2Error::StatusError(CtapStatus::PinBlocked)) => {
            // Wrong PIN or blocked — reset required.
            if !info.transports_for_reset.is_empty() {
                let current = match get_device().transport() {
                    Transport::Usb => "usb",
                    Transport::Nfc => "nfc",
                };
                if !info
                    .transports_for_reset
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(current))
                {
                    eprintln!(
                        "FIDO setup: reset not allowed over {current} \
                         (transports_for_reset={:?}); skipping PIN tests",
                        info.transports_for_reset
                    );
                    return Err(false);
                }
            }
            Ok(false)
        }
        Err(e) => {
            panic!("FIDO setup: unexpected error checking PIN: {e}");
        }
    }
}

/// One-time setup: ensure the FIDO PIN is in a known state.
fn setup_fido_pin() -> bool {
    use yubikit::platform::hidapi::HidFidoConnection;

    eprintln!("FIDO setup: initializing PIN state...");

    let is_usb = get_device().transport() == Transport::Usb;

    // Helper closures for opening sessions on the appropriate transport.
    let open_hid = || -> Result<Ctap2Session<HidFidoConnection>, String> {
        let conn = get_device().open_fido().map_err(|e| e.to_string())?;
        let ctap = CtapSession::new_fido(conn).map_err(|(e, _)| e.to_string())?;
        Ctap2Session::new(ctap).map_err(|(e, _)| e.to_string())
    };
    let open_nfc = || -> Result<Ctap2Session<PcscSmartCardConnection>, String> {
        let conn = open_smartcard_connection(&TestConnection::SmartCard);
        let ctap = CtapSession::new(conn).map_err(|(e, _)| e.to_string())?;
        Ctap2Session::new(ctap).map_err(|(e, _)| e.to_string())
    };

    // Check current PIN state.
    let needs_reset = if is_usb {
        let session = open_hid().unwrap_or_else(|e| panic!("FIDO setup: open failed: {e}"));
        match check_pin_state(session) {
            Ok(true) => {
                eprintln!("FIDO setup: PIN already set to TEST_PIN, no reset needed");
                return true;
            }
            Ok(false) => true,
            Err(_) => return false,
        }
    } else {
        let session = open_nfc().unwrap_or_else(|e| panic!("FIDO setup: open failed: {e}"));
        match check_pin_state(session) {
            Ok(true) => {
                eprintln!("FIDO setup: PIN already set to TEST_PIN, no reset needed");
                return true;
            }
            Ok(false) => true,
            Err(_) => return false,
        }
    };

    if needs_reset {
        eprintln!("FIDO setup: PIN mismatch or blocked, resetting applet...");
        let Some(ctrl) = get_controller() else {
            eprintln!("FIDO setup: no controller available, cannot reset");
            return false;
        };
        // Reinsert to satisfy the "recently powered up" window for FIDO reset.
        reinsert_device();

        if is_usb {
            let mut session =
                open_hid().unwrap_or_else(|e| panic!("FIDO setup: open (post-reinsert): {e}"));
            let info = session.get_info().ok();
            let long_touch = info
                .as_ref()
                .map(|i| i.long_touch_for_reset)
                .unwrap_or(false);
            if long_touch {
                ctrl.touch();
            }
            let result = session.reset(
                Some(&mut |status: u8| {
                    if status == 0x02 && !long_touch {
                        ctrl.touch();
                    }
                }),
                None,
            );
            if long_touch {
                ctrl.release();
            }
            result.unwrap_or_else(|e| panic!("FIDO setup: reset failed: {e}"));
        } else {
            let mut session =
                open_nfc().unwrap_or_else(|e| panic!("FIDO setup: open (post-reinsert): {e}"));
            let info = session.get_info().ok();
            let long_touch = info
                .as_ref()
                .map(|i| i.long_touch_for_reset)
                .unwrap_or(false);
            if long_touch {
                ctrl.touch();
            }
            let result = session.reset(
                Some(&mut |status: u8| {
                    if status == 0x02 && !long_touch {
                        ctrl.touch();
                    }
                }),
                None,
            );
            if long_touch {
                ctrl.release();
            }
            result.unwrap_or_else(|e| panic!("FIDO setup: reset failed: {e}"));
        }
        eprintln!("FIDO setup: reset done");
    }

    // Set the PIN on a fresh connection (avoids stale cached state after reset).
    if is_usb {
        let session = open_hid().unwrap_or_else(|e| panic!("FIDO setup: re-open after reset: {e}"));
        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .unwrap_or_else(|e| panic!("FIDO setup: ClientPin::new failed: {e}"));
        match cp.set_pin(&ctap2_pin(TEST_PIN)) {
            Ok(()) => {}
            Err(Ctap2Error::StatusError(CtapStatus::PinPolicyViolation)) => {
                eprintln!(
                    "FIDO setup: TEST_PIN rejected by PIN complexity policy; \
                     skipping PIN-dependent tests"
                );
                return false;
            }
            Err(e) => panic!("FIDO setup: set_pin failed: {e}"),
        }
    } else {
        let session = open_nfc().unwrap_or_else(|e| panic!("FIDO setup: re-open after reset: {e}"));
        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .unwrap_or_else(|e| panic!("FIDO setup: ClientPin::new failed: {e}"));
        match cp.set_pin(&ctap2_pin(TEST_PIN)) {
            Ok(()) => {}
            Err(Ctap2Error::StatusError(CtapStatus::PinPolicyViolation)) => {
                eprintln!(
                    "FIDO setup: TEST_PIN rejected by PIN complexity policy; \
                     skipping PIN-dependent tests"
                );
                return false;
            }
            Err(e) => panic!("FIDO setup: set_pin failed: {e}"),
        }
    }
    eprintln!("FIDO setup: PIN set to TEST_PIN");
    true
}

fn ensure_fido_pin() -> bool {
    use std::sync::OnceLock;
    static FIDO_PIN_READY: OnceLock<bool> = OnceLock::new();
    *FIDO_PIN_READY.get_or_init(setup_fido_pin)
}

/// Skip the calling test if the global FIDO PIN setup failed.
macro_rules! require_fido_pin {
    () => {
        if std::env::var("YUBIKEY_SERIAL").is_err() && std::env::var("YUBIKEY_NO_SERIAL").is_err() {
            skip!("YUBIKEY_SERIAL or YUBIKEY_NO_SERIAL not set");
        }
        if !ensure_fido_pin() {
            skip!("FIDO reset blocked for current transport (see setup output)");
        }
    };
}

/// Whether the FIDO CCID interface is usable.
///
/// Over NFC it is always available; over USB the FIDOCCID capability must be
/// enabled in the device's configuration.
fn fido_ccid_available() -> bool {
    let dev = get_device();
    if dev.transport() == Transport::Nfc {
        return true;
    }
    dev.info()
        .config
        .enabled_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE)
        .contains(Capability::FIDOCCID)
}

/// Skip a SmartCard / SmartCardScp11b test if FIDOCCID is not enabled over USB.
macro_rules! require_fido_ccid {
    ($tc:expr) => {
        if matches!(
            $tc,
            TestConnection::SmartCard | TestConnection::SmartCardScp11b
        ) && !fido_ccid_available()
        {
            skip!("{:?}: FIDOCCID not enabled over USB", $tc);
        }
    };
}

/// Get a PIN token, skipping the test if the PIN is wrong or auth is blocked.
macro_rules! get_pin_token_or_skip {
    ($cp:expr, $pin:expr, $perms:expr, $rpid:expr) => {
        match $cp.get_pin_token($pin, $perms, $rpid) {
            Ok(t) => t,
            Err(Ctap2Error::StatusError(CtapStatus::PinInvalid)) => {
                skip!("device PIN is not TEST_PIN; reset FIDO applet to rerun");
            }
            Err(Ctap2Error::StatusError(CtapStatus::PinAuthBlocked)) => {
                skip!("PIN auth blocked (re-power/re-tap device to clear)");
            }
            Err(e) => panic!("get_pin_token failed: {e}"),
        }
    };
}

/// Run a FIDO test body against any transport variant.
///
/// Handles skip checks (FIDO2 capability, FIDOCCID for SmartCard, USB for HID),
/// then provides an `open` closure and the authenticator `info` to the body.
/// Call `open()` to get a new `Ctap2Session` — can be called multiple times
/// for tests that need separate sessions (e.g. with reset_up_budget between).
macro_rules! with_fido_session {
    ($tc:expr, |$open:ident, $info:ident| $body:block) => {{
        skip_if_needed!($tc);
        require_capability!(Capability::FIDO2);
        match &$tc {
            TestConnection::UsbHid => {
                require_transport!(Transport::Usb);
                let $open = || {
                    let conn = get_device().open_fido().expect("open FIDO HID");
                    let ctap = CtapSession::new_fido(conn)
                        .map_err(|(e, _)| e)
                        .expect("CtapSession::new_fido");
                    Ctap2Session::new(ctap)
                        .map_err(|(e, _)| e)
                        .expect("Ctap2Session::new")
                };
                let mut _probe = $open();
                let $info = _probe.get_info().expect("get_info");
                drop(_probe);
                $body
            }
            _ => {
                require_fido_ccid!($tc);
                let $open = || {
                    let conn = open_smartcard_connection(&$tc);
                    let ctap = if let Some((kid, kvn, ref pk)) = scp_params(&$tc) {
                        let params = make_scp_key_params(kid, kvn, pk);
                        CtapSession::new_with_scp(conn, &params)
                            .map_err(|(e, _)| e)
                            .expect("CtapSession::new_with_scp")
                    } else {
                        CtapSession::new(conn)
                            .map_err(|(e, _)| e)
                            .expect("CtapSession::new")
                    };
                    Ctap2Session::new(ctap)
                        .map_err(|(e, _)| e)
                        .expect("Ctap2Session::new")
                };
                let mut _probe = $open();
                let $info = _probe.get_info().expect("get_info");
                drop(_probe);
                $body
            }
        }
    }};
}

/// [`UserInteraction`] for tests: uses the controller for UP, always returns `TEST_PIN`.
struct TestInteraction {
    controller: Arc<dyn Controller>,
}

impl TestInteraction {
    fn new() -> Self {
        Self {
            controller: get_controller()
                .expect("TestInteraction requires a controller (set CONTROLLER for USB)"),
        }
    }
}

impl yubikit::webauthn::UserInteraction for TestInteraction {
    fn prompt_up(&self) {
        self.controller.touch();
    }
    fn request_pin(&self, _permissions: Permissions, _rp_id: Option<&str>) -> Option<Ctap2Pin> {
        Some(ctap2_pin(TEST_PIN))
    }
    fn request_uv(&self, _permissions: Permissions, _rp_id: Option<&str>) -> bool {
        false
    }
}

// ── Generic helpers (work for any C: Connection + 'static) ───────────────

/// Verify that authenticatorGetInfo returns valid data on all transports.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_get_info(#[case] tc: TestConnection) {
    with_fido_session!(tc, |_open, info| {
        assert!(!info.versions.is_empty(), "versions should not be empty");
        assert!(
            info.versions.iter().any(|v| v.starts_with("FIDO_2_")),
            "expected a FIDO_2_x version, got: {:?}",
            info.versions
        );
        assert_ne!(info.aaguid, Aaguid::NONE, "AAGUID should not be all zeros");
        assert!(!info.options.is_empty(), "options should not be empty");
    });
}

/// Verify that PIN retries can be read (no UP required) on all transports.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_pin_retries(#[case] tc: TestConnection) {
    with_fido_session!(tc, |open, info| {
        if info.options.get("clientPin") != Some(&true) {
            skip!("clientPin not supported or not configured");
        }
        let session = open();
        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .expect("ClientPin::new");
        match cp.get_pin_retries() {
            Ok((retries, _)) => {
                assert!(retries <= 8, "retries should be <= 8, got {retries}");
            }
            Err(Ctap2Error::StatusError(CtapStatus::PinNotSet)) => {
                eprintln!("PIN not set (no retries to report)");
            }
            Err(e) => panic!("get_pin_retries: {e}"),
        }
    });
}

/// Exercise ClientPin operations: get token, wrong pin, change pin.
///
/// Tests both PIN protocol versions across all transports.
/// Changes the PIN during the test and restores it at the end.
#[rstest]
#[case::smart_card_v1(TestConnection::SmartCard, PinProtocol::V1)]
#[case::smart_card_v2(TestConnection::SmartCard, PinProtocol::V2)]
#[case::scp11b_v1(TestConnection::SmartCardScp11b, PinProtocol::V1)]
#[case::scp11b_v2(TestConnection::SmartCardScp11b, PinProtocol::V2)]
#[case::usb_hid_v1(TestConnection::UsbHid, PinProtocol::V1)]
#[case::usb_hid_v2(TestConnection::UsbHid, PinProtocol::V2)]
fn test_ctap2_client_pin(#[case] tc: TestConnection, #[case] protocol: PinProtocol) {
    require_fido_pin!();
    with_fido_session!(tc, |open, info| {
        if info.options.get("clientPin") != Some(&true) {
            skip!("clientPin not set");
        }
        let supported_protocols = &info.pin_uv_protocols;
        if !supported_protocols.contains(&protocol.version()) {
            skip!(
                "PIN protocol {} not supported (supported: {:?})",
                protocol.version(),
                supported_protocols
            );
        }

        // ── Get PIN token with correct PIN ───────────────────────────────
        let session = open();
        let mut cp = ClientPin::new_with_protocol(session, protocol);
        let token = get_pin_token_or_skip!(cp, &ctap2_pin(TEST_PIN), None, None);
        assert!(!token.is_empty(), "PIN token should not be empty");

        // ── Get PIN token with permissions ───────────────────────────────
        let token2 = get_pin_token_or_skip!(
            cp,
            &ctap2_pin(TEST_PIN),
            Some(Permissions::CREDENTIAL_MGMT),
            None
        );
        assert!(!token2.is_empty());

        // ── Wrong PIN should fail ────────────────────────────────────────
        let wrong_result = cp.get_pin_token(&ctap2_pin("wrong-pin-999"), None, None);
        match wrong_result {
            Err(Ctap2Error::StatusError(CtapStatus::PinInvalid)) => {
                // Expected result: wrong PIN should be rejected.
            }
            Err(e) => panic!("unexpected error for wrong PIN: {e}"),
            Ok(_) => panic!("wrong PIN should not succeed"),
        }

        // ── PIN retries should have decreased ────────────────────────────
        let (retries, _) = cp.get_pin_retries().expect("get_pin_retries");
        assert!(retries < 8, "retries should have decreased");

        // ── Change PIN ───────────────────────────────────────────────────
        const TEMP_PIN: &str = "99887766";
        match cp.change_pin(&ctap2_pin(TEST_PIN), &ctap2_pin(TEMP_PIN)) {
            Ok(()) => {}
            Err(Ctap2Error::StatusError(CtapStatus::PinPolicyViolation)) => {
                skip!("PIN complexity policy rejected TEMP_PIN");
            }
            Err(e) => panic!("change_pin to TEMP_PIN: {e}"),
        }

        // Verify new PIN works
        let token3 = cp
            .get_pin_token(&ctap2_pin(TEMP_PIN), None, None)
            .expect("get_pin_token with TEMP_PIN");
        assert!(!token3.is_empty());

        // Old PIN should fail now
        match cp.get_pin_token(&ctap2_pin(TEST_PIN), None, None) {
            Err(Ctap2Error::StatusError(CtapStatus::PinInvalid)) => {
                // Expected result: old PIN should no longer work.
            }
            Err(e) => {
                // Restore PIN before panicking
                let _ = cp.change_pin(&ctap2_pin(TEMP_PIN), &ctap2_pin(TEST_PIN));
                panic!("unexpected error for old PIN: {e}");
            }
            Ok(_) => {
                let _ = cp.change_pin(&ctap2_pin(TEMP_PIN), &ctap2_pin(TEST_PIN));
                panic!("old PIN should not work after change");
            }
        }

        // ── Restore original PIN ─────────────────────────────────────────
        cp.change_pin(&ctap2_pin(TEMP_PIN), &ctap2_pin(TEST_PIN))
            .expect("restore PIN to TEST_PIN");

        // Confirm restored PIN works
        let token4 = cp
            .get_pin_token(&ctap2_pin(TEST_PIN), None, None)
            .expect("get_pin_token after restore");
        assert!(!token4.is_empty());
    });
}

/// Verify that authenticatorSelection succeeds (UP is satisfied
/// immediately because the card is on the reader for NFC).
///
/// Requires CTAP 2.1 or the FIDO_2_1_PRE preview.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_selection(#[case] tc: TestConnection) {
    with_fido_session!(tc, |open, info| {
        let supports_selection = info
            .versions
            .iter()
            .any(|v| v == "FIDO_2_1" || v == "FIDO_2_1_PRE");
        if !supports_selection {
            skip!("authenticatorSelection requires CTAP 2.1");
        }

        reset_up_budget();
        let ctrl = require_controller!();
        let mut session = open();
        match session.selection(
            Some(&mut |status: u8| {
                if status == 0x02 {
                    ctrl.touch();
                }
            }),
            None,
        ) {
            Ok(()) => eprintln!("selection: OK"),
            Err(Ctap2Error::StatusError(CtapStatus::InvalidCommand))
            | Err(Ctap2Error::StatusError(CtapStatus::InvalidCbor)) => {
                skip!("authenticatorSelection not supported by this device");
            }
            Err(e) => panic!("  selection: {e}"),
        }
    });
}

/// Register a credential then verify it via assertion using [`WebAuthnClient`].
///
/// Two separate connections are used: one for make_credential and one
/// for get_assertion. Each physical "tap" (logical connection) gives
/// one user-presence (UP) budget. Closing and reopening the smartcard
/// connection resets that budget for the next UP-requiring command.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_make_and_get_credential(#[case] tc: TestConnection) {
    use yubikit::webauthn::{
        AuthenticatorSelectionCriteria, DefaultClientDataCollector,
        PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
        PublicKeyCredentialRpEntity, PublicKeyCredentialType, ResidentKeyRequirement,
        UserVerificationRequirement, WebAuthnClient,
    };
    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, _info| {
        reset_up_budget();

        // ── Registration ─────────────────────────────────────────────────
        let session = open();
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut mc_client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "Rust Device Tests".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"test-user-01".to_vec(),
                name: Some("test@rs.example".to_string()),
                display_name: Some("Test User".to_string()),
            },
            challenge: vec![0x42; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7, // ES256
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Discouraged),
                user_verification: Some(UserVerificationRequirement::Preferred),
                ..Default::default()
            }),
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: None,
        };

        let reg = mc_client
            .make_credential(&create_options, None)
            .expect("make_credential");
        let cred_id = reg.id.clone();
        assert!(!cred_id.is_empty(), "credential ID should not be empty");

        drop(mc_client);
        reset_up_budget();

        // ── Authentication ────────────────────────────────────────────────
        let session2 = open();
        let collector2 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut ga_client = WebAuthnClient::new(session2, TestInteraction::new(), collector2);

        let get_options = PublicKeyCredentialRequestOptions {
            challenge: vec![0xAB; 32],
            timeout: None,
            rp_id: Some(TEST_RP_ID.to_string()),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred_id.clone(),
                transports: None,
            }]),
            user_verification: Some(UserVerificationRequirement::Preferred),
            hints: None,
            extensions: None,
        };

        let assertions = ga_client
            .get_assertion(&get_options, None)
            .expect("get_assertion");
        assert!(!assertions.is_empty(), "expected at least one assertion");
        let a = &assertions[0];
        assert!(
            !a.response.signature.is_empty(),
            "signature should not be empty"
        );
        assert!(
            !a.response.authenticator_data.is_empty(),
            "auth_data should not be empty"
        );
        let flags = a.response.authenticator_data[32];
        assert!(flags & 0x01 != 0, "UP flag should be set in assertion");
    });
}

/// Verify attestation: make a credential with direct attestation, parse the
/// attestation object, extract the x5c certificate and signature, then verify
/// the signature over `authData || SHA-256(clientDataJSON)`.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_attestation(#[case] tc: TestConnection) {
    use sha2::{Digest, Sha256};
    use x509_cert::der::Decode;
    use yubikit::cbor;
    use yubikit::webauthn::{
        AttestationConveyancePreference, AuthenticatorSelectionCriteria,
        DefaultClientDataCollector, PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRpEntity, PublicKeyCredentialType, ResidentKeyRequirement,
        UserVerificationRequirement, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, _info| {
        reset_up_budget();

        let session = open();
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "Rust Attestation Test".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"attest-user-01".to_vec(),
                name: Some("attest@rs.example".to_string()),
                display_name: Some("Attestation User".to_string()),
            },
            challenge: vec![0xCA; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7, // ES256
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Discouraged),
                user_verification: Some(UserVerificationRequirement::Preferred),
                ..Default::default()
            }),
            hints: None,
            attestation: Some(AttestationConveyancePreference::Direct),
            attestation_formats: None,
            extensions: None,
        };

        let reg = client
            .make_credential(&create_options, None)
            .expect("make_credential");

        // Parse the attestation object (CBOR map: "fmt", "authData", "attStmt")
        let att_obj =
            cbor::decode(&reg.response.attestation_object).expect("decode attestation_object");
        let att_map = match &att_obj {
            cbor::Value::Map(m) => m,
            _ => panic!("attestation_object is not a CBOR map"),
        };

        let fmt = att_map
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (cbor::Value::Text(k), cbor::Value::Text(v)) if k == "fmt" => Some(v.as_str()),
                _ => None,
            })
            .expect("missing 'fmt' in attestation object");
        eprintln!("attestation format: {fmt}");
        assert_eq!(fmt, "packed", "expected packed attestation from YubiKey");

        let auth_data = att_map
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (cbor::Value::Text(k), cbor::Value::Bytes(b)) if k == "authData" => Some(b),
                _ => None,
            })
            .expect("missing 'authData' in attestation object");

        let att_stmt = att_map
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (cbor::Value::Text(k), cbor::Value::Map(m)) if k == "attStmt" => Some(m),
                _ => None,
            })
            .expect("missing 'attStmt' in attestation object");

        // Extract x5c (array of DER certificates) and sig from attStmt
        let x5c = att_stmt
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (cbor::Value::Text(k), cbor::Value::Array(arr)) if k == "x5c" => Some(arr),
                _ => None,
            })
            .expect("missing 'x5c' in attStmt");
        assert!(!x5c.is_empty(), "x5c array should not be empty");

        let cert_der = match &x5c[0] {
            cbor::Value::Bytes(b) => b,
            _ => panic!("x5c[0] is not bytes"),
        };

        let sig_bytes = att_stmt
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (cbor::Value::Text(k), cbor::Value::Bytes(b)) if k == "sig" => Some(b),
                _ => None,
            })
            .expect("missing 'sig' in attStmt");

        // Parse the attestation certificate and extract the public key
        let cert = x509_cert::Certificate::from_der(cert_der).expect("parse x5c certificate");
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let pub_key_bytes = spki.subject_public_key.as_bytes().expect("public key bits");
        let alg_oid = spki.algorithm.oid;
        eprintln!("attestation cert algorithm OID: {alg_oid}");

        // The signed message is: authData || SHA-256(clientDataJSON)
        let client_data_hash = Sha256::digest(&reg.response.client_data_json);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        // Verify the signature based on the certificate's key algorithm
        use x509_cert::der::oid::ObjectIdentifier;
        const OID_EC_PUBLIC_KEY: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        const OID_ML_DSA_44: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
        const OID_ML_DSA_65: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        const OID_ML_DSA_87: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

        if alg_oid == OID_EC_PUBLIC_KEY {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key =
                VerifyingKey::from_sec1_bytes(pub_key_bytes).expect("parse P-256 public key");
            let signature = Signature::from_der(sig_bytes).expect("parse DER signature");
            verifying_key
                .verify(&signed_data, &signature)
                .expect("P-256 attestation signature verification failed");
        } else if alg_oid == OID_ML_DSA_44 {
            use ml_dsa::{MlDsa44, Signature, VerifyingKey, common::KeyInit, signature::Verifier};
            let vk_bytes: &[u8; 1312] = pub_key_bytes
                .try_into()
                .expect("ML-DSA-44 public key must be 1312 bytes");
            let vk = VerifyingKey::<MlDsa44>::new(vk_bytes.into());
            let sig =
                Signature::<MlDsa44>::try_from(sig_bytes.as_slice()).expect("parse ML-DSA-44 sig");
            vk.verify(&signed_data, &sig)
                .expect("ML-DSA-44 attestation signature verification failed");
        } else if alg_oid == OID_ML_DSA_65 {
            use ml_dsa::{MlDsa65, Signature, VerifyingKey, common::KeyInit, signature::Verifier};
            let vk_bytes: &[u8; 1952] = pub_key_bytes
                .try_into()
                .expect("ML-DSA-65 public key must be 1952 bytes");
            let vk = VerifyingKey::<MlDsa65>::new(vk_bytes.into());
            let sig =
                Signature::<MlDsa65>::try_from(sig_bytes.as_slice()).expect("parse ML-DSA-65 sig");
            vk.verify(&signed_data, &sig)
                .expect("ML-DSA-65 attestation signature verification failed");
        } else if alg_oid == OID_ML_DSA_87 {
            use ml_dsa::{MlDsa87, Signature, VerifyingKey, common::KeyInit, signature::Verifier};
            let vk_bytes: &[u8; 2592] = pub_key_bytes
                .try_into()
                .expect("ML-DSA-87 public key must be 2592 bytes");
            let vk = VerifyingKey::<MlDsa87>::new(vk_bytes.into());
            let sig =
                Signature::<MlDsa87>::try_from(sig_bytes.as_slice()).expect("parse ML-DSA-87 sig");
            vk.verify(&signed_data, &sig)
                .expect("ML-DSA-87 attestation signature verification failed");
        } else {
            panic!("unsupported attestation certificate algorithm OID: {alg_oid}");
        }

        eprintln!("attestation signature verified successfully");
    });
}

/// Full credential management lifecycle: create, enumerate, update, delete.
///
/// Mirrors python-fido2's `test_list_and_delete` + `test_update`:
/// 1. Record initial metadata (cred count, remaining)
/// 2. Create a discoverable credential (resident key)
/// 3. Verify metadata count increased
/// 4. Enumerate RPs and credentials, validate returned data
/// 5. Update user info and verify the change
/// 6. Delete the credential
/// 7. Verify metadata count back to original
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_credential_management(#[case] tc: TestConnection) {
    use yubikit::webauthn::{
        AuthenticatorSelectionCriteria, DefaultClientDataCollector,
        PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        ResidentKeyRequirement, UserVerificationRequirement, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, info| {
        if info.options.get("credMgmt") != Some(&true)
            && !(info.versions.contains(&"FIDO_2_1_PRE".to_string())
                && info.options.get("credentialMgmtPreview") == Some(&true))
        {
            skip!("CredentialManagement not supported");
        }

        // ── Step 1: Get initial metadata ─────────────────────────────────
        reset_up_budget();
        let session = open();
        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .expect("ClientPin");
        let token = get_pin_token_or_skip!(
            cp,
            &ctap2_pin(TEST_PIN),
            Some(Permissions::CREDENTIAL_MGMT),
            None
        );
        let protocol = cp.protocol();
        let session = cp.into_session();
        let mut credmgmt = CredentialManagement::new(session, protocol, token)
            .map_err(|(e, _)| e)
            .expect("CredentialManagement::new");

        let (initial_existing, initial_remaining) = match credmgmt.get_metadata() {
            Ok(v) => v,
            Err(e) => {
                if device_is_fips() && get_device().transport() == Transport::Nfc {
                    skip!("CredentialManagement blocked on FIPS+NFC: {e:?}");
                }
                panic!("get_metadata: {e:?}");
            }
        };
        eprintln!("initial: existing={initial_existing}, remaining={initial_remaining}");
        assert!(initial_remaining > 0, "no remaining credential slots");
        drop(credmgmt);

        // ── Step 2: Create a discoverable credential ─────────────────────
        reset_up_budget();
        let session = open();
        let rp_id = "credmgmt-test.rs.example";
        let collector = DefaultClientDataCollector::new(format!("https://{rp_id}"));
        let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let user_id = b"credmgmt-user-01".to_vec();
        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "CredMgmt Test RP".to_string(),
                id: Some(rp_id.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: user_id.clone(),
                name: Some("testuser@example.com".to_string()),
                display_name: Some("Test User".to_string()),
            },
            challenge: vec![0xDD; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7, // ES256
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Required),
                user_verification: Some(UserVerificationRequirement::Preferred),
                ..Default::default()
            }),
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: None,
        };

        let reg = client
            .make_credential(&create_options, None)
            .expect("make_credential (discoverable)");
        let cred_id = reg.id.clone();
        assert!(!cred_id.is_empty());
        drop(client);

        // ── Step 3: Verify metadata count increased ──────────────────────
        reset_up_budget();
        let session = open();
        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .expect("ClientPin");
        let token = get_pin_token_or_skip!(
            cp,
            &ctap2_pin(TEST_PIN),
            Some(Permissions::CREDENTIAL_MGMT),
            None
        );
        let protocol = cp.protocol();
        let session = cp.into_session();
        let mut credmgmt = CredentialManagement::new(session, protocol, token)
            .map_err(|(e, _)| e)
            .expect("CredentialManagement::new");

        let (existing_after_create, remaining_after_create) =
            credmgmt.get_metadata().expect("get_metadata after create");
        eprintln!(
            "after create: existing={existing_after_create}, remaining={remaining_after_create}"
        );
        assert_eq!(
            existing_after_create,
            initial_existing + 1,
            "existing count should increase by 1"
        );
        assert!(
            remaining_after_create < initial_remaining,
            "remaining should decrease"
        );

        // ── Step 4: Enumerate RPs and credentials ────────────────────────
        let rps = credmgmt.enumerate_rps().expect("enumerate_rps");
        let our_rp = rps
            .iter()
            .find(|r| r.rp.id == rp_id)
            .expect("our RP should be in the list");
        eprintln!("found RP: {}", our_rp.rp.id);

        let creds = credmgmt
            .enumerate_creds(&our_rp.rp_id_hash)
            .expect("enumerate_creds");
        let our_cred = creds
            .iter()
            .find(|c| c.credential_id.id == cred_id)
            .expect("our credential should be listed");
        assert_eq!(our_cred.user.id, user_id);
        eprintln!("credential user.id matches");
        // third_party_payment should not be set
        assert_ne!(our_cred.third_party_payment, Some(true));

        // ── Step 5: Update user info (if supported) ──────────────────────
        if credmgmt.is_update_supported() {
            let updated_user = PublicKeyCredentialUserEntity {
                id: user_id.clone(),
                name: Some("updated@example.com".to_string()),
                display_name: Some("Updated User".to_string()),
            };
            credmgmt
                .update_user_info(&our_cred.credential_id, &updated_user)
                .expect("update_user_info");

            // Re-enumerate to verify
            let creds = credmgmt
                .enumerate_creds(&our_rp.rp_id_hash)
                .expect("enumerate_creds after update");
            let updated_cred = creds
                .iter()
                .find(|c| c.credential_id.id == cred_id)
                .expect("credential after update");
            if updated_cred.user.name.is_some() {
                assert_eq!(
                    updated_cred.user.name.as_deref(),
                    Some("updated@example.com")
                );
            }
            if updated_cred.user.display_name.is_some() {
                assert_eq!(
                    updated_cred.user.display_name.as_deref(),
                    Some("Updated User")
                );
            }
            eprintln!("user info updated successfully");
        } else {
            eprintln!("update_user_info not supported, skipping");
        }

        // ── Step 6: Delete the credential ────────────────────────────────
        credmgmt
            .delete_cred(&our_cred.credential_id)
            .expect("delete_cred");
        eprintln!("credential deleted");

        // ── Step 7: Verify metadata count back to original ───────────────
        let (final_existing, final_remaining) =
            credmgmt.get_metadata().expect("get_metadata after delete");
        eprintln!("after delete: existing={final_existing}, remaining={final_remaining}");
        assert_eq!(
            final_existing, initial_existing,
            "existing count should return to initial"
        );
        assert_eq!(
            final_remaining, initial_remaining,
            "remaining count should return to initial"
        );
    });
}

/// Verify that wrong permissions cause PIN_AUTH_INVALID error.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_credential_management_wrong_permissions(#[case] tc: TestConnection) {
    require_fido_pin!();
    with_fido_session!(tc, |open, info| {
        if info.options.get("credMgmt") != Some(&true)
            && !(info.versions.contains(&"FIDO_2_1_PRE".to_string())
                && info.options.get("credentialMgmtPreview") == Some(&true))
        {
            skip!("CredentialManagement not supported");
        }

        // Get a token with LARGE_BLOB_WRITE permission (wrong for credmgmt)
        reset_up_budget();
        let session = open();
        let mut cp = ClientPin::new(session)
            .map_err(|(e, _)| e)
            .expect("ClientPin");
        let token = get_pin_token_or_skip!(
            cp,
            &ctap2_pin(TEST_PIN),
            Some(Permissions::LARGE_BLOB_WRITE),
            None
        );
        let protocol = cp.protocol();
        let session = cp.into_session();
        let mut credmgmt = CredentialManagement::new(session, protocol, token)
            .map_err(|(e, _)| e)
            .expect("CredentialManagement::new");

        let result = credmgmt.get_metadata();
        assert!(
            result.is_err(),
            "get_metadata should fail with wrong permissions"
        );
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("PinAuthInvalid") || err_str.contains("0x33"),
            "expected PIN_AUTH_INVALID, got: {err}"
        );
        eprintln!("correctly rejected with wrong permissions");
    });
}

/// Verify that the large-blob array can be read (no UP required).
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_ctap2_large_blobs(#[case] tc: TestConnection) {
    with_fido_session!(tc, |open, info| {
        if info.options.get("largeBlobs") != Some(&true) {
            skip!("largeBlobs not supported");
        }

        let session = open();
        // Reads don't require a PIN token; pass dummy values.
        let mut lb = LargeBlobs::new(session, PinProtocol::V1, vec![])
            .map_err(|(e, _)| e)
            .expect("LargeBlobs::new");
        let blob_array = lb.read_blob_array().expect("read_blob_array");
        eprintln!("large blob array: {} bytes", blob_array.len());
    });
}

/// Verify that cancelling a CTAP2 selection command over USB works.
///
/// Sends an authenticatorSelection command and cancels it after the
/// first keepalive, checking that the authenticator responds with
/// KeepaliveCancel (0x2D) promptly.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_fido_selection_cancel(#[case] tc: TestConnection) {
    require_transport!(Transport::Usb);
    with_fido_session!(tc, |open, info| {
        let supports_selection = info
            .versions
            .iter()
            .any(|v| v == "FIDO_2_1" || v == "FIDO_2_1_PRE");
        if !supports_selection {
            skip!("authenticatorSelection requires CTAP 2.1");
        }

        let mut session = open();
        let got_keepalive = std::sync::atomic::AtomicBool::new(false);
        let start = std::time::Instant::now();
        let result = session.selection(
            Some(&mut |_status| {
                got_keepalive.store(true, std::sync::atomic::Ordering::Relaxed);
            }),
            Some(&|| got_keepalive.load(std::sync::atomic::Ordering::Relaxed)),
        );
        let elapsed = start.elapsed();

        match result {
            Ok(()) => {
                // UP was satisfied without touch (shouldn't happen on USB without touch)
                eprintln!("selection: OK (UP satisfied without cancel)");
                if get_device().transport() == Transport::Usb {
                    panic!("  (unexpected on USB transport without touch)");
                }
            }
            Err(Ctap2Error::StatusError(CtapStatus::KeepaliveCancel)) => {
                eprintln!("selection: cancelled after keepalive ({elapsed:?})");
            }
            Err(e) => panic!("Unexpected error: {e}"),
        }

        assert!(
            elapsed.as_secs() < 10,
            "Cancel took too long: {elapsed:?} (expected < 10s)"
        );
    });
}

// ── WebAuthn Extension Tests ─────────────────────────────────────────────

/// Test credProtect extension: create credentials at each protection level.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::usb_hid(TestConnection::UsbHid)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
fn test_webauthn_cred_protect(#[case] tc: TestConnection) {
    use yubikit::webauthn::extensions::RegistrationExtensionInputs;
    use yubikit::webauthn::extensions::cred_protect::{CredProtectPolicy, RegistrationInput};
    use yubikit::webauthn::{
        DefaultClientDataCollector, PublicKeyCredentialCreationOptions,
        PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        PublicKeyCredentialUserEntity, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, info| {
        if !info.extensions.iter().any(|e| e == "credProtect") {
            skip!("credProtect extension not supported");
        }

        let policies = [
            (CredProtectPolicy::UserVerificationOptional, "level1"),
            (
                CredProtectPolicy::UserVerificationOptionalWithCredentialIDList,
                "level2",
            ),
            (CredProtectPolicy::UserVerificationRequired, "level3"),
        ];

        for (policy, label) in &policies {
            reset_up_budget();

            let session = open();
            let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
            let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

            let create_options = PublicKeyCredentialCreationOptions {
                rp: PublicKeyCredentialRpEntity {
                    name: "CredProtect Test".to_string(),
                    id: Some(TEST_RP_ID.to_string()),
                },
                user: PublicKeyCredentialUserEntity {
                    id: format!("cp-{label}").into_bytes(),
                    name: Some(format!("cp-{label}@test")),
                    display_name: Some(format!("CP {label}")),
                },
                challenge: vec![0x10; 32],
                pub_key_cred_params: vec![PublicKeyCredentialParameters {
                    type_: PublicKeyCredentialType::PublicKey,
                    alg: -7,
                }],
                timeout: None,
                exclude_credentials: None,
                authenticator_selection: None,
                hints: None,
                attestation: None,
                attestation_formats: None,
                extensions: Some(RegistrationExtensionInputs {
                    cred_protect: Some(RegistrationInput {
                        policy: *policy,
                        enforce: true,
                    }),
                    ..Default::default()
                }),
            };

            let reg = client
                .make_credential(&create_options, None)
                .expect("make_credential");
            assert!(!reg.id.is_empty());

            if let Some(ref ext) = reg.client_extension_results
                && let Some(ref cp) = ext.cred_protect
            {
                eprintln!("  {label}: policy={:?}", cp.policy);
                assert_eq!(cp.policy, *policy);
            } else {
                eprintln!("  {label}: credential created (no extension echo)");
            }
        }
    });
}

/// Test credBlob extension: store a blob during registration, retrieve during assertion.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_webauthn_cred_blob(#[case] tc: TestConnection) {
    use yubikit::webauthn::extensions::cred_blob::RegistrationInput;
    use yubikit::webauthn::extensions::{
        AuthenticationExtensionInputs, RegistrationExtensionInputs,
    };
    use yubikit::webauthn::{
        DefaultClientDataCollector, PublicKeyCredentialCreationOptions,
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
        PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        PublicKeyCredentialUserEntity, UserVerificationRequirement, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, info| {
        if !info.extensions.iter().any(|e| e == "credBlob") {
            skip!("credBlob extension not supported");
        }

        let blob_data = b"test-cred-blob-data".to_vec();

        // ── Registration with credBlob ───────────────────────────────────
        reset_up_budget();

        let session = open();
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "CredBlob Test".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"blob-test-user".to_vec(),
                name: Some("blob@test".to_string()),
                display_name: Some("Blob Test".to_string()),
            },
            challenge: vec![0x20; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: Some(RegistrationExtensionInputs {
                cred_blob: Some(RegistrationInput {
                    blob: blob_data.clone(),
                }),
                ..Default::default()
            }),
        };

        let reg = client
            .make_credential(&create_options, None)
            .expect("make_credential with credBlob");
        let cred_id = reg.id.clone();
        assert!(!cred_id.is_empty());

        if let Some(ref ext) = reg.client_extension_results
            && let Some(ref cb) = ext.cred_blob
        {
            assert!(cb.stored, "credBlob should be stored");
            eprintln!("  credBlob stored: {}", cb.stored);
        }

        drop(client);

        // ── Authentication with getCredBlob ──────────────────────────────
        reset_up_budget();

        let session2 = open();
        let collector2 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut ga_client = WebAuthnClient::new(session2, TestInteraction::new(), collector2);

        let get_options = PublicKeyCredentialRequestOptions {
            challenge: vec![0x21; 32],
            timeout: None,
            rp_id: Some(TEST_RP_ID.to_string()),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred_id,
                transports: None,
            }]),
            user_verification: Some(UserVerificationRequirement::Discouraged),
            hints: None,
            extensions: Some(AuthenticationExtensionInputs {
                get_cred_blob: Some(true),
                ..Default::default()
            }),
        };

        let assertions = ga_client
            .get_assertion(&get_options, None)
            .expect("get_assertion with getCredBlob");
        assert!(!assertions.is_empty());

        if let Some(ref ext) = assertions[0].client_extension_results
            && let Some(ref cb) = ext.cred_blob
        {
            assert_eq!(cb.blob, blob_data, "retrieved blob should match stored");
            eprintln!("  credBlob retrieved: {} bytes", cb.blob.len());
        } else {
            panic!("credBlob not returned in assertion extensions");
        }
    });
}

/// Test PRF extension (hmac-secret): derive a secret and verify determinism.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_webauthn_prf(#[case] tc: TestConnection) {
    use yubikit::webauthn::extensions::prf::{AuthenticationInput, PrfEval, RegistrationInput};
    use yubikit::webauthn::extensions::{
        AuthenticationExtensionInputs, RegistrationExtensionInputs,
    };
    use yubikit::webauthn::{
        DefaultClientDataCollector, PublicKeyCredentialCreationOptions,
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
        PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        PublicKeyCredentialUserEntity, UserVerificationRequirement, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, info| {
        if !info.extensions.iter().any(|e| e == "hmac-secret") {
            skip!("hmac-secret (PRF) extension not supported");
        }

        // ── Registration with PRF enabled ────────────────────────────────
        reset_up_budget();

        let session = open();
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "PRF Test".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"prf-test-user".to_vec(),
                name: Some("prf@test".to_string()),
                display_name: Some("PRF Test".to_string()),
            },
            challenge: vec![0x30; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: Some(RegistrationExtensionInputs {
                prf: Some(RegistrationInput { eval: None }),
                ..Default::default()
            }),
        };

        let reg = client
            .make_credential(&create_options, None)
            .expect("make_credential with PRF");
        let cred_id = reg.id.clone();
        assert!(!cred_id.is_empty());

        if let Some(ref ext) = reg.client_extension_results
            && let Some(ref prf) = ext.prf
        {
            assert!(prf.enabled, "PRF should be enabled");
            eprintln!("  PRF enabled: {}", prf.enabled);
        }

        drop(client);

        // ── First authentication with PRF eval ───────────────────────────
        reset_up_budget();

        let session2 = open();
        let collector2 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut ga_client = WebAuthnClient::new(session2, TestInteraction::new(), collector2);

        let salt = b"test PRF salt input".to_vec();
        let get_options = PublicKeyCredentialRequestOptions {
            challenge: vec![0x31; 32],
            timeout: None,
            rp_id: Some(TEST_RP_ID.to_string()),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred_id.clone(),
                transports: None,
            }]),
            user_verification: Some(UserVerificationRequirement::Discouraged),
            hints: None,
            extensions: Some(AuthenticationExtensionInputs {
                prf: Some(AuthenticationInput {
                    eval: Some(PrfEval {
                        first: salt.clone(),
                        second: None,
                    }),
                    eval_by_credential: Default::default(),
                }),
                ..Default::default()
            }),
        };

        let assertions = ga_client
            .get_assertion(&get_options, None)
            .expect("get_assertion with PRF");
        assert!(!assertions.is_empty());

        let secret1 = assertions[0]
            .client_extension_results
            .as_ref()
            .and_then(|e| e.prf.as_ref())
            .map(|p| p.results.first.clone())
            .expect("PRF result should be present");
        assert_eq!(secret1.len(), 32, "PRF output should be 32 bytes");
        eprintln!("  PRF secret: {} bytes", secret1.len());

        drop(ga_client);

        // ── Second authentication: same salt → same secret ───────────────
        reset_up_budget();

        let session3 = open();
        let collector3 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut ga_client2 = WebAuthnClient::new(session3, TestInteraction::new(), collector3);

        let get_options2 = PublicKeyCredentialRequestOptions {
            challenge: vec![0x32; 32],
            timeout: None,
            rp_id: Some(TEST_RP_ID.to_string()),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred_id,
                transports: None,
            }]),
            user_verification: Some(UserVerificationRequirement::Discouraged),
            hints: None,
            extensions: Some(AuthenticationExtensionInputs {
                prf: Some(AuthenticationInput {
                    eval: Some(PrfEval {
                        first: salt,
                        second: None,
                    }),
                    eval_by_credential: Default::default(),
                }),
                ..Default::default()
            }),
        };

        let assertions2 = ga_client2
            .get_assertion(&get_options2, None)
            .expect("get_assertion PRF (second)");

        let secret2 = assertions2[0]
            .client_extension_results
            .as_ref()
            .and_then(|e| e.prf.as_ref())
            .map(|p| p.results.first.clone())
            .expect("PRF result should be present (second)");
        assert_eq!(secret1, secret2, "same salt should produce same PRF secret");
        eprintln!("  PRF determinism verified");
    });
}

/// Test largeBlob extension: write and read back a blob.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_webauthn_large_blob(#[case] tc: TestConnection) {
    use yubikit::webauthn::extensions::large_blob::{
        AuthenticationInput, LargeBlobSupport, RegistrationInput,
    };
    use yubikit::webauthn::extensions::{
        AuthenticationExtensionInputs, RegistrationExtensionInputs,
    };
    use yubikit::webauthn::{
        AuthenticatorSelectionCriteria, DefaultClientDataCollector,
        PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions,
        PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
        ResidentKeyRequirement, UserVerificationRequirement, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, info| {
        if info.options.get("largeBlobs") != Some(&true) {
            skip!("largeBlobs not supported");
        }

        // ── Registration with largeBlob support required ─────────────────
        reset_up_budget();

        let session = open();
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "LargeBlob Test".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"largeblob-test-user".to_vec(),
                name: Some("lb@test".to_string()),
                display_name: Some("LargeBlob Test".to_string()),
            },
            challenge: vec![0x40; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                resident_key: Some(ResidentKeyRequirement::Required),
                user_verification: None,
            }),
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: Some(RegistrationExtensionInputs {
                large_blob: Some(RegistrationInput {
                    support: LargeBlobSupport::Required,
                }),
                ..Default::default()
            }),
        };

        let reg = client
            .make_credential(&create_options, None)
            .expect("make_credential with largeBlob");
        let cred_id = reg.id.clone();
        assert!(!cred_id.is_empty());

        if let Some(ref ext) = reg.client_extension_results
            && let Some(ref lb) = ext.large_blob
        {
            assert!(lb.supported, "largeBlob should be supported");
            eprintln!("  largeBlob supported: {}", lb.supported);
        }

        drop(client);

        // ── Write blob ───────────────────────────────────────────────────
        let blob_data = b"hello from largeBlob test!".to_vec();
        reset_up_budget();

        let session2 = open();
        let collector2 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut write_client = WebAuthnClient::new(session2, TestInteraction::new(), collector2);

        let write_options = PublicKeyCredentialRequestOptions {
            challenge: vec![0x41; 32],
            timeout: None,
            rp_id: Some(TEST_RP_ID.to_string()),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred_id.clone(),
                transports: None,
            }]),
            user_verification: Some(UserVerificationRequirement::Discouraged),
            hints: None,
            extensions: Some(AuthenticationExtensionInputs {
                large_blob: Some(AuthenticationInput::write(blob_data.clone())),
                ..Default::default()
            }),
        };

        let assertions = write_client
            .get_assertion(&write_options, None)
            .expect("get_assertion (largeBlob write)");

        if let Some(ref ext) = assertions[0].client_extension_results
            && let Some(ref lb) = ext.large_blob
        {
            if lb.written == Some(false) && get_device().transport() == Transport::Nfc {
                skip!("largeBlob write not supported over NFC+SCP on this key");
            }
            assert_eq!(lb.written, Some(true), "blob should be written");
            eprintln!("  largeBlob written: {:?}", lb.written);
        }

        drop(write_client);

        // ── Read blob back ───────────────────────────────────────────────
        reset_up_budget();

        let session3 = open();
        let collector3 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut read_client = WebAuthnClient::new(session3, TestInteraction::new(), collector3);

        let read_options = PublicKeyCredentialRequestOptions {
            challenge: vec![0x42; 32],
            timeout: None,
            rp_id: Some(TEST_RP_ID.to_string()),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred_id,
                transports: None,
            }]),
            user_verification: Some(UserVerificationRequirement::Discouraged),
            hints: None,
            extensions: Some(AuthenticationExtensionInputs {
                large_blob: Some(AuthenticationInput::read()),
                ..Default::default()
            }),
        };

        let assertions = read_client
            .get_assertion(&read_options, None)
            .expect("get_assertion (largeBlob read)");

        if let Some(ref ext) = assertions[0].client_extension_results
            && let Some(ref lb) = ext.large_blob
        {
            let read_data = lb.blob.as_ref().expect("blob data should be present");
            assert_eq!(read_data, &blob_data, "read blob should match written");
            eprintln!("  largeBlob read: {} bytes", read_data.len());
        } else {
            panic!("largeBlob not returned in read assertion");
        }
    });
}

/// Test credProps extension: verify rk property is reported correctly.
#[rstest]
#[case::smart_card(TestConnection::SmartCard)]
#[case::scp11b(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_webauthn_cred_props(#[case] tc: TestConnection) {
    use yubikit::webauthn::extensions::RegistrationExtensionInputs;
    use yubikit::webauthn::{
        AuthenticatorSelectionCriteria, DefaultClientDataCollector,
        PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters,
        PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
        ResidentKeyRequirement, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, info| {
        let _ = &info; // available if needed for feature checks

        // ── Non-resident credential ──────────────────────────────────────
        reset_up_budget();

        let session = open();
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "CredProps Test".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"cprops-nr".to_vec(),
                name: Some("cprops-nr@test".to_string()),
                display_name: Some("CredProps NR".to_string()),
            },
            challenge: vec![0x50; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                resident_key: Some(ResidentKeyRequirement::Discouraged),
                user_verification: None,
            }),
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: Some(RegistrationExtensionInputs {
                cred_props: Some(true),
                ..Default::default()
            }),
        };

        let reg = client
            .make_credential(&create_options, None)
            .expect("make_credential (non-rk, credProps)");
        assert!(!reg.id.is_empty());

        if let Some(ref ext) = reg.client_extension_results
            && let Some(ref cp) = ext.cred_props
        {
            eprintln!("  non-rk credential: rk={}", cp.rk);
            assert!(!cp.rk, "non-resident credential should have rk=false");
        }

        drop(client);

        // ── Resident credential ──────────────────────────────────────────
        reset_up_budget();

        let session2 = open();
        let collector2 = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut client2 = WebAuthnClient::new(session2, TestInteraction::new(), collector2);

        let create_options_rk = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "CredProps Test".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"cprops-rk".to_vec(),
                name: Some("cprops-rk@test".to_string()),
                display_name: Some("CredProps RK".to_string()),
            },
            challenge: vec![0x51; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                resident_key: Some(ResidentKeyRequirement::Required),
                user_verification: None,
            }),
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: Some(RegistrationExtensionInputs {
                cred_props: Some(true),
                ..Default::default()
            }),
        };

        let reg = client2
            .make_credential(&create_options_rk, None)
            .expect("make_credential (rk, credProps)");
        assert!(!reg.id.is_empty());

        if let Some(ref ext) = reg.client_extension_results
            && let Some(ref cp) = ext.cred_props
        {
            eprintln!("  rk credential: rk={}", cp.rk);
            assert!(cp.rk, "resident credential should have rk=true");
        }
    });
}

// ─── previewSign extension ───────────────────────────────────────────

use super::arkg_p256;

#[rstest]
#[case::smartcard(TestConnection::SmartCard)]
#[case::scp(TestConnection::SmartCardScp11b)]
#[case::usb_hid(TestConnection::UsbHid)]
fn test_webauthn_preview_sign(#[case] tc: TestConnection) {
    use sha2::{Digest, Sha256};
    use yubikit::webauthn::extensions::RegistrationExtensionInputs;
    use yubikit::webauthn::extensions::sign::{GenerateKeyInput, RegistrationInput};
    use yubikit::webauthn::{
        DefaultClientDataCollector, PublicKeyCredentialCreationOptions,
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
        PublicKeyCredentialType, PublicKeyCredentialUserEntity, WebAuthnClient,
    };

    require_fido_pin!();
    require_controller!();
    with_fido_session!(tc, |open, info| {
        if !info.extensions.iter().any(|e| e == "previewSign") {
            skip!("previewSign extension not supported");
        }

        // ESP256_SPLIT_ARKG_PLACEHOLDER = -65539
        const ALG_ESP256_SPLIT_ARKG: i64 = -65539;

        // ── Registration with previewSign (key generation) ────────────────
        reset_up_budget();

        let session = open();
        let collector = DefaultClientDataCollector::new(format!("https://{TEST_RP_ID}"));
        let mut client = WebAuthnClient::new(session, TestInteraction::new(), collector);

        let create_options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "Sign Test".to_string(),
                id: Some(TEST_RP_ID.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"sign-test-user".to_vec(),
                name: Some("sign@test".to_string()),
                display_name: Some("Sign Test".to_string()),
            },
            challenge: vec![0x60; 32],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7, // ES256 for the credential itself
            }],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: Some(RegistrationExtensionInputs {
                preview_sign: Some(RegistrationInput {
                    generate_key: GenerateKeyInput {
                        algorithms: vec![ALG_ESP256_SPLIT_ARKG],
                    },
                }),
                ..Default::default()
            }),
        };

        let reg = client
            .make_credential(&create_options, None)
            .expect("make_credential with previewSign");
        let credential_id = reg.id.clone();
        assert!(
            !credential_id.is_empty(),
            "credential ID should not be empty"
        );

        // Verify extension output
        let ext = reg
            .client_extension_results
            .as_ref()
            .expect("should have extension results");
        let sign_out = ext
            .preview_sign
            .as_ref()
            .expect("should have previewSign output");

        let generated = &sign_out.generated_key;
        assert_eq!(
            generated.algorithm, ALG_ESP256_SPLIT_ARKG,
            "algorithm should be ESP256_SPLIT_ARKG_PLACEHOLDER"
        );
        assert!(
            !generated.public_key.is_empty(),
            "public_key should not be empty (COSE_Key)"
        );
        assert!(
            !generated.attestation_object.is_empty(),
            "attestation_object should not be empty"
        );

        // Parse the ARKG master public key and derive a child key
        let master_key = arkg_p256::ArkgMasterKey::from_cbor(&generated.public_key);
        let ctx = b"yubikit-rs.test_webauthn_preview_sign";
        let ikm: Vec<u8> = (0..32).collect(); // deterministic IKM for testing
        let (derived_pk, args_cbor) = arkg_p256::derive_public_key(&master_key, &ikm, ctx);

        // ── Authentication with previewSign (signing) ────────────────────
        let message = b"test message for previewSign";
        let ph_data = Sha256::digest(message);

        drop(client);
        reset_up_budget();

        let mut session2 = open();

        // Build the previewSign extension input for getAssertion
        let sign_entries: Vec<(yubikit::cbor::Value, yubikit::cbor::Value)> = vec![
            (
                yubikit::cbor::Value::Int(2),
                yubikit::cbor::Value::Bytes(generated.key_handle.clone()),
            ),
            (
                yubikit::cbor::Value::Int(6),
                yubikit::cbor::Value::Bytes(ph_data.to_vec()),
            ),
            (
                yubikit::cbor::Value::Int(7),
                yubikit::cbor::Value::Bytes(args_cbor),
            ),
        ];
        let ext_cbor = yubikit::cbor::Value::Map(vec![(
            yubikit::cbor::Value::Text("previewSign".to_string()),
            yubikit::cbor::Value::Map(sign_entries),
        )]);

        // Get PIN token and compute pin_uv_auth
        let mut cp = ClientPin::new_with_protocol(session2, PinProtocol::V2);
        let token = cp
            .get_pin_token(
                &ctap2_pin(TEST_PIN),
                Some(Permissions::GET_ASSERTION),
                Some(TEST_RP_ID),
            )
            .expect("get_pin_token for GA");
        session2 = cp.into_session();

        let client_data_hash = Sha256::digest(b"dummy client data for test");
        let pin_auth = PinProtocol::V2.authenticate(&token, &client_data_hash);

        let allow = vec![PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: credential_id.clone(),
            transports: None,
        }];

        let ctrl = require_controller!();
        let resp = session2
            .get_assertion(
                TEST_RP_ID,
                &client_data_hash,
                Some(&allow),
                Some(ext_cbor),
                None,
                Some(&pin_auth),
                Some(2),
                Some(&mut |status: u8| {
                    if status == 0x02 {
                        ctrl.touch();
                    }
                }),
                None,
            )
            .expect("get_assertion with previewSign");

        // Parse the extension output from authenticator data
        // Auth data: rpIdHash(32) + flags(1) + counter(4) + [extensions if ED flag set]
        let auth_data = &resp.auth_data;
        let flags = auth_data[32];
        assert!(flags & 0x80 != 0, "ED flag should be set in auth_data");

        let ext_cbor_bytes = &auth_data[37..];
        let ext_parsed = yubikit::cbor::decode(ext_cbor_bytes).expect("decode extensions CBOR");
        let entries = ext_parsed.as_map().expect("extensions should be a map");
        let sign_ext = entries
            .iter()
            .find(|(k, _)| k.as_text() == Some("previewSign"))
            .expect("previewSign extension in auth_data");
        let signature = sign_ext
            .1
            .map_get_int(6)
            .and_then(|v| v.as_bytes())
            .expect("signature at key 6");

        // Verify the ECDSA signature with the ARKG-derived public key
        arkg_p256::verify_signature(&derived_pk, message, signature);
    });
}
