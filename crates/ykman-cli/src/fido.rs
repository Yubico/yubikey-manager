// Copyright (c) 2026 Yubico AB
// All rights reserved.
//
//   Redistribution and use in source and binary forms, with or
//   without modification, are permitted provided that the following
//   conditions are met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//    2. Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! FIDO CLI commands.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use yubikit::cbor::Value;
use yubikit::core::{Connection, Transport};
use yubikit::ctap::CtapSession;
use yubikit::ctap2::{
    BioEnrollment, BioResult, ClientPin, Config, CredentialManagement, Ctap2Error, Ctap2Session,
    CtapStatus, Info, Permissions, PinProtocol, TemplateInfo,
};
use yubikit::device::{ReinsertStatus, YubiKeyDevice};
use yubikit::management::Capability;

use crate::scp::{self, ScpParams};
use crate::util::CliError;

const KEEPALIVE_PROCESSING: u8 = 1;
const KEEPALIVE_UPNEEDED: u8 = 2;

// ---------------------------------------------------------------------------
// Session opening — macro to handle HID vs SmartCard generics
// ---------------------------------------------------------------------------

/// Opens a FIDO CTAP2 session and executes the body with the session bound.
///
/// Prefers HID when no SCP is required; falls back to SmartCard (NFC/CCID).
/// The body receives `$session: Ctap2Session<C>` and must return
/// `Result<T, CliError>`.
macro_rules! with_fido_session {
    ($dev:expr, $scp_params:expr, |$session:ident| $body:block) => {{
        let scp_config = if $scp_params.is_explicit() {
            Some(scp::resolve_scp($dev, $scp_params, Capability::FIDO2)?)
        } else {
            None
        };

        if scp_config.is_none()
            && let Ok(conn) = $dev.open_fido()
        {
            let ctap = CtapSession::new_fido(conn)
                .map_err(|(e, _)| CliError(format!("Failed to initialize CTAP: {e}")))?;
            let $session = Ctap2Session::new(ctap)
                .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;
            $body
        } else {
            let conn = $dev
                .open_smartcard()
                .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
            let ctap = if let Some(ref scp_cfg) = scp_config {
                if let Some(params) = scp::to_scp_key_params(scp_cfg) {
                    CtapSession::new_with_scp(conn, &params)
                } else {
                    CtapSession::new(conn)
                }
            } else {
                CtapSession::new(conn)
            }
            .map_err(|(e, _)| CliError(format!("Failed to initialize CTAP: {e}")))?;
            let $session = Ctap2Session::new(ctap)
                .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;
            $body
        }
    }};
}

// ---------------------------------------------------------------------------
// Generic helper functions (work for any Connection type)
// ---------------------------------------------------------------------------

fn get_ctap_status<E: std::error::Error + Send + Sync + 'static>(
    e: &Ctap2Error<E>,
) -> Option<CtapStatus> {
    match e {
        Ctap2Error::StatusError(s) => Some(*s),
        _ => None,
    }
}

fn format_pin_error<E: std::error::Error + Send + Sync + 'static>(
    client_pin: &mut ClientPin<impl Connection + 'static>,
    context: &str,
    e: &Ctap2Error<E>,
) -> CliError {
    match get_ctap_status(e) {
        Some(CtapStatus::PinInvalid) => {
            if let Ok((retries, _)) = client_pin.get_pin_retries() {
                CliError(format!("Wrong PIN, {retries} attempt(s) remaining."))
            } else {
                CliError(format!("{context}: {e}"))
            }
        }
        Some(CtapStatus::PinBlocked) => CliError("PIN is blocked.".into()),
        Some(CtapStatus::PinAuthBlocked) => CliError(
            "PIN authentication is currently blocked. Remove and re-insert the YubiKey.".into(),
        ),
        _ => CliError(format!("{context}: {e}")),
    }
}

fn require_pin_from_info(
    info: &Info,
    pin: Option<&str>,
    feature: &str,
) -> Result<String, CliError> {
    if info.options.get("clientPin") != Some(&true) {
        return Err(CliError(format!(
            "{feature} requires having a PIN. Set a PIN first."
        )));
    }
    match pin {
        Some(p) => Ok(p.to_string()),
        None => {
            eprint!("Enter your PIN: ");
            rpassword::read_password().map_err(|e| CliError(format!("Failed to read PIN: {e}")))
        }
    }
}

fn get_pin_token_inner<C: Connection + 'static>(
    client_pin: &mut ClientPin<C>,
    pin: &str,
    permissions: Permissions,
) -> Result<(Vec<u8>, PinProtocol), CliError> {
    let token = client_pin
        .get_pin_token(pin, Some(permissions), None)
        .map_err(|e| format_pin_error(client_pin, "PIN authentication failed", &e))?;
    Ok((token, client_pin.protocol()))
}

fn get_optional_pin_token_inner<C: Connection + 'static>(
    client_pin: &mut ClientPin<C>,
    info: &Info,
    pin: Option<&str>,
    permissions: Permissions,
) -> Result<(Option<Vec<u8>>, Option<PinProtocol>), CliError> {
    if info.options.get("clientPin") != Some(&true) {
        return Ok((None, None));
    }
    let pin_str = require_pin_from_info(info, pin, "This feature")?;
    let (token, protocol) = get_pin_token_inner(client_pin, &pin_str, permissions)?;
    Ok((Some(token), Some(protocol)))
}

fn map_enroll_error<E: std::error::Error + Send + Sync + 'static>(
    e: Ctap2Error<E>,
    context: &str,
) -> CliError {
    if get_ctap_status(&e) == Some(CtapStatus::KeepaliveCancel) {
        CliError("Fingerprint enrollment aborted by user.".to_string())
    } else {
        CliError(format!("{context}: {e}"))
    }
}

// ---------------------------------------------------------------------------
// CLI command implementations
// ---------------------------------------------------------------------------

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let dev_info = dev.info();
    let transport = dev.transport();

    // Check if FIDO2 is enabled
    let fido2_enabled = dev_info
        .config
        .enabled_capabilities
        .get(&transport)
        .is_some_and(|caps: &Capability| caps.contains(Capability::FIDO2));

    if fido2_enabled {
        with_fido_session!(dev, scp_params, |ctap2| {
            let ctap_info = ctap2.info().clone();

            // FIPS status
            if dev_info.fips_capable.contains(Capability::FIDO2) {
                println!(
                    "FIPS approved:  {}",
                    if dev_info.fips_approved.contains(Capability::FIDO2) {
                        "Yes"
                    } else {
                        "No"
                    }
                );
            }

            // AAGUID
            println!("AAGUID:         {}", ctap_info.aaguid);

            // PIN status
            let mut client_pin = ClientPin::new(ctap2)
                .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
            if ctap_info.options.get("clientPin") == Some(&true) {
                if ctap_info.force_pin_change {
                    println!(
                        "NOTE: The FIDO PIN is disabled and must be changed before it can be used!"
                    );
                }
                match client_pin.get_pin_retries() {
                    Ok((retries, power_cycle)) => {
                        if retries > 0 {
                            print!("PIN:            {retries} attempt(s) remaining");
                            if power_cycle.is_some_and(|pc| pc > 0) {
                                print!(
                                    "\nPIN is temporarily blocked. \
                                     Remove and re-insert the YubiKey to unblock."
                                );
                            }
                            println!();
                        } else {
                            println!("PIN:            Blocked");
                        }
                    }
                    Err(e) => println!("PIN:            Error: {e}"),
                }
            } else {
                println!("PIN:            Not set");
            }

            // Minimum PIN length
            println!("Minimum PIN length: {}", ctap_info.min_pin_length);

            // Fingerprint status
            let bio_enroll = ctap_info.options.get("bioEnroll");
            match bio_enroll {
                Some(true) => match client_pin.get_uv_retries() {
                    Ok(retries) => {
                        if retries > 0 {
                            println!("Fingerprints:   Registered, {retries} attempt(s) remaining");
                        } else {
                            println!("Fingerprints:   Registered, blocked until PIN is verified");
                        }
                    }
                    Err(e) => println!("Fingerprints:   Error: {e}"),
                },
                Some(false) => println!("Fingerprints:   Not registered"),
                None => {}
            }

            // Always Require UV
            if let Some(&always_uv) = ctap_info.options.get("alwaysUv") {
                println!(
                    "Always Require UV: {}",
                    if always_uv { "On" } else { "Off" }
                );
            }

            // Remaining discoverable credentials
            if let Some(remaining) = ctap_info.remaining_disc_creds {
                println!("Credential storage remaining: {remaining}");
            }

            // Enterprise Attestation
            if let Some(&ep) = ctap_info.options.get("ep") {
                println!(
                    "Enterprise Attestation: {}",
                    if ep { "Enabled" } else { "Disabled" }
                );
            }

            Ok(())
        })
    } else {
        // FIDO2 not enabled — check if supported
        let fido2_supported = dev_info
            .supported_capabilities
            .get(&transport)
            .is_some_and(|caps: &Capability| caps.contains(Capability::FIDO2));
        if fido2_supported {
            println!("CTAP2:          Disabled");
            println!("PIN:            Disabled");
        } else {
            println!("CTAP2:          Not supported");
            println!("PIN:            Not supported");
        }
        Ok(())
    }
}

pub fn run_reset(
    dev: &mut YubiKeyDevice,
    scp_params: &ScpParams,
    force: bool,
) -> Result<(), CliError> {
    let info = dev.info();
    let transport = dev.transport();

    // Check if FIDO reset is blocked
    if info.reset_blocked.contains(Capability::FIDO2) {
        return Err(CliError(
            "Cannot perform FIDO reset when PIV is configured, \
             use 'ykman config reset' for full factory reset."
                .to_string(),
        ));
    }

    let fido2_enabled = info
        .config
        .enabled_capabilities
        .get(&transport)
        .is_some_and(|caps: &Capability| caps.contains(Capability::FIDO2));

    if !fido2_enabled {
        return Err(CliError(
            "FIDO2 is not enabled on this YubiKey.".to_string(),
        ));
    }

    if !force {
        eprint!(
            "WARNING! This will delete all FIDO credentials, including FIDO U2F \
             credentials, and restore factory settings. Proceed? [y/N] "
        );
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| CliError(format!("Failed to read input: {e}")))?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Err(CliError("Reset aborted by user.".to_string()));
        }

        // Close and reinsert
        dev.reinsert(
            &|status| match (transport, status) {
                (Transport::Usb, ReinsertStatus::Remove) => {
                    eprintln!("Remove your YubiKey from the USB port.")
                }
                (Transport::Usb, ReinsertStatus::Reinsert) => {
                    eprintln!("Re-insert your YubiKey now...")
                }
                (Transport::Nfc, ReinsertStatus::Remove) => {
                    eprintln!("Remove your YubiKey from the NFC reader.")
                }
                (Transport::Nfc, ReinsertStatus::Reinsert) => {
                    eprintln!("Place your YubiKey back on the NFC reader now...")
                }
            },
            &|| false,
        )
        .map_err(|e| CliError(format!("Reinsert failed: {e}")))?;
    }

    with_fido_session!(dev, scp_params, |ctap2| {
        run_reset_inner(ctap2, transport)
    })
}

fn run_reset_inner<C: Connection + 'static>(
    mut ctap2: Ctap2Session<C>,
    transport: Transport,
) -> Result<(), CliError> {
    let ctap_info = ctap2.info().clone();

    // Check transport restrictions
    let transports_for_reset = &ctap_info.transports_for_reset;
    if !transports_for_reset.is_empty() {
        let transport_name = match transport {
            Transport::Usb => "usb",
            Transport::Nfc => "nfc",
        };
        if !transports_for_reset.iter().any(|t| t == transport_name) {
            return Err(CliError(format!(
                "Cannot perform FIDO reset over the current transport. \
                 Allowed transports: {}",
                transports_for_reset.join(", ")
            )));
        }
    }

    let touch_msg = if ctap_info.long_touch_for_reset {
        "Press and hold the YubiKey button for 5 seconds to confirm."
    } else {
        "Touch the YubiKey to confirm."
    };

    // Set up Ctrl+C handler for cancellation
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    let _ = ctrlc::set_handler(move || {
        cancel_clone.store(true, Ordering::Relaxed);
    });

    let is_cancelled = || cancel.load(Ordering::Relaxed);
    let result = ctap2.reset(
        Some(&mut |status| {
            if status == KEEPALIVE_UPNEEDED {
                eprintln!("{touch_msg}");
            } else if status == KEEPALIVE_PROCESSING {
                eprintln!("Reset in progress, DO NOT REMOVE YOUR YUBIKEY!");
            }
        }),
        Some(&is_cancelled),
    );

    match result {
        Ok(()) => {
            println!("FIDO application has been reset.");
            Ok(())
        }
        Err(ref e) => match get_ctap_status(e) {
            Some(CtapStatus::UserActionTimeout) => Err(CliError(
                "Reset failed. You need to touch your YubiKey to confirm the reset.".to_string(),
            )),
            Some(CtapStatus::NotAllowed | CtapStatus::PinAuthBlocked) => Err(CliError(
                "Reset failed. Reset must be triggered within 5 seconds after the \
                     YubiKey is inserted."
                    .to_string(),
            )),
            Some(CtapStatus::KeepaliveCancel) => {
                Err(CliError("Reset aborted by user.".to_string()))
            }
            _ => Err(CliError(format!("FIDO reset failed: {e}"))),
        },
    }
}

pub fn run_access_change_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        let pin_is_set = ctap2.info().options.get("clientPin") == Some(&true);
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;

        if pin_is_set {
            // Change existing PIN
            let current_pin = match pin {
                Some(p) => p.to_string(),
                None => {
                    eprint!("Enter your current PIN: ");
                    rpassword::read_password()
                        .map_err(|e| CliError(format!("Failed to read PIN: {e}")))?
                }
            };
            let new = match new_pin {
                Some(p) => p.to_string(),
                None => {
                    eprint!("Enter your new PIN: ");
                    let p1 = rpassword::read_password()
                        .map_err(|e| CliError(format!("Failed to read PIN: {e}")))?;
                    eprint!("Confirm your new PIN: ");
                    let p2 = rpassword::read_password()
                        .map_err(|e| CliError(format!("Failed to read PIN: {e}")))?;
                    if p1 != p2 {
                        return Err(CliError("PINs do not match.".to_string()));
                    }
                    p1
                }
            };
            client_pin
                .change_pin(&current_pin, &new)
                .map_err(|e| format_pin_error(&mut client_pin, "Failed to change PIN", &e))?;
            println!("PIN has been changed.");
        } else {
            // Set new PIN
            let new = match new_pin.or(pin) {
                Some(p) => p.to_string(),
                None => {
                    eprint!("Enter your new PIN: ");
                    let p1 = rpassword::read_password()
                        .map_err(|e| CliError(format!("Failed to read PIN: {e}")))?;
                    eprint!("Confirm your new PIN: ");
                    let p2 = rpassword::read_password()
                        .map_err(|e| CliError(format!("Failed to read PIN: {e}")))?;
                    if p1 != p2 {
                        return Err(CliError("PINs do not match.".to_string()));
                    }
                    p1
                }
            };
            client_pin
                .set_pin(&new)
                .map_err(|e| CliError(format!("Failed to set PIN: {e}")))?;
            println!("PIN has been set.");
        }

        Ok(())
    })
}

pub fn run_access_verify_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        let pin_str = require_pin_from_info(ctap2.info(), pin, "PIN verification")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;

        // Get a PIN token to verify the PIN
        client_pin
            .get_pin_token(&pin_str, None, None)
            .map_err(|e| format_pin_error(&mut client_pin, "PIN verification failed", &e))?;

        println!("PIN verified.");
        Ok(())
    })
}

pub fn run_access_force_change(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        if !ctap2
            .info()
            .options
            .get("setMinPINLength")
            .copied()
            .unwrap_or(false)
        {
            return Err(CliError(
                "Force change PIN is not supported on this YubiKey.".to_string(),
            ));
        }
        let pin_str = require_pin_from_info(ctap2.info(), pin, "Force change PIN")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::AUTHENTICATOR_CFG)?;
        let session = client_pin.into_session();

        let mut config = Config::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to create config: {e}")))?;
        config
            .set_min_pin_length(None, None, true)
            .map_err(|e| CliError(format!("Failed to set force change: {e}")))?;

        println!("Force PIN change set.");
        Ok(())
    })
}

pub fn run_access_set_min_length(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    length: u32,
    pin: Option<&str>,
    rp_ids: &[String],
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        {
            let info = ctap2.info();
            if !info
                .options
                .get("setMinPINLength")
                .copied()
                .unwrap_or(false)
            {
                return Err(CliError(
                    "Set minimum PIN length is not supported on this YubiKey.".to_string(),
                ));
            }

            if (length as usize) < info.min_pin_length {
                return Err(CliError(format!(
                    "Cannot set a minimum length shorter than {}.",
                    info.min_pin_length
                )));
            }

            let max_rpids = info.max_rpids_for_min_pin.unwrap_or(0);
            if !rp_ids.is_empty() && rp_ids.len() > max_rpids {
                return Err(CliError(format!(
                    "Authenticator supports up to {max_rpids} RP IDs ({} given).",
                    rp_ids.len()
                )));
            }
        }

        let pin_str = require_pin_from_info(ctap2.info(), pin, "Set minimum PIN length")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::AUTHENTICATOR_CFG)?;
        let session = client_pin.into_session();

        let mut config = Config::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to create config: {e}")))?;
        let rp_arg = if rp_ids.is_empty() {
            None
        } else {
            Some(rp_ids)
        };
        config
            .set_min_pin_length(Some(length), rp_arg, false)
            .map_err(|e| CliError(format!("Failed to set minimum PIN length: {e}")))?;

        println!("Minimum PIN length set.");
        Ok(())
    })
}

pub fn run_credentials_list(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
    csv: bool,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        if !ctap2
            .info()
            .options
            .get("credMgmt")
            .or(ctap2.info().options.get("credentialMgmtPreview"))
            .copied()
            .unwrap_or(false)
        {
            return Err(CliError(
                "Credential management is not supported on this YubiKey.".to_string(),
            ));
        }

        let pin_str = require_pin_from_info(ctap2.info(), pin, "Credential Management")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::CREDENTIAL_MGMT)?;
        let session = client_pin.into_session();

        let mut credman = CredentialManagement::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to create credential manager: {e}")))?;

        let rps = credman
            .enumerate_rps()
            .map_err(|e| CliError(format!("Failed to enumerate RPs: {e}")))?;

        if rps.is_empty() {
            println!("No discoverable credentials.");
            return Ok(());
        }

        // Collect all credentials
        let mut all_creds: Vec<(String, Vec<u8>, Vec<u8>, String, String)> = Vec::new();
        for rp_resp in &rps {
            let rp_id = cbor_u32_map_get_text(rp_resp, 3, "id").unwrap_or_default();
            let rp_id_hash = cbor_u32_map_get_bytes(rp_resp, 4).unwrap_or_default();

            let creds = credman
                .enumerate_creds(&rp_id_hash)
                .map_err(|e| CliError(format!("Failed to enumerate credentials: {e}")))?;

            for cred_resp in &creds {
                let user_name = cbor_u32_map_get_text(cred_resp, 6, "name").unwrap_or_default();
                let display_name =
                    cbor_u32_map_get_text(cred_resp, 6, "displayName").unwrap_or_default();
                let user_id = cbor_u32_map_get_nested_bytes(cred_resp, 6, "id").unwrap_or_default();
                let cred_id_bytes =
                    cbor_u32_map_get_nested_bytes(cred_resp, 7, "id").unwrap_or_default();

                all_creds.push((
                    rp_id.clone(),
                    cred_id_bytes,
                    user_id,
                    user_name,
                    display_name,
                ));
            }
        }

        if csv {
            println!("credential_id,rp_id,user_name,user_display_name,user_id");
            for (rp_id, cred_id, user_id, user_name, display_name) in &all_creds {
                println!(
                    "{},{},{},{},{}",
                    csv_escape(&hex::encode(cred_id)),
                    csv_escape(rp_id),
                    csv_escape(user_name),
                    csv_escape(display_name),
                    csv_escape(&hex::encode(user_id)),
                );
            }
        } else {
            // Determine shortest unique credential ID prefix
            let mut ln = 4;
            while all_creds
                .iter()
                .map(|(_, id, _, _, _)| {
                    hex::encode(id)[..ln.min(hex::encode(id).len())].to_string()
                })
                .collect::<std::collections::HashSet<_>>()
                .len()
                < all_creds.len()
            {
                ln += 1;
            }

            // Collect rows for table formatting
            let headings = ["Credential ID", "RP ID", "Username", "Display name"];
            let rows: Vec<[String; 4]> = all_creds
                .iter()
                .map(|(rp_id, cred_id, _, user_name, display_name)| {
                    let hex_id = hex::encode(cred_id);
                    let short_id = format!("{}...", &hex_id[..ln.min(hex_id.len())]);
                    [
                        short_id,
                        rp_id.clone(),
                        user_name.clone(),
                        display_name.clone(),
                    ]
                })
                .collect();

            // Calculate column widths
            let mut widths = headings.map(|h| h.len());
            for row in &rows {
                for (i, cell) in row.iter().enumerate() {
                    widths[i] = widths[i].max(cell.len());
                }
            }

            // Print header
            let header: Vec<String> = headings
                .iter()
                .enumerate()
                .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
                .collect();
            println!("{}", header.join("  "));

            // Print rows
            for row in &rows {
                let formatted: Vec<String> = row
                    .iter()
                    .enumerate()
                    .map(|(i, cell)| format!("{:width$}", cell, width = widths[i]))
                    .collect();
                println!("{}", formatted.join("  "));
            }
        }

        Ok(())
    })
}

pub fn run_credentials_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    credential_id: &str,
    pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        let pin_str = require_pin_from_info(ctap2.info(), pin, "Credential Management")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::CREDENTIAL_MGMT)?;
        let session = client_pin.into_session();

        let mut credman = CredentialManagement::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to create credential manager: {e}")))?;
        let search = credential_id.trim_end_matches('.').to_lowercase();

        // Find matching credentials
        let rps = credman
            .enumerate_rps()
            .map_err(|e| CliError(format!("Failed to enumerate RPs: {e}")))?;

        let mut hits = Vec::new();
        for rp_resp in &rps {
            let rp_id = cbor_u32_map_get_text(rp_resp, 3, "id").unwrap_or_default();
            let rp_id_hash = cbor_u32_map_get_bytes(rp_resp, 4).unwrap_or_default();

            let creds = credman.enumerate_creds(&rp_id_hash).unwrap_or_default();
            for cred_resp in &creds {
                let user_name = cbor_u32_map_get_text(cred_resp, 6, "name").unwrap_or_default();
                let display_name =
                    cbor_u32_map_get_text(cred_resp, 6, "displayName").unwrap_or_default();
                let cred_id_bytes =
                    cbor_u32_map_get_nested_bytes(cred_resp, 7, "id").unwrap_or_default();
                let cred_id_hex = hex::encode(&cred_id_bytes);

                if cred_id_hex.starts_with(&search) {
                    // Build the credentialID CBOR value for deletion
                    if let Some(v) = cred_resp.get(&7).cloned() {
                        hits.push((rp_id.clone(), user_name, display_name, cred_id_hex, v));
                    }
                }
            }
        }

        match hits.len() {
            0 => Err(CliError("No matches, nothing to be done.".to_string())),
            1 => {
                let (rp_id, user_name, display_name, cred_id_hex, cred_id_val) = &hits[0];
                if !force {
                    eprint!("Delete {rp_id} {user_name} {display_name} ({cred_id_hex})? [y/N] ");
                    let mut answer = String::new();
                    std::io::stdin()
                        .read_line(&mut answer)
                        .map_err(|e| CliError(format!("Failed to read input: {e}")))?;
                    if !answer.trim().eq_ignore_ascii_case("y") {
                        return Err(CliError("Deletion aborted.".to_string()));
                    }
                }
                println!("Deleting credential, DO NOT REMOVE YOUR YUBIKEY!");
                credman
                    .delete_cred(cred_id_val)
                    .map_err(|e| CliError(format!("Failed to delete credential: {e}")))?;
                println!("Credential deleted.");
                Ok(())
            }
            _ => Err(CliError(
                "Multiple matches, make the credential ID more specific.".to_string(),
            )),
        }
    })
}

pub fn run_credentials_update(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    credential_id: &str,
    name: Option<&str>,
    display_name: Option<&str>,
    pin: Option<&str>,
) -> Result<(), CliError> {
    if name.is_none() && display_name.is_none() {
        return Err(CliError(
            "At least one of --name or --display-name must be provided.".to_string(),
        ));
    }

    with_fido_session!(dev, scp_params, |ctap2| {
        let pin_str = require_pin_from_info(ctap2.info(), pin, "Credential Management")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::CREDENTIAL_MGMT)?;
        let session = client_pin.into_session();

        let mut credman = CredentialManagement::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to create credential manager: {e}")))?;

        if !credman.is_update_supported() {
            return Err(CliError(
                "Credential update is not supported on this YubiKey.".to_string(),
            ));
        }

        let search = credential_id.trim_end_matches('.').to_lowercase();

        let rps = credman
            .enumerate_rps()
            .map_err(|e| CliError(format!("Failed to enumerate RPs: {e}")))?;

        let mut hits = Vec::new();
        for rp_resp in &rps {
            let rp_id = cbor_u32_map_get_text(rp_resp, 3, "id").unwrap_or_default();
            let rp_id_hash = cbor_u32_map_get_bytes(rp_resp, 4).unwrap_or_default();

            let creds = credman.enumerate_creds(&rp_id_hash).unwrap_or_default();
            for cred_resp in &creds {
                let user_name = cbor_u32_map_get_text(cred_resp, 6, "name").unwrap_or_default();
                let cred_id_bytes =
                    cbor_u32_map_get_nested_bytes(cred_resp, 7, "id").unwrap_or_default();
                let cred_id_hex = hex::encode(&cred_id_bytes);

                if cred_id_hex.starts_with(&search) {
                    // We need the credentialID value and the current user map
                    let cred_id_val = cred_resp.get(&7).cloned();
                    let user_val = cred_resp.get(&6).cloned();
                    if let (Some(cid), Some(user)) = (cred_id_val, user_val) {
                        hits.push((rp_id.clone(), user_name, cred_id_hex, cid, user));
                    }
                }
            }
        }

        match hits.len() {
            0 => Err(CliError("No matches, nothing to be done.".to_string())),
            1 => {
                let (rp_id, user_name, _cred_id_hex, cred_id_val, user_val) = &hits[0];

                // Build updated user map from existing, overriding specified fields
                let mut user_entries: Vec<(Value, Value)> = Vec::new();
                if let Value::Map(entries) = user_val {
                    for (k, v) in entries {
                        let key_name = k.as_text().unwrap_or("");
                        match key_name {
                            "name" => {
                                if let Some(n) = name {
                                    user_entries.push((k.clone(), Value::Text(n.to_string())));
                                } else {
                                    user_entries.push((k.clone(), v.clone()));
                                }
                            }
                            "displayName" => {
                                if let Some(dn) = display_name {
                                    user_entries.push((k.clone(), Value::Text(dn.to_string())));
                                } else {
                                    user_entries.push((k.clone(), v.clone()));
                                }
                            }
                            _ => {
                                user_entries.push((k.clone(), v.clone()));
                            }
                        }
                    }
                }

                // Add fields that weren't in the original map
                let has_name = user_entries
                    .iter()
                    .any(|(k, _)| k.as_text() == Some("name"));
                let has_display_name = user_entries
                    .iter()
                    .any(|(k, _)| k.as_text() == Some("displayName"));
                if let Some(n) = name
                    && !has_name
                {
                    user_entries.push((Value::Text("name".into()), Value::Text(n.to_string())));
                }
                if let Some(dn) = display_name
                    && !has_display_name
                {
                    user_entries.push((
                        Value::Text("displayName".into()),
                        Value::Text(dn.to_string()),
                    ));
                }

                let updated_user = Value::Map(user_entries);

                println!("Updating credential for {} (user: {})", rp_id, user_name);
                credman
                    .update_user_info(cred_id_val, &updated_user)
                    .map_err(|e| CliError(format!("Failed to update credential: {e}")))?;
                println!("Credential updated.");
                Ok(())
            }
            _ => Err(CliError(
                "Multiple matches, make the credential ID more specific.".to_string(),
            )),
        }
    })
}

pub fn run_fingerprints_list(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        if !ctap2.info().options.contains_key("bioEnroll") {
            return Err(CliError(
                "Fingerprints are not supported on this YubiKey.".to_string(),
            ));
        }

        let pin_str = require_pin_from_info(ctap2.info(), pin, "Biometrics")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::BIO_ENROLL)?;
        let session = client_pin.into_session();

        let mut bio = BioEnrollment::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to initialize bio enrollment: {e}")))?;

        let enrollments = match bio.enumerate_enrollments() {
            Ok(resp) => {
                // Extract template infos array (key 0x07)
                match resp.get(&(BioResult::TemplateInfos as u32)) {
                    Some(Value::Array(infos)) => infos.clone(),
                    _ => vec![],
                }
            }
            Err(Ctap2Error::StatusError(CtapStatus::InvalidOption)) => vec![],
            Err(e) => return Err(CliError(format!("Failed to enumerate fingerprints: {e}"))),
        };

        if enrollments.is_empty() {
            println!("No fingerprints registered.");
        } else {
            for info in &enrollments {
                if let Value::Map(entries) = info {
                    let id = entries
                        .iter()
                        .find(|(k, _)| matches!(k, Value::Int(n) if *n == TemplateInfo::Id as i64))
                        .and_then(|(_, v)| v.as_bytes())
                        .map(hex::encode)
                        .unwrap_or_default();
                    let name = entries
                        .iter()
                        .find(
                            |(k, _)| matches!(k, Value::Int(n) if *n == TemplateInfo::Name as i64),
                        )
                        .and_then(|(_, v)| v.as_text());
                    if let Some(name) = name {
                        println!("ID: {id} ({name})");
                    } else {
                        println!("ID: {id}");
                    }
                }
            }
        }

        Ok(())
    })
}

pub fn run_fingerprints_add(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    name: &str,
    pin: Option<&str>,
) -> Result<(), CliError> {
    if name.len() > 15 {
        return Err(CliError(
            "Fingerprint name must be a maximum of 15 characters.".to_string(),
        ));
    }

    with_fido_session!(dev, scp_params, |ctap2| {
        let pin_str = require_pin_from_info(ctap2.info(), pin, "Biometrics")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::BIO_ENROLL)?;
        let session = client_pin.into_session();

        let mut bio = BioEnrollment::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to initialize bio enrollment: {e}")))?;

        // Set up Ctrl+C handler for cancellation
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        let _ = ctrlc::set_handler(move || {
            cancel_clone.store(true, Ordering::Relaxed);
        });

        let is_cancelled = || cancel.load(Ordering::Relaxed);

        // Begin enrollment
        eprintln!("Place your finger against the sensor now...");
        let resp = bio
            .enroll_begin(None, Some(&mut |_| {}), Some(&is_cancelled))
            .map_err(|e| map_enroll_error(e, "Enrollment failed"))?;

        let template_id = resp
            .get(&(BioResult::TemplateId as u32))
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())
            .ok_or_else(|| CliError("Missing template ID in enrollment response".to_string()))?;
        let remaining = resp
            .get(&(BioResult::RemainingSamples as u32))
            .and_then(|v| v.as_int())
            .unwrap_or(0) as u32;

        if remaining > 0 {
            eprintln!("{remaining} more scans needed.");
        }

        // Continue capturing
        let mut scans_remaining = remaining;
        while scans_remaining > 0 {
            eprintln!("Place your finger against the sensor now...");
            match bio.enroll_capture_next(
                &template_id,
                None,
                Some(&mut |_| {}),
                Some(&is_cancelled),
            ) {
                Ok(resp) => {
                    scans_remaining = resp
                        .get(&(BioResult::RemainingSamples as u32))
                        .and_then(|v| v.as_int())
                        .unwrap_or(0) as u32;
                    if scans_remaining > 0 {
                        eprintln!("{scans_remaining} more scans needed.");
                    }
                }
                Err(e) => {
                    if get_ctap_status(&e) == Some(CtapStatus::KeepaliveCancel) {
                        return Err(CliError(
                            "Fingerprint enrollment aborted by user.".to_string(),
                        ));
                    }
                    if get_ctap_status(&e) == Some(CtapStatus::FpDatabaseFull) {
                        return Err(CliError(
                            "Fingerprint storage full. Remove some fingerprints first.".to_string(),
                        ));
                    }
                    if get_ctap_status(&e) == Some(CtapStatus::UserActionTimeout) {
                        return Err(CliError(
                            "Failed to add fingerprint due to user inactivity.".to_string(),
                        ));
                    }
                    eprintln!("Capture failed. Re-center your finger, and try again.");
                }
            }
        }

        eprintln!("Capture complete.");
        bio.set_name(&template_id, name)
            .map_err(|e| CliError(format!("Failed to set fingerprint name: {e}")))?;
        println!("Fingerprint registered.");
        Ok(())
    })
}

pub fn run_fingerprints_rename(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    template_id: &str,
    name: &str,
    pin: Option<&str>,
) -> Result<(), CliError> {
    if name.len() > 15 {
        return Err(CliError(
            "Fingerprint name must be a maximum of 15 characters.".to_string(),
        ));
    }

    with_fido_session!(dev, scp_params, |ctap2| {
        let pin_str = require_pin_from_info(ctap2.info(), pin, "Biometrics")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::BIO_ENROLL)?;
        let session = client_pin.into_session();

        let mut bio = BioEnrollment::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to initialize bio enrollment: {e}")))?;

        let key = hex::decode(template_id)
            .map_err(|e| CliError(format!("Invalid template ID hex: {e}")))?;

        bio.set_name(&key, name)
            .map_err(|e| CliError(format!("Failed to rename fingerprint: {e}")))?;
        println!("Fingerprint renamed.");
        Ok(())
    })
}

pub fn run_fingerprints_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    template_id: &str,
    pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        let pin_str = require_pin_from_info(ctap2.info(), pin, "Biometrics")?;
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) =
            get_pin_token_inner(&mut client_pin, &pin_str, Permissions::BIO_ENROLL)?;
        let session = client_pin.into_session();

        let mut bio = BioEnrollment::new(session, protocol, token)
            .map_err(|e| CliError(format!("Failed to initialize bio enrollment: {e}")))?;

        let key = hex::decode(template_id)
            .map_err(|_| CliError(format!("Invalid template ID hex: {template_id}")))?;

        if !force {
            eprint!("Delete fingerprint {template_id}? [y/N] ");
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(|e| CliError(format!("Failed to read input: {e}")))?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                return Err(CliError("Deletion aborted.".to_string()));
            }
        }

        bio.remove_enrollment(&key)
            .map_err(|e| CliError(format!("Failed to delete fingerprint: {e}")))?;
        println!("Fingerprint deleted.");
        Ok(())
    })
}

pub fn run_config_toggle_always_uv(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        let always_uv = match ctap2.info().options.get("alwaysUv") {
            Some(&v) => v,
            None => {
                return Err(CliError(
                    "Always Require UV is not supported on this YubiKey.".to_string(),
                ));
            }
        };

        let info = dev.info();
        if info.fips_capable.contains(Capability::FIDO2) {
            return Err(CliError(
                "Always Require UV cannot be disabled on this YubiKey.".to_string(),
            ));
        }

        let ctap_info = ctap2.info().clone();
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) = get_optional_pin_token_inner(
            &mut client_pin,
            &ctap_info,
            pin,
            Permissions::AUTHENTICATOR_CFG,
        )?;
        let session = client_pin.into_session();

        let mut config = if let (Some(token), Some(protocol)) = (token, protocol) {
            Config::new(session, protocol, token)
        } else {
            Config::new_unauthenticated(session)
        }
        .map_err(|e| CliError(format!("Failed to create config: {e}")))?;
        config
            .toggle_always_uv()
            .map_err(|e| CliError(format!("Failed to toggle Always Require UV: {e}")))?;

        println!(
            "Always Require UV is {}.",
            if always_uv { "off" } else { "on" }
        );
        Ok(())
    })
}

pub fn run_config_enable_ep_attestation(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    with_fido_session!(dev, scp_params, |ctap2| {
        {
            let options = &ctap2.info().options;
            if !options.contains_key("ep") {
                return Err(CliError(
                    "Enterprise Attestation is not supported on this YubiKey.".to_string(),
                ));
            }
            if options.get("alwaysUv") == Some(&true) && options.get("clientPin") != Some(&true) {
                return Err(CliError(
                    "Enabling Enterprise Attestation requires a PIN when alwaysUv is enabled."
                        .to_string(),
                ));
            }
        }

        let ctap_info = ctap2.info().clone();
        let mut client_pin = ClientPin::new(ctap2)
            .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
        let (token, protocol) = get_optional_pin_token_inner(
            &mut client_pin,
            &ctap_info,
            pin,
            Permissions::AUTHENTICATOR_CFG,
        )?;
        let session = client_pin.into_session();

        let mut config = if let (Some(token), Some(protocol)) = (token, protocol) {
            Config::new(session, protocol, token)
        } else {
            Config::new_unauthenticated(session)
        }
        .map_err(|e| CliError(format!("Failed to create config: {e}")))?;
        config
            .enable_enterprise_attestation()
            .map_err(|e| CliError(format!("Failed to enable Enterprise Attestation: {e}")))?;

        println!("Enterprise Attestation enabled.");
        Ok(())
    })
}

// --- CBOR map helper functions for BTreeMap<u32, Value> ---

fn cbor_u32_map_get_text(map: &BTreeMap<u32, Value>, key: u32, field: &str) -> Option<String> {
    let entity = map.get(&key)?;
    if let Value::Map(entries) = entity {
        for (k, v) in entries {
            if k.as_text() == Some(field) {
                return v.as_text().map(|s| s.to_string());
            }
        }
    }
    None
}

fn cbor_u32_map_get_bytes(map: &BTreeMap<u32, Value>, key: u32) -> Option<Vec<u8>> {
    map.get(&key)?.as_bytes().map(|b| b.to_vec())
}

fn cbor_u32_map_get_nested_bytes(
    map: &BTreeMap<u32, Value>,
    key: u32,
    field: &str,
) -> Option<Vec<u8>> {
    let entity = map.get(&key)?;
    if let Value::Map(entries) = entity {
        for (k, v) in entries {
            if k.as_text() == Some(field) {
                return v.as_bytes().map(|b| b.to_vec());
            }
        }
    }
    None
}

/// Escape a field for CSV output. Quotes the field if it contains commas,
/// quotes, or newlines.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}
