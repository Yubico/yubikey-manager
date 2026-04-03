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

use std::sync::atomic::{AtomicBool, Ordering};

use fido2_client::ctap::{CtapDevice, CtapError, CtapStatus};
use fido2_client::ctap2::Ctap2;
use fido2_client::pin::{ClientPin, PinProtocol};
use fido2_server::cbor::Value;
use yubikit::core::Transport;
use yubikit::device::{ReinsertStatus, YubiKeyDevice};
use yubikit::management::Capability;

use crate::ctap_device::{HidCtapDevice, SmartCardCtapDevice};
use crate::scp::{self, ScpParams};
use crate::util::CliError;

// --- CLI command implementations ---

/// Open a FIDO connection as a CtapDevice, preferring HID, falling back to SmartCard.
///
/// When SCP params are explicit, always uses SmartCard connection.
/// Otherwise tries HID first (USB direct), then SmartCard (NFC or USB CCID).
enum FidoDevice {
    Hid(HidCtapDevice),
    SmartCard(SmartCardCtapDevice<yubikit::transport::pcsc::PcscSmartCardConnection>),
}

impl FidoDevice {
    fn as_ctap_device(&self) -> &dyn CtapDevice {
        match self {
            Self::Hid(d) => d,
            Self::SmartCard(d) => d,
        }
    }
}

fn open_fido_device(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<FidoDevice, CliError> {
    if scp_params.is_explicit() {
        // SCP requires SmartCard transport
        let scp_config = scp::resolve_scp(dev, scp_params, Capability::FIDO2)?;
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        if let Some(params) = scp::to_scp_key_params(&scp_config) {
            SmartCardCtapDevice::new_with_scp(conn, &params)
        } else {
            SmartCardCtapDevice::new(conn)
        }
        .map(FidoDevice::SmartCard)
        .map_err(|e| CliError(format!("Failed to open FIDO over SmartCard: {e}")))
    } else if dev.open_fido().is_ok() {
        let conn = dev
            .open_fido()
            .map_err(|e| CliError(format!("Failed to open FIDO connection: {e}")))?;
        Ok(FidoDevice::Hid(HidCtapDevice::new(conn)))
    } else {
        // Fall back to SmartCard (NFC reader)
        let conn = dev
            .open_smartcard()
            .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
        SmartCardCtapDevice::new(conn)
            .map(FidoDevice::SmartCard)
            .map_err(|e| CliError(format!("Failed to open FIDO over SmartCard: {e}")))
    }
}

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let info = dev.info();
    let transport = dev.transport();

    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();

    // Check if FIDO2 is enabled
    let fido2_enabled = info
        .config
        .enabled_capabilities
        .get(&transport)
        .is_some_and(|caps: &Capability| caps.contains(Capability::FIDO2));

    if fido2_enabled {
        let ctap2 = Ctap2::new(ctap_dev, false)
            .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;
        let ctap_info = ctap2.info();

        // FIPS status
        if info.fips_capable.contains(Capability::FIDO2) {
            println!(
                "FIPS approved:  {}",
                if info.fips_approved.contains(Capability::FIDO2) {
                    "Yes"
                } else {
                    "No"
                }
            );
        }

        // AAGUID
        println!("AAGUID:         {}", ctap_info.aaguid);

        // PIN status
        let client_pin = ClientPin::new(&ctap2, None)
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
    } else {
        // FIDO2 not enabled — check if supported
        let fido2_supported = info
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
    }

    Ok(())
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

    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();

    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;
    let ctap_info = ctap2.info();

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
        &mut |status| {
            if status == fido2_client::ctap::keepalive::UPNEEDED {
                eprintln!("{touch_msg}");
            } else if status == fido2_client::ctap::keepalive::PROCESSING {
                eprintln!("Reset in progress, DO NOT REMOVE YOUR YUBIKEY!");
            }
        },
        Some(&is_cancelled),
    );

    match result {
        Ok(()) => {
            println!("FIDO application has been reset.");
            Ok(())
        }
        Err(e) => {
            if e.get_status() == Some(fido2_client::ctap::CtapStatus::UserActionTimeout) {
                Err(CliError(
                    "Reset failed. You need to touch your YubiKey to confirm the reset."
                        .to_string(),
                ))
            } else if matches!(
                e.get_status(),
                Some(
                    fido2_client::ctap::CtapStatus::NotAllowed
                        | fido2_client::ctap::CtapStatus::PinAuthBlocked
                )
            ) {
                Err(CliError(
                    "Reset failed. Reset must be triggered within 5 seconds after the \
                     YubiKey is inserted."
                        .to_string(),
                ))
            } else if e.get_status() == Some(fido2_client::ctap::CtapStatus::KeepaliveCancel) {
                Err(CliError("Reset aborted by user.".to_string()))
            } else {
                Err(CliError(format!("FIDO reset failed: {e}")))
            }
        }
    }
}

pub fn run_access_change_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();

    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;

    let pin_is_set = ctap2.info().options.get("clientPin") == Some(&true);

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
            .map_err(|e| CliError(format!("Failed to change PIN: {e}")))?;
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
}

pub fn run_access_verify_pin(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();

    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;

    let pin_str = require_pin(&ctap2, pin, "PIN verification")?;

    // Get a PIN token to verify the PIN
    client_pin
        .get_pin_token(&pin_str, None, None)
        .map_err(|e| CliError(format!("PIN verification failed: {e}")))?;

    println!("PIN verified.");
    Ok(())
}

/// Require a PIN to be set and prompt if not provided.
fn map_enroll_error(e: CtapError, context: &str) -> CliError {
    if e.get_status() == Some(CtapStatus::KeepaliveCancel) {
        CliError("Fingerprint enrollment aborted by user.".to_string())
    } else {
        CliError(format!("{context}: {e}"))
    }
}

fn require_pin(ctap2: &Ctap2, pin: Option<&str>, feature: &str) -> Result<String, CliError> {
    if ctap2.info().options.get("clientPin") != Some(&true) {
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

/// Get a PIN token with the given permissions.
fn get_pin_token<'a>(
    client_pin: &'a ClientPin<'a>,
    pin: &str,
    permissions: u32,
) -> Result<(Vec<u8>, &'a PinProtocol), CliError> {
    let token = client_pin
        .get_pin_token(pin, Some(permissions), None)
        .map_err(|e| CliError(format!("PIN authentication failed: {e}")))?;
    Ok((token, client_pin.protocol()))
}

/// Get an optional PIN token — only required if a PIN is set on the device.
fn get_optional_pin_token<'a>(
    ctap2: &Ctap2,
    client_pin: &'a ClientPin<'a>,
    pin: Option<&str>,
    permissions: u32,
) -> Result<(Option<Vec<u8>>, Option<&'a PinProtocol>), CliError> {
    if ctap2.info().options.get("clientPin") != Some(&true) {
        return Ok((None, None));
    }
    let pin_str = require_pin(ctap2, pin, "This feature")?;
    let (token, protocol) = get_pin_token(client_pin, &pin_str, permissions)?;
    Ok((Some(token), Some(protocol)))
}

pub fn run_access_force_change(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    let options = &ctap2.info().options;
    if !options.get("setMinPINLength").copied().unwrap_or(false) {
        return Err(CliError(
            "Force change PIN is not supported on this YubiKey.".to_string(),
        ));
    }
    let pin_str = require_pin(&ctap2, pin, "Force change PIN")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x20)?; // AuthenticatorConfig

    let config = fido2_client::config::Config::from_parts(&ctap2, Some(protocol), Some(&token));
    config
        .set_min_pin_length(None, None, true)
        .map_err(|e| CliError(format!("Failed to set force change: {e}")))?;

    println!("Force PIN change set.");
    Ok(())
}

pub fn run_access_set_min_length(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    length: u32,
    pin: Option<&str>,
    rp_ids: &[String],
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

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

    if !rp_ids.is_empty() && rp_ids.len() > info.max_rpids_for_min_pin {
        return Err(CliError(format!(
            "Authenticator supports up to {} RP IDs ({} given).",
            info.max_rpids_for_min_pin,
            rp_ids.len()
        )));
    }

    let pin_str = require_pin(&ctap2, pin, "Set minimum PIN length")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x20)?;

    let config = fido2_client::config::Config::from_parts(&ctap2, Some(protocol), Some(&token));
    let rp_strs: Vec<&str> = rp_ids.iter().map(|s| s.as_str()).collect();
    let rp_arg = if rp_strs.is_empty() {
        None
    } else {
        Some(rp_strs.as_slice())
    };
    config
        .set_min_pin_length(Some(length), rp_arg, false)
        .map_err(|e| CliError(format!("Failed to set minimum PIN length: {e}")))?;

    println!("Minimum PIN length set.");
    Ok(())
}

pub fn run_credentials_list(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

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

    let pin_str = require_pin(&ctap2, pin, "Credential Management")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x04)?; // CredentialManagement

    let credman = fido2_client::credman::CredentialManagement::new(&ctap2, protocol, &token);

    let rps = credman
        .enumerate_rps()
        .map_err(|e| CliError(format!("Failed to enumerate RPs: {e}")))?;

    if rps.is_empty() {
        println!("No discoverable credentials.");
        return Ok(());
    }

    for rp_resp in &rps {
        let rp_map = match rp_resp {
            Value::Map(m) => m,
            _ => continue,
        };
        // Key 3 = rp entity, Key 4 = rpIDHash
        let rp_id = cbor_map_get_text(rp_map, 3, "id").unwrap_or_default();
        let rp_id_hash = cbor_map_get_bytes(rp_map, 4).unwrap_or_default();

        let creds = credman
            .enumerate_creds(&rp_id_hash)
            .map_err(|e| CliError(format!("Failed to enumerate credentials: {e}")))?;

        for cred_resp in &creds {
            let cred_map = match cred_resp {
                Value::Map(m) => m,
                _ => continue,
            };
            // Key 6 = user entity, Key 7 = credentialID
            let user_name = cbor_map_get_text(cred_map, 6, "name").unwrap_or_default();
            let display_name = cbor_map_get_text(cred_map, 6, "displayName").unwrap_or_default();
            let cred_id_bytes = cbor_map_get_nested_bytes(cred_map, 7, "id").unwrap_or_default();
            let cred_id_hex = hex::encode(&cred_id_bytes);

            println!(
                "{}... {} {} {}",
                &cred_id_hex[..8.min(cred_id_hex.len())],
                rp_id,
                user_name,
                display_name
            );
        }
    }

    Ok(())
}

pub fn run_credentials_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    credential_id: &str,
    pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    let pin_str = require_pin(&ctap2, pin, "Credential Management")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x04)?;

    let credman = fido2_client::credman::CredentialManagement::new(&ctap2, protocol, &token);
    let search = credential_id.trim_end_matches('.').to_lowercase();

    // Find matching credentials
    let rps = credman
        .enumerate_rps()
        .map_err(|e| CliError(format!("Failed to enumerate RPs: {e}")))?;

    let mut hits = Vec::new();
    for rp_resp in &rps {
        let rp_map = match rp_resp {
            Value::Map(m) => m,
            _ => continue,
        };
        let rp_id = cbor_map_get_text(rp_map, 3, "id").unwrap_or_default();
        let rp_id_hash = cbor_map_get_bytes(rp_map, 4).unwrap_or_default();

        let creds = credman.enumerate_creds(&rp_id_hash).unwrap_or_default();
        for cred_resp in &creds {
            let cred_map = match cred_resp {
                Value::Map(m) => m,
                _ => continue,
            };
            let user_name = cbor_map_get_text(cred_map, 6, "name").unwrap_or_default();
            let display_name = cbor_map_get_text(cred_map, 6, "displayName").unwrap_or_default();
            let cred_id_bytes = cbor_map_get_nested_bytes(cred_map, 7, "id").unwrap_or_default();
            let cred_id_hex = hex::encode(&cred_id_bytes);

            if cred_id_hex.starts_with(&search) {
                // Build the credentialID CBOR value for deletion
                let cred_id_value = cbor_map_get_value(cred_map, 7).cloned();
                if let Some(v) = cred_id_value {
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
                .delete_cred(cred_id_val.clone())
                .map_err(|e| CliError(format!("Failed to delete credential: {e}")))?;
            println!("Credential deleted.");
            Ok(())
        }
        _ => Err(CliError(
            "Multiple matches, make the credential ID more specific.".to_string(),
        )),
    }
}

pub fn run_fingerprints_list(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    if !ctap2.info().options.contains_key("bioEnroll") {
        return Err(CliError(
            "Fingerprints are not supported on this YubiKey.".to_string(),
        ));
    }

    let pin_str = require_pin(&ctap2, pin, "Biometrics")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x08)?; // BioEnrollment

    let bio = fido2_client::bio::FPBioEnrollment::new(&ctap2, protocol, &token)
        .map_err(|e| CliError(format!("Failed to initialize bio enrollment: {e}")))?;

    let enrollments = match bio.enumerate_enrollments() {
        Ok(resp) => {
            // Extract template infos array (key 0x07)
            let template_infos = match &resp {
                Value::Map(entries) => entries
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Int(0x07)))
                    .map(|(_, v)| v),
                _ => None,
            };
            match template_infos {
                Some(Value::Array(infos)) => infos.clone(),
                _ => vec![],
            }
        }
        Err(CtapError::StatusError(CtapStatus::InvalidOption)) => vec![],
        Err(e) => return Err(CliError(format!("Failed to enumerate fingerprints: {e}"))),
    };

    if enrollments.is_empty() {
        println!("No fingerprints registered.");
    } else {
        for info in &enrollments {
            if let Value::Map(entries) = info {
                let id = entries
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Int(0x01)))
                    .and_then(|(_, v)| v.as_bytes())
                    .map(hex::encode)
                    .unwrap_or_default();
                let name = entries
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Int(0x02)))
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

    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    let pin_str = require_pin(&ctap2, pin, "Biometrics")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x08)?;

    let bio = fido2_client::bio::FPBioEnrollment::new(&ctap2, protocol, &token)
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
    let (template_id, _status, remaining) = bio
        .enroll_begin(None, &mut |_| {}, Some(&is_cancelled))
        .map_err(|e| map_enroll_error(e, "Enrollment failed"))?;

    if remaining > 0 {
        eprintln!("{remaining} more scans needed.");
    }

    // Continue capturing
    let mut scans_remaining = remaining;
    while scans_remaining > 0 {
        eprintln!("Place your finger against the sensor now...");
        match bio.enroll_capture_next(&template_id, None, &mut |_| {}, Some(&is_cancelled)) {
            Ok((_status, remaining)) => {
                scans_remaining = remaining;
                if remaining > 0 {
                    eprintln!("{remaining} more scans needed.");
                }
            }
            Err(e) => {
                if e.get_status() == Some(CtapStatus::KeepaliveCancel) {
                    return Err(CliError(
                        "Fingerprint enrollment aborted by user.".to_string(),
                    ));
                }
                if e.get_status() == Some(CtapStatus::FpDatabaseFull) {
                    return Err(CliError(
                        "Fingerprint storage full. Remove some fingerprints first.".to_string(),
                    ));
                }
                if e.get_status() == Some(CtapStatus::UserActionTimeout) {
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

    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    let pin_str = require_pin(&ctap2, pin, "Biometrics")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x08)?;

    let bio = fido2_client::bio::FPBioEnrollment::new(&ctap2, protocol, &token)
        .map_err(|e| CliError(format!("Failed to initialize bio enrollment: {e}")))?;

    let key =
        hex::decode(template_id).map_err(|e| CliError(format!("Invalid template ID hex: {e}")))?;

    bio.set_name(&key, name)
        .map_err(|e| CliError(format!("Failed to rename fingerprint: {e}")))?;
    println!("Fingerprint renamed.");
    Ok(())
}

pub fn run_fingerprints_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    template_id: &str,
    pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    let pin_str = require_pin(&ctap2, pin, "Biometrics")?;
    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_pin_token(&client_pin, &pin_str, 0x08)?;

    let bio = fido2_client::bio::FPBioEnrollment::new(&ctap2, protocol, &token)
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
}

pub fn run_config_toggle_always_uv(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    let options = &ctap2.info().options;
    let always_uv = match options.get("alwaysUv") {
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

    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_optional_pin_token(&ctap2, &client_pin, pin, 0x20)?; // AuthenticatorConfig

    let config = fido2_client::config::Config::from_parts(&ctap2, protocol, token.as_deref());
    config
        .toggle_always_uv()
        .map_err(|e| CliError(format!("Failed to toggle Always Require UV: {e}")))?;

    println!(
        "Always Require UV is {}.",
        if always_uv { "off" } else { "on" }
    );
    Ok(())
}

pub fn run_config_enable_ep_attestation(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let fido_device = open_fido_device(dev, scp_params)?;
    let ctap_dev = fido_device.as_ctap_device();
    let ctap2 = Ctap2::new(ctap_dev, false)
        .map_err(|e| CliError(format!("Failed to initialize CTAP2: {e}")))?;

    let options = &ctap2.info().options;
    if !options.contains_key("ep") {
        return Err(CliError(
            "Enterprise Attestation is not supported on this YubiKey.".to_string(),
        ));
    }
    if options.get("alwaysUv") == Some(&true) && options.get("clientPin") != Some(&true) {
        return Err(CliError(
            "Enabling Enterprise Attestation requires a PIN when alwaysUv is enabled.".to_string(),
        ));
    }

    let client_pin = ClientPin::new(&ctap2, None)
        .map_err(|e| CliError(format!("Failed to create ClientPin: {e}")))?;
    let (token, protocol) = get_optional_pin_token(&ctap2, &client_pin, pin, 0x20)?; // AuthenticatorConfig

    let config = fido2_client::config::Config::from_parts(&ctap2, protocol, token.as_deref());
    config
        .enable_enterprise_attestation()
        .map_err(|e| CliError(format!("Failed to enable Enterprise Attestation: {e}")))?;

    println!("Enterprise Attestation enabled.");
    Ok(())
}

// --- CBOR map helper functions ---

fn cbor_map_get_value(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
        .map(|(_, v)| v)
}

fn cbor_map_get_text(map: &[(Value, Value)], key: i64, field: &str) -> Option<String> {
    let entity = cbor_map_get_value(map, key)?;
    if let Value::Map(entries) = entity {
        for (k, v) in entries {
            if k.as_text() == Some(field) {
                return v.as_text().map(|s| s.to_string());
            }
        }
    }
    None
}

fn cbor_map_get_bytes(map: &[(Value, Value)], key: i64) -> Option<Vec<u8>> {
    cbor_map_get_value(map, key)?.as_bytes().map(|b| b.to_vec())
}

fn cbor_map_get_nested_bytes(map: &[(Value, Value)], key: i64, field: &str) -> Option<Vec<u8>> {
    let entity = cbor_map_get_value(map, key)?;
    if let Value::Map(entries) = entity {
        for (k, v) in entries {
            if k.as_text() == Some(field) {
                return v.as_bytes().map(|b| b.to_vec());
            }
        }
    }
    None
}
