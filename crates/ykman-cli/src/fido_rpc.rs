//! FIDO CLI commands backed by the RPC subprocess.
//!
//! Each function mirrors the corresponding `fido::run_*` function but uses an
//! [`RpcClient`] to communicate with a `ykman rpc` subprocess instead of
//! accessing the YubiKey directly.

use serde_json::{Value, json};

use crate::rpc::client::RpcClient;
use crate::util::CliError;

/// The CTAP2 target path, using the "ctap" (HID) connection by default.
const CTAP2: &[&str] = &["ctap", "ctap2"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Unlock the CTAP2 node with a PIN.
fn unlock(client: &mut RpcClient, pin: &str) -> Result<(), CliError> {
    client
        .call("unlock", CTAP2, json!({"pin": pin}), None, false)
        .map(|_| ())
}

/// Get CTAP2 node data.
fn get_ctap2_data(client: &mut RpcClient) -> Result<Value, CliError> {
    let result = client.get(CTAP2)?;
    Ok(result.body.get("data").cloned().unwrap_or(json!({})))
}

/// Get the `info.options` object from ctap2 data.
fn get_options(data: &Value) -> Value {
    data.get("info")
        .and_then(|i| i.get("options"))
        .cloned()
        .unwrap_or(json!({}))
}

/// Check if a PIN is set on the device.
fn has_pin(data: &Value) -> bool {
    get_options(data).get("clientPin") == Some(&json!(true))
}

/// Require PIN if clientPin is set, returning the PIN string.
fn require_pin(
    client: &mut RpcClient,
    data: &Value,
    pin: Option<&str>,
    purpose: &str,
) -> Result<String, CliError> {
    if !has_pin(data) {
        return Err(CliError(format!(
            "{purpose} requires a PIN, but no PIN is set. Use 'ykman fido access change-pin' first."
        )));
    }
    let pin_str = match pin {
        Some(p) => p.to_string(),
        None => {
            eprint!("Enter your PIN: ");
            rpassword::read_password().map_err(|e| CliError(format!("Failed to read PIN: {e}")))?
        }
    };
    unlock(client, &pin_str)?;
    Ok(pin_str)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// FIDO Info
// ---------------------------------------------------------------------------

pub fn run_info(client: &mut RpcClient) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    let info = data
        .get("info")
        .ok_or_else(|| CliError("Missing info".into()))?;
    let options = get_options(&data);

    // AAGUID
    if let Some(aaguid) = info.get("aaguid").and_then(|v| v.as_str()) {
        // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        let formatted = if aaguid.len() == 32 && !aaguid.contains('-') {
            format!(
                "{}-{}-{}-{}-{}",
                &aaguid[..8],
                &aaguid[8..12],
                &aaguid[12..16],
                &aaguid[16..20],
                &aaguid[20..],
            )
        } else {
            aaguid.to_string()
        };
        println!("AAGUID:         {formatted}");
    }

    // PIN status
    if options.get("clientPin") == Some(&json!(true)) {
        if info.get("force_pin_change") == Some(&json!(true)) {
            println!("NOTE: The FIDO PIN is disabled and must be changed before it can be used!");
        }
        let retries = data
            .get("pin_retries")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if retries > 0 {
            print!("PIN:            {retries} attempt(s) remaining");
            if let Some(pc) = data.get("power_cycle").and_then(|v| v.as_u64())
                && pc > 0
            {
                print!(
                    "\nPIN is temporarily blocked. \
                     Remove and re-insert the YubiKey to unblock."
                );
            }
            println!();
        } else {
            println!("PIN:            Blocked");
        }
    } else {
        println!("PIN:            Not set");
    }

    // Minimum PIN length
    if let Some(min_len) = info.get("min_pin_length").and_then(|v| v.as_u64()) {
        println!("Minimum PIN length: {min_len}");
    }

    // Fingerprint status
    if let Some(bio) = options.get("bioEnroll") {
        if bio == &json!(true) {
            if let Some(uv_retries) = data.get("uv_retries").and_then(|v| v.as_u64()) {
                if uv_retries > 0 {
                    println!("Fingerprints:   Registered, {uv_retries} attempt(s) remaining");
                } else {
                    println!("Fingerprints:   Registered, blocked until PIN is verified");
                }
            } else {
                println!("Fingerprints:   Registered");
            }
        } else {
            println!("Fingerprints:   Not registered");
        }
    }

    // Always Require UV
    if let Some(always_uv) = options.get("alwaysUv").and_then(|v| v.as_bool()) {
        println!(
            "Always Require UV: {}",
            if always_uv { "On" } else { "Off" }
        );
    }

    // Remaining discoverable credentials
    if let Some(remaining) = info.get("remaining_disc_creds").and_then(|v| v.as_u64()) {
        println!("Credential storage remaining: {remaining}");
    }

    // Enterprise Attestation
    if let Some(ep) = options.get("ep").and_then(|v| v.as_bool()) {
        println!(
            "Enterprise Attestation: {}",
            if ep { "Enabled" } else { "Disabled" }
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

pub fn run_reset(client: &mut RpcClient, force: bool) -> Result<(), CliError> {
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
    }

    let data = get_ctap2_data(client)?;
    let long_touch = data
        .get("info")
        .and_then(|i| i.get("long_touch_for_reset"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let signal_handler = move |status: &str, body: &Value| {
        if status == "reset"
            && let Some(state) = body.get("state").and_then(|v| v.as_str())
        {
            match state {
                "remove" => eprintln!("Remove your YubiKey from the USB port."),
                "insert" => eprintln!("Re-insert your YubiKey now..."),
                "touch" => {
                    if long_touch {
                        eprintln!("Press and hold the YubiKey button for 5 seconds to confirm.");
                    } else {
                        eprintln!("Touch the YubiKey to confirm.");
                    }
                }
                _ => {}
            }
        }
    };

    match client.call("reset", CTAP2, json!({}), Some(&signal_handler), true) {
        Ok(_) => {
            println!("FIDO application has been reset.");
            Ok(())
        }
        Err(e) => {
            let msg = e.0.to_lowercase();
            if msg.contains("keepalivecancel") || msg.contains("keepalive_cancel") {
                Err(CliError("Reset aborted by user.".to_string()))
            } else if msg.contains("useractiontimeout") || msg.contains("user_action_timeout") {
                Err(CliError(
                    "Reset failed. You need to touch your YubiKey to confirm the reset."
                        .to_string(),
                ))
            } else if msg.contains("notallowed") || msg.contains("pinauthblocked") {
                Err(CliError(
                    "Reset failed. Reset must be triggered within 5 seconds after the \
                     YubiKey is inserted."
                        .to_string(),
                ))
            } else {
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Access — change-pin, verify-pin, force-change, set-min-length
// ---------------------------------------------------------------------------

pub fn run_access_change_pin(
    client: &mut RpcClient,
    pin: Option<&str>,
    new_pin: Option<&str>,
) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    let pin_is_set = has_pin(&data);

    if pin_is_set {
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
        client.call(
            "set_pin",
            CTAP2,
            json!({"pin": current_pin, "new_pin": new}),
            None,
            false,
        )?;
        println!("PIN has been changed.");
    } else {
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
        client.call("set_pin", CTAP2, json!({"new_pin": new}), None, false)?;
        println!("PIN has been set.");
    }

    Ok(())
}

pub fn run_access_verify_pin(client: &mut RpcClient, pin: Option<&str>) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    require_pin(client, &data, pin, "PIN verification")?;
    println!("PIN verified.");
    Ok(())
}

pub fn run_access_force_change(client: &mut RpcClient, pin: Option<&str>) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    if get_options(&data).get("setMinPINLength") != Some(&json!(true)) {
        return Err(CliError(
            "Force change PIN is not supported on this YubiKey.".to_string(),
        ));
    }
    require_pin(client, &data, pin, "Force change PIN")?;
    client.call("force_pin_change", CTAP2, json!({}), None, false)?;
    println!("Force PIN change set.");
    Ok(())
}

pub fn run_access_set_min_length(
    client: &mut RpcClient,
    length: u32,
    pin: Option<&str>,
    rp_ids: &[String],
) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    let info = data
        .get("info")
        .ok_or_else(|| CliError("Missing info".into()))?;

    if get_options(&data).get("setMinPINLength") != Some(&json!(true)) {
        return Err(CliError(
            "Set minimum PIN length is not supported on this YubiKey.".to_string(),
        ));
    }

    let current_min = info
        .get("min_pin_length")
        .and_then(|v| v.as_u64())
        .unwrap_or(4);
    if (length as u64) < current_min {
        return Err(CliError(format!(
            "Cannot set a minimum length shorter than {current_min}."
        )));
    }

    let max_rpids = info
        .get("max_rpids_for_min_pin")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    if !rp_ids.is_empty() && rp_ids.len() > max_rpids {
        return Err(CliError(format!(
            "Authenticator supports up to {max_rpids} RP IDs ({} given).",
            rp_ids.len()
        )));
    }

    require_pin(client, &data, pin, "Set minimum PIN length")?;

    let mut body = json!({"min_pin_length": length});
    if !rp_ids.is_empty() {
        body["rp_ids"] = json!(rp_ids);
    }
    client.call("set_min_pin_length", CTAP2, body, None, false)?;
    println!("Minimum PIN length set.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Collect all credentials from the RPC tree. Returns (rp_id, cred_id_hex,
/// user_name, display_name, user_id_hex) tuples.
fn collect_credentials(
    client: &mut RpcClient,
) -> Result<Vec<(String, String, String, String, String)>, CliError> {
    let creds_result = client.get(&[CTAP2[0], CTAP2[1], "credentials"])?;
    let children = creds_result
        .body
        .get("children")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let mut all_creds = Vec::new();

    for (rp_id, _rp_data) in &children {
        let rp_target: Vec<&str> = vec![CTAP2[0], CTAP2[1], "credentials", rp_id.as_str()];
        let rp_result = client.get(&rp_target)?;
        let rp_children = rp_result
            .body
            .get("children")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        for (cred_id_hex, cred_data) in &rp_children {
            let user_name = cred_data
                .get("user_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let display_name = cred_data
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let user_id = cred_data
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            all_creds.push((
                rp_id.clone(),
                cred_id_hex.clone(),
                user_name,
                display_name,
                user_id,
            ));
        }
    }

    Ok(all_creds)
}

pub fn run_credentials_list(
    client: &mut RpcClient,
    pin: Option<&str>,
    csv: bool,
) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    require_pin(client, &data, pin, "Credential Management")?;

    let all_creds = collect_credentials(client)?;

    if all_creds.is_empty() {
        println!("No discoverable credentials.");
        return Ok(());
    }

    if csv {
        println!("credential_id,rp_id,user_name,user_display_name,user_id");
        for (rp_id, cred_id, user_name, display_name, user_id) in &all_creds {
            println!(
                "{},{},{},{},{}",
                csv_escape(cred_id),
                csv_escape(rp_id),
                csv_escape(user_name),
                csv_escape(display_name),
                csv_escape(user_id),
            );
        }
    } else {
        // Determine shortest unique credential ID prefix
        let mut ln = 4;
        while all_creds
            .iter()
            .map(|(_, id, _, _, _)| id[..ln.min(id.len())].to_string())
            .collect::<std::collections::HashSet<_>>()
            .len()
            < all_creds.len()
        {
            ln += 1;
        }

        let headings = ["Credential ID", "RP ID", "Username", "Display name"];
        let rows: Vec<[String; 4]> = all_creds
            .iter()
            .map(|(rp_id, cred_id, user_name, display_name, _)| {
                let short_id = format!("{}...", &cred_id[..ln.min(cred_id.len())]);
                [
                    short_id,
                    rp_id.clone(),
                    user_name.clone(),
                    display_name.clone(),
                ]
            })
            .collect();

        let mut widths = headings.map(|h| h.len());
        for row in &rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.len());
            }
        }

        let header: Vec<String> = headings
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
            .collect();
        println!("{}", header.join("  "));

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
}

pub fn run_credentials_delete(
    client: &mut RpcClient,
    credential_id: &str,
    pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    require_pin(client, &data, pin, "Credential Management")?;

    let all_creds = collect_credentials(client)?;
    let search = credential_id.trim_end_matches('.').to_lowercase();

    let hits: Vec<_> = all_creds
        .iter()
        .filter(|(_, cred_id, _, _, _)| cred_id.starts_with(&search))
        .collect();

    match hits.len() {
        0 => Err(CliError("No matches, nothing to be done.".to_string())),
        1 => {
            let (rp_id, cred_id_hex, user_name, display_name, _) = hits[0];
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
            // Navigate to the specific credential and delete
            let target: Vec<&str> = vec![
                CTAP2[0],
                CTAP2[1],
                "credentials",
                rp_id.as_str(),
                cred_id_hex.as_str(),
            ];
            client.call("delete", &target, json!({}), None, false)?;
            println!("Credential deleted.");
            Ok(())
        }
        _ => Err(CliError(
            "Multiple matches, make the credential ID more specific.".to_string(),
        )),
    }
}

pub fn run_credentials_update(
    _client: &mut RpcClient,
    _credential_id: &str,
    _name: Option<&str>,
    _display_name: Option<&str>,
    _pin: Option<&str>,
) -> Result<(), CliError> {
    // Note: credential update (update_user_info) is not exposed via the RPC
    // node tree. Fall back to non-RPC mode for this command, or add an RPC
    // action later.
    Err(CliError(
        "Credential update is not yet supported in RPC mode.".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

pub fn run_fingerprints_list(client: &mut RpcClient, pin: Option<&str>) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    if get_options(&data).get("bioEnroll").is_none() {
        return Err(CliError(
            "Fingerprints are not supported on this YubiKey.".to_string(),
        ));
    }

    require_pin(client, &data, pin, "Biometrics")?;

    let fp_result = client.get(&[CTAP2[0], CTAP2[1], "fingerprints"])?;
    let children = fp_result
        .body
        .get("children")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    if children.is_empty() {
        println!("No fingerprints registered.");
    } else {
        for (id, fp_data) in &children {
            if let Some(name) = fp_data.get("name").and_then(|v| v.as_str()) {
                println!("ID: {id} ({name})");
            } else {
                println!("ID: {id}");
            }
        }
    }

    Ok(())
}

pub fn run_fingerprints_add(
    client: &mut RpcClient,
    name: &str,
    pin: Option<&str>,
) -> Result<(), CliError> {
    if name.len() > 15 {
        return Err(CliError(
            "Fingerprint name must be a maximum of 15 characters.".to_string(),
        ));
    }

    let data = get_ctap2_data(client)?;
    require_pin(client, &data, pin, "Biometrics")?;

    let signal_handler = |status: &str, body: &Value| match status {
        "capture" => {
            if let Some(remaining) = body.get("remaining").and_then(|v| v.as_u64())
                && remaining > 0
            {
                eprintln!("{remaining} more scans needed.");
            }
            eprintln!("Place your finger against the sensor now...");
        }
        "capture-error" => {
            eprintln!("Capture failed. Re-center your finger, and try again.");
        }
        _ => {}
    };

    eprintln!("Place your finger against the sensor now...");
    client.call(
        "add",
        &[CTAP2[0], CTAP2[1], "fingerprints"],
        json!({"name": name}),
        Some(&signal_handler),
        true,
    )?;
    eprintln!("Capture complete.");
    println!("Fingerprint registered.");
    Ok(())
}

pub fn run_fingerprints_rename(
    client: &mut RpcClient,
    template_id: &str,
    name: &str,
    pin: Option<&str>,
) -> Result<(), CliError> {
    if name.len() > 15 {
        return Err(CliError(
            "Fingerprint name must be a maximum of 15 characters.".to_string(),
        ));
    }

    let data = get_ctap2_data(client)?;
    require_pin(client, &data, pin, "Biometrics")?;

    let target: Vec<&str> = vec![CTAP2[0], CTAP2[1], "fingerprints", template_id];
    client.call("rename", &target, json!({"name": name}), None, false)?;
    println!("Fingerprint renamed.");
    Ok(())
}

pub fn run_fingerprints_delete(
    client: &mut RpcClient,
    template_id: &str,
    pin: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    require_pin(client, &data, pin, "Biometrics")?;

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

    let target: Vec<&str> = vec![CTAP2[0], CTAP2[1], "fingerprints", template_id];
    client.call("delete", &target, json!({}), None, false)?;
    println!("Fingerprint deleted.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

pub fn run_config_toggle_always_uv(
    client: &mut RpcClient,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    let options = get_options(&data);

    let always_uv = match options.get("alwaysUv").and_then(|v| v.as_bool()) {
        Some(v) => v,
        None => {
            return Err(CliError(
                "Always Require UV is not supported on this YubiKey.".to_string(),
            ));
        }
    };

    if has_pin(&data) {
        require_pin(client, &data, pin, "Toggle Always Require UV")?;
    }
    client.call("toggle_always_uv", CTAP2, json!({}), None, false)?;

    println!(
        "Always Require UV is {}.",
        if always_uv { "off" } else { "on" }
    );
    Ok(())
}

pub fn run_config_enable_ep_attestation(
    client: &mut RpcClient,
    pin: Option<&str>,
) -> Result<(), CliError> {
    let data = get_ctap2_data(client)?;
    let options = get_options(&data);

    if !options.as_object().is_some_and(|o| o.contains_key("ep")) {
        return Err(CliError(
            "Enterprise Attestation is not supported on this YubiKey.".to_string(),
        ));
    }
    if options.get("alwaysUv") == Some(&json!(true))
        && options.get("clientPin") != Some(&json!(true))
    {
        return Err(CliError(
            "Enabling Enterprise Attestation requires a PIN when alwaysUv is enabled.".to_string(),
        ));
    }

    if has_pin(&data) {
        require_pin(client, &data, pin, "Enable Enterprise Attestation")?;
    }
    client.call("enable_ep_attestation", CTAP2, json!({}), None, false)?;

    println!("Enterprise Attestation enabled.");
    Ok(())
}
