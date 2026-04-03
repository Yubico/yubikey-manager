use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::oath::parse_b32_key;
use yubikit::otp::{modhex_decode, modhex_encode};
use yubikit::yubiotp::{
    ACC_CODE_SIZE, KEY_SIZE, NdefType, Slot, SlotConfiguration, UID_SIZE, YubiOtpCcidSession,
    YubiOtpOtpSession, YubiOtpSession,
};

use crate::cli_enums::{CliCalcDigits, CliHotpDigits, CliKeyboardLayout, CliOtpSlot, CliPacing};
use crate::keyboard::{self, MODHEX_CHARS};
use crate::scp::{self, ScpConfig, ScpParams};
use crate::util::{self, CliError};

/// Open an OTP session, preferring HID. Falls back to SmartCard if HID is
/// unavailable, SCP is specified, or the device is on NFC.
fn open_session(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
) -> Result<Box<dyn YubiOtpSession>, CliError> {
    let scp_config = scp::resolve_scp(dev, scp_params, Capability::OTP)?;

    // If SCP is needed or NFC, must use SmartCard
    if !matches!(scp_config, ScpConfig::None) || scp::is_nfc(dev) {
        return open_sc(dev, scp_config);
    }

    // Try OTP HID first
    if let Ok(conn) = dev.open_otp()
        && let Ok(session) = YubiOtpOtpSession::new(conn)
    {
        return Ok(Box::new(session));
    }

    // Fall back to SmartCard
    open_sc(dev, scp_config)
}

fn open_sc(
    dev: &YubiKeyDevice,
    scp_config: ScpConfig,
) -> Result<Box<dyn YubiOtpSession>, CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    match scp_config {
        ScpConfig::None => {
            let session = YubiOtpCcidSession::new(conn)
                .map_err(|(e, _)| CliError(format!("Failed to open OTP session: {e}")))?;
            Ok(Box::new(session))
        }
        ref config => {
            let params = scp::to_scp_key_params(config)
                .expect("non-None ScpConfig must convert to ScpKeyParams");
            let session = YubiOtpCcidSession::new_with_scp(conn, &params)
                .map_err(|(e, _)| CliError(format!("Failed to open OTP session: {e}")))?;
            Ok(Box::new(session))
        }
    }
}

fn cli_to_keyboard_layout(layout: CliKeyboardLayout) -> keyboard::KeyboardLayout {
    match layout {
        CliKeyboardLayout::Us => keyboard::KeyboardLayout::Us,
        CliKeyboardLayout::Uk => keyboard::KeyboardLayout::Uk,
        CliKeyboardLayout::De => keyboard::KeyboardLayout::De,
        CliKeyboardLayout::Fr => keyboard::KeyboardLayout::Fr,
        CliKeyboardLayout::It => keyboard::KeyboardLayout::It,
        CliKeyboardLayout::Bepo => keyboard::KeyboardLayout::Bepo,
        CliKeyboardLayout::Norman => keyboard::KeyboardLayout::Norman,
        CliKeyboardLayout::Modhex => keyboard::KeyboardLayout::Modhex,
    }
}

fn encode_password(password: &str, layout: CliKeyboardLayout) -> Result<Vec<u8>, CliError> {
    let map = keyboard::scancodes(cli_to_keyboard_layout(layout));
    password
        .chars()
        .map(|c| {
            map.get(&c).copied().ok_or_else(|| {
                CliError(format!(
                    "Character '{c}' not supported in {layout:?} layout"
                ))
            })
        })
        .collect()
}

fn generate_static_pw(length: usize, layout: CliKeyboardLayout) -> Result<String, CliError> {
    let chars: Vec<char> = if matches!(layout, CliKeyboardLayout::Modhex) {
        MODHEX_CHARS.chars().collect()
    } else {
        keyboard::scancodes(cli_to_keyboard_layout(layout))
            .keys()
            .copied()
            .filter(|c| !"\t\n ".contains(*c))
            .collect()
    };
    let mut pw = String::with_capacity(length);
    let mut rand_bytes = vec![0u8; length];
    getrandom::fill(&mut rand_bytes)
        .map_err(|e| CliError(format!("Failed to generate random: {e}")))?;
    for b in rand_bytes {
        pw.push(chars[b as usize % chars.len()]);
    }
    Ok(pw)
}

fn parse_access_code(s: &str) -> Result<[u8; ACC_CODE_SIZE], CliError> {
    let bytes = hex::decode(s).map_err(|_| CliError("Access code must be hex-encoded.".into()))?;
    if bytes.len() != ACC_CODE_SIZE {
        return Err(CliError(format!(
            "Access code must be {ACC_CODE_SIZE} bytes ({} hex chars).",
            ACC_CODE_SIZE * 2
        )));
    }
    let mut arr = [0u8; ACC_CODE_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn confirm(msg: &str) -> bool {
    eprint!("{msg} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn confirm_slot_overwrite(session: &dyn YubiOtpSession, slot: Slot) {
    let state = session.get_config_state();
    if state.is_configured(slot).unwrap_or(false)
        && !confirm(&format!(
            "Slot {} is already configured. Overwrite configuration?",
            slot.map(1, 2)
        ))
    {
        std::process::exit(1);
    }
}

fn format_oath_code(response: &[u8], digits: u8) -> String {
    let offs = (response[response.len() - 1] & 0xF) as usize;
    let code = u32::from_be_bytes([
        response[offs] & 0x7F,
        response[offs + 1],
        response[offs + 2],
        response[offs + 3],
    ]);
    let modulus = 10u32.pow(digits as u32);
    format!("{:0>width$}", code % modulus, width = digits as usize)
}

fn b32_encode(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: true }, data)
}

fn parse_hex_key(s: &str) -> Result<Vec<u8>, CliError> {
    hex::decode(s).map_err(|_| CliError("Key must be hex-encoded.".into()))
}

fn prompt_for_touch() {
    eprintln!("Touch your YubiKey...");
}

pub fn run_info(dev: &YubiKeyDevice, scp_params: &ScpParams) -> Result<(), CliError> {
    let session = open_session(dev, scp_params)?;
    let state = session.get_config_state();
    for slot in [Slot::One, Slot::Two] {
        let num = slot.map(1, 2);
        let configured = state.is_configured(slot).map_or("unknown".into(), |b| {
            if b {
                "programmed".to_string()
            } else {
                "empty".to_string()
            }
        });
        println!("Slot {num}: {configured}");
    }
    Ok(())
}

pub fn run_swap(dev: &YubiKeyDevice, scp_params: &ScpParams, force: bool) -> Result<(), CliError> {
    if !force && !confirm("Swap the two slot configurations?") {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_session(dev, scp_params)?;
    session
        .swap_slots()
        .map_err(|e| CliError(format!("Failed to swap slots: {e}")))?;
    eprintln!("Slot configurations swapped.");
    Ok(())
}

pub fn run_delete(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    let session = open_session(dev, scp_params)?;
    if !force && matches!(session.get_config_state().is_configured(slot), Ok(false)) {
        return Err(CliError("Not possible to delete an empty slot.".into()));
    }
    if !force && !confirm(&format!("Delete slot {}?", slot.map(1, 2))) {
        return Err(CliError("Aborted.".into()));
    }
    drop(session);

    let mut session = open_session(dev, scp_params)?;
    session
        .delete_slot(slot, acc.as_ref().map(|a| a.as_slice()))
        .map_err(|e| CliError(format!("Failed to delete slot: {e}")))?;
    eprintln!("Configuration slot {} deleted.", slot.map(1, 2));
    Ok(())
}

pub fn run_ndef(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    prefix: Option<&str>,
    ndef_type: NdefType,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;
    let nt = ndef_type;
    if !force
        && !confirm(&format!(
            "Configure slot {} for NDEF ({ndef_type:?})?",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_session(dev, scp_params)?;
    session
        .set_ndef_configuration(slot, prefix, acc.as_ref().map(|a| a.as_slice()), nt)
        .map_err(|e| CliError(format!("Failed to configure NDEF: {e}")))?;
    eprintln!("NDEF configuration updated.");
    Ok(())
}

pub fn run_yubiotp(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    public_id: Option<&str>,
    private_id: Option<&str>,
    key: Option<&str>,
    serial_public_id: bool,
    generate_private_id: bool,
    generate_key: bool,
    enter: Option<bool>,
    access_code: Option<&str>,
    force: bool,
    config_output: Option<&str>,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    if public_id.is_some() && serial_public_id {
        return Err(CliError(
            "Invalid options: --public-id conflicts with --serial-public-id.".into(),
        ));
    }
    if private_id.is_some() && generate_private_id {
        return Err(CliError(
            "Invalid options: --private-id conflicts with --generate-private-id.".into(),
        ));
    }
    if key.is_some() && generate_key {
        return Err(CliError(
            "Invalid options: --key conflicts with --generate-key.".into(),
        ));
    }

    // Resolve public ID
    let pub_id_bytes: Vec<u8> = if serial_public_id {
        let mut session = open_session(dev, scp_params)?;
        let serial = session
            .get_serial()
            .map_err(|e| CliError(format!("Failed to get serial: {e}")))?;
        let mut id = vec![0xffu8, 0x00];
        id.extend_from_slice(&serial.to_be_bytes());
        eprintln!("Using YubiKey serial as public ID: {}", modhex_encode(&id));
        id
    } else if let Some(pid) = public_id {
        modhex_decode(pid).map_err(|_| CliError("Invalid modhex public ID.".into()))?
    } else if force {
        return Err(CliError(
            "Public ID not given. Remove the --force flag, or add the --serial-public-id flag or --public-id option.".into(),
        ));
    } else {
        let pid = util::prompt("Enter public ID")?;
        if pid.len() % 2 != 0 {
            return Err(CliError(
                "Invalid public ID, length must be a multiple of 2.".into(),
            ));
        }
        modhex_decode(&pid).map_err(|_| CliError("Invalid modhex public ID.".into()))?
    };

    // Resolve private ID
    let priv_id: [u8; UID_SIZE] = if generate_private_id {
        let mut id = [0u8; UID_SIZE];
        getrandom::fill(&mut id).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        eprintln!("Using a randomly generated private ID: {}", hex::encode(id));
        id
    } else if let Some(pid) = private_id {
        let bytes =
            hex::decode(pid).map_err(|_| CliError("Private ID must be hex-encoded.".into()))?;
        if bytes.len() != UID_SIZE {
            return Err(CliError(format!(
                "Private ID must be {UID_SIZE} bytes ({} hex chars).",
                UID_SIZE * 2
            )));
        }
        let mut arr = [0u8; UID_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    } else if force {
        return Err(CliError(
            "Private ID not given. Remove the --force flag, or add the --generate-private-id flag or --private-id option.".into(),
        ));
    } else {
        let pid = util::prompt("Enter private ID")?;
        let bytes =
            hex::decode(&pid).map_err(|_| CliError("Private ID must be hex-encoded.".into()))?;
        if bytes.len() != UID_SIZE {
            return Err(CliError(format!(
                "Private ID must be {UID_SIZE} bytes ({} hex chars).",
                UID_SIZE * 2
            )));
        }
        let mut arr = [0u8; UID_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    };

    // Resolve key
    let key_bytes: [u8; KEY_SIZE] = if generate_key {
        let mut k = [0u8; KEY_SIZE];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        eprintln!("Using a randomly generated secret key: {}", hex::encode(k));
        k
    } else if let Some(k) = key {
        let bytes = hex::decode(k).map_err(|_| CliError("Key must be hex-encoded.".into()))?;
        if bytes.len() != KEY_SIZE {
            return Err(CliError(format!(
                "Key must be {KEY_SIZE} bytes ({} hex chars).",
                KEY_SIZE * 2
            )));
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    } else if force {
        return Err(CliError(
            "Secret key not given. Remove the --force flag, or add the --generate-key flag or --key option.".into(),
        ));
    } else {
        let k = util::prompt("Enter secret key")?;
        let bytes = hex::decode(&k).map_err(|_| CliError("Key must be hex-encoded.".into()))?;
        if bytes.len() != KEY_SIZE {
            return Err(CliError(format!(
                "Key must be {KEY_SIZE} bytes ({} hex chars).",
                KEY_SIZE * 2
            )));
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    };

    if !force
        && !confirm(&format!(
            "Program a YubiOTP credential in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }

    let mut config = SlotConfiguration::yubiotp(&pub_id_bytes, &priv_id, &key_bytes)
        .map_err(|e| CliError(format!("Invalid configuration: {e}")))?;
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    if let Some(output_path) = config_output {
        // Get serial for CSV
        let serial = session
            .get_serial()
            .map_err(|e| CliError(format!("Failed to get serial: {e}")))?;
        let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        let access_code_hex = acc.as_ref().map_or(String::new(), hex::encode);
        let csv_line = format!(
            "{},{},{},{},{},{},",
            serial,
            modhex_encode(&pub_id_bytes),
            hex::encode(priv_id),
            hex::encode(key_bytes),
            access_code_hex,
            timestamp,
        );
        util::write_file_or_stdout(output_path, (csv_line + "\n").as_bytes())?;
        eprintln!("Configuration parameters written to {output_path}.");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_static(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    password: Option<&str>,
    generate: bool,
    length: usize,
    keyboard_layout: CliKeyboardLayout,
    enter: Option<bool>,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    let pw = if let Some(p) = password {
        if p.len() > 38 {
            return Err(CliError(
                "Password too long (maximum length is 38 characters).".into(),
            ));
        }
        p.to_string()
    } else if generate {
        generate_static_pw(length, keyboard_layout)?
    } else {
        util::prompt("Enter a static password")?
    };

    let scan_codes = encode_password(&pw, keyboard_layout)?;

    if !force {
        let session = open_session(dev, scp_params)?;
        confirm_slot_overwrite(session.as_ref(), slot);
    }

    let mut config = SlotConfiguration::static_password(&scan_codes)
        .map_err(|e| CliError(format!("Invalid configuration: {e}")))?;
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    eprintln!("Static password stored in slot {}.", slot.map(1, 2));
    Ok(())
}

pub fn run_chalresp(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    key: Option<&str>,
    totp: bool,
    touch: bool,
    generate: bool,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    let key_bytes: Vec<u8> = if let Some(k) = key {
        if generate {
            return Err(CliError(
                "Invalid options: --generate conflicts with KEY argument.".into(),
            ));
        }
        if totp {
            parse_b32_key(k).map_err(|_| CliError("Invalid Base32-encoded key.".into()))?
        } else {
            parse_hex_key(k)?
        }
    } else if generate {
        let mut k = vec![0u8; 20];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        if totp {
            eprintln!(
                "Using a randomly generated key (base32): {}",
                b32_encode(&k)
            );
        } else {
            eprintln!("Using a randomly generated key (hex): {}", hex::encode(&k));
        }
        k
    } else if force {
        return Err(CliError(
            "No secret key given. Remove the --force flag, set the KEY argument or set the --generate flag.".into(),
        ));
    } else if totp {
        loop {
            let input = util::prompt("Enter a secret key (base32)")?;
            match parse_b32_key(&input) {
                Ok(k) => break k,
                Err(e) => eprintln!("{e}"),
            }
        }
    } else {
        let input = util::prompt("Enter a secret key")?;
        parse_hex_key(&input)?
    };

    let cred_type = if totp { "TOTP" } else { "challenge-response" };
    if !force
        && !confirm(&format!(
            "Program a {cred_type} credential in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }

    let mut config = SlotConfiguration::hmac_sha1(&key_bytes)
        .map_err(|e| CliError(format!("Invalid key: {e}")))?;
    if touch {
        config = config.require_touch(true);
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    eprintln!("{cred_type} credential stored in slot {}.", slot.map(1, 2));
    Ok(())
}

pub fn run_calculate(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    challenge: Option<&str>,
    totp: bool,
    digits: CliCalcDigits,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let digits = digits.as_u8();

    let challenge_bytes: Vec<u8> = if totp {
        if let Some(c) = challenge {
            let ts: u64 = c
                .parse()
                .map_err(|_| CliError("Timestamp challenge for TOTP must be an integer.".into()))?;
            (ts / 30).to_be_bytes().to_vec()
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            (now / 30).to_be_bytes().to_vec()
        }
    } else if let Some(c) = challenge {
        hex::decode(c).map_err(|_| CliError("Challenge must be hex-encoded.".into()))?
    } else {
        let input = util::prompt("Enter a challenge (hex)")?;
        hex::decode(&input).map_err(|_| CliError("Challenge must be hex-encoded.".into()))?
    };

    let mut session = open_session(dev, scp_params)?;

    // Check that slot is configured
    if matches!(session.get_config_state().is_configured(slot), Ok(false)) {
        return Err(CliError(
            "Cannot perform challenge-response on an empty slot.".into(),
        ));
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let prompted = AtomicBool::new(false);
    let on_keepalive = |status: u8| {
        if status == 2 && !prompted.swap(true, std::sync::atomic::Ordering::Relaxed) {
            prompt_for_touch();
        }
    };

    let result = session
        .calculate_hmac_sha1_with_cancel(slot, &challenge_bytes, Some(cancel), Some(&on_keepalive))
        .map_err(|e| CliError(format!("Failed to calculate: {e}")))?;

    if totp {
        println!("{}", format_oath_code(&result, digits));
    } else {
        println!("{}", hex::encode(&result));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_hotp(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    key: Option<&str>,
    digits: CliHotpDigits,
    counter: u32,
    enter: Option<bool>,
    access_code: Option<&str>,
    force: bool,
    identifier: Option<&str>,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let acc = access_code.map(parse_access_code).transpose()?;

    let key_bytes = if let Some(k) = key {
        parse_b32_key(k).map_err(|_| CliError("Invalid Base32-encoded key.".into()))?
    } else {
        loop {
            let input = util::prompt("Enter a secret key (base32)")?;
            match parse_b32_key(&input) {
                Ok(k) => break k,
                Err(e) => eprintln!("{e}"),
            }
        }
    };

    // Parse token identifier
    let (token_id, mh1, mh2) = if let Some(ident) = identifier {
        let ident = if ident == "-" { "ubhe" } else { ident };
        let ident = match ident.len() {
            4 => {
                let mut session = open_session(dev, scp_params)?;
                let serial = session
                    .get_serial()
                    .map_err(|e| CliError(format!("Failed to get serial: {e}")))?;
                format!("{ident}{serial:08}")
            }
            8 => format!("ubhe{ident}"),
            12 => ident.to_string(),
            _ => return Err(CliError("Incorrect length for token identifier.".into())),
        };

        let (omp_m, omp) = parse_modhex_or_bcd(&ident[..2])?;
        let (tt_m, tt) = parse_modhex_or_bcd(&ident[2..4])?;
        let (mui_m, mui) = parse_modhex_or_bcd(&ident[4..])?;

        if tt_m && !omp_m {
            return Err(CliError(
                "TT can only be modhex encoded if OMP is as well.".into(),
            ));
        }
        if mui_m && !(omp_m && tt_m) {
            return Err(CliError(
                "MUI can only be modhex encoded if OMP and TT are as well.".into(),
            ));
        }

        let mut tid = Vec::new();
        tid.extend_from_slice(&omp);
        tid.extend_from_slice(&tt);
        tid.extend_from_slice(&mui);

        let mh1 = if mui_m { true } else { omp_m && !tt_m };
        let mh2 = mui_m || tt_m;
        (tid, mh1, mh2)
    } else {
        (vec![], false, false)
    };

    if !force
        && !confirm(&format!(
            "Program a HOTP credential in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }

    let mut config =
        SlotConfiguration::hotp(&key_bytes).map_err(|e| CliError(format!("Invalid key: {e}")))?;
    if matches!(digits, CliHotpDigits::Eight) {
        config = config.digits8(true);
    }
    if counter > 0 {
        config = config
            .imf(counter)
            .map_err(|e| CliError(format!("Invalid counter: {e}")))?;
    }
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }
    if !token_id.is_empty() {
        config = config
            .token_id(&token_id, mh1, mh2)
            .map_err(|e| CliError(format!("Invalid token identifier: {e}")))?;
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    eprintln!("HOTP credential stored in slot {}.", slot.map(1, 2));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_settings(
    dev: &YubiKeyDevice,
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    enter: Option<bool>,
    pacing: Option<CliPacing>,
    use_numeric: Option<bool>,
    serial_usb_visible: Option<bool>,
    new_access_code: Option<&str>,
    delete_access_code: bool,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let cur_acc = access_code.map(parse_access_code).transpose()?;

    if new_access_code.is_some() && delete_access_code {
        return Err(CliError(
            "--new-access-code conflicts with --delete-access-code.".into(),
        ));
    }

    if delete_access_code && access_code.is_none() {
        return Err(CliError(
            "--delete-access-code used without providing an access code (see \"ykman otp --help\" for more info).".into(),
        ));
    }

    let session = open_session(dev, scp_params)?;
    if matches!(session.get_config_state().is_configured(slot), Ok(false)) {
        return Err(CliError(
            "Not possible to update settings on an empty slot.".into(),
        ));
    }
    drop(session);

    let new_acc = if delete_access_code {
        None
    } else if let Some(nac) = new_access_code {
        Some(parse_access_code(nac)?)
    } else {
        cur_acc
    };

    if !force
        && !confirm(&format!(
            "Update the settings for slot {}? All existing settings will be overwritten.",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }

    let mut config = SlotConfiguration::update();
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }
    if let Some(p) = pacing {
        let p = p.as_u8();
        config = config.pacing(p >= 20, p >= 40);
    }
    if let Some(v) = use_numeric {
        config = config.use_numeric(v);
    }
    if let Some(v) = serial_usb_visible {
        config = config.serial_usb_visible(v);
    }

    let mut session = open_session(dev, scp_params)?;
    session
        .update_configuration(
            slot,
            &config,
            new_acc.as_ref().map(|a| a.as_slice()),
            cur_acc.as_ref().map(|a| a.as_slice()),
        )
        .map_err(|e| CliError(format!("Failed to update settings: {e}")))?;

    eprintln!("Settings for slot {} updated.", slot.map(1, 2));
    Ok(())
}

/// Parse a value as modhex or BCD (decimal digits encoded as hex).
/// Returns (is_modhex, decoded_bytes).
fn parse_modhex_or_bcd(value: &str) -> Result<(bool, Vec<u8>), CliError> {
    if let Ok(bytes) = modhex_decode(value) {
        return Ok((true, bytes));
    }
    // Try to parse as decimal digits (BCD)
    if value.chars().all(|c| c.is_ascii_digit()) {
        let bytes =
            hex::decode(value).map_err(|_| CliError("Value must be modhex or decimal.".into()))?;
        return Ok((false, bytes));
    }
    Err(CliError("Value must be modhex or decimal.".into()))
}
