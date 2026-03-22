use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::otp_codec::{modhex_decode, modhex_encode};
use yubikit_rs::yubiotp::{
    NdefType, Slot, SlotConfiguration, YubiOtpOtpSession, YubiOtpSession, ACC_CODE_SIZE,
    KEY_SIZE, UID_SIZE,
};

use crate::util::CliError;

const SHIFT: u8 = 0x80;

fn us_scancodes() -> HashMap<char, u8> {
    let mut m = HashMap::new();
    for (i, c) in "abcdefghijklmnopqrstuvwxyz".chars().enumerate() {
        m.insert(c, 0x04 + i as u8);
        m.insert(c.to_ascii_uppercase(), 0x04 + i as u8 | SHIFT);
    }
    let digits = [
        ('1', 0x1E),
        ('2', 0x1F),
        ('3', 0x20),
        ('4', 0x21),
        ('5', 0x22),
        ('6', 0x23),
        ('7', 0x24),
        ('8', 0x25),
        ('9', 0x26),
        ('0', 0x27),
    ];
    for (c, sc) in digits {
        m.insert(c, sc);
    }
    let symbols = [
        ('!', 0x1E | SHIFT),
        ('@', 0x1F | SHIFT),
        ('#', 0x20 | SHIFT),
        ('$', 0x21 | SHIFT),
        ('%', 0x22 | SHIFT),
        ('^', 0xA3),
        ('&', 0x24 | SHIFT),
        ('*', 0x25 | SHIFT),
        ('(', 0x26 | SHIFT),
        (')', 0x27 | SHIFT),
        ('-', 0x2D),
        ('_', 0xAD),
        ('=', 0x2E),
        ('+', 0x2E | SHIFT),
        ('[', 0x2F),
        ('{', 0x2F | SHIFT),
        (']', 0x30),
        ('}', 0x30 | SHIFT),
        ('\\', 0x32),
        ('|', 0x32 | SHIFT),
        (';', 0x33),
        (':', 0x33 | SHIFT),
        ('\'', 0x34),
        ('"', 0x34 | SHIFT),
        ('`', 0x35),
        ('~', 0x35 | SHIFT),
        (',', 0x36),
        ('<', 0x36 | SHIFT),
        ('.', 0x37),
        ('>', 0x37 | SHIFT),
        ('/', 0x38),
        ('?', 0x38 | SHIFT),
    ];
    for (c, sc) in symbols {
        m.insert(c, sc);
    }
    m
}

const MODHEX_CHARS: &str = "cbdefghijklnrtuv";

fn modhex_scancodes() -> HashMap<char, u8> {
    let mut m = HashMap::new();
    for c in MODHEX_CHARS.chars() {
        let idx = "abcdefghijklmnopqrstuvwxyz"
            .find(c)
            .unwrap();
        m.insert(c, 0x04 + idx as u8);
    }
    m
}

fn encode_password(password: &str, layout: &str) -> Result<Vec<u8>, CliError> {
    let map = match layout.to_ascii_uppercase().as_str() {
        "US" => us_scancodes(),
        "MODHEX" => modhex_scancodes(),
        _ => return Err(CliError(format!("Unsupported keyboard layout: {layout}. Supported: US, MODHEX"))),
    };
    password
        .chars()
        .map(|c| {
            map.get(&c)
                .copied()
                .ok_or_else(|| CliError(format!("Character '{c}' not supported in {layout} layout")))
        })
        .collect()
}

fn generate_static_pw(length: usize, layout: &str) -> Result<String, CliError> {
    let chars: Vec<char> = match layout.to_ascii_uppercase().as_str() {
        "US" => us_scancodes().keys().copied().filter(|c| !"\t\n ".contains(*c)).collect(),
        "MODHEX" => MODHEX_CHARS.chars().collect(),
        _ => return Err(CliError(format!("Unsupported keyboard layout: {layout}"))),
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

fn parse_slot(s: &str) -> Result<Slot, CliError> {
    match s {
        "1" => Ok(Slot::One),
        "2" => Ok(Slot::Two),
        _ => Err(CliError("Slot must be 1 or 2.".into())),
    }
}

fn parse_access_code(s: &str) -> Result<[u8; ACC_CODE_SIZE], CliError> {
    let bytes = hex::decode(s)
        .map_err(|_| CliError("Access code must be hex-encoded.".into()))?;
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

// Use SmartCard-based session (works over both USB and NFC)
fn open_sc_session(
    dev: &YubiKeyDevice,
) -> Result<YubiOtpSession<impl yubikit_rs::iso7816::SmartCardConnection + use<'_>>, CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;
    YubiOtpSession::new(conn).map_err(|e| CliError(format!("Failed to open OTP session: {e}")))
}

fn open_otp_session(dev: &YubiKeyDevice) -> Result<YubiOtpOtpSession, CliError> {
    let conn = dev
        .open_otp()
        .map_err(|e| CliError(format!("Failed to open OTP HID connection: {e}")))?;
    YubiOtpOtpSession::new(conn)
        .map_err(|e| CliError(format!("Failed to open OTP session: {e}")))
}

pub fn run_info(dev: &YubiKeyDevice) -> Result<(), CliError> {
    let session = open_sc_session(dev)?;
    let state = session.get_config_state();
    for slot in [Slot::One, Slot::Two] {
        let num = slot.map(1, 2);
        let configured = state
            .is_configured(slot)
            .map_or("unknown".into(), |b| {
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

pub fn run_swap(dev: &YubiKeyDevice, force: bool) -> Result<(), CliError> {
    if !force && !confirm("Swap the two OTP slot configurations?") {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_sc_session(dev)?;
    session
        .swap_slots()
        .map_err(|e| CliError(format!("Failed to swap slots: {e}")))?;
    println!("Slot configurations swapped.");
    Ok(())
}

pub fn run_delete(
    dev: &YubiKeyDevice,
    slot: &str,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let acc = access_code.map(parse_access_code).transpose()?;
    if !force && !confirm(&format!("Delete slot {}?", slot.map(1, 2))) {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_sc_session(dev)?;
    session
        .delete_slot(slot, acc.as_ref().map(|a| a.as_slice()))
        .map_err(|e| CliError(format!("Failed to delete slot: {e}")))?;
    println!("Slot {} deleted.", slot.map(1, 2));
    Ok(())
}

pub fn run_ndef(
    dev: &YubiKeyDevice,
    slot: &str,
    prefix: Option<&str>,
    ndef_type: &str,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let acc = access_code.map(parse_access_code).transpose()?;
    let nt = match ndef_type.to_ascii_uppercase().as_str() {
        "URI" => NdefType::Uri,
        "TEXT" => NdefType::Text,
        _ => return Err(CliError("NDEF type must be URI or TEXT.".into())),
    };
    if !force
        && !confirm(&format!(
            "Configure slot {} for NDEF ({ndef_type})?",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_sc_session(dev)?;
    session
        .set_ndef_configuration(slot, prefix, acc.as_ref().map(|a| a.as_slice()), nt)
        .map_err(|e| CliError(format!("Failed to configure NDEF: {e}")))?;
    println!("NDEF configured for slot {}.", slot.map(1, 2));
    Ok(())
}

pub fn run_yubiotp(
    dev: &YubiKeyDevice,
    slot: &str,
    public_id: Option<&str>,
    private_id: Option<&str>,
    key: Option<&str>,
    serial_public_id: bool,
    generate_private_id: bool,
    generate_key: bool,
    enter: Option<bool>,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let acc = access_code.map(parse_access_code).transpose()?;

    // Resolve public ID
    let pub_id_bytes: Vec<u8> = if serial_public_id {
        let mut session = open_sc_session(dev)?;
        let serial = session
            .get_serial()
            .map_err(|e| CliError(format!("Failed to get serial: {e}")))?;
        let mut id = vec![0xffu8, 0x00];
        id.extend_from_slice(&serial.to_be_bytes());
        id
    } else if let Some(pid) = public_id {
        modhex_decode(pid).map_err(|_| CliError("Invalid modhex public ID.".into()))?
    } else {
        return Err(CliError(
            "Provide --public-id or --serial-public-id.".into(),
        ));
    };

    // Resolve private ID
    let priv_id: [u8; UID_SIZE] = if generate_private_id {
        let mut id = [0u8; UID_SIZE];
        getrandom::fill(&mut id)
            .map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        id
    } else if let Some(pid) = private_id {
        let bytes = hex::decode(pid)
            .map_err(|_| CliError("Private ID must be hex-encoded.".into()))?;
        if bytes.len() != UID_SIZE {
            return Err(CliError(format!(
                "Private ID must be {UID_SIZE} bytes ({} hex chars).",
                UID_SIZE * 2
            )));
        }
        let mut arr = [0u8; UID_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        return Err(CliError(
            "Provide --private-id or --generate-private-id.".into(),
        ));
    };

    // Resolve key
    let key_bytes: [u8; KEY_SIZE] = if generate_key {
        let mut k = [0u8; KEY_SIZE];
        getrandom::fill(&mut k)
            .map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        k
    } else if let Some(k) = key {
        let bytes =
            hex::decode(k).map_err(|_| CliError("Key must be hex-encoded.".into()))?;
        if bytes.len() != KEY_SIZE {
            return Err(CliError(format!(
                "Key must be {KEY_SIZE} bytes ({} hex chars).",
                KEY_SIZE * 2
            )));
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        return Err(CliError("Provide --key or --generate-key.".into()));
    };

    if !force
        && !confirm(&format!(
            "Program Yubico OTP in slot {}?",
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

    let mut session = open_sc_session(dev)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    println!("Yubico OTP programmed in slot {}.", slot.map(1, 2));
    println!("Public ID: {}", modhex_encode(&pub_id_bytes));
    println!("Private ID: {}", hex::encode(priv_id));
    println!("Key: {}", hex::encode(key_bytes));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_static(
    dev: &YubiKeyDevice,
    slot: &str,
    password: Option<&str>,
    generate: bool,
    length: usize,
    keyboard_layout: &str,
    enter: Option<bool>,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let acc = access_code.map(parse_access_code).transpose()?;

    let pw = if generate {
        generate_static_pw(length, keyboard_layout)?
    } else if let Some(p) = password {
        p.to_string()
    } else {
        return Err(CliError(
            "Provide a password or use --generate.".into(),
        ));
    };

    let scan_codes = encode_password(&pw, keyboard_layout)?;

    if !force
        && !confirm(&format!(
            "Program static password in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }

    let mut config = SlotConfiguration::static_password(&scan_codes)
        .map_err(|e| CliError(format!("Invalid configuration: {e}")))?;
    if let Some(cr) = enter {
        config = config.append_cr(cr);
    }

    let mut session = open_sc_session(dev)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    if generate {
        println!("Static password set in slot {}: {pw}", slot.map(1, 2));
    } else {
        println!("Static password set in slot {}.", slot.map(1, 2));
    }
    Ok(())
}

pub fn run_chalresp(
    dev: &YubiKeyDevice,
    slot: &str,
    key: Option<&str>,
    totp: bool,
    touch: bool,
    generate: bool,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let acc = access_code.map(parse_access_code).transpose()?;

    let key_bytes: Vec<u8> = if generate {
        let mut k = vec![0u8; 20];
        getrandom::fill(&mut k)
            .map_err(|e| CliError(format!("Failed to generate: {e}")))?;
        k
    } else if let Some(k) = key {
        hex::decode(k).map_err(|_| CliError("Key must be hex-encoded.".into()))?
    } else {
        return Err(CliError("Provide a key or use --generate.".into()));
    };

    if !force
        && !confirm(&format!(
            "Program challenge-response in slot {}?",
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
    if totp {
        config = config.digits8(true);
    }

    let mut session = open_sc_session(dev)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    println!(
        "Challenge-response (HMAC-SHA1) programmed in slot {}.",
        slot.map(1, 2)
    );
    Ok(())
}

pub fn run_calculate(
    dev: &YubiKeyDevice,
    slot: &str,
    challenge: Option<&str>,
    totp: bool,
    digits: u8,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;

    let challenge_bytes: Vec<u8> = if totp {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let period = 30u64;
        (now / period).to_be_bytes().to_vec()
    } else if let Some(c) = challenge {
        hex::decode(c).map_err(|_| CliError("Challenge must be hex-encoded.".into()))?
    } else {
        return Err(CliError(
            "Provide a challenge or use --totp.".into(),
        ));
    };

    // Prefer OTP HID for challenge-response (supports touch keepalive)
    let result = if let Ok(mut session) = open_otp_session(dev) {
        session
            .calculate_hmac_sha1(slot, &challenge_bytes, None, None)
            .map_err(|e| CliError(format!("Failed to calculate: {e}")))?
    } else {
        let mut session = open_sc_session(dev)?;
        session
            .calculate_hmac_sha1(slot, &challenge_bytes)
            .map_err(|e| CliError(format!("Failed to calculate: {e}")))?
    };

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
    slot: &str,
    key: Option<&str>,
    digits: &str,
    counter: u32,
    enter: Option<bool>,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let acc = access_code.map(parse_access_code).transpose()?;

    let key_bytes = key
        .ok_or_else(|| CliError("A key is required.".into()))
        .and_then(|k| {
            hex::decode(k).map_err(|_| CliError("Key must be hex-encoded.".into()))
        })?;

    if !force
        && !confirm(&format!(
            "Program HOTP in slot {}?",
            slot.map(1, 2)
        ))
    {
        return Err(CliError("Aborted.".into()));
    }

    let mut config = SlotConfiguration::hotp(&key_bytes)
        .map_err(|e| CliError(format!("Invalid key: {e}")))?;
    if digits == "8" {
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

    let mut session = open_sc_session(dev)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    println!("HOTP programmed in slot {}.", slot.map(1, 2));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_settings(
    dev: &YubiKeyDevice,
    slot: &str,
    enter: Option<bool>,
    pacing: Option<u8>,
    use_numeric: Option<bool>,
    serial_usb_visible: Option<bool>,
    new_access_code: Option<&str>,
    delete_access_code: bool,
    access_code: Option<&str>,
    force: bool,
) -> Result<(), CliError> {
    let slot = parse_slot(slot)?;
    let cur_acc = access_code.map(parse_access_code).transpose()?;
    let new_acc = if delete_access_code {
        Some([0u8; ACC_CODE_SIZE])
    } else {
        new_access_code.map(parse_access_code).transpose()?
    };

    if !force
        && !confirm(&format!(
            "Update settings for slot {}?",
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
        config = config.pacing(p >= 20, p >= 40);
    }
    if let Some(v) = use_numeric {
        config = config.use_numeric(v);
    }
    if let Some(v) = serial_usb_visible {
        config = config.serial_usb_visible(v);
    }

    let mut session = open_sc_session(dev)?;
    session
        .update_configuration(
            slot,
            &config,
            new_acc.as_ref().map(|a| a.as_slice()),
            cur_acc.as_ref().map(|a| a.as_slice()),
        )
        .map_err(|e| CliError(format!("Failed to update settings: {e}")))?;

    println!("Settings updated for slot {}.", slot.map(1, 2));
    Ok(())
}
