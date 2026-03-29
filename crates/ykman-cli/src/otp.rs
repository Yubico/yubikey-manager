use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;
use yubikit::otp::{modhex_decode, modhex_encode};
use yubikit::yubiotp::{
    ACC_CODE_SIZE, KEY_SIZE, NdefType, Slot, SlotConfiguration, UID_SIZE, YubiOtpCcidSession,
    YubiOtpOtpSession, YubiOtpSession,
};

use crate::cli_enums::{CliCalcDigits, CliHotpDigits, CliKeyboardLayout, CliOtpSlot, CliPacing};
use crate::scp::{self, ScpConfig, ScpParams};
use crate::util::CliError;

const SHIFT: u8 = 0x80;

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

fn us_scancodes() -> HashMap<char, u8> {
    let mut m = HashMap::new();
    for (i, c) in "abcdefghijklmnopqrstuvwxyz".chars().enumerate() {
        m.insert(c, 0x04 + i as u8);
        m.insert(c.to_ascii_uppercase(), (0x04 + i as u8) | SHIFT);
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

fn uk_scancodes() -> HashMap<char, u8> {
    HashMap::from([
        ('a', 0x04),
        ('b', 0x05),
        ('c', 0x06),
        ('d', 0x07),
        ('e', 0x08),
        ('f', 0x09),
        ('g', 0x0A),
        ('h', 0x0B),
        ('i', 0x0C),
        ('j', 0x0D),
        ('k', 0x0E),
        ('l', 0x0F),
        ('m', 0x10),
        ('n', 0x11),
        ('o', 0x12),
        ('p', 0x13),
        ('q', 0x14),
        ('r', 0x15),
        ('s', 0x16),
        ('t', 0x17),
        ('u', 0x18),
        ('v', 0x19),
        ('w', 0x1A),
        ('x', 0x1B),
        ('y', 0x1C),
        ('z', 0x1D),
        ('A', SHIFT | 0x04),
        ('B', SHIFT | 0x05),
        ('C', SHIFT | 0x06),
        ('D', SHIFT | 0x07),
        ('E', SHIFT | 0x08),
        ('F', SHIFT | 0x09),
        ('G', SHIFT | 0x0A),
        ('H', SHIFT | 0x0B),
        ('I', SHIFT | 0x0C),
        ('J', SHIFT | 0x0D),
        ('K', SHIFT | 0x0E),
        ('L', SHIFT | 0x0F),
        ('M', SHIFT | 0x10),
        ('N', SHIFT | 0x11),
        ('O', SHIFT | 0x12),
        ('P', SHIFT | 0x13),
        ('Q', SHIFT | 0x14),
        ('R', SHIFT | 0x15),
        ('S', SHIFT | 0x16),
        ('T', SHIFT | 0x17),
        ('U', SHIFT | 0x18),
        ('V', SHIFT | 0x19),
        ('W', SHIFT | 0x1A),
        ('X', SHIFT | 0x1B),
        ('Y', SHIFT | 0x1C),
        ('Z', SHIFT | 0x1D),
        ('0', 0x27),
        ('1', 0x1E),
        ('2', 0x1F),
        ('3', 0x20),
        ('4', 0x21),
        ('5', 0x22),
        ('6', 0x23),
        ('7', 0x24),
        ('8', 0x25),
        ('9', 0x26),
        ('\t', 0x2B),
        ('\n', 0x28),
        ('!', SHIFT | 0x1E),
        ('@', SHIFT | 0x34),
        ('£', SHIFT | 0x20),
        ('$', SHIFT | 0x21),
        ('%', SHIFT | 0x22),
        ('&', SHIFT | 0x24),
        ('\'', 0x34),
        ('`', 0x35),
        ('(', SHIFT | 0x26),
        (')', SHIFT | 0x27),
        ('*', SHIFT | 0x25),
        ('+', SHIFT | 0x2E),
        (',', 0x36),
        ('-', 0x2D),
        ('.', 0x37),
        ('/', 0x38),
        (':', SHIFT | 0x33),
        (';', 0x33),
        ('<', SHIFT | 0x36),
        ('=', 0x2E),
        ('>', SHIFT | 0x37),
        ('?', SHIFT | 0x38),
        ('"', SHIFT | 0x1F),
        ('[', 0x2F),
        ('#', 0x32),
        (']', 0x30),
        ('^', 0xA3),
        ('_', 0xAD),
        ('{', SHIFT | 0x2F),
        ('}', SHIFT | 0x30),
        ('~', SHIFT | 0x32),
        ('¬', SHIFT | 0x35),
        (' ', 0x2C),
    ])
}

fn de_scancodes() -> HashMap<char, u8> {
    HashMap::from([
        ('a', 0x04),
        ('b', 0x05),
        ('c', 0x06),
        ('d', 0x07),
        ('e', 0x08),
        ('f', 0x09),
        ('g', 0x0A),
        ('h', 0x0B),
        ('i', 0x0C),
        ('j', 0x0D),
        ('k', 0x0E),
        ('l', 0x0F),
        ('m', 0x10),
        ('n', 0x11),
        ('o', 0x12),
        ('p', 0x13),
        ('q', 0x14),
        ('r', 0x15),
        ('s', 0x16),
        ('t', 0x17),
        ('u', 0x18),
        ('v', 0x19),
        ('w', 0x1A),
        ('x', 0x1B),
        ('y', 0x1D),
        ('z', 0x1C),
        ('A', SHIFT | 0x04),
        ('B', SHIFT | 0x05),
        ('C', SHIFT | 0x06),
        ('D', SHIFT | 0x07),
        ('E', SHIFT | 0x08),
        ('F', SHIFT | 0x09),
        ('G', SHIFT | 0x0A),
        ('H', SHIFT | 0x0B),
        ('I', SHIFT | 0x0C),
        ('J', SHIFT | 0x0D),
        ('K', SHIFT | 0x0E),
        ('L', SHIFT | 0x0F),
        ('M', SHIFT | 0x10),
        ('N', SHIFT | 0x11),
        ('O', SHIFT | 0x12),
        ('P', SHIFT | 0x13),
        ('Q', SHIFT | 0x14),
        ('R', SHIFT | 0x15),
        ('S', SHIFT | 0x16),
        ('T', SHIFT | 0x17),
        ('U', SHIFT | 0x18),
        ('V', SHIFT | 0x19),
        ('W', SHIFT | 0x1A),
        ('X', SHIFT | 0x1B),
        ('Y', SHIFT | 0x1D),
        ('Z', SHIFT | 0x1C),
        ('0', 0x27),
        ('1', 0x1E),
        ('2', 0x1F),
        ('3', 0x20),
        ('4', 0x21),
        ('5', 0x22),
        ('6', 0x23),
        ('7', 0x24),
        ('8', 0x25),
        ('9', 0x26),
        ('\t', 0x2B),
        ('\n', 0x28),
        ('!', SHIFT | 0x1E),
        ('"', SHIFT | 0x1F),
        ('#', 0x32),
        ('$', SHIFT | 0x21),
        ('%', SHIFT | 0x22),
        ('&', SHIFT | 0x23),
        ('\'', SHIFT | 0x32),
        ('(', SHIFT | 0x25),
        (')', SHIFT | 0x26),
        ('*', SHIFT | 0x30),
        ('+', 0x30),
        (',', 0x36),
        ('-', 0x38),
        ('.', 0x37),
        ('/', SHIFT | 0x24),
        (':', SHIFT | 0x37),
        (';', SHIFT | 0x36),
        ('<', 0x64),
        ('=', SHIFT | 0x27),
        ('>', SHIFT | 0x64),
        ('?', SHIFT | 0x2D),
        ('^', 0x35),
        ('_', SHIFT | 0x38),
        (' ', 0x2C),
        ('`', SHIFT | 0x2D),
        ('§', SHIFT | 0x20),
        ('´', 0x2E),
        ('Ä', SHIFT | 0x34),
        ('Ö', SHIFT | 0x33),
        ('Ü', SHIFT | 0x2F),
        ('ß', 0x2D),
        ('ä', 0x34),
        ('ö', 0x33),
        ('ü', 0x2F),
    ])
}

fn fr_scancodes() -> HashMap<char, u8> {
    HashMap::from([
        ('a', 0x14),
        ('b', 0x05),
        ('c', 0x06),
        ('d', 0x07),
        ('e', 0x08),
        ('f', 0x09),
        ('g', 0x0A),
        ('h', 0x0B),
        ('i', 0x0C),
        ('j', 0x0D),
        ('k', 0x0E),
        ('l', 0x0F),
        ('m', 0x33),
        ('n', 0x11),
        ('o', 0x12),
        ('p', 0x13),
        ('q', 0x04),
        ('r', 0x15),
        ('s', 0x16),
        ('t', 0x17),
        ('u', 0x18),
        ('v', 0x19),
        ('w', 0x1D),
        ('x', 0x1B),
        ('y', 0x1C),
        ('z', 0x1A),
        ('A', SHIFT | 0x14),
        ('B', SHIFT | 0x05),
        ('C', SHIFT | 0x06),
        ('D', SHIFT | 0x07),
        ('E', SHIFT | 0x08),
        ('F', SHIFT | 0x09),
        ('G', SHIFT | 0x0A),
        ('H', SHIFT | 0x0B),
        ('I', SHIFT | 0x0C),
        ('J', SHIFT | 0x0D),
        ('K', SHIFT | 0x0E),
        ('L', SHIFT | 0x0F),
        ('M', SHIFT | 0x33),
        ('N', SHIFT | 0x11),
        ('O', SHIFT | 0x12),
        ('P', SHIFT | 0x13),
        ('Q', SHIFT | 0x04),
        ('R', SHIFT | 0x15),
        ('S', SHIFT | 0x16),
        ('T', SHIFT | 0x17),
        ('U', SHIFT | 0x18),
        ('V', SHIFT | 0x19),
        ('W', SHIFT | 0x1D),
        ('X', SHIFT | 0x1B),
        ('Y', SHIFT | 0x1C),
        ('Z', SHIFT | 0x1A),
        ('0', SHIFT | 0x27),
        ('1', SHIFT | 0x1E),
        ('2', SHIFT | 0x1F),
        ('3', SHIFT | 0x20),
        ('4', SHIFT | 0x21),
        ('5', SHIFT | 0x22),
        ('6', SHIFT | 0x23),
        ('7', SHIFT | 0x24),
        ('8', SHIFT | 0x25),
        ('9', SHIFT | 0x26),
        ('\t', 0x2B),
        ('\n', 0x28),
        (' ', 0x2C),
        ('!', 0x38),
        ('"', 0x20),
        ('$', 0x30),
        ('%', SHIFT | 0x34),
        ('&', 0x1E),
        ('\'', 0x21),
        ('(', 0x22),
        (')', 0x2D),
        ('*', 0x31),
        ('+', SHIFT | 0x2E),
        (',', 0x10),
        ('-', 0x23),
        ('.', SHIFT | 0x36),
        ('/', SHIFT | 0x37),
        (':', 0x37),
        (';', 0x36),
        ('<', 0x64),
        ('=', 0x2E),
        ('_', 0x25),
        ('\x7f', 0x2A),
        ('£', SHIFT | 0x30),
        ('§', SHIFT | 0x38),
        ('°', SHIFT | 0x2D),
        ('²', 0x35),
        ('µ', SHIFT | 0x31),
        ('à', 0x27),
        ('ç', 0x26),
        ('è', 0x24),
        ('é', 0x1F),
        ('ù', 0x34),
    ])
}

fn it_scancodes() -> HashMap<char, u8> {
    HashMap::from([
        ('\t', 0x2B),
        ('\n', 0x28),
        (' ', 0x2C),
        ('!', SHIFT | 0x1E),
        ('"', SHIFT | 0x1F),
        ('#', 0x32),
        ('$', SHIFT | 0x21),
        ('%', SHIFT | 0x22),
        ('&', SHIFT | 0x23),
        ('\'', 0x2D),
        ('(', SHIFT | 0x25),
        (')', SHIFT | 0x26),
        ('*', 0x55),
        ('+', 0x30),
        (',', 0x36),
        ('-', 0x38),
        ('.', 0x63),
        ('/', SHIFT | 0x24),
        ('0', 0x27),
        ('1', 0x1E),
        ('2', 0x1F),
        ('3', 0x20),
        ('4', 0x21),
        ('5', 0x22),
        ('6', 0x23),
        ('7', 0x24),
        ('8', 0x25),
        ('9', 0x26),
        (':', 0xB7),
        (';', 0xB6),
        ('<', 0x64),
        ('=', SHIFT | 0x27),
        ('>', SHIFT | 0x64),
        ('?', SHIFT | 0x2D),
        ('@', 0x24),
        ('A', SHIFT | 0x04),
        ('B', SHIFT | 0x05),
        ('C', SHIFT | 0x06),
        ('D', SHIFT | 0x07),
        ('E', SHIFT | 0x08),
        ('F', SHIFT | 0x09),
        ('G', SHIFT | 0x0A),
        ('H', SHIFT | 0x0B),
        ('I', SHIFT | 0x0C),
        ('J', SHIFT | 0x0D),
        ('K', SHIFT | 0x0E),
        ('L', SHIFT | 0x0F),
        ('M', SHIFT | 0x10),
        ('N', SHIFT | 0x11),
        ('O', SHIFT | 0x12),
        ('P', SHIFT | 0x13),
        ('Q', SHIFT | 0x14),
        ('R', SHIFT | 0x15),
        ('S', SHIFT | 0x16),
        ('T', SHIFT | 0x17),
        ('U', SHIFT | 0x18),
        ('V', SHIFT | 0x19),
        ('W', SHIFT | 0x1A),
        ('X', SHIFT | 0x1B),
        ('Y', SHIFT | 0x1C),
        ('Z', SHIFT | 0x1D),
        ('\\', 0x35),
        ('^', 0xAE),
        ('_', 0xB8),
        ('`', SHIFT | 0x2D),
        ('a', 0x04),
        ('b', 0x05),
        ('c', 0x06),
        ('d', 0x07),
        ('e', 0x08),
        ('f', 0x09),
        ('g', 0x0A),
        ('h', 0x0B),
        ('i', 0x0C),
        ('j', 0x0D),
        ('k', 0x0E),
        ('l', 0x0F),
        ('m', 0x10),
        ('n', 0x11),
        ('o', 0x12),
        ('p', 0x13),
        ('q', 0x14),
        ('r', 0x15),
        ('s', 0x16),
        ('t', 0x17),
        ('u', 0x18),
        ('v', 0x19),
        ('w', 0x1A),
        ('x', 0x1B),
        ('y', 0x1C),
        ('z', 0x1D),
        ('|', 0xB5),
        ('£', 0xA0),
        ('§', 0xB2),
        ('°', 0xB4),
        ('ç', 0xB3),
        ('è', 0x2F),
        ('é', SHIFT | 0x2F),
        ('à', 0x34),
        ('ì', 0x2E),
        ('ò', 0x33),
        ('ù', 0x31),
    ])
}

fn bepo_scancodes() -> HashMap<char, u8> {
    HashMap::from([
        ('\t', SHIFT | 0x2B),
        ('\n', SHIFT | 0x28),
        (' ', 0x2C),
        ('!', SHIFT | 0x1C),
        ('"', 0x1E),
        ('#', SHIFT | 0x35),
        ('$', 0x35),
        ('%', 0x2E),
        ('\'', 0x11),
        ('(', 0x21),
        (')', 0x22),
        ('*', 0x27),
        ('+', 0x24),
        (',', 0x0A),
        ('-', 0x25),
        ('.', 0x19),
        ('/', 0x26),
        ('0', SHIFT | 0x27),
        ('1', SHIFT | 0x1E),
        ('2', SHIFT | 0x1F),
        ('3', SHIFT | 0x20),
        ('4', SHIFT | 0x21),
        ('5', SHIFT | 0x22),
        ('6', SHIFT | 0x23),
        ('7', SHIFT | 0x24),
        ('8', SHIFT | 0x25),
        ('9', SHIFT | 0x26),
        (':', SHIFT | 0x19),
        (';', SHIFT | 0x0A),
        ('=', 0x2D),
        ('?', SHIFT | 0x11),
        ('@', 0x23),
        ('A', SHIFT | 0x04),
        ('B', SHIFT | 0x14),
        ('C', SHIFT | 0x0B),
        ('D', SHIFT | 0x0C),
        ('E', SHIFT | 0x09),
        ('F', SHIFT | 0x38),
        ('G', SHIFT | 0x36),
        ('H', SHIFT | 0x37),
        ('I', SHIFT | 0x07),
        ('J', SHIFT | 0x13),
        ('K', SHIFT | 0x05),
        ('L', SHIFT | 0x12),
        ('M', SHIFT | 0x34),
        ('N', SHIFT | 0x33),
        ('O', SHIFT | 0x15),
        ('P', SHIFT | 0x08),
        ('Q', SHIFT | 0x10),
        ('R', SHIFT | 0x0F),
        ('S', SHIFT | 0x0E),
        ('T', SHIFT | 0x0D),
        ('U', SHIFT | 0x16),
        ('V', SHIFT | 0x18),
        ('W', SHIFT | 0x30),
        ('X', SHIFT | 0x06),
        ('Y', SHIFT | 0x1B),
        ('Z', SHIFT | 0x2F),
        ('`', SHIFT | 0x2E),
        ('a', 0x04),
        ('b', 0x14),
        ('c', 0x0B),
        ('d', 0x0C),
        ('e', 0x09),
        ('f', 0x38),
        ('g', 0x36),
        ('h', 0x37),
        ('i', 0x07),
        ('j', 0x13),
        ('k', 0x05),
        ('l', 0x12),
        ('m', 0x34),
        ('n', 0x33),
        ('o', 0x15),
        ('p', 0x08),
        ('q', 0x10),
        ('r', 0x0F),
        ('s', 0x0E),
        ('t', 0x0D),
        ('u', 0x16),
        ('v', 0x18),
        ('w', 0x30),
        ('x', 0x06),
        ('y', 0x1B),
        ('z', 0x2F),
        ('\u{a0}', SHIFT | 0x2C),
        ('«', 0x1F),
        ('°', SHIFT | 0x2D),
        ('»', 0x20),
        ('À', SHIFT | 0x1D),
        ('Ç', SHIFT | 0x31),
        ('È', SHIFT | 0x17),
        ('É', SHIFT | 0x1A),
        ('Ê', SHIFT | 0x64),
        ('à', 0x1D),
        ('ç', 0x31),
        ('è', 0x17),
        ('é', 0x1A),
        ('ê', 0x64),
    ])
}

fn norman_scancodes() -> HashMap<char, u8> {
    HashMap::from([
        ('a', 0x04),
        ('b', 0x05),
        ('c', 0x06),
        ('d', 0x08),
        ('e', 0x07),
        ('f', 0x15),
        ('g', 0x0A),
        ('h', 0x33),
        ('i', 0x0E),
        ('j', 0x1C),
        ('k', 0x17),
        ('l', 0x12),
        ('m', 0x10),
        ('n', 0x0D),
        ('o', 0x0F),
        ('p', 0x11),
        ('q', 0x14),
        ('r', 0x0C),
        ('s', 0x16),
        ('t', 0x09),
        ('u', 0x18),
        ('v', 0x19),
        ('w', 0x1A),
        ('x', 0x1B),
        ('y', 0x0B),
        ('z', 0x1D),
        ('A', SHIFT | 0x04),
        ('B', SHIFT | 0x05),
        ('C', SHIFT | 0x06),
        ('D', SHIFT | 0x08),
        ('E', SHIFT | 0x07),
        ('F', SHIFT | 0x15),
        ('G', SHIFT | 0x0A),
        ('H', SHIFT | 0x33),
        ('I', SHIFT | 0x0E),
        ('J', SHIFT | 0x1C),
        ('K', SHIFT | 0x17),
        ('L', SHIFT | 0x12),
        ('M', SHIFT | 0x10),
        ('N', SHIFT | 0x0D),
        ('O', SHIFT | 0x0F),
        ('P', SHIFT | 0x11),
        ('Q', SHIFT | 0x14),
        ('R', SHIFT | 0x0C),
        ('S', SHIFT | 0x16),
        ('T', SHIFT | 0x09),
        ('U', SHIFT | 0x18),
        ('V', SHIFT | 0x19),
        ('W', SHIFT | 0x1A),
        ('X', SHIFT | 0x1B),
        ('Y', SHIFT | 0x0B),
        ('Z', SHIFT | 0x1D),
        ('0', 0x27),
        ('1', 0x1E),
        ('2', 0x1F),
        ('3', 0x20),
        ('4', 0x21),
        ('5', 0x22),
        ('6', 0x23),
        ('7', 0x24),
        ('8', 0x25),
        ('9', 0x26),
        ('\t', 0x2B),
        ('\n', 0x28),
        ('!', SHIFT | 0x1E),
        ('"', SHIFT | 0x34),
        ('#', SHIFT | 0x20),
        ('$', SHIFT | 0x21),
        ('%', SHIFT | 0x22),
        ('&', SHIFT | 0x24),
        ('\'', 0x34),
        ('`', 0x35),
        ('(', SHIFT | 0x26),
        (')', SHIFT | 0x27),
        ('*', SHIFT | 0x25),
        ('+', SHIFT | 0x2E),
        (',', 0x36),
        ('-', 0x2D),
        ('.', 0x37),
        ('/', 0x38),
        (':', SHIFT | 0x33),
        (';', 0x13),
        ('<', SHIFT | 0x36),
        ('=', 0x2E),
        ('>', SHIFT | 0x37),
        ('?', SHIFT | 0x38),
        ('@', SHIFT | 0x1F),
        ('[', 0x2F),
        ('\\', 0x32),
        (']', 0x30),
        ('^', 0xA3),
        ('_', 0xAD),
        ('{', SHIFT | 0x2F),
        ('}', SHIFT | 0x30),
        ('|', SHIFT | 0x32),
        ('~', SHIFT | 0x35),
        (' ', 0x2C),
    ])
}

fn modhex_scancodes() -> HashMap<char, u8> {
    let mut m = HashMap::new();
    for c in MODHEX_CHARS.chars() {
        let idx = "abcdefghijklmnopqrstuvwxyz".find(c).unwrap();
        m.insert(c, 0x04 + idx as u8);
    }
    m
}

fn scancodes_for_layout(layout: CliKeyboardLayout) -> HashMap<char, u8> {
    match layout {
        CliKeyboardLayout::Us => us_scancodes(),
        CliKeyboardLayout::Uk => uk_scancodes(),
        CliKeyboardLayout::De => de_scancodes(),
        CliKeyboardLayout::Fr => fr_scancodes(),
        CliKeyboardLayout::It => it_scancodes(),
        CliKeyboardLayout::Bepo => bepo_scancodes(),
        CliKeyboardLayout::Norman => norman_scancodes(),
        CliKeyboardLayout::Modhex => modhex_scancodes(),
    }
}

fn encode_password(password: &str, layout: CliKeyboardLayout) -> Result<Vec<u8>, CliError> {
    let map = scancodes_for_layout(layout);
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
        scancodes_for_layout(layout)
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
    if !force && !confirm("Swap the two OTP slot configurations?") {
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
    if !force && !confirm(&format!("Delete slot {}?", slot.map(1, 2))) {
        return Err(CliError("Aborted.".into()));
    }
    let mut session = open_session(dev, scp_params)?;
    session
        .delete_slot(slot, acc.as_ref().map(|a| a.as_slice()))
        .map_err(|e| CliError(format!("Failed to delete slot: {e}")))?;
    eprintln!("Slot {} deleted.", slot.map(1, 2));
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
    eprintln!("NDEF configured for slot {}.", slot.map(1, 2));
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

    // Resolve public ID
    let pub_id_bytes: Vec<u8> = if serial_public_id {
        let mut session = open_session(dev, scp_params)?;
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
        getrandom::fill(&mut id).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
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
    } else {
        return Err(CliError(
            "Provide --private-id or --generate-private-id.".into(),
        ));
    };

    // Resolve key
    let key_bytes: [u8; KEY_SIZE] = if generate_key {
        let mut k = [0u8; KEY_SIZE];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
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
    } else {
        return Err(CliError("Provide --key or --generate-key.".into()));
    };

    if !force && !confirm(&format!("Program Yubico OTP in slot {}?", slot.map(1, 2))) {
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

    eprintln!("Yubico OTP programmed in slot {}.", slot.map(1, 2));
    println!("Public ID: {}", modhex_encode(&pub_id_bytes));
    println!("Private ID: {}", hex::encode(priv_id));
    println!("Key: {}", hex::encode(key_bytes));

    if let Some(output_path) = config_output {
        // Get serial for CSV
        let serial = {
            let mut session = open_session(dev, scp_params)?;
            session
                .get_serial()
                .map_err(|e| CliError(format!("Failed to get serial: {e}")))?
        };
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
        crate::util::write_file_or_stdout(output_path, (csv_line + "\n").as_bytes())?;
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

    let pw = if generate {
        generate_static_pw(length, keyboard_layout)?
    } else if let Some(p) = password {
        p.to_string()
    } else {
        return Err(CliError("Provide a password or use --generate.".into()));
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

    let mut session = open_session(dev, scp_params)?;
    session
        .put_configuration(slot, &config, acc.as_ref().map(|a| a.as_slice()), None)
        .map_err(|e| CliError(format!("Failed to program: {e}")))?;

    if generate {
        eprintln!("Static password set in slot {}: {pw}", slot.map(1, 2));
    } else {
        eprintln!("Static password set in slot {}.", slot.map(1, 2));
    }
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

    let key_bytes: Vec<u8> = if generate {
        let mut k = vec![0u8; 20];
        getrandom::fill(&mut k).map_err(|e| CliError(format!("Failed to generate: {e}")))?;
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

    let mut session = open_session(dev, scp_params)?;
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
    scp_params: &ScpParams,
    slot: CliOtpSlot,
    challenge: Option<&str>,
    totp: bool,
    digits: CliCalcDigits,
) -> Result<(), CliError> {
    let slot: Slot = slot.into();
    let digits = digits.as_u8();

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
        return Err(CliError("Provide a challenge or use --totp.".into()));
    };

    // Prefer OTP HID for challenge-response (supports touch keepalive)
    let mut session = open_session(dev, scp_params)?;
    let result = session
        .calculate_hmac_sha1(slot, &challenge_bytes)
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

    let key_bytes = key
        .ok_or_else(|| CliError("A key is required.".into()))
        .and_then(|k| hex::decode(k).map_err(|_| CliError("Key must be hex-encoded.".into())))?;

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

    if !force && !confirm(&format!("Program HOTP in slot {}?", slot.map(1, 2))) {
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

    eprintln!("HOTP programmed in slot {}.", slot.map(1, 2));
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
    let new_acc = if delete_access_code {
        Some([0u8; ACC_CODE_SIZE])
    } else {
        new_access_code.map(parse_access_code).transpose()?
    };

    if !force && !confirm(&format!("Update settings for slot {}?", slot.map(1, 2))) {
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

    eprintln!("Settings updated for slot {}.", slot.map(1, 2));
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
