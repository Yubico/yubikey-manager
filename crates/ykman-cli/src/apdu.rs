use yubikit_rs::core_types::Version;
use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::iso7816::{Aid, SmartCardProtocol};

use crate::util::CliError;

fn parse_apdu(s: &str) -> Result<(u8, u8, u8, u8, Vec<u8>, Option<u16>, Option<u16>), CliError> {
    // Format: [CLA]INS[P1P2][:DATA][/LE][=EXPECTED_SW]
    let s = s.trim();

    // Check for expected SW suffix (=XXXX)
    let (main_str, expected_sw) = if let Some((m, sw_str)) = s.rsplit_once('=') {
        let sw = u16::from_str_radix(sw_str, 16)
            .map_err(|_| CliError(format!("Invalid expected SW: {sw_str}")))?;
        (m, Some(sw))
    } else {
        (s, None)
    };

    // Split off LE suffix
    let (main_part, le) = if let Some((m, le_str)) = main_str.rsplit_once('/') {
        let le = u16::from_str_radix(le_str, 16)
            .map_err(|_| CliError(format!("Invalid LE: {le_str}")))?;
        (m, Some(le))
    } else {
        (main_str, None)
    };

    // Split off DATA
    let (header, data) = if let Some((h, d)) = main_part.split_once(':') {
        let data = hex::decode(d).map_err(|_| CliError(format!("Invalid hex data: {d}")))?;
        (h, data)
    } else {
        (main_part, Vec::new())
    };

    // Parse header bytes
    let header_bytes =
        hex::decode(header).map_err(|_| CliError(format!("Invalid hex header: {header}")))?;

    let (cla, ins, p1, p2) = match header_bytes.len() {
        1 => (0x00, header_bytes[0], 0x00, 0x00),
        2 => (0x00, header_bytes[0], header_bytes[1], 0x00),
        3 => (0x00, header_bytes[0], header_bytes[1], header_bytes[2]),
        4 => (
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ),
        _ => {
            return Err(CliError(format!(
                "Invalid APDU header length: {}",
                header_bytes.len()
            )));
        }
    };

    Ok((cla, ins, p1, p2, data, le, expected_sw))
}

fn app_to_aid(app: &str) -> Result<&'static [u8], CliError> {
    match app {
        "otp" => Ok(Aid::OTP),
        "management" => Ok(Aid::MANAGEMENT),
        "openpgp" => Ok(Aid::OPENPGP),
        "oath" => Ok(Aid::OATH),
        "piv" => Ok(Aid::PIV),
        "fido" => Ok(Aid::FIDO),
        "hsmauth" => Ok(Aid::HSMAUTH),
        "secure-domain" => Ok(Aid::SECURE_DOMAIN),
        _ => Err(CliError(format!("Unknown app: {app}"))),
    }
}

pub fn run_apdu(
    dev: &YubiKeyDevice,
    apdus: &[String],
    no_pretty: bool,
    app: Option<&str>,
    short: bool,
) -> Result<(), CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;

    let mut protocol = SmartCardProtocol::new(conn);

    if short {
        protocol.configure_force_short(Version(0, 0, 0), true);
    }

    // Select app if specified
    if let Some(app_name) = app {
        let aid = app_to_aid(app_name)?;
        protocol
            .select(aid)
            .map_err(|e| CliError(format!("Failed to select {app_name}: {e}")))?;
        if !no_pretty {
            eprintln!("Selected application: {app_name}");
        }
    }

    for apdu_str in apdus {
        let (cla, ins, p1, p2, data, _le, expected_sw) = parse_apdu(apdu_str)?;

        if !no_pretty {
            eprintln!(
                ">> {:02X} {:02X} {:02X} {:02X} {}",
                cla,
                ins,
                p1,
                p2,
                if data.is_empty() {
                    String::new()
                } else {
                    hex::encode(&data)
                }
            );
        }

        let response = protocol.send_apdu(cla, ins, p1, p2, &data);

        match response {
            Ok(resp) => {
                let sw = 0x9000u16;
                if no_pretty {
                    if !resp.is_empty() {
                        print!("{}", hex::encode(&resp));
                    }
                    println!("{sw:04X}");
                } else {
                    if !resp.is_empty() {
                        eprintln!("<< {} ({} bytes)", hex::encode(&resp), resp.len());
                    }
                    eprintln!("SW: {sw:04X}");
                }

                if let Some(expected) = expected_sw {
                    if sw != expected {
                        return Err(CliError(format!(
                            "Expected SW {expected:04X}, got {sw:04X}"
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(CliError(format!("APDU error: {e}")));
            }
        }
    }
    Ok(())
}
