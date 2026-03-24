use yubikit_rs::core_types::Version;
use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::iso7816::{Aid, SmartCardConnection, SmartCardError, SmartCardProtocol};

use crate::util::CliError;

/// Parsed APDU: (cla, ins, p1, p2, data, le), expected_sw
type ParsedApdu = ((u8, u8, u8, u8, Vec<u8>, u16), Option<u16>);

fn parse_apdu(s: &str) -> Result<ParsedApdu, CliError> {
    // Format: [CLA]INS[P1P2][:DATA][/LE][=EXPECTED_SW]
    let s = s.trim();

    // Check for expected SW suffix: "=" alone means 9000, "=XXXX" means that SW
    let (main_str, expected_sw) = if let Some(idx) = s.rfind('=') {
        let sw_str = &s[idx + 1..];
        let sw = if sw_str.is_empty() {
            0x9000
        } else {
            u16::from_str_radix(sw_str, 16)
                .map_err(|_| CliError(format!("Invalid expected SW: {sw_str}")))?
        };
        (&s[..idx], Some(sw))
    } else {
        (s, None)
    };

    // Split off LE suffix (/XX)
    let (main_part, le) = if let Some((m, le_str)) = main_str.rsplit_once('/') {
        let le = u16::from(
            u8::from_str_radix(le_str, 16)
                .map_err(|_| CliError(format!("Invalid LE: {le_str}")))?,
        );
        (m, le)
    } else {
        (main_str, 0)
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

    Ok(((cla, ins, p1, p2, data, le), expected_sw))
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

fn hex_spaced(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Print response in the same format as Python ykman.
fn print_response(resp: &[u8], sw: u16, no_pretty: bool) {
    if resp.is_empty() {
        println!("RECV (SW={sw:04X})");
    } else {
        println!("RECV (SW={sw:04X}):");
        if no_pretty {
            println!("{}", hex::encode_upper(resp));
        } else {
            for i in (0..resp.len()).step_by(16) {
                let chunk = &resp[i..resp.len().min(i + 16)];
                let hex_part = chunk
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let ascii_part: String = chunk
                    .iter()
                    .map(|&b| if b > 31 && b < 127 { b as char } else { '·' })
                    .collect();
                println!("{:<50}{ascii_part}", hex_part);
            }
        }
    }
}

pub fn run_apdu(
    dev: &YubiKeyDevice,
    apdus: &[String],
    no_pretty: bool,
    app: Option<&str>,
    short: bool,
    send_apdu: &[String],
) -> Result<(), CliError> {
    if apdus.is_empty() && send_apdu.is_empty() && app.is_none() {
        return Err(CliError("No commands provided.".into()));
    }
    if (app.is_some() || !apdus.is_empty()) && !send_apdu.is_empty() {
        return Err(CliError(
            "Cannot mix positional APDUs and -s/--send-apdu.".into(),
        ));
    }

    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;

    if !send_apdu.is_empty() {
        // Raw send-apdu mode: send full hex APDUs directly
        let mut is_first = true;
        for apdu_hex in send_apdu {
            if !is_first {
                println!();
            }
            is_first = false;
            let apdu_bytes = hex::decode(apdu_hex)
                .map_err(|_| CliError(format!("Invalid hex APDU: {apdu_hex}")))?;
            println!("SEND: {}", hex_spaced(&apdu_bytes));
            let (resp, sw) = conn
                .send_and_receive(&apdu_bytes)
                .map_err(|e| CliError(format!("APDU error: {e}")))?;
            print_response(&resp, sw, no_pretty);
        }
        return Ok(());
    }

    // Standard mode with protocol
    let mut protocol = SmartCardProtocol::new(conn);

    if short {
        protocol.configure_force_short(Version(0, 0, 0), true);
    }

    let mut is_first = true;

    // Select app if specified
    if let Some(app_name) = app {
        is_first = false;
        let aid = app_to_aid(app_name)?;
        println!("SELECT AID: {}", hex_spaced(aid));
        let resp = protocol
            .select(aid)
            .map_err(|e| CliError(format!("Failed to select {app_name}: {e}")))?;
        print_response(&resp, 0x9000, no_pretty);
    }

    for apdu_str in apdus {
        let ((cla, ins, p1, p2, data, le), expected_sw) = parse_apdu(apdu_str)?;

        if !is_first {
            println!();
        }
        is_first = false;

        // Format SEND line like Python: header -- data (LE=XX)
        let mut send_line = format!("{:02X} {:02X} {:02X} {:02X}", cla, ins, p1, p2);
        if !data.is_empty() {
            send_line.push_str(&format!(" -- {}", hex_spaced(&data)));
        }
        if le > 0 {
            send_line.push_str(&format!(" (LE={le:02X})"));
        }
        println!("SEND: {send_line}");

        // Send APDU and capture both success and error responses
        let (resp, sw) = match protocol.send_apdu_with_le(cla, ins, p1, p2, &data, le) {
            Ok(resp) => (resp, 0x9000u16),
            Err(SmartCardError::Apdu { data, sw }) => (data, sw),
            Err(e) => return Err(CliError(format!("APDU error: {e}"))),
        };

        print_response(&resp, sw, no_pretty);

        if let Some(expected) = expected_sw {
            if sw != expected {
                return Err(CliError(format!(
                    "Aborted due to error (expected SW={expected:04X})."
                )));
            }
        }
    }
    Ok(())
}
