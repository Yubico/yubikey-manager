use yubikit_rs::device::YubiKeyDevice;
use yubikit_rs::iso7816::SmartCardConnection;

use crate::util::CliError;

fn parse_apdu(s: &str) -> Result<(u8, u8, u8, u8, Vec<u8>, Option<u16>), CliError> {
    // Format: [CLA]INS[P1P2][:DATA][/LE]
    // Example: 00A40400:A000000308 or A4:A000000308 or A4
    let s = s.trim();

    // Split off LE suffix
    let (main_part, le) = if let Some((m, le_str)) = s.rsplit_once('/') {
        let le = u16::from_str_radix(le_str, 16)
            .map_err(|_| CliError(format!("Invalid LE: {le_str}")))?;
        (m, Some(le))
    } else {
        (s, None)
    };

    // Split off DATA
    let (header, data) = if let Some((h, d)) = main_part.split_once(':') {
        let data = hex::decode(d)
            .map_err(|_| CliError(format!("Invalid hex data: {d}")))?;
        (h, data)
    } else {
        (main_part, Vec::new())
    };

    // Parse header bytes
    let header_bytes = hex::decode(header)
        .map_err(|_| CliError(format!("Invalid hex header: {header}")))?;

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
        _ => return Err(CliError(format!("Invalid APDU header length: {}", header_bytes.len()))),
    };

    Ok((cla, ins, p1, p2, data, le))
}

pub fn run_apdu(
    dev: &YubiKeyDevice,
    apdus: &[String],
    no_pretty: bool,
) -> Result<(), CliError> {
    let conn = dev
        .open_smartcard()
        .map_err(|e| CliError(format!("Failed to open connection: {e}")))?;

    for apdu_str in apdus {
        let (cla, ins, p1, p2, data, _le) = parse_apdu(apdu_str)?;

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

        // Build full APDU
        let mut apdu = vec![cla, ins, p1, p2];
        if !data.is_empty() {
            if data.len() <= 255 {
                apdu.push(data.len() as u8);
            } else {
                apdu.push(0x00);
                apdu.push((data.len() >> 8) as u8);
                apdu.push(data.len() as u8);
            }
            apdu.extend_from_slice(&data);
        }
        // Le
        apdu.push(0x00);

        let (response, sw) = conn
            .send_and_receive(&apdu)
            .map_err(|e| CliError(format!("APDU error: {e}")))?;

        if no_pretty {
            if !response.is_empty() {
                print!("{}", hex::encode(&response));
            }
            println!("{:04X}", sw);
        } else {
            if !response.is_empty() {
                eprintln!("<< {} ({} bytes)", hex::encode(&response), response.len());
            }
            eprintln!("SW: {:04X}", sw);
        }
    }
    Ok(())
}
