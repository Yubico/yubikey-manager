use yubikit::device::{get_name, list_readers, read_info_ccid, read_info_otp};
use yubikit::management::{Capability, DeviceInfo, ManagementFidoSession, ReleaseType};
use yubikit::smartcard::Transport;
use yubikit::transport::ctaphid::{FidoConnection, list_fido_devices};
use yubikit::transport::otphid::{OtpConnection, list_otp_devices};
use yubikit::transport::pcsc::PcscConnection;

use crate::util::CliError;

fn cap_names(cap: Capability) -> String {
    let names: &[(Capability, &str)] = &[
        (Capability::OTP, "OTP"),
        (Capability::U2F, "U2F"),
        (Capability::FIDO2, "FIDO2"),
        (Capability::OATH, "OATH"),
        (Capability::PIV, "PIV"),
        (Capability::OPENPGP, "OPENPGP"),
        (Capability::HSMAUTH, "HSMAUTH"),
    ];
    let mut parts = Vec::new();
    for &(c, name) in names {
        if cap.contains(c) {
            parts.push(name);
        }
    }
    if parts.is_empty() {
        return format!(": 0x{:x}", cap.0);
    }
    format!("{}: 0x{:x}", parts.join("|"), cap.0)
}

fn print_device_info(info: &DeviceInfo, indent: &str) {
    println!("{indent}DeviceInfo:");
    println!("{indent}  config:");
    println!("{indent}    enabled_capabilities:");
    if let Some(usb) = info.config.enabled_capabilities.get(&Transport::Usb) {
        println!("{indent}      USB: {}", cap_names(*usb));
    }
    if let Some(nfc) = info.config.enabled_capabilities.get(&Transport::Nfc) {
        println!("{indent}      NFC: {}", cap_names(*nfc));
    }
    println!();
    println!(
        "{indent}    auto_eject_timeout:         {}",
        info.config.auto_eject_timeout.unwrap_or(0)
    );
    println!(
        "{indent}    challenge_response_timeout: {}",
        info.config.challenge_response_timeout.unwrap_or(0)
    );
    println!(
        "{indent}    device_flags:               {}",
        info.config
            .device_flags
            .map(|f| f.0.to_string())
            .unwrap_or_else(|| "0".into())
    );
    println!(
        "{indent}    nfc_restricted:             {}",
        if info.config.nfc_restricted == Some(true) {
            "True"
        } else {
            "False"
        }
    );
    println!();
    println!(
        "{indent}  serial:         {}",
        info.serial
            .map(|s| s.to_string())
            .unwrap_or_else(|| "None".into())
    );
    println!("{indent}  version:        {}", info.version);
    println!("{indent}  form_factor:    {}", info.form_factor);
    println!("{indent}  supported_capabilities:");
    if let Some(usb) = info.supported_capabilities.get(&Transport::Usb) {
        println!("{indent}    USB: {}", cap_names(*usb));
    }
    if let Some(nfc) = info.supported_capabilities.get(&Transport::Nfc) {
        println!("{indent}    NFC: {}", cap_names(*nfc));
    }
    println!();
    println!(
        "{indent}  is_locked:      {}",
        if info.is_locked { "True" } else { "False" }
    );
    println!(
        "{indent}  is_fips:        {}",
        if info.is_fips { "True" } else { "False" }
    );
    println!(
        "{indent}  is_sky:         {}",
        if info.is_sky { "True" } else { "False" }
    );
    println!(
        "{indent}  part_number:    {}",
        info.part_number.as_deref().unwrap_or("None")
    );
    println!("{indent}  fips_capable:   {}", cap_names(info.fips_capable));
    println!(
        "{indent}  fips_approved:  {}",
        cap_names(info.fips_approved)
    );
    println!(
        "{indent}  pin_complexity: {}",
        if info.pin_complexity { "True" } else { "False" }
    );
    println!(
        "{indent}  reset_blocked:  {}",
        cap_names(info.reset_blocked)
    );

    if info.version_qualifier.release_type != ReleaseType::Final {
        println!("{indent}  version_qualifier:");
        println!("{indent}    version:   {}", info.version_qualifier.version);
        println!(
            "{indent}    type:      {}",
            info.version_qualifier.release_type
        );
        println!(
            "{indent}    iteration: {}",
            info.version_qualifier.iteration
        );
    }
}

pub fn run_diagnose() -> Result<(), CliError> {
    println!("ykman:         {}", env!("CARGO_PKG_VERSION"));
    println!("Platform:         {}", std::env::consts::OS);
    println!("Arch:             {}", std::env::consts::ARCH);

    // PC/SC readers
    println!();
    print!("Detected PC/SC readers:");
    let readers = match list_readers() {
        Ok(readers) => {
            if readers.is_empty() {
                println!(" (none)");
            } else {
                println!();
                for r in &readers {
                    let status = match PcscConnection::new(r, false) {
                        Ok(_) => "Success".to_string(),
                        Err(e) => format!("Error: {e}"),
                    };
                    println!("  {r}: {status}");
                }
            }
            readers
        }
        Err(e) => {
            println!(" Error: {e}");
            Vec::new()
        }
    };

    // YubiKeys over PC/SC
    println!();
    let mut pcsc_found = false;
    println!("Detected YubiKeys over PC/SC:");
    for reader in &readers {
        if !reader.to_ascii_lowercase().contains("yubi") {
            continue;
        }
        pcsc_found = true;
        println!("  {reader}:");

        // Open a single connection and reuse it across all sessions.
        // Each session consumes the connection; we reclaim it via into_connection().
        // If a session fails to open, the connection is lost and we must re-open.
        let conn = match PcscConnection::new(reader, false) {
            Ok(c) => c,
            Err(e) => {
                println!("    Error opening connection: {e}");
                continue;
            }
        };

        // Management / DeviceInfo
        println!("    Management:");
        let conn = match read_info_ccid(conn) {
            Ok((info, c)) => {
                let name = get_name(&info);
                print_device_info(&info, "      ");
                println!();
                println!("      Name: {name}");
                c
            }
            Err(e) => {
                println!("      Error: {e}");
                match PcscConnection::new(reader, false) {
                    Ok(c) => c,
                    Err(_) => continue,
                }
            }
        };

        // PIV
        println!();
        println!("    PIV:");
        let conn = match yubikit::piv::PivSession::new(conn) {
            Ok(mut session) => {
                println!("      PIV version:              {}", session.version());
                if let Ok(meta) = session.get_pin_metadata() {
                    println!(
                        "      PIN tries remaining:      {}/{}",
                        meta.attempts_remaining, meta.total_attempts
                    );
                }
                if let Ok(meta) = session.get_puk_metadata() {
                    println!(
                        "      PUK tries remaining:      {}/{}",
                        meta.attempts_remaining, meta.total_attempts
                    );
                }
                if let Ok(meta) = session.get_management_key_metadata() {
                    println!("      Management key algorithm: {}", meta.key_type);
                }
                if let Ok(meta) = session.get_pin_metadata()
                    && meta.default_value
                {
                    println!("      WARNING: Using default PIN!");
                }
                if let Ok(meta) = session.get_puk_metadata()
                    && meta.default_value
                {
                    println!("      WARNING: Using default PUK!");
                }
                if let Ok(meta) = session.get_management_key_metadata()
                    && meta.default_value
                {
                    println!("      WARNING: Using default Management key!");
                }
                use yubikit::piv::{ObjectId, Slot};
                match session.get_object(ObjectId::Chuid) {
                    Ok(data) => {
                        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
                        println!("      CHUID: {hex}");
                    }
                    Err(_) => println!("      CHUID: No data available"),
                }
                match session.get_object(ObjectId::Capability) {
                    Ok(data) => {
                        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
                        println!("      CCC:   {hex}");
                    }
                    Err(_) => println!("      CCC:   No data available"),
                }
                let slots = [
                    (Slot::Authentication, "9A", "AUTHENTICATION"),
                    (Slot::Signature, "9C", "DIGITAL SIGNATURE"),
                    (Slot::KeyManagement, "9D", "KEY MANAGEMENT"),
                    (Slot::CardAuth, "9E", "CARD AUTH"),
                ];
                for (slot, hex, name) in slots {
                    if let Ok(meta) = session.get_slot_metadata(slot) {
                        println!("      Slot {hex} ({name}):");
                        println!("        Private key type: {}", meta.key_type);
                        if let Ok(cert_bytes) = session.get_certificate(slot) {
                            use sha2::{Digest, Sha256};
                            let fp = Sha256::digest(&cert_bytes);
                            let fp_hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
                            println!("        Fingerprint:      {fp_hex}");
                        }
                    }
                }
                session.into_connection()
            }
            Err(e) => {
                println!("      Error: {e}");
                match PcscConnection::new(reader, false) {
                    Ok(c) => c,
                    Err(_) => continue,
                }
            }
        };

        // OATH
        println!();
        println!("    OATH:");
        let conn = match yubikit::oath::OathSession::new(conn) {
            Ok(session) => {
                println!("      Oath version:       {}", session.version());
                println!(
                    "      Password protected: {}",
                    if session.locked() { "True" } else { "False" }
                );
                session.into_connection()
            }
            Err(e) => {
                println!("      Error: {e}");
                match PcscConnection::new(reader, false) {
                    Ok(c) => c,
                    Err(_) => continue,
                }
            }
        };

        // OpenPGP
        println!();
        println!("    OpenPGP:");
        let conn = match yubikit::openpgp::OpenPgpSession::new(conn) {
            Ok(mut session) => {
                let aid_ver = session.aid().version();
                println!(
                    "      OpenPGP version:            {}.{}",
                    aid_ver.0, aid_ver.1
                );
                println!("      Application version:        {}", session.version());
                if let Ok(pw_status) = session.get_pin_status() {
                    println!(
                        "      PIN tries remaining:        {}",
                        pw_status.attempts_user
                    );
                    println!(
                        "      Reset code tries remaining: {}",
                        pw_status.attempts_reset
                    );
                    println!(
                        "      Admin PIN tries remaining:  {}",
                        pw_status.attempts_admin
                    );
                    let sig_policy = match pw_status.pin_policy_user {
                        yubikit::openpgp::PinPolicy::Once => "Once",
                        yubikit::openpgp::PinPolicy::Always => "Always",
                    };
                    println!("      Require PIN for signature:  {sig_policy}");
                }
                if let Ok(kdf) = session.get_kdf() {
                    let enabled = !matches!(kdf, yubikit::openpgp::Kdf::None);
                    println!(
                        "      KDF enabled:                {}",
                        if enabled { "True" } else { "False" }
                    );
                }
                session.into_connection()
            }
            Err(e) => {
                println!("      Error: {e}");
                match PcscConnection::new(reader, false) {
                    Ok(c) => c,
                    Err(_) => continue,
                }
            }
        };

        // YubiHSM Auth
        println!();
        println!("    YubiHSM Auth:");
        match yubikit::hsmauth::HsmAuthSession::new(conn) {
            Ok(mut session) => {
                println!(
                    "      YubiHSM Auth version:             {}",
                    session.version()
                );
                if let Ok(retries) = session.get_management_key_retries() {
                    println!("      Management key retries remaining: {retries}/8");
                }
            }
            Err(e) => println!("      Error: {e}"),
        }
    }
    if !pcsc_found {
        println!("  (none)");
    }

    // YubiKeys over HID OTP
    println!();
    print!("Detected YubiKeys over HID OTP:");
    match list_otp_devices() {
        Ok(hid_devices) => {
            if hid_devices.is_empty() {
                println!(" (none)");
            } else {
                println!();
                for hid in &hid_devices {
                    println!(
                        "  OtpYubiKeyDevice(pid={:04x}, path='{}'):",
                        hid.pid, hid.path
                    );

                    // Open one connection and reuse for both Management and OTP sessions
                    let conn = match OtpConnection::new(&hid.path) {
                        Ok(c) => c,
                        Err(e) => {
                            println!("    Error opening connection: {e}");
                            continue;
                        }
                    };

                    println!("    Management:");
                    let conn = match read_info_otp(conn) {
                        Ok((info, conn)) => {
                            let name = get_name(&info);
                            print_device_info(&info, "      ");
                            println!();
                            println!("      Name: {name}");
                            conn
                        }
                        Err(e) => {
                            println!("      Error: {e}");
                            match OtpConnection::new(&hid.path) {
                                Ok(c) => c,
                                Err(_) => continue,
                            }
                        }
                    };

                    println!();
                    println!("    OTP:");
                    match yubikit::yubiotp::YubiOtpOtpSession::new(conn) {
                        Ok(session) => {
                            let state = session.get_config_state();
                            let s1 = state
                                .is_configured(yubikit::yubiotp::Slot::One)
                                .map_or("unknown".into(), |b| {
                                    if b { "True" } else { "False" }.to_string()
                                });
                            let s2 = state
                                .is_configured(yubikit::yubiotp::Slot::Two)
                                .map_or("unknown".into(), |b| {
                                    if b { "True" } else { "False" }.to_string()
                                });
                            let t1 = state
                                .is_touch_triggered(yubikit::yubiotp::Slot::One)
                                .map_or("unknown".into(), |b| {
                                    if b { "True" } else { "False" }.to_string()
                                });
                            let t2 = state
                                .is_touch_triggered(yubikit::yubiotp::Slot::Two)
                                .map_or("unknown".into(), |b| {
                                    if b { "True" } else { "False" }.to_string()
                                });
                            println!(
                                "      ConfigState(configured: ({s1}, {s2}), \
                                     touch_triggered: ({t1}, {t2}), \
                                     led_inverted: {})",
                                if state.is_led_inverted() {
                                    "True"
                                } else {
                                    "False"
                                }
                            );
                        }
                        Err(e) => println!("      Error: {e}"),
                    }
                }
            }
        }
        Err(e) => println!(" Error: {e}"),
    }

    // YubiKeys over HID FIDO
    println!();
    print!("Detected YubiKeys over HID FIDO:");
    match list_fido_devices() {
        Ok(fido_devices) => {
            if fido_devices.is_empty() {
                println!(" (none)");
            } else {
                println!();
                for fido in &fido_devices {
                    println!(
                        "  CtapYubiKeyDevice(pid={:04x}, path='{}'):",
                        fido.pid, fido.path
                    );
                    match FidoConnection::open(fido) {
                        Ok(conn) => {
                            let (v1, v2, v3) = conn.device_version();
                            let caps = conn.capabilities();
                            println!("    CTAP device version: {v1}.{v2}.{v3}");
                            println!("    Capabilities:        {:#04x}", caps.raw());

                            println!("    Management:");
                            match ManagementFidoSession::new(conn) {
                                Ok(mut session) => match session.read_device_info_unchecked() {
                                    Ok(info) => {
                                        let name = get_name(&info);
                                        print_device_info(&info, "      ");
                                        println!();
                                        println!("      Name: {name}");
                                    }
                                    Err(e) => println!("      Error: {e}"),
                                },
                                Err(e) => println!("      Error: {e}"),
                            }
                        }
                        Err(e) => println!("    Error: {e}"),
                    }
                }
            }
        }
        Err(e) => println!(" Error: {e}"),
    }

    println!();
    println!("End of diagnostics");
    Ok(())
}
