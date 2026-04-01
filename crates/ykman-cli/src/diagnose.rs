use yubikit::core::Transport;
use yubikit::device::{get_name, list_readers, read_info_ccid, read_info_fido, read_info_otp};
use yubikit::management::{Capability, DeviceInfo, ReleaseType};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::transport::otphid::{HidOtpConnection, list_otp_devices};
use yubikit::transport::pcsc::{PcscSmartCardConnection, is_reader_usb};
use yubikit::yubiotp::YubiOtpSession;

use crate::fido::HidCtapDevice;
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

fn print_ctap2_info(info: &fido2_client::ctap2::Info) {
    println!("      versions:      {:?}", info.versions);
    if !info.extensions.is_empty() {
        println!("      extensions:    {:?}", info.extensions);
    }
    println!("      aaguid:        {}", info.aaguid);
    if !info.options.is_empty() {
        println!("      options:");
        for (k, v) in &info.options {
            println!("        {k}: {v}");
        }
    }
    println!("      max_msg_size:  {}", info.max_msg_size);
    if !info.pin_uv_protocols.is_empty() {
        println!("      pin_uv_auth_protocols: {:?}", info.pin_uv_protocols);
    }
    if info.max_creds_in_list > 0 {
        println!("      max_creds_in_list:     {}", info.max_creds_in_list);
    }
    if info.max_cred_id_length > 0 {
        println!("      max_cred_id_length:    {}", info.max_cred_id_length);
    }
    if !info.transports.is_empty() {
        println!("      transports:    {:?}", info.transports);
    }
    if info.min_pin_length != 4 {
        println!("      min_pin_length: {}", info.min_pin_length);
    }
    if info.firmware_version > 0 {
        println!("      firmware_version: {}", info.firmware_version);
    }
    if let Some(remaining) = info.remaining_disc_creds {
        println!("      remaining_disc_creds: {remaining}");
    }
    if info.force_pin_change {
        println!("      force_pin_change: true");
    }
}

fn print_ctap2_pin_status(ctap2: &fido2_client::ctap2::Ctap2) {
    let info = ctap2.info();
    if info.options.get("clientPin") == Some(&true) {
        match fido2_client::pin::ClientPin::new(ctap2, None) {
            Ok(client_pin) => {
                match client_pin.get_pin_retries() {
                    Ok((retries, power_cycle)) => {
                        print!("      PIN retries: {retries}");
                        if let Some(pc) = power_cycle {
                            print!(" (power_cycle: {pc})");
                        }
                        println!();
                    }
                    Err(e) => println!("      PIN retries error: {e}"),
                }
                // Fingerprint status
                let bio_enroll = info.options.get("bioEnroll");
                match bio_enroll {
                    Some(true) => match client_pin.get_uv_retries() {
                        Ok(retries) => println!("      UV retries: {retries}"),
                        Err(e) => println!("      UV retries error: {e}"),
                    },
                    Some(false) => println!("      Fingerprints: Not configured"),
                    _ => {}
                }
            }
            Err(e) => println!("      ClientPin error: {e}"),
        }
    } else if info.options.contains_key("clientPin") {
        println!("      PIN: Not configured");
    }
}

pub fn run_diagnose() -> Result<(), CliError> {
    println!("ykman:            {}", env!("CARGO_PKG_VERSION"));
    println!("Platform:         {}", std::env::consts::OS);
    println!("Arch:             {}", std::env::consts::ARCH);

    // YubiKeys over PC/SC (USB and NFC readers)
    println!();
    print!("Detected YubiKeys over PC/SC:");
    match list_readers() {
        Ok(readers) => {
            // Collect readers with a YubiKey present, caching NFC read results
            let yubikey_readers: Vec<(&String, Option<DeviceInfo>)> = readers
                .iter()
                .filter_map(|r| {
                    if is_reader_usb(r) {
                        return Some((r, None));
                    }
                    // NFC: verify a YubiKey is present, cache the result
                    let conn = PcscSmartCardConnection::new(r, false).ok()?;
                    let (info, _) = read_info_ccid(conn).ok()?;
                    Some((r, Some(info)))
                })
                .collect();

            if yubikey_readers.is_empty() {
                println!(" (none)");
            } else {
                println!();
                for (reader, cached_info) in &yubikey_readers {
                    println!("  {reader}:");

                    let conn = match PcscSmartCardConnection::new(reader, false) {
                        Ok(c) => c,
                        Err(e) => {
                            println!("    Error opening connection: {e}");
                            continue;
                        }
                    };

                    // Management / DeviceInfo
                    println!("    Management:");
                    let conn = if let Some(info) = cached_info {
                        // NFC reader: reuse cached info, read fresh connection for remaining probes
                        let name = get_name(info);
                        print_device_info(info, "      ");
                        println!();
                        println!("      Name: {name}");
                        conn
                    } else {
                        match read_info_ccid(conn) {
                            Ok((info, c)) => {
                                let name = get_name(&info);
                                print_device_info(&info, "      ");
                                println!();
                                println!("      Name: {name}");
                                c
                            }
                            Err(e) => {
                                println!("      Error: {e}");
                                match PcscSmartCardConnection::new(reader, false) {
                                    Ok(c) => c,
                                    Err(_) => continue,
                                }
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
                                    let hex: String =
                                        data.iter().map(|b| format!("{b:02x}")).collect();
                                    println!("      CHUID: {hex}");
                                }
                                Err(_) => println!("      CHUID: No data available"),
                            }
                            match session.get_object(ObjectId::Capability) {
                                Ok(data) => {
                                    let hex: String =
                                        data.iter().map(|b| format!("{b:02x}")).collect();
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
                                        let fp_hex: String =
                                            fp.iter().map(|b| format!("{b:02x}")).collect();
                                        println!("        Fingerprint:      {fp_hex}");
                                    }
                                }
                            }
                            session.into_connection()
                        }
                        Err((e, conn)) => {
                            println!("      Error: {e}");
                            conn
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
                        Err((e, conn)) => {
                            println!("      Error: {e}");
                            conn
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
                        Err((e, conn)) => {
                            println!("      Error: {e}");
                            conn
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
                        Err((e, _)) => println!("      Error: {e}"),
                    }
                }
            }
        }
        Err(e) => println!(" Error: {e}"),
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
                    let conn = match HidOtpConnection::new(&hid.path) {
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
                        Err((e, conn)) => {
                            println!("      Error: {e}");
                            match conn.or_else(|| HidOtpConnection::new(&hid.path).ok()) {
                                Some(c) => c,
                                None => continue,
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
                        Err((e, _)) => println!("      Error: {e}"),
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
                    match HidFidoConnection::open(fido) {
                        Ok(conn) => {
                            let (v1, v2, v3) = conn.device_version();
                            let caps = conn.capabilities();
                            println!("    CTAP device version: {v1}.{v2}.{v3}");
                            println!("    Capabilities:        {:#04x}", caps.raw());

                            // CTAP2 Info
                            if caps.has_cbor() {
                                println!("    CTAP2 Info:");
                                let adapter = HidCtapDevice::new(conn);
                                match fido2_client::ctap2::Ctap2::new(&adapter, false) {
                                    Ok(ctap2) => {
                                        print_ctap2_info(ctap2.info());
                                        // PIN status
                                        print_ctap2_pin_status(&ctap2);
                                    }
                                    Err(e) => println!("      Error: {e}"),
                                }
                                let conn = adapter.into_connection();

                                println!("    Management:");
                                match read_info_fido(conn) {
                                    Ok((info, _conn)) => {
                                        let name = get_name(&info);
                                        print_device_info(&info, "      ");
                                        println!();
                                        println!("      Name: {name}");
                                    }
                                    Err((e, _)) => println!("      Error: {e}"),
                                }
                            } else {
                                println!("    Management:");
                                match read_info_fido(conn) {
                                    Ok((info, _conn)) => {
                                        let name = get_name(&info);
                                        print_device_info(&info, "      ");
                                        println!();
                                        println!("      Name: {name}");
                                    }
                                    Err((e, _)) => println!("      Error: {e}"),
                                }
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
