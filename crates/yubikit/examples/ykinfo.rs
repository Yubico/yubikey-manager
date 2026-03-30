//! Sample CLI demonstrating the yubikit API.
//!
//! This example enumerates connected YubiKeys, displays device information,
//! and optionally shows details from each application (OATH, PIV, OpenPGP, etc.).
//!
//! Usage:
//!   cargo run -p yubikit --example ykinfo
//!   cargo run -p yubikit --example ykinfo -- --serial 12345678
//!   cargo run -p yubikit --example ykinfo -- --all
//!   cargo run -p yubikit --example ykinfo -- --list-readers
//!   cargo run -p yubikit --example ykinfo -- --reader ACR122

use std::env;
use yubikit::core::Transport;
use yubikit::core::{Version, set_override_version};
use yubikit::device::{
    YubiKeyDevice, list_devices, list_devices_ccid, list_devices_fido, list_devices_otp,
    list_readers, open_reader,
};
use yubikit::hsmauth::HsmAuthSession;
use yubikit::management::{Capability, ReleaseType};
use yubikit::oath::OathSession;
use yubikit::openpgp::OpenPgpSession;
use yubikit::piv::PivSession;
use yubikit::securitydomain::SecurityDomainSession;
use yubikit::yubiotp::{YubiOtpCcidSession, YubiOtpSession};

fn main() {
    let args: Vec<String> = env::args().collect();
    let serial_filter: Option<u32> = args
        .windows(2)
        .find(|w| w[0] == "--serial")
        .and_then(|w| w[1].parse().ok());
    let show_all = args.iter().any(|a| a == "--all");
    let list_readers_flag = args.iter().any(|a| a == "--list-readers");
    let reader_filter: Option<&str> = args
        .windows(2)
        .find(|w| w[0] == "--reader")
        .map(|w| w[1].as_str());

    if list_readers_flag {
        match list_readers() {
            Ok(readers) => {
                if readers.is_empty() {
                    println!("No PC/SC readers found.");
                } else {
                    println!("Available PC/SC readers:");
                    for r in &readers {
                        println!("  {r}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to list readers: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let devices: Vec<YubiKeyDevice> = if let Some(filter) = reader_filter {
        let filter_lower = filter.to_ascii_lowercase();
        let readers = match list_readers() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to list readers: {e}");
                std::process::exit(1);
            }
        };
        let matching: Vec<_> = readers
            .into_iter()
            .filter(|r| r.to_ascii_lowercase().contains(&filter_lower))
            .collect();
        if matching.is_empty() {
            eprintln!("No reader matching \"{filter}\" found.");
            std::process::exit(1);
        }
        let mut devs = Vec::new();
        for reader in &matching {
            match open_reader(reader) {
                Ok(dev) => devs.push(dev),
                Err(e) => eprintln!("Warning: could not open reader \"{reader}\": {e}"),
            }
        }
        devs
    } else {
        match list_devices(&[list_devices_ccid, list_devices_otp, list_devices_fido]) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to enumerate devices: {e}");
                std::process::exit(1);
            }
        }
    };

    if devices.is_empty() {
        println!("No YubiKeys found.");
        return;
    }

    println!("Found {} YubiKey(s):\n", devices.len());

    for dev in &devices {
        if let Some(s) = serial_filter
            && dev.serial() != Some(s)
        {
            continue;
        }

        print_device_info(dev);

        if show_all {
            print_application_details(dev);
        }

        println!();
    }
}

fn print_device_info(dev: &YubiKeyDevice) {
    let info = dev.info();

    println!("── {} ──", dev.name());
    println!(
        "  Serial:      {}",
        info.serial.map_or("N/A".into(), |s| s.to_string())
    );
    println!("  Version:     {}", info.version);
    println!("  Form factor: {}", info.form_factor);

    if info.version == Version(0, 0, 1) {
        let real_version = info.version_qualifier.version;
        println!(
            "  Development device, overriding version to {}",
            real_version
        );
        set_override_version(real_version);
    } else if info.version_qualifier.release_type != ReleaseType::Final {
        println!(
            "  Pre-release device, overriding version to {}",
            info.version
        );
        set_override_version(info.version);
    }

    if info.is_fips {
        println!("  FIPS:        yes");
    }
    if info.is_sky {
        println!("  Security Key: yes");
    }
    if info.pin_complexity {
        println!("  PIN complexity: enforced");
    }

    // Capabilities
    for transport in [Transport::Usb, Transport::Nfc] {
        if let Some(cap) = info.supported_capabilities.get(&transport)
            && !cap.is_empty()
        {
            println!("  {transport:?} capabilities: {cap}");
        }
    }
}

fn print_application_details(dev: &YubiKeyDevice) {
    let caps = dev
        .info()
        .supported_capabilities
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);

    if caps.contains(Capability::OATH) {
        print_oath_info(dev);
    }
    if caps.contains(Capability::PIV) {
        print_piv_info(dev);
    }
    if caps.contains(Capability::OPENPGP) {
        print_openpgp_info(dev);
    }
    if caps.contains(Capability::OTP) {
        print_yubiotp_info(dev);
    }
    if caps.contains(Capability::HSMAUTH) {
        print_hsmauth_info(dev);
    }
    print_securitydomain_info(dev);
}

fn print_oath_info(dev: &YubiKeyDevice) {
    let conn = match dev.open_smartcard() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut session = match OathSession::new(conn) {
        Ok(s) => s,
        Err((e, _)) => {
            println!("\n  [OATH] Error: {e}");
            return;
        }
    };

    println!("\n  [OATH] version {}", session.version());
    match session.list_credentials() {
        Ok(creds) => println!("  [OATH] {} credential(s) stored", creds.len()),
        Err(e) => println!("  [OATH] Could not list credentials: {e}"),
    }
}

fn print_piv_info(dev: &YubiKeyDevice) {
    let conn = match dev.open_smartcard() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut session = match PivSession::new(conn) {
        Ok(s) => s,
        Err((e, _)) => {
            println!("\n  [PIV] Error: {e}");
            return;
        }
    };

    println!("\n  [PIV] version {}", session.version());
    match session.get_pin_attempts() {
        Ok(n) => println!("  [PIV] PIN attempts remaining: {n}"),
        Err(e) => println!("  [PIV] Could not read PIN attempts: {e}"),
    }
}

fn print_openpgp_info(dev: &YubiKeyDevice) {
    let conn = match dev.open_smartcard() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut session = match OpenPgpSession::new(conn) {
        Ok(s) => s,
        Err((e, _)) => {
            println!("\n  [OpenPGP] Error: {e}");
            return;
        }
    };

    println!("\n  [OpenPGP] version {}", session.version());
    match session.get_application_related_data() {
        Ok(data) => {
            let (major, minor) = data.aid.version();
            println!("  [OpenPGP] application version: {major}.{minor}");
        }
        Err(e) => println!("  [OpenPGP] Could not read application data: {e}"),
    }
}

fn print_yubiotp_info(dev: &YubiKeyDevice) {
    let conn = match dev.open_smartcard() {
        Ok(c) => c,
        Err(_) => return,
    };
    match YubiOtpCcidSession::new(conn) {
        Ok(session) => {
            println!("\n  [YubiOTP] version {}", session.version());
        }
        Err((e, _)) => {
            println!("\n  [YubiOTP] Error: {e}");
        }
    }
}

fn print_hsmauth_info(dev: &YubiKeyDevice) {
    let conn = match dev.open_smartcard() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut session = match HsmAuthSession::new(conn) {
        Ok(s) => s,
        Err((e, _)) => {
            println!("\n  [HSM Auth] Error: {e}");
            return;
        }
    };

    println!("\n  [HSM Auth] version {}", session.version());
    match session.list_credentials() {
        Ok(creds) => println!("  [HSM Auth] {} credential(s) stored", creds.len()),
        Err(e) => println!("  [HSM Auth] Could not list credentials: {e}"),
    }
}

fn print_securitydomain_info(dev: &YubiKeyDevice) {
    let conn = match dev.open_smartcard() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut session = match SecurityDomainSession::new(conn) {
        Ok(s) => s,
        Err(_) => return, // Not all devices have this
    };

    println!("\n  [Security Domain] version {}", session.version());
    match session.get_key_information() {
        Ok(keys) => println!("  [Security Domain] {} key set(s)", keys.len()),
        Err(e) => println!("  [Security Domain] Could not read keys: {e}"),
    }
}
