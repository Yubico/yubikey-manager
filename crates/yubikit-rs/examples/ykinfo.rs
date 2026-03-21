//! Sample CLI demonstrating the yubikit-rs API.
//!
//! This example enumerates connected YubiKeys, displays device information,
//! and optionally shows details from each application (OATH, PIV, OpenPGP, etc.).
//!
//! Usage:
//!   cargo run -p yubikit-rs --example ykinfo
//!   cargo run -p yubikit-rs --example ykinfo -- --serial 12345678
//!   cargo run -p yubikit-rs --example ykinfo -- --all

use std::env;
use yubikit_rs::device::{list_devices, YubiKeyDevice};
use yubikit_rs::hsmauth::HsmAuthSession;
use yubikit_rs::iso7816::Transport;
use yubikit_rs::management::Capability;
use yubikit_rs::oath::OathSession;
use yubikit_rs::openpgp::OpenPgpSession;
use yubikit_rs::piv::PivSession;
use yubikit_rs::securitydomain::SecurityDomainSession;
use yubikit_rs::yubiotp::YubiOtpSession;

fn main() {
    let args: Vec<String> = env::args().collect();
    let serial_filter: Option<u32> = args
        .windows(2)
        .find(|w| w[0] == "--serial")
        .and_then(|w| w[1].parse().ok());
    let show_all = args.iter().any(|a| a == "--all");

    let devices = match list_devices() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to enumerate devices: {e}");
            std::process::exit(1);
        }
    };

    if devices.is_empty() {
        println!("No YubiKeys found.");
        return;
    }

    println!("Found {} YubiKey(s):\n", devices.len());

    for dev in &devices {
        if let Some(s) = serial_filter {
            if dev.serial() != Some(s) {
                continue;
            }
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
    println!("  Serial:      {}", info.serial.map_or("N/A".into(), |s| s.to_string()));
    println!("  Version:     {}", info.version);
    println!("  Form factor: {}", info.form_factor);

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
        if let Some(cap) = info.supported_capabilities.get(&transport) {
            if !cap.is_empty() {
                println!("  {transport:?} capabilities: {cap}");
            }
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
        Err(e) => {
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
        Err(e) => {
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
        Err(e) => {
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
    match YubiOtpSession::new(conn) {
        Ok(session) => {
            println!("\n  [YubiOTP] version {}", session.version());
        }
        Err(e) => {
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
        Err(e) => {
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
