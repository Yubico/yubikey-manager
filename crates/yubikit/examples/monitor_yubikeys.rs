// Copyright 2026 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Print physical YubiKey events as they happen.
//!
//! Run with:
//!
//! ```text
//! cargo run -p yubikit --example monitor_yubikeys
//! ```
//!
//! Unlike `monitor_device_events`, which reports low-level interface nodes,
//! this example aggregates those nodes into physical devices and reports
//! Added/Changed/Removed events for each. Press Enter (or Ctrl+C) to stop.

use std::io::BufRead;

use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::UsbInterface;
use yubikit::platform::monitor::{YubiKey, YubiKeyEvent, monitor_yubikeys};

fn describe(yk: &YubiKey) -> String {
    let dev = yk.device();
    let info = dev.info();
    let transport = match dev.transport() {
        Transport::Usb => "usb",
        Transport::Nfc => "nfc",
    };
    let interfaces: Vec<&str> = {
        let ifaces = dev.usb_interfaces();
        let mut v = Vec::new();
        if ifaces.contains(UsbInterface::OTP) {
            v.push("OTP");
        }
        if ifaces.contains(UsbInterface::FIDO) {
            v.push("FIDO");
        }
        if ifaces.contains(UsbInterface::CCID) {
            v.push("CCID");
        }
        v
    };
    format!(
        "id={} '{}' serial={:?} version={} transport={transport} interfaces={} nodes=[{}]",
        yk.id(),
        dev.name(),
        info.serial,
        info.version,
        interfaces.join("+"),
        node_kinds(yk),
    )
}

fn node_kinds(yk: &YubiKey) -> String {
    use yubikit::platform::monitor::DeviceNode;
    yk.nodes()
        .iter()
        .map(|n| match n {
            DeviceNode::UsbReaderNode { .. } => "Reader",
            DeviceNode::CardNode { .. } => "Card",
            DeviceNode::HidOtpNode { .. } => "OTP",
            DeviceNode::HidFidoNode { .. } => "FIDO",
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn main() {
    println!("Monitoring physical YubiKeys. Press Enter (or Ctrl+C) to stop.\n");

    let interfaces = UsbInterface::OTP | UsbInterface::CCID | UsbInterface::FIDO;

    let handle = monitor_yubikeys(interfaces, move |event| match event {
        YubiKeyEvent::Added(yk) => println!("+ Added    {}", describe(&yk)),
        YubiKeyEvent::Changed(yk) => println!("~ Changed  {}", describe(&yk)),
        YubiKeyEvent::Removed(yk) => println!("- Removed  {}", describe(&yk)),
    });

    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);

    println!("Stopping monitor...");
    handle.stop();
}
