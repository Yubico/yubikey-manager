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

//! Print YubiKey device interface events as they happen.
//!
//! Run with:
//!
//! ```text
//! cargo run -p yubikit --example monitor_device_events
//! ```
//!
//! The example prints an event for every currently-connected interface, then
//! prints events as devices are connected and disconnected. Press Enter to
//! stop, or Ctrl+C to quit.

use std::io::BufRead;

use yubikit::management::UsbInterface;
use yubikit::platform::monitor::{DeviceNode, NodeEvent, monitor_device_events};

fn describe(node: &DeviceNode) -> String {
    match node {
        DeviceNode::UsbReaderNode { reader_name, pid } => {
            format!("UsbReader  pid={pid:#06x} reader='{reader_name}'")
        }
        DeviceNode::CardNode {
            reader_name,
            device_info,
        } => {
            format!(
                "Card       serial={:?} version={} reader='{reader_name}'",
                device_info.serial, device_info.version
            )
        }
        DeviceNode::HidOtpNode {
            hid_path,
            pid,
            device_info,
        } => {
            format!(
                "HidOtp     pid={pid:#06x} serial={:?} version={} path='{hid_path}'",
                device_info.serial, device_info.version
            )
        }
        DeviceNode::HidFidoNode {
            hid_path,
            pid,
            device_info,
        } => {
            format!(
                "HidFido    pid={pid:#06x} serial={:?} version={} path='{hid_path}'",
                device_info.serial, device_info.version
            )
        }
    }
}

fn main() {
    println!("Monitoring YubiKey device events. Press Enter (or Ctrl+C) to stop.\n");

    let interfaces = UsbInterface::OTP | UsbInterface::CCID | UsbInterface::FIDO;

    let mut readers = 0i64;
    let mut cards = 0i64;
    let mut otp = 0i64;
    let mut fido = 0i64;

    let handle = monitor_device_events(interfaces, move |event| {
        let (sign, node) = match &event {
            NodeEvent::Added(node) => ("+", node),
            NodeEvent::Removed(node) => ("-", node),
        };
        let delta = if matches!(event, NodeEvent::Added(_)) {
            1
        } else {
            -1
        };
        match node {
            DeviceNode::UsbReaderNode { .. } => readers += delta,
            DeviceNode::CardNode { .. } => cards += delta,
            DeviceNode::HidOtpNode { .. } => otp += delta,
            DeviceNode::HidFidoNode { .. } => fido += delta,
        }
        println!("{sign} {}", describe(node));
        println!("  totals: readers={readers} cards={cards} otp={otp} fido={fido}\n");
    });

    // Block until the user presses Enter, then stop the monitor cleanly.
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);

    println!("Stopping monitor...");
    handle.stop();
}
