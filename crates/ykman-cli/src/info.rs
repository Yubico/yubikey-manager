use anyhow::{Context, Result, ensure};
use yubikit::core::{Transport, Version};
use yubikit::device::{DeviceError, YubiKeyDevice};
use yubikit::management::{
    Capability, ManagementError, ManagementSession, StorageInfo, UsbInterface,
};
use yubikit::smartcard::{SmartCardError, Sw};

use crate::util::print_table;

pub fn run(dev: &dyn YubiKeyDevice, check_fips: bool) -> Result<()> {
    let info = dev.info();

    let mut rows = vec![("Device type", dev.name())];
    if let Some(serial) = info.serial {
        rows.push(("Serial number", serial.to_string()));
    }
    if info.version != yubikit::core::Version(0, 0, 0) {
        rows.push(("Firmware version", info.version_name()));
    } else {
        rows.push((
            "Firmware version",
            "Uncertain, re-run with only one YubiKey connected".to_string(),
        ));
    }
    if info.form_factor != yubikit::management::FormFactor::Unknown {
        rows.push(("Form factor", info.form_factor.to_string()));
    }

    // Show USB interfaces only when connected via USB
    let is_usb = dev.transport() == Transport::Usb;
    if is_usb {
        let usb_ifaces = dev.usb_interfaces();
        if usb_ifaces.0 != 0 {
            rows.push(("Enabled USB interfaces", usb_ifaces.to_string()));
        }
    }
    print_table(rows);

    // NFC status
    if info.supported_capabilities.contains_key(&Transport::Nfc) {
        let nfc_status = match info.config.nfc_restricted {
            Some(true) => "restricted",
            _ => {
                if info
                    .config
                    .enabled_capabilities
                    .get(&Transport::Nfc)
                    .is_some_and(|c| !c.is_empty())
                {
                    "enabled"
                } else {
                    "disabled"
                }
            }
        };
        println!("NFC transport is {nfc_status}");
    }
    if info.pin_complexity {
        println!("PIN complexity is enforced");
    }
    if info.is_locked {
        println!("Configured capabilities are protected by a lock code");
    }

    println!();
    print_app_status_table(
        &info.supported_capabilities,
        &info.config.enabled_capabilities,
    );

    if !info.fips_capable.is_empty() {
        println!();
        println!("FIPS approved applications");
        let mut rows = Vec::new();
        for &cap in Capability::ALL {
            if info.fips_capable.contains(cap) {
                let approved = info.fips_approved.contains(cap);
                rows.push((
                    format!("  {}", cap.display_name()),
                    if approved {
                        "Yes".to_string()
                    } else {
                        "No".to_string()
                    },
                ));
            }
        }
        print_table(rows);
    }

    if let Some(storage) = read_storage_info(dev)? {
        let rows = storage_rows(&storage).context("Invalid storage information")?;
        println!("\nStorage");
        print_table(rows);
    }

    if check_fips {
        println!();
        if info.fips_capable.is_empty() {
            println!("FIPS approved mode: Not applicable (device is not FIPS capable)");
        } else {
            let all_approved = Capability::ALL
                .iter()
                .all(|&cap| !info.fips_capable.contains(cap) || info.fips_approved.contains(cap));
            print_table([(
                "FIPS approved mode",
                if all_approved { "Yes" } else { "No" }.to_string(),
            )]);
        }
    }

    Ok(())
}

fn read_storage_info(dev: &dyn YubiKeyDevice) -> Result<Option<StorageInfo>> {
    if dev.info().version < Version(6, 0, 0)
        || (dev.transport() == Transport::Usb && !dev.usb_interfaces().contains(UsbInterface::CCID))
    {
        return Ok(None);
    }
    let connection = match dev.open_smartcard() {
        Ok(connection) => connection,
        Err(error @ DeviceError::UnsupportedFeature("pcsc")) => {
            log::debug!("Storage information unavailable: {error}");
            return Ok(None);
        }
        Err(error) => {
            return Err(error)
                .context("Failed to open smartcard connection for storage information");
        }
    };
    let mut session = match ManagementSession::new(connection) {
        Ok(session) => session,
        Err((ManagementError::Connection(SmartCardError::ApplicationNotAvailable), _)) => {
            log::debug!("Storage information unavailable: management application not available");
            return Ok(None);
        }
        Err((error, _)) => {
            return Err(error).context("Failed to open management session for storage information");
        }
    };
    match session.read_storage_info() {
        Ok(info) => Ok(Some(info)),
        Err(error @ ManagementError::NotSupported(_)) => {
            log::debug!("Storage information unavailable: {error}");
            Ok(None)
        }
        Err(ManagementError::Connection(SmartCardError::Apdu { sw, .. }))
            if matches!(
                Sw::from_u16(sw),
                Some(Sw::InvalidInstruction | Sw::FunctionNotSupported)
            ) =>
        {
            log::debug!("Storage reporting is not supported (SW={sw:04x})");
            Ok(None)
        }
        Err(error) => Err(error).context("Failed to read storage information"),
    }
}

const STORAGE_PAGE_SIZE: u64 = 256;

#[derive(Default)]
struct StorageUsage {
    pages: u64,
    objects: u64,
}

fn format_storage_size(pages: u64) -> String {
    let bytes = pages * STORAGE_PAGE_SIZE;
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

fn storage_rows(info: &StorageInfo) -> Result<Vec<(&'static str, String)>> {
    ensure!(
        info.entries.iter().any(|entry| entry.id == 0),
        "Storage response is missing free-space statistics"
    );
    let mut free = StorageUsage::default();
    let mut apps = [
        ("FIDO2", StorageUsage::default()),
        ("PIV", StorageUsage::default()),
        ("OpenPGP", StorageUsage::default()),
        ("Other", StorageUsage::default()),
    ];
    for entry in &info.entries {
        let usage = match entry.id {
            0 => &mut free,
            1 | 2 => &mut apps[1].1,
            3 => &mut apps[2].1,
            4 | 5 => &mut apps[0].1,
            _ => &mut apps[3].1,
        };
        usage.pages += u64::from(entry.pages);
        usage.objects += u64::from(entry.objects);
    }
    let used_pages: u64 = apps.iter().map(|(_, usage)| usage.pages).sum();
    let used_objects: u64 = apps.iter().map(|(_, usage)| usage.objects).sum();
    let mut rows = vec![
        (
            "Used",
            format!(
                "{} of {}",
                format_storage_size(used_pages),
                format_storage_size(used_pages + free.pages)
            ),
        ),
        ("Free", format_storage_size(free.pages)),
        (
            "Objects",
            format!(
                "{used_objects} of {} used ({} free)",
                used_objects + free.objects,
                free.objects
            ),
        ),
    ];
    rows.extend(
        apps.into_iter()
            .filter(|(_, usage)| usage.pages > 0 || usage.objects > 0)
            .map(|(name, usage)| {
                (
                    name,
                    format!(
                        "{} ({} {})",
                        format_storage_size(usage.pages),
                        usage.objects,
                        if usage.objects == 1 {
                            "object"
                        } else {
                            "objects"
                        }
                    ),
                )
            }),
    );
    Ok(rows)
}

fn print_app_status_table(
    supported: &std::collections::HashMap<Transport, Capability>,
    enabled: &std::collections::HashMap<Transport, Capability>,
) {
    let usb_supported = supported
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);
    let usb_enabled = enabled
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);
    let nfc_supported = supported.get(&Transport::Nfc).copied();
    let nfc_enabled = enabled
        .get(&Transport::Nfc)
        .copied()
        .unwrap_or(Capability::NONE);

    let has_nfc = nfc_supported.is_some();
    let nfc_supported = nfc_supported.unwrap_or(Capability::NONE);

    let mut rows = Vec::new();
    if has_nfc {
        rows.push(vec!["Applications", "USB", "NFC"]);
    } else {
        rows.push(vec!["Applications", "USB"]);
    }
    for &cap in Capability::ALL {
        let usb_status = if usb_supported.contains(cap) {
            if usb_enabled.contains(cap) {
                // FIDO_CCID is "Inactive" when FIDO2 is not also enabled
                if cap == Capability::FIDOCCID && !usb_enabled.contains(Capability::FIDO2) {
                    "Inactive"
                } else {
                    "Enabled"
                }
            } else {
                "Disabled"
            }
        } else {
            "Not available"
        };
        // FIDO_CCID is USB-only; show "N/A" for NFC
        let nfc_status = if cap == Capability::FIDOCCID {
            "N/A"
        } else if nfc_supported.contains(cap) {
            if nfc_enabled.contains(cap) {
                "Enabled"
            } else {
                "Disabled"
            }
        } else {
            "Not available"
        };
        // Only show capabilities that are supported on at least one transport
        if usb_supported.contains(cap) || (has_nfc && nfc_supported.contains(cap)) {
            if has_nfc {
                rows.push(vec![cap.display_name(), usb_status, nfc_status]);
            } else {
                rows.push(vec![cap.display_name(), usb_status]);
            }
        }
    }

    print_table(rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubikit::__internal::tlv::tlv_encode;
    use yubikit::core::Connection;
    use yubikit::device::ReinsertStatus;
    use yubikit::fido::FidoConnection;
    use yubikit::management::{DeviceInfo, StorageStatsEntry};
    use yubikit::otp::OtpConnection;
    use yubikit::smartcard::SmartCardConnection;

    fn storage_info(entries: &[(u8, u16, u16)]) -> StorageInfo {
        StorageInfo {
            entries: entries
                .iter()
                .map(|&(id, objects, pages)| StorageStatsEntry { id, objects, pages })
                .collect(),
        }
    }

    #[test]
    fn storage_combines_piv_and_fido_identifiers() {
        let info = storage_info(&[
            (2, 3, 24),
            (5, 2, 4),
            (0, 143, 400),
            (1, 2, 8),
            (3, 4, 32),
            (4, 6, 12),
        ]);
        assert_eq!(
            storage_rows(&info).unwrap(),
            [
                ("Used", "20.0 KiB of 120.0 KiB".into()),
                ("Free", "100.0 KiB".into()),
                ("Objects", "17 of 160 used (143 free)".into()),
                ("FIDO2", "4.0 KiB (8 objects)".into()),
                ("PIV", "8.0 KiB (5 objects)".into()),
                ("OpenPGP", "8.0 KiB (4 objects)".into()),
            ]
        );
    }

    #[test]
    fn storage_preserves_unknown_and_inline_usage() {
        let info = storage_info(&[(0, 3, 8), (255, 3, 3), (2, 1, 0), (4, 0, 0), (8, 2, 1)]);
        assert_eq!(
            storage_rows(&info).unwrap(),
            [
                ("Used", "1.0 KiB of 3.0 KiB".into()),
                ("Free", "2.0 KiB".into()),
                ("Objects", "6 of 9 used (3 free)".into()),
                ("PIV", "0 B (1 object)".into()),
                ("Other", "1.0 KiB (5 objects)".into()),
            ]
        );
    }

    #[test]
    fn storage_zero_capacity_and_missing_free_space() {
        assert_eq!(
            storage_rows(&storage_info(&[(0, 0, 0)])).unwrap(),
            [
                ("Used", "0 B of 0 B".into()),
                ("Free", "0 B".into()),
                ("Objects", "0 of 0 used (0 free)".into()),
            ]
        );
        for entries in [&[][..], &[(1, 1, 1)][..]] {
            assert!(
                storage_rows(&storage_info(entries))
                    .unwrap_err()
                    .to_string()
                    .contains("missing free-space")
            );
        }
    }

    #[test]
    fn storage_totals_exceed_individual_record_limits() {
        let info = storage_info(&[
            (0, u16::MAX, u16::MAX),
            (1, u16::MAX, u16::MAX),
            (2, u16::MAX, u16::MAX),
        ]);
        let rows = storage_rows(&info).unwrap();
        assert_eq!(
            rows[2],
            ("Objects", "131070 of 196605 used (65535 free)".into())
        );
        assert_eq!(rows[3], ("PIV", "32767.5 KiB (131070 objects)".into()));
        assert_eq!(format_storage_size(1), "256 B");
    }

    #[derive(Clone)]
    struct StorageDevice {
        info: DeviceInfo,
        transport: Transport,
        interfaces: UsbInterface,
        allow_open: bool,
        fail_open: bool,
        response: Vec<u8>,
        sw: u16,
    }

    impl Default for StorageDevice {
        fn default() -> Self {
            Self {
                info: DeviceInfo::parse(&[0], Version(6, 0, 0)).unwrap(),
                transport: Transport::Usb,
                interfaces: UsbInterface::CCID,
                allow_open: true,
                fail_open: false,
                response: tlv_encode(1, &[0, 0, 10, 0, 100]),
                sw: 0x9000,
            }
        }
    }

    struct StorageConnection {
        transport: Transport,
        response: Vec<u8>,
        sw: u16,
    }

    impl Connection for StorageConnection {
        type Error = SmartCardError;

        fn close(&mut self) {}
    }

    impl SmartCardConnection for StorageConnection {
        fn transport(&self) -> Transport {
            self.transport
        }

        fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
            match &apdu[..4] {
                [0, 0xa4, 4, 0] => Ok((b"6.0.0".to_vec(), 0x9000)),
                [0, 0x30, 0, 0] => Ok((self.response.clone(), self.sw)),
                _ => panic!("Unexpected APDU: {apdu:02x?}"),
            }
        }
    }

    impl YubiKeyDevice for StorageDevice {
        fn info(&self) -> &DeviceInfo {
            &self.info
        }

        fn transport(&self) -> Transport {
            self.transport
        }

        fn name(&self) -> String {
            "Test YubiKey".into()
        }

        fn usb_interfaces(&self) -> UsbInterface {
            self.interfaces
        }

        fn open_smartcard(&self) -> Result<Box<dyn SmartCardConnection + Send>, DeviceError> {
            assert!(self.allow_open, "Storage must not open a connection");
            if self.fail_open {
                return Err(DeviceError::CcidUnavailable);
            }
            Ok(Box::new(StorageConnection {
                transport: self.transport,
                response: self.response.clone(),
                sw: self.sw,
            }))
        }

        fn open_fido(&self) -> Result<Box<dyn FidoConnection + Send>, DeviceError> {
            panic!("Storage must use a smartcard connection")
        }

        fn open_otp(&self) -> Result<Box<dyn OtpConnection + Send>, DeviceError> {
            panic!("Storage must use a smartcard connection")
        }

        fn reinsert(
            &mut self,
            _: &dyn Fn(ReinsertStatus),
            _: &dyn Fn() -> bool,
        ) -> Result<(), DeviceError> {
            panic!("Storage must not reinsert")
        }

        fn clone_box(&self) -> Box<dyn YubiKeyDevice> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn info_reads_storage_over_smartcard() {
        for transport in [Transport::Usb, Transport::Nfc] {
            let device = StorageDevice {
                transport,
                ..Default::default()
            };
            let info = read_storage_info(&device).unwrap().unwrap();
            assert_eq!(info, storage_info(&[(0, 10, 100)]));
            run(&device, true).unwrap();
        }
    }

    #[test]
    fn info_skips_storage_without_opening_unsupported_devices() {
        for version in [Version(0, 0, 0), Version(3, 3, 0), Version(5, 7, 2)] {
            let mut device = StorageDevice {
                allow_open: false,
                ..Default::default()
            };
            device.info.version = version;
            assert!(read_storage_info(&device).unwrap().is_none());
            run(&device, false).unwrap();
        }
        let device = StorageDevice {
            interfaces: UsbInterface::FIDO,
            allow_open: false,
            ..Default::default()
        };
        assert!(read_storage_info(&device).unwrap().is_none());
        run(&device, false).unwrap();
    }

    #[test]
    fn info_skips_unsupported_storage_commands() {
        for sw in [0x6d00, 0x6a81] {
            let device = StorageDevice {
                sw,
                ..Default::default()
            };
            assert!(read_storage_info(&device).unwrap().is_none());
            run(&device, false).unwrap();
        }
    }

    #[test]
    fn info_surfaces_storage_failures() {
        let device = StorageDevice {
            fail_open: true,
            ..Default::default()
        };
        assert!(
            format!("{:#}", run(&device, false).unwrap_err()).contains("reader is unavailable")
        );
        for sw in [0x6982, 0x6f00] {
            let device = StorageDevice {
                sw,
                ..Default::default()
            };
            assert!(
                run(&device, false)
                    .unwrap_err()
                    .to_string()
                    .contains("Failed to read storage")
            );
        }
        for response in [vec![1, 1, 0], tlv_encode(1, &[1, 0, 1, 0, 1])] {
            let device = StorageDevice {
                response,
                ..Default::default()
            };
            assert!(run(&device, false).is_err());
        }
    }
}
