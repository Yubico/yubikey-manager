use yubikit::core::{Transport, Version, set_override_version};
use yubikit::device::YubiKeyDevice;
use yubikit::management::{Capability, ReleaseType};

#[cfg(feature = "hardware")]
use yubikit::platform::device::scan_usb_devices;

use crate::list;
use crate::scp::ScpParams;
use crate::util::CliError;

pub struct CommandContext {
    serial: Option<u32>,
    scp_params: ScpParams,
}

impl CommandContext {
    pub fn new(serial: Option<u32>, scp_params: ScpParams) -> Self {
        Self { serial, scp_params }
    }

    pub fn device(&self) -> Result<Box<dyn YubiKeyDevice>, CliError> {
        let dev = get_device(self.serial)?;
        apply_version_override(dev.as_ref());
        Ok(dev)
    }

    pub fn device_for(&self, capability: Capability) -> Result<Box<dyn YubiKeyDevice>, CliError> {
        let dev = self.device()?;
        check_capability(dev.as_ref(), capability)?;
        self.check_scp_version(dev.as_ref())?;
        Ok(dev)
    }

    pub fn device_with_scp_check(&self) -> Result<Box<dyn YubiKeyDevice>, CliError> {
        let dev = self.device()?;
        self.check_scp_version(dev.as_ref())?;
        Ok(dev)
    }

    pub fn device_with_min_version(
        &self,
        required: Version,
        feature: &str,
    ) -> Result<Box<dyn YubiKeyDevice>, CliError> {
        let dev = self.device()?;
        check_version(dev.as_ref(), required, feature)?;
        self.check_scp_version(dev.as_ref())?;
        Ok(dev)
    }

    fn check_scp_version(&self, dev: &dyn YubiKeyDevice) -> Result<(), CliError> {
        check_scp_version(dev, &self.scp_params)
    }
}

fn select_device(
    devices: Vec<Box<dyn YubiKeyDevice>>,
    serial: Option<u32>,
) -> Result<Box<dyn YubiKeyDevice>, CliError> {
    match (serial, devices.len()) {
        (None, 0) => {
            #[cfg(feature = "hardware")]
            {
                let (scan_pids, _) = scan_usb_devices();
                if !scan_pids.is_empty() {
                    return Err(CliError(
                        "A YubiKey was detected, but FIDO access on Windows requires \
                         running as Administrator."
                            .into(),
                    ));
                }
            }
            Err(CliError("No YubiKey detected!".into()))
        }
        (None, 1) => Ok(devices.into_iter().next().unwrap()),
        (None, n) => {
            let mut msg = format!("Multiple YubiKeys detected ({n}):");
            for dev in &devices {
                msg.push_str(&format!("\n- {}", list::describe_device(dev.as_ref())));
            }
            msg.push_str("\nUse --device SERIAL to specify which one to use.");
            Err(CliError(msg))
        }
        (Some(s), _) => devices
            .into_iter()
            .find(|d| d.info().serial == Some(s))
            .ok_or_else(|| CliError(format!("YubiKey with serial {s} not found."))),
    }
}

pub fn get_device(serial: Option<u32>) -> Result<Box<dyn YubiKeyDevice>, CliError> {
    let mut source = ykman::device::get_device_source();
    let devices = source
        .list_devices()
        .map_err(|e| CliError(format!("Failed to list devices: {e}")))?;
    select_device(devices, serial)
}

pub fn check_capability(dev: &dyn YubiKeyDevice, capability: Capability) -> Result<(), CliError> {
    let info = dev.info();
    let transport = dev.transport();
    let name = capability_name(capability);

    let supported = info
        .supported_capabilities
        .get(&transport)
        .copied()
        .unwrap_or(Capability::NONE);

    if !supported.contains(capability) {
        return Err(CliError(format!(
            "{name} is not available on this YubiKey."
        )));
    }

    let enabled = info
        .config
        .enabled_capabilities
        .get(&transport)
        .copied()
        .unwrap_or(Capability::NONE);

    if !enabled.contains(capability) {
        let transport_name = match transport {
            Transport::Usb => "USB",
            Transport::Nfc => "NFC",
        };
        return Err(CliError(format!(
            "{name} is currently disabled on this YubiKey over {transport_name}.\n\n\
             Use 'ykman config {transport}' to enable it.",
            transport = transport_name.to_lowercase()
        )));
    }

    Ok(())
}

fn capability_name(cap: Capability) -> &'static str {
    if cap == Capability::OATH {
        "OATH"
    } else if cap == Capability::PIV {
        "PIV"
    } else if cap == Capability::OPENPGP {
        "OpenPGP"
    } else if cap == Capability::OTP {
        "OTP"
    } else if cap == Capability::HSMAUTH {
        "YubiHSM Auth"
    } else {
        "Application"
    }
}

pub fn check_version(
    dev: &dyn YubiKeyDevice,
    required: Version,
    feature: &str,
) -> Result<(), CliError> {
    let version = dev.info().version;
    if version < required {
        Err(CliError(format!(
            "{feature} requires YubiKey {required} or later (this device has {version}).",
        )))
    } else {
        Ok(())
    }
}

fn check_scp_version(dev: &dyn YubiKeyDevice, scp: &ScpParams) -> Result<(), CliError> {
    if scp.scp03_keys.is_some() {
        check_version(dev, Version(5, 3, 0), "SCP03")?;
    }
    if scp.scp11_private_key.is_some()
        || !scp.scp11_certificates.is_empty()
        || scp.sd_ref.is_some()
        || scp.oce_ref.is_some()
        || scp.ca_cert.is_some()
    {
        check_version(dev, Version(5, 7, 2), "SCP11")?;
    }
    Ok(())
}

fn apply_version_override(dev: &dyn YubiKeyDevice) {
    let info = dev.info();
    if info.version_qualifier.release_type != ReleaseType::Final {
        set_override_version(info.version_qualifier.version);
    }
}
