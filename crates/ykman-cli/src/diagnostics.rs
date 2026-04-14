//! Diagnostics data collection for YubiKey Manager.
//!
//! Provides a `run_diagnostics()` function that probes all connected YubiKeys
//! across all transports and returns a serializable report.

use std::collections::BTreeMap;

use serde::Serialize;

use yubikit::core::Connection;
use yubikit::core::Transport;
use yubikit::device::{get_name, list_readers, read_info_ccid, read_info_fido, read_info_otp};
use yubikit::management::{Capability, DeviceInfo, ReleaseType};
use yubikit::transport::ctaphid::{HidFidoConnection, list_fido_devices};
use yubikit::transport::otphid::{HidOtpConnection, list_otp_devices};
use yubikit::transport::pcsc::{PcscSmartCardConnection, is_reader_usb};

use yubikit::yubiotp::YubiOtpSession;

use yubikit::ctap::CtapSession;
use yubikit::ctap2::{ClientPin, Ctap2Session};

/// A value that is either a successful result or an error message.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ResultOrError<T: Serialize> {
    Ok(T),
    Err(String),
}

impl<T: Serialize> From<Result<T, String>> for ResultOrError<T> {
    fn from(r: Result<T, String>) -> Self {
        match r {
            Ok(v) => ResultOrError::Ok(v),
            Err(e) => ResultOrError::Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level report
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DiagnosticsReport {
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub pcsc: ResultOrError<PcscDiag>,
    pub otp: ResultOrError<BTreeMap<String, OtpDeviceDiag>>,
    pub fido: ResultOrError<BTreeMap<String, FidoDeviceDiag>>,
}

#[derive(Debug, Serialize)]
pub struct PcscDiag {
    pub readers: BTreeMap<String, String>,
    pub yubikeys: BTreeMap<String, PcscDeviceDiag>,
}

// ---------------------------------------------------------------------------
// PC/SC
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PcscDeviceDiag {
    pub management: ResultOrError<ManagementDiag>,
    pub piv: ResultOrError<PivDiag>,
    pub oath: ResultOrError<OathDiag>,
    pub openpgp: ResultOrError<OpenPgpDiag>,
    pub hsmauth: ResultOrError<HsmAuthDiag>,
}

// ---------------------------------------------------------------------------
// HID OTP
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct OtpDeviceDiag {
    pub management: ResultOrError<ManagementDiag>,
    pub otp: ResultOrError<OtpConfigDiag>,
}

#[derive(Debug, Serialize)]
pub struct OtpConfigDiag {
    pub slot1_configured: Option<bool>,
    pub slot2_configured: Option<bool>,
    pub slot1_touch_triggered: Option<bool>,
    pub slot2_touch_triggered: Option<bool>,
    pub led_inverted: bool,
}

// ---------------------------------------------------------------------------
// HID FIDO
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct FidoDeviceDiag {
    pub ctap_version: String,
    pub capabilities: u8,
    pub ctap2: ResultOrError<Ctap2Diag>,
    pub management: ResultOrError<ManagementDiag>,
}

#[derive(Debug, Serialize)]
pub struct Ctap2Diag {
    pub info: Ctap2InfoDiag,
    pub pin: ResultOrError<PinStatusDiag>,
}

#[derive(Debug, Serialize)]
pub struct PinStatusDiag {
    pub configured: bool,
    pub retries: Option<u32>,
    pub power_cycle: Option<u32>,
    pub bio_enroll: Option<BioEnrollDiag>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum BioEnrollDiag {
    Configured { uv_retries: u32 },
    NotConfigured,
}

// ---------------------------------------------------------------------------
// Shared sub-structs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ManagementDiag {
    pub name: String,
    pub device_info: DeviceInfoDiag,
}

#[derive(Debug, Serialize)]
pub struct DeviceInfoDiag {
    pub serial: Option<u32>,
    pub version: String,
    pub form_factor: String,
    pub supported_capabilities: BTreeMap<String, CapabilityDiag>,
    pub config: DeviceConfigDiag,
    pub is_locked: bool,
    pub is_fips: bool,
    pub is_sky: bool,
    pub part_number: Option<String>,
    pub fips_capable: CapabilityDiag,
    pub fips_approved: CapabilityDiag,
    pub pin_complexity: bool,
    pub reset_blocked: CapabilityDiag,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_qualifier: Option<VersionQualifierDiag>,
}

#[derive(Debug, Serialize)]
pub struct DeviceConfigDiag {
    pub enabled_capabilities: BTreeMap<String, CapabilityDiag>,
    pub auto_eject_timeout: u16,
    pub challenge_response_timeout: u8,
    pub device_flags: u8,
    pub nfc_restricted: bool,
}

#[derive(Debug)]
pub struct CapabilityDiag {
    pub names: Vec<String>,
    pub value: u16,
}

impl Serialize for CapabilityDiag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = if self.names.is_empty() {
            format!("0x{:x}", self.value)
        } else {
            format!("{}: 0x{:x}", self.names.join("|"), self.value)
        };
        serializer.serialize_str(&s)
    }
}

#[derive(Debug, Serialize)]
pub struct VersionQualifierDiag {
    pub version: String,
    pub release_type: String,
    pub iteration: u8,
}

// ---------------------------------------------------------------------------
// Session diagnostics
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PivDiag {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_tries: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub puk_tries: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_key_algorithm: Option<String>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ccc: Option<String>,
    pub slots: BTreeMap<String, PivSlotDiag>,
}

#[derive(Debug, Serialize)]
pub struct PivSlotDiag {
    pub key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OathDiag {
    pub version: String,
    pub password_protected: bool,
}

#[derive(Debug, Serialize)]
pub struct OpenPgpDiag {
    pub openpgp_version: String,
    pub application_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_tries: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_code_tries: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_pin_tries: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_pin_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct HsmAuthDiag {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_key_retries: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Ctap2InfoDiag {
    pub versions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    pub aaguid: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, bool>,
    pub max_msg_size: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pin_uv_auth_protocols: Vec<u32>,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub max_creds_in_list: usize,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub max_cred_id_length: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
    #[serde(skip_serializing_if = "is_four")]
    pub min_pin_length: usize,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub firmware_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_disc_creds: Option<u32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub force_pin_change: bool,
}

fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_four(v: &usize) -> bool {
    *v == 4
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn cap_diag(cap: Capability) -> CapabilityDiag {
    let all: &[(Capability, &str)] = &[
        (Capability::OTP, "OTP"),
        (Capability::U2F, "U2F"),
        (Capability::FIDO2, "FIDO2"),
        (Capability::OATH, "OATH"),
        (Capability::PIV, "PIV"),
        (Capability::OPENPGP, "OPENPGP"),
        (Capability::HSMAUTH, "HSMAUTH"),
    ];
    let names: Vec<String> = all
        .iter()
        .filter(|(c, _)| cap.contains(*c))
        .map(|(_, n)| n.to_string())
        .collect();
    CapabilityDiag {
        names,
        value: cap.0,
    }
}

fn transport_name(t: Transport) -> &'static str {
    match t {
        Transport::Usb => "USB",
        Transport::Nfc => "NFC",
    }
}

fn caps_map(
    caps: &std::collections::HashMap<Transport, Capability>,
) -> BTreeMap<String, CapabilityDiag> {
    caps.iter()
        .map(|(t, c)| (transport_name(*t).to_string(), cap_diag(*c)))
        .collect()
}

fn device_info_diag(info: &DeviceInfo) -> DeviceInfoDiag {
    let vq = if info.version_qualifier.release_type != ReleaseType::Final {
        Some(VersionQualifierDiag {
            version: info.version_qualifier.version.to_string(),
            release_type: format!("{}", info.version_qualifier.release_type),
            iteration: info.version_qualifier.iteration,
        })
    } else {
        None
    };

    DeviceInfoDiag {
        serial: info.serial,
        version: info.version.to_string(),
        form_factor: format!("{}", info.form_factor),
        supported_capabilities: caps_map(&info.supported_capabilities),
        config: DeviceConfigDiag {
            enabled_capabilities: caps_map(&info.config.enabled_capabilities),
            auto_eject_timeout: info.config.auto_eject_timeout.unwrap_or(0),
            challenge_response_timeout: info.config.challenge_response_timeout.unwrap_or(0),
            device_flags: info.config.device_flags.map(|f| f.0).unwrap_or(0),
            nfc_restricted: info.config.nfc_restricted == Some(true),
        },
        is_locked: info.is_locked,
        is_fips: info.is_fips,
        is_sky: info.is_sky,
        part_number: info.part_number.clone(),
        fips_capable: cap_diag(info.fips_capable),
        fips_approved: cap_diag(info.fips_approved),
        pin_complexity: info.pin_complexity,
        reset_blocked: cap_diag(info.reset_blocked),
        version_qualifier: vq,
    }
}

fn management_diag(info: &DeviceInfo) -> ManagementDiag {
    ManagementDiag {
        name: get_name(info),
        device_info: device_info_diag(info),
    }
}

fn ctap2_info_diag(info: &yubikit::ctap2::Info) -> Ctap2InfoDiag {
    Ctap2InfoDiag {
        versions: info.versions.clone(),
        extensions: info.extensions.clone(),
        aaguid: info.aaguid.to_string(),
        options: info.options.clone(),
        max_msg_size: info.max_msg_size,
        pin_uv_auth_protocols: info.pin_uv_protocols.clone(),
        max_creds_in_list: info.max_creds_in_list.unwrap_or(0),
        max_cred_id_length: info.max_cred_id_length.unwrap_or(0),
        transports: info.transports.clone(),
        min_pin_length: info.min_pin_length,
        firmware_version: info.firmware_version.unwrap_or(0),
        remaining_disc_creds: info.remaining_disc_creds,
        force_pin_change: info.force_pin_change,
    }
}

// ---------------------------------------------------------------------------
// Probing functions
// ---------------------------------------------------------------------------

fn probe_piv(conn: PcscSmartCardConnection) -> (ResultOrError<PivDiag>, PcscSmartCardConnection) {
    match yubikit::piv::PivSession::new(conn) {
        Ok(mut session) => {
            let version = session.version().to_string();
            let pin_tries = session
                .get_pin_metadata()
                .ok()
                .map(|m| format!("{}/{}", m.attempts_remaining, m.total_attempts));
            let puk_tries = session
                .get_puk_metadata()
                .ok()
                .map(|m| format!("{}/{}", m.attempts_remaining, m.total_attempts));
            let mgmt_algo = session
                .get_management_key_metadata()
                .ok()
                .map(|m| format!("{}", m.key_type));

            let mut warnings = Vec::new();
            if let Ok(meta) = session.get_pin_metadata()
                && meta.default_value
            {
                warnings.push("Using default PIN!".to_string());
            }
            if let Ok(meta) = session.get_puk_metadata()
                && meta.default_value
            {
                warnings.push("Using default PUK!".to_string());
            }
            if let Ok(meta) = session.get_management_key_metadata()
                && meta.default_value
            {
                warnings.push("Using default Management key!".to_string());
            }

            use yubikit::piv::{ObjectId, Slot};
            let chuid = session
                .get_object(ObjectId::Chuid)
                .ok()
                .map(|d| hex::encode(&d));
            let ccc = session
                .get_object(ObjectId::Capability)
                .ok()
                .map(|d| hex::encode(&d));

            let slot_specs = [
                (Slot::Authentication, "9A", "AUTHENTICATION"),
                (Slot::Signature, "9C", "DIGITAL SIGNATURE"),
                (Slot::KeyManagement, "9D", "KEY MANAGEMENT"),
                (Slot::CardAuth, "9E", "CARD AUTH"),
            ];
            let mut slots = BTreeMap::new();
            for (slot, hex_id, name) in slot_specs {
                if let Ok(meta) = session.get_slot_metadata(slot) {
                    let fingerprint = session.get_certificate(slot).ok().map(|cert_bytes| {
                        use sha2::{Digest, Sha256};
                        let fp = Sha256::digest(&cert_bytes);
                        hex::encode(fp)
                    });
                    slots.insert(
                        format!("{hex_id} ({name})"),
                        PivSlotDiag {
                            key_type: format!("{}", meta.key_type),
                            fingerprint,
                        },
                    );
                }
            }

            let conn = session.into_connection();
            (
                ResultOrError::Ok(PivDiag {
                    version,
                    pin_tries,
                    puk_tries,
                    management_key_algorithm: mgmt_algo,
                    warnings,
                    chuid,
                    ccc,
                    slots,
                }),
                conn,
            )
        }
        Err((e, conn)) => (ResultOrError::Err(format!("{e}")), conn),
    }
}

fn probe_oath(conn: PcscSmartCardConnection) -> (ResultOrError<OathDiag>, PcscSmartCardConnection) {
    match yubikit::oath::OathSession::new(conn) {
        Ok(session) => {
            let diag = OathDiag {
                version: session.version().to_string(),
                password_protected: session.locked(),
            };
            (ResultOrError::Ok(diag), session.into_connection())
        }
        Err((e, conn)) => (ResultOrError::Err(format!("{e}")), conn),
    }
}

fn probe_openpgp(
    conn: PcscSmartCardConnection,
) -> (ResultOrError<OpenPgpDiag>, PcscSmartCardConnection) {
    match yubikit::openpgp::OpenPgpSession::new(conn) {
        Ok(mut session) => {
            let aid_ver = session.aid().version();
            let openpgp_version = format!("{}.{}", aid_ver.0, aid_ver.1);
            let application_version = session.version().to_string();

            let (pin_tries, reset_code_tries, admin_pin_tries, sig_policy) =
                match session.get_pin_status() {
                    Ok(pw) => {
                        let policy = match pw.pin_policy_user {
                            yubikit::openpgp::PinPolicy::Once => "Once",
                            yubikit::openpgp::PinPolicy::Always => "Always",
                        };
                        (
                            Some(pw.attempts_user),
                            Some(pw.attempts_reset),
                            Some(pw.attempts_admin),
                            Some(policy.to_string()),
                        )
                    }
                    Err(_) => (None, None, None, None),
                };

            let kdf_enabled = session
                .get_kdf()
                .ok()
                .map(|kdf| !matches!(kdf, yubikit::openpgp::Kdf::None));

            let conn = session.into_connection();
            (
                ResultOrError::Ok(OpenPgpDiag {
                    openpgp_version,
                    application_version,
                    pin_tries,
                    reset_code_tries,
                    admin_pin_tries,
                    signature_pin_policy: sig_policy,
                    kdf_enabled,
                }),
                conn,
            )
        }
        Err((e, conn)) => (ResultOrError::Err(format!("{e}")), conn),
    }
}

fn probe_hsmauth(
    conn: PcscSmartCardConnection,
) -> (ResultOrError<HsmAuthDiag>, PcscSmartCardConnection) {
    match yubikit::hsmauth::HsmAuthSession::new(conn) {
        Ok(mut session) => {
            let version = session.version().to_string();
            let retries = session
                .get_management_key_retries()
                .ok()
                .map(|r| format!("{r}/8"));
            // HsmAuthSession doesn't have into_connection, just drop it
            // We need to get the connection back somehow
            let conn = session.into_connection();
            (
                ResultOrError::Ok(HsmAuthDiag {
                    version,
                    management_key_retries: retries,
                }),
                conn,
            )
        }
        Err((e, conn)) => (ResultOrError::Err(format!("{e}")), conn),
    }
}

fn probe_ctap2_pin<C: Connection + 'static>(
    ctap2: Ctap2Session<C>,
) -> (ResultOrError<PinStatusDiag>, Ctap2Session<C>) {
    let info = ctap2.info().clone();
    if info.options.get("clientPin") != Some(&true) {
        return (
            ResultOrError::Ok(PinStatusDiag {
                configured: false,
                retries: None,
                power_cycle: None,
                bio_enroll: None,
            }),
            ctap2,
        );
    }

    let bio_enroll_option = info.options.get("bioEnroll").copied();

    match ClientPin::new(ctap2) {
        Ok(mut client_pin) => {
            let (retries, power_cycle) = client_pin.get_pin_retries().unwrap_or((0, None));

            let bio_enroll = match bio_enroll_option {
                Some(true) => Some(
                    client_pin
                        .get_uv_retries()
                        .map(|r| BioEnrollDiag::Configured { uv_retries: r })
                        .unwrap_or(BioEnrollDiag::NotConfigured),
                ),
                Some(false) => Some(BioEnrollDiag::NotConfigured),
                _ => None,
            };

            let ctap2 = client_pin.into_session();
            (
                ResultOrError::Ok(PinStatusDiag {
                    configured: true,
                    retries: Some(retries),
                    power_cycle,
                    bio_enroll,
                }),
                ctap2,
            )
        }
        Err((e, ctap2)) => (
            ResultOrError::Err(format!("ClientPin::new failed: {e}")),
            ctap2,
        ),
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

fn device_key_pcsc(reader: &str) -> String {
    let transport = if is_reader_usb(reader) { "USB" } else { "NFC" };
    format!("CCID ({reader}, [{transport}])")
}

fn device_key_otp(pid: u16, path: &str) -> String {
    format!("OTP (pid={pid:04x}, path={path})")
}

fn device_key_fido(pid: u16, path: &str) -> String {
    format!("FIDO (pid={pid:04x}, path={path})")
}

fn probe_pcsc() -> ResultOrError<PcscDiag> {
    match list_readers() {
        Ok(readers) => {
            // Test all readers for connectivity
            let mut reader_status = BTreeMap::new();
            for reader in &readers {
                let status = match PcscSmartCardConnection::new(reader, false) {
                    Ok(conn) => {
                        drop(conn);
                        "Success".to_string()
                    }
                    Err(e) => format!("{e}"),
                };
                reader_status.insert(reader.clone(), status);
            }

            // Collect readers with a YubiKey present, caching NFC read results
            let yubikey_readers: Vec<(&String, Option<DeviceInfo>)> = readers
                .iter()
                .filter_map(|r| {
                    if is_reader_usb(r) {
                        return Some((r, None));
                    }
                    let conn = PcscSmartCardConnection::new(r, false).ok()?;
                    let (info, _) = read_info_ccid(conn).ok()?;
                    Some((r, Some(info)))
                })
                .collect();

            let mut yubikeys = BTreeMap::new();
            for (reader, cached_info) in &yubikey_readers {
                let key = device_key_pcsc(reader);

                let conn = match PcscSmartCardConnection::new(reader, false) {
                    Ok(c) => c,
                    Err(e) => {
                        yubikeys.insert(
                            key,
                            PcscDeviceDiag {
                                management: ResultOrError::Err(format!(
                                    "Error opening connection: {e}"
                                )),
                                piv: ResultOrError::Err("skipped".to_string()),
                                oath: ResultOrError::Err("skipped".to_string()),
                                openpgp: ResultOrError::Err("skipped".to_string()),
                                hsmauth: ResultOrError::Err("skipped".to_string()),
                            },
                        );
                        continue;
                    }
                };

                let (mgmt, conn) = if let Some(info) = cached_info {
                    (ResultOrError::Ok(management_diag(info)), conn)
                } else {
                    match read_info_ccid(conn) {
                        Ok((info, c)) => (ResultOrError::Ok(management_diag(&info)), c),
                        Err(e) => {
                            let mgmt = ResultOrError::Err(format!("{e}"));
                            match PcscSmartCardConnection::new(reader, false) {
                                Ok(c) => (mgmt, c),
                                Err(_) => {
                                    yubikeys.insert(
                                        key,
                                        PcscDeviceDiag {
                                            management: mgmt,
                                            piv: ResultOrError::Err("skipped".to_string()),
                                            oath: ResultOrError::Err("skipped".to_string()),
                                            openpgp: ResultOrError::Err("skipped".to_string()),
                                            hsmauth: ResultOrError::Err("skipped".to_string()),
                                        },
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                };

                let (piv, conn) = probe_piv(conn);
                let (oath, conn) = probe_oath(conn);
                let (openpgp, conn) = probe_openpgp(conn);
                let (hsmauth, _conn) = probe_hsmauth(conn);

                yubikeys.insert(
                    key,
                    PcscDeviceDiag {
                        management: mgmt,
                        piv,
                        oath,
                        openpgp,
                        hsmauth,
                    },
                );
            }
            ResultOrError::Ok(PcscDiag {
                readers: reader_status,
                yubikeys,
            })
        }
        Err(e) => ResultOrError::Err(format!("{e}")),
    }
}

fn probe_otp() -> ResultOrError<BTreeMap<String, OtpDeviceDiag>> {
    match list_otp_devices() {
        Ok(hid_devices) => {
            let mut devices = BTreeMap::new();
            for hid in &hid_devices {
                let key = device_key_otp(hid.pid, &hid.path);

                let conn = match HidOtpConnection::new(&hid.path) {
                    Ok(c) => c,
                    Err(e) => {
                        devices.insert(
                            key,
                            OtpDeviceDiag {
                                management: ResultOrError::Err(format!(
                                    "Error opening connection: {e}"
                                )),
                                otp: ResultOrError::Err("skipped".to_string()),
                            },
                        );
                        continue;
                    }
                };

                let (mgmt, conn) = match read_info_otp(conn) {
                    Ok((info, c)) => (ResultOrError::Ok(management_diag(&info)), c),
                    Err((e, conn_opt)) => {
                        let mgmt = ResultOrError::Err(format!("{e}"));
                        match conn_opt.or_else(|| HidOtpConnection::new(&hid.path).ok()) {
                            Some(c) => (mgmt, c),
                            None => {
                                devices.insert(
                                    key,
                                    OtpDeviceDiag {
                                        management: mgmt,
                                        otp: ResultOrError::Err("skipped".to_string()),
                                    },
                                );
                                continue;
                            }
                        }
                    }
                };

                let otp = match YubiOtpSession::new_otp(conn) {
                    Ok(session) => {
                        let state = session.get_config_state();
                        ResultOrError::Ok(OtpConfigDiag {
                            slot1_configured: state.is_configured(yubikit::yubiotp::Slot::One).ok(),
                            slot2_configured: state.is_configured(yubikit::yubiotp::Slot::Two).ok(),
                            slot1_touch_triggered: state
                                .is_touch_triggered(yubikit::yubiotp::Slot::One)
                                .ok(),
                            slot2_touch_triggered: state
                                .is_touch_triggered(yubikit::yubiotp::Slot::Two)
                                .ok(),
                            led_inverted: state.is_led_inverted(),
                        })
                    }
                    Err((e, _)) => ResultOrError::Err(format!("{e}")),
                };

                devices.insert(
                    key,
                    OtpDeviceDiag {
                        management: mgmt,
                        otp,
                    },
                );
            }
            ResultOrError::Ok(devices)
        }
        Err(e) => ResultOrError::Err(format!("{e}")),
    }
}

fn probe_fido() -> ResultOrError<BTreeMap<String, FidoDeviceDiag>> {
    match list_fido_devices() {
        Ok(fido_devices) => {
            let mut devices = BTreeMap::new();
            for fido in &fido_devices {
                let key = device_key_fido(fido.pid, &fido.path);

                match HidFidoConnection::open(fido) {
                    Ok(conn) => {
                        let (v1, v2, v3) = conn.device_version();
                        let caps = conn.capabilities();

                        if caps.has_cbor() {
                            let (ctap2, mgmt) = match CtapSession::new_fido(conn) {
                                Ok(ctap) => match Ctap2Session::new(ctap) {
                                    Ok(ctap2) => {
                                        let info_diag = ctap2_info_diag(ctap2.info());
                                        let (pin, ctap2) = probe_ctap2_pin(ctap2);
                                        let ctap2_diag = ResultOrError::Ok(Ctap2Diag {
                                            info: info_diag,
                                            pin,
                                        });

                                        let conn = ctap2.into_session().into_connection();
                                        let mgmt = match read_info_fido(conn) {
                                            Ok((info, _)) => {
                                                ResultOrError::Ok(management_diag(&info))
                                            }
                                            Err((e, _)) => ResultOrError::Err(format!("{e}")),
                                        };
                                        (ctap2_diag, mgmt)
                                    }
                                    Err((e, _)) => (
                                        ResultOrError::Err(format!("{e}")),
                                        ResultOrError::Err(format!("{e}")),
                                    ),
                                },
                                Err((e, _)) => (
                                    ResultOrError::Err(format!("{e}")),
                                    ResultOrError::Err(format!("{e}")),
                                ),
                            };

                            devices.insert(
                                key,
                                FidoDeviceDiag {
                                    ctap_version: format!("{v1}.{v2}.{v3}"),
                                    capabilities: caps.raw(),
                                    ctap2,
                                    management: mgmt,
                                },
                            );
                        } else {
                            let mgmt = match read_info_fido(conn) {
                                Ok((info, _)) => ResultOrError::Ok(management_diag(&info)),
                                Err((e, _)) => ResultOrError::Err(format!("{e}")),
                            };

                            devices.insert(
                                key,
                                FidoDeviceDiag {
                                    ctap_version: format!("{v1}.{v2}.{v3}"),
                                    capabilities: caps.raw(),
                                    ctap2: ResultOrError::Err("No CBOR support".to_string()),
                                    management: mgmt,
                                },
                            );
                        }
                    }
                    Err(e) => {
                        devices.insert(
                            key,
                            FidoDeviceDiag {
                                ctap_version: "unknown".to_string(),
                                capabilities: 0,
                                ctap2: ResultOrError::Err(format!("{e}")),
                                management: ResultOrError::Err("skipped".to_string()),
                            },
                        );
                    }
                }
            }
            ResultOrError::Ok(devices)
        }
        Err(e) => ResultOrError::Err(format!("{e}")),
    }
}

/// Run full diagnostics across all transports and return a serializable report.
pub fn run_diagnostics() -> DiagnosticsReport {
    DiagnosticsReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        pcsc: probe_pcsc(),
        otp: probe_otp(),
        fido: probe_fido(),
    }
}
