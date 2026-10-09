use anyhow::Result;

use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::{Capability, ManagementSession, StorageInfo, StorageStatsEntry};

use crate::color;
use crate::util::print_table;

/// Width of the label column for the device block and the Used:/Free: lines.
const LABEL_WIDTH: usize = 24;
/// Width of the storage usage bar, in cells.
const BAR_WIDTH: usize = 52;

pub fn run(dev: &dyn YubiKeyDevice, check_fips: bool) -> Result<()> {
    let info = dev.info();
    let unicode = use_unicode();

    print_field("Device type", &dev.name());
    if let Some(serial) = info.serial {
        print_field("Serial number", &serial.to_string());
    }
    if info.version != yubikit::core::Version(0, 0, 0) {
        print_field("Firmware version", &info.version_name());
    } else {
        print_field(
            "Firmware version",
            "Uncertain, re-run with only one YubiKey connected",
        );
    }
    if info.form_factor != yubikit::management::FormFactor::Unknown {
        print_field("Form factor", &info.form_factor.to_string());
    }

    // Show USB interfaces only when connected via USB
    let is_usb = dev.transport() == Transport::Usb;
    if is_usb {
        let usb_ifaces = dev.usb_interfaces();
        if usb_ifaces.0 != 0 {
            print_field("Enabled USB interfaces", &usb_ifaces.to_string());
        }
    }

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
    print_applications(
        &info.supported_capabilities,
        &info.config.enabled_capabilities,
        info.fips_capable,
        info.fips_approved,
    );

    print_storage_section(dev, &info.version, unicode);

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

/// Whether the terminal is expected to support UTF-8 block characters. Falls
/// back to plain ASCII (`#`/`-`) when the locale doesn't advertise UTF-8.
pub(crate) fn use_unicode() -> bool {
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(val) = std::env::var(var)
            && !val.is_empty()
        {
            let upper = val.to_uppercase();
            return upper.contains("UTF-8") || upper.contains("UTF8");
        }
    }
    // No locale information available (e.g. Windows): assume UTF-8 capable.
    cfg!(windows)
}

fn print_field(label: &str, value: &str) {
    let prefix = pad_label(label);
    let value = color::bright(value);
    println!("{prefix}{value}");
}

/// Render a subtly dimmed `label:` padded to [`LABEL_WIDTH`], ready to be
/// followed directly by a value.
fn pad_label(label: &str) -> String {
    let plain_label = format!("{label}:");
    let pad = LABEL_WIDTH.saturating_sub(plain_label.len().min(LABEL_WIDTH));
    format!("{}{}", color::dim(&plain_label), " ".repeat(pad))
}

/// Width of the application name column, matching [`LABEL_WIDTH`] so the
/// APPLICATIONS section lines up with the device details above it.
const APP_NAME_WIDTH: usize = LABEL_WIDTH;
/// Column width for each USB/NFC status cell in the two-transport
/// applications table (including its right-padding), wide enough for the
/// spelled-out `Enabled`/`Disabled`/`Not available` status text.
const APP_COL_WIDTH: usize = 15;

fn print_applications(
    supported: &std::collections::HashMap<Transport, Capability>,
    enabled: &std::collections::HashMap<Transport, Capability>,
    fips_capable: Capability,
    fips_approved: Capability,
) {
    let usb_supported = supported
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);
    let usb_enabled = enabled
        .get(&Transport::Usb)
        .copied()
        .unwrap_or(Capability::NONE);
    let nfc_supported_opt = supported.get(&Transport::Nfc).copied();
    let nfc_enabled = enabled
        .get(&Transport::Nfc)
        .copied()
        .unwrap_or(Capability::NONE);
    let nfc_supported = nfc_supported_opt.unwrap_or(Capability::NONE);
    let has_nfc = nfc_supported_opt.is_some();

    let apps: Vec<Capability> = Capability::ALL
        .iter()
        .copied()
        .filter(|&cap| usb_supported.contains(cap) || nfc_supported.contains(cap))
        .collect();

    // Left-align the USB/NFC columns, matching the label column above the
    // APPLICATIONS section ([`LABEL_WIDTH`]) so the whole screen lines up.
    let header = format!("{:<APP_NAME_WIDTH$}", "APPLICATIONS");
    let header = if has_nfc {
        format!("{header}{:<APP_COL_WIDTH$}{:<APP_COL_WIDTH$}", "USB", "NFC")
    } else {
        format!("{header}{:<APP_COL_WIDTH$}", "USB")
    };
    // FIPS devices get a third column with each application's approval.
    let show_fips = !fips_capable.is_empty();
    let header = if show_fips {
        format!("{header}{:<APP_COL_WIDTH$}", "FIPS")
    } else {
        header
    };
    println!("{}", header.trim_end());
    for cap in apps {
        let name = format!("{:<APP_NAME_WIDTH$}", cap.display_name());
        let usb_cell = usb_status_cell(cap, usb_supported.contains(cap), usb_enabled);
        let nfc_cell = if has_nfc {
            nfc_status_cell(cap, nfc_supported.contains(cap), nfc_enabled)
        } else {
            String::new()
        };
        let fips_cell = if show_fips {
            fips_status_cell(fips_capable.contains(cap), fips_approved.contains(cap))
        } else {
            String::new()
        };
        println!(
            "{}",
            format!("{name}{usb_cell}{nfc_cell}{fips_cell}").trim_end()
        );
    }
}

/// USB status text for one application row: `Enabled`/`Disabled` in the
/// general case; FIDO_CCID is a special-cased USB interface flag that's
/// `Inactive` when it's enabled but FIDO2 itself isn't (matching the
/// original table's vocabulary).
fn usb_status_cell(cap: Capability, available: bool, usb_enabled: Capability) -> String {
    let text = if !available {
        "Not available"
    } else if usb_enabled.contains(cap) {
        if cap == Capability::FIDOCCID && !usb_enabled.contains(Capability::FIDO2) {
            "Inactive"
        } else {
            "Enabled"
        }
    } else {
        "Disabled"
    };
    status_cell(text)
}

/// NFC status text for one application row: FIDO_CCID is a USB-only
/// interface flag, so it's always `N/A` over NFC regardless of support.
fn nfc_status_cell(cap: Capability, available: bool, nfc_enabled: Capability) -> String {
    let text = if cap == Capability::FIDOCCID {
        "N/A"
    } else if !available {
        "Not available"
    } else if nfc_enabled.contains(cap) {
        "Enabled"
    } else {
        "Disabled"
    };
    status_cell(text)
}

/// FIPS status text for one application row: `Yes`/`No` for applications
/// the device can run in a FIPS approved mode; anything else (e.g. Yubico
/// OTP, which has no FIPS status) is `Not available`.
fn fips_status_cell(capable: bool, approved: bool) -> String {
    let text = if !capable {
        "Not available"
    } else if approved {
        "Yes"
    } else {
        "No"
    };
    status_cell(text)
}

/// Left-align a status cell's text within [`APP_COL_WIDTH`]. Positive states
/// (`Enabled`, `Yes`) are bold; negative ones (`Disabled`, `No`,
/// `Not available`) stay plain so they recede.
fn status_cell(text: &str) -> String {
    let pad = " ".repeat(APP_COL_WIDTH.saturating_sub(text.len()));
    if matches!(text, "Enabled" | "Yes") {
        format!("{}{pad}", color::bright(text))
    } else {
        format!("{text}{pad}")
    }
}

struct StorageApp {
    /// Row label. For grouped rows (see `group`) this is just the child's
    /// own short label (e.g. "certificates", "keys"); the shared group
    /// name (e.g. "PIV") is printed separately as a header above them.
    name: &'static str,
    used_bytes: u64,
    objects: u32,
    object_label: &'static str,
    color: color::Swatch,
    /// If set, this row is a child of a named group (e.g. `Some("PIV")`
    /// for both the certificates and keys rows): the legend prints one
    /// combined header row for the group (summed bytes/objects across all
    /// its currently-visible children) followed by each child indented
    /// underneath, rather than showing this row as its own top-level
    /// entry.
    group: Option<&'static str>,
}

impl StorageApp {
    /// A row is worth showing if it has *any* footprint — either flash
    /// pages (`used_bytes`) or object/header slots (`objects`). These can
    /// be nonzero independently: an object small enough to fit inline in
    /// its header (reportedly under ~208 bytes) consumes an object slot
    /// but zero pages, so checking `used_bytes` alone would wrongly hide
    /// an app that's genuinely in use, just entirely inline.
    fn is_visible(&self) -> bool {
        self.used_bytes > 0 || self.objects > 0
    }
}

/// Everything [`print_storage_section`] needs: the byte-level breakdown
/// (`apps`/`total_bytes`), plus the separate "object slots" (headrar)
/// capacity. Pages and object slots are two independent finite resources:
/// an object always needs one free slot *and* enough free pages, so a
/// device can be effectively full (no free slots) while still showing free
/// page space, or vice versa. `total_objects`/`free_objects` let the UI
/// respect the slot limit as its own tracked parameter, not just a detail
/// folded into the free-space byte count.
struct StorageSummary {
    total_bytes: u64,
    apps: Vec<StorageApp>,
    total_objects: u32,
    free_objects: u32,
}

/// Bytes per storage page. Every object rounds up to a whole number of
/// pages, e.g. an object using 600 bytes still occupies 768 bytes (3
/// pages) of the pool.
const PAGE_SIZE: u64 = 256;

/// Object-type id reported by the Management application's dedicated
/// `GET STORAGE INFO` command (`00 30 00 00`, instruction `0x30`). Id 0 is
/// always "free space"; the rest are assigned per application as new ones
/// gain reporting support.
const ID_FREE: u8 = 0x00;
const ID_PIV_OBJECTS: u8 = 0x01;
const ID_PIV_KEYS: u8 = 0x02;
const ID_OPENPGP_KEYS: u8 = 0x03;
const ID_FIDO_CREDENTIALS: u8 = 0x04;
const ID_OATH: u8 = 0x05;

/// A single decoded storage-stats entry: how many objects of this type are
/// stored, and how many pages they occupy in total. Widened to `u32` from
/// the SDK's [`StorageStatsEntry`] (`u16` fields, since a single id's
/// count/pages always fits in 16 bits) to match [`StorageApp`]/
/// [`StorageSummary`]'s totals, which can exceed that once summed.
#[derive(Default, Clone, Copy)]
struct StatsEntry {
    objects: u32,
    pages: u32,
}

impl From<StorageStatsEntry> for StatsEntry {
    fn from(e: StorageStatsEntry) -> Self {
        Self {
            objects: e.objects as u32,
            pages: e.pages as u32,
        }
    }
}

// Simulated response, captured from a real YubiKey 6 while the dedicated
// `GET STORAGE INFO` management command was under development. Used as a
// local fallback for demoing/visual verification (`YKMAN_FAKE_STORAGE=1`)
// until an alpha key with real storage reporting is available.
//
// Layout: a single TLV — 1-byte tag (`0x01`), 1-byte length, then payload:
// a run of 5-byte records, each `id (1 byte) | objects (u16 BE) | pages
// (u16 BE)`. This used to be tag `0x1C` nested inside the larger
// `GET DEVICE INFO` response (hence the extra wrapping seen in the two
// older samples below); now that it's its own command, the response is
// just this one TLV with no outer length byte or sibling tags to skip.
//
// Lighter-usage sample (mostly empty FIDO2, no PIV objects yet, plenty of
// free object slots and page space), kept here for later re-use. Captured
// while this was still nested under DeviceInfo tag `0x1C`:
// const SAMPLE_STORAGE_INFO_RESPONSE: &[u8] = &[
//     0x1D, 0x1B, 0x00, 0x1C, 0x19, 0x00, 0x00, 0x8D, 0x01, 0x9C, 0x01, 0x00, 0x00, 0x00, 0x00,
//     0x02, 0x00, 0x01, 0x00, 0x08, 0x03, 0x00, 0x04, 0x00, 0x20, 0x04, 0x00, 0x0E, 0x00, 0x1C,
// ];

// Heavier-usage sample (154 FIDO2 passkeys). Also a useful edge case: 0
// free *objects* (headrar) but 129 free *pages* (sidor) remain — all
// object slots exhausted even though raw page space is not, exactly the
// scenario the "Objects" line below is meant to surface. Also captured
// while still nested under DeviceInfo tag `0x1C`, kept here for later
// re-use:
// const SAMPLE_STORAGE_INFO_RESPONSE: &[u8] = &[
//     0x1D, 0x1B, 0x00, 0x1C, 0x19, 0x00, 0x00, 0x00, 0x00, 0x81, 0x01, 0x00, 0x01, 0x00, 0x03,
//     0x02, 0x00, 0x01, 0x00, 0x08, 0x03, 0x00, 0x04, 0x00, 0x20, 0x04, 0x00, 0x9A, 0x01, 0x34,
// ];

/// Current sample: first capture from the new, standalone `GET STORAGE
/// INFO` command. Same six real-world totals as the previous two samples
/// underneath (480 pages / 120 KB, 160 object slots) — same physical
/// device, different snapshot in time — plus the first appearance of id
/// `0x05`, reserved for OATH ahead of it actually reporting any usage yet.
const SAMPLE_STORAGE_INFO_RESPONSE: &[u8] = &[
    0x01, 0x1E, 0x00, 0x00, 0x91, 0x01, 0x95, 0x01, 0x00, 0x02, 0x00, 0x07, 0x02, 0x00, 0x03, 0x00,
    0x18, 0x03, 0x00, 0x04, 0x00, 0x20, 0x04, 0x00, 0x06, 0x00, 0x0C, 0x05, 0x00, 0x00, 0x00, 0x00,
];

/// Builds the STORAGE section's data from a decoded [`StorageInfo`] —
/// either read live from a device over CCID (see
/// [`read_device_storage_info`]), or the captured
/// [`SAMPLE_STORAGE_INFO_RESPONSE`] when demoing without a storage-capable
/// key (see [`sample_storage_info`]). Total and free space are derived
/// from the data itself (free pages plus every used id's pages) rather
/// than a fixed constant, since capacity is expected to grow as more
/// object types gain reporting support. Ids with no reporting support yet
/// (YubiHSM Auth) are left at zero usage, which keeps them out of the
/// bar/legend until a real id exists for them.
fn storage_summary_from_info(info: &StorageInfo) -> StorageSummary {
    let entry = |id: u8| info.entry(id).map(StatsEntry::from).unwrap_or_default();
    let bytes_of = |e: StatsEntry| e.pages as u64 * PAGE_SIZE;

    let piv_objects = entry(ID_PIV_OBJECTS);
    let piv_keys = entry(ID_PIV_KEYS);
    let openpgp = entry(ID_OPENPGP_KEYS);
    let fido = entry(ID_FIDO_CREDENTIALS);
    let oath = entry(ID_OATH);
    let free = entry(ID_FREE);

    // Any id in the blob that this client doesn't recognise yet (e.g. a
    // future app type added by newer firmware than this build knows about)
    // is folded into a single "Other" bucket instead of silently vanishing
    // from the totals. This keeps `total_bytes`/`total_objects` correct
    // even when parsing data from firmware newer than this client.
    const KNOWN_IDS: &[u8] = &[
        ID_FREE,
        ID_PIV_OBJECTS,
        ID_PIV_KEYS,
        ID_OPENPGP_KEYS,
        ID_FIDO_CREDENTIALS,
        ID_OATH,
    ];
    let other = info
        .entries
        .iter()
        .filter(|e| !KNOWN_IDS.contains(&e.id))
        .map(|&e| StatsEntry::from(e))
        .fold(StatsEntry::default(), |acc, e| StatsEntry {
            objects: acc.objects + e.objects,
            pages: acc.pages + e.pages,
        });

    let apps = vec![
        StorageApp {
            name: "FIDO2",
            used_bytes: bytes_of(fido),
            objects: fido.objects,
            object_label: "passkeys",
            color: color::Swatch::Red,
            group: None,
        },
        // PIV objects (certificates etc.) and PIV keys are reported as two
        // separate ids; shown here as two child rows sharing both a colour
        // (so the bar still reads as one seamless "PIV" block — adjacent
        // same-coloured segments have no visible seam) and a group header
        // (printed in the legend as a combined "PIV" row above them).
        StorageApp {
            name: "certificates",
            used_bytes: bytes_of(piv_objects),
            objects: piv_objects.objects,
            object_label: "certificates",
            color: color::Swatch::Yellow,
            group: Some("PIV"),
        },
        StorageApp {
            name: "keys",
            used_bytes: bytes_of(piv_keys),
            objects: piv_keys.objects,
            object_label: "keys",
            color: color::Swatch::Yellow,
            group: Some("PIV"),
        },
        StorageApp {
            name: "OATH",
            used_bytes: bytes_of(oath),
            objects: oath.objects,
            object_label: "accounts",
            color: color::Swatch::Green,
            group: None,
        },
        StorageApp {
            name: "OpenPGP",
            used_bytes: bytes_of(openpgp),
            objects: openpgp.objects,
            object_label: "keys",
            color: color::Swatch::Blue,
            group: None,
        },
        // YubiHSM Auth reporting isn't implemented yet either; same as OATH.
        StorageApp {
            name: "YubiHSM Auth",
            used_bytes: 0,
            objects: 0,
            object_label: "credentials",
            color: color::Swatch::Magenta,
            group: None,
        },
        // Catches ids this client build doesn't know about yet; stays
        // hidden (like OATH/YubiHSM Auth above) unless the device actually
        // reports an unrecognised id with nonzero usage.
        StorageApp {
            name: "Other",
            used_bytes: bytes_of(other),
            objects: other.objects,
            object_label: "objects",
            color: color::Swatch::Cyan,
            group: None,
        },
    ];

    let used_bytes: u64 = apps.iter().map(|a| a.used_bytes).sum();
    let total_bytes = bytes_of(free) + used_bytes;
    // Object-slot capacity is derived the same way as byte capacity: free
    // slots plus every used id's slots. Every sample seen so far puts this
    // at a fixed 160 regardless of how pages are distributed, consistent
    // with it being a separate, flash-independent limit.
    let used_objects: u32 = apps.iter().map(|a| a.objects).sum();
    let total_objects = free.objects + used_objects;

    StorageSummary {
        total_bytes,
        apps,
        total_objects,
        free_objects: free.objects,
    }
}

/// Decodes the captured [`SAMPLE_STORAGE_INFO_RESPONSE`] for local
/// demoing/visual verification without a storage-capable key. Only used
/// when `YKMAN_FAKE_STORAGE` is set (see [`print_storage_section`]); the
/// sample bytes are a known-good capture, so a parse failure here would
/// indicate a bug in this build rather than bad device data.
fn sample_storage_info() -> StorageSummary {
    let info =
        StorageInfo::parse(SAMPLE_STORAGE_INFO_RESPONSE).expect("sample storage data is valid");
    storage_summary_from_info(&info)
}

/// Reads storage stats from the connected key over CCID (the only
/// transport storage reporting supports so far). Returns `None` on any
/// failure — e.g. firmware without storage support, or no smartcard
/// interface available — in which case the STORAGE section is simply
/// omitted, same as it's always been for keys predating this feature.
fn read_device_storage_info(dev: &dyn YubiKeyDevice) -> Option<StorageInfo> {
    let conn = dev.open_smartcard().ok()?;
    let mut session = ManagementSession::new(conn).ok()?;
    session.read_storage_info().ok()
}

fn fmt_kb(bytes: u64) -> String {
    if bytes == 0 {
        "0 B".to_string()
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
}

/// Percentage of `total`, rounded to an integer; values below 0.5% but above
/// zero print as `<1%` rather than rounding down to `0%`.
fn pct_str(bytes: u64, total: u64) -> String {
    if total == 0 {
        return "0%".to_string();
    }
    let p = bytes as f64 / total as f64 * 100.0;
    if p > 0.0 && p < 0.5 {
        "<1%".to_string()
    } else {
        format!("{}%", p.round() as i64)
    }
}

/// Rounds each value's share of `total` to a whole percentage using the
/// largest-remainder method, so the printed rows always sum to exactly
/// 100% — unlike rounding each row independently with [`pct_str`], which
/// can drift a point or two off (e.g. `48% + 31% + 21% = 100%` rounding to
/// `48% + 31% + 22%` in isolation). A value that rounds down to `0%` but is
/// still nonzero prints as `<1%`, same as `pct_str`.
fn allocate_percentages(values: &[u64], total: u64) -> Vec<String> {
    if total == 0 || values.is_empty() {
        return values.iter().map(|_| "0%".to_string()).collect();
    }
    let exacts: Vec<f64> = values
        .iter()
        .map(|&v| v as f64 / total as f64 * 100.0)
        .collect();
    let floors: Vec<i64> = exacts.iter().map(|e| e.floor() as i64).collect();
    let base_sum: i64 = floors.iter().sum();
    let remaining = (100 - base_sum).clamp(0, values.len() as i64) as usize;

    let mut by_remainder: Vec<usize> = (0..values.len()).collect();
    by_remainder.sort_by(|&a, &b| {
        let ra = exacts[a] - floors[a] as f64;
        let rb = exacts[b] - floors[b] as f64;
        rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut finals = floors;
    for &idx in by_remainder.iter().take(remaining) {
        finals[idx] += 1;
    }

    finals
        .iter()
        .zip(exacts.iter())
        .map(|(&f, &e)| {
            if f == 0 && e > 0.0 {
                "<1%".to_string()
            } else {
                format!("{f}%")
            }
        })
        .collect()
}

/// Minimum firmware version expected to expose the STORAGE section once
/// alpha-key version reporting is confirmed and this can be gated
/// up-front rather than relying solely on `read_storage_info()` failing.
/// Currently unused: no version check is applied yet (still exercised by
/// `storage_requires_firmware_6_0_0_or_above`), since it's unclear what
/// alpha firmware reports for its version. Failing the real
/// `GET STORAGE INFO` read already hides the section for keys that don't
/// support it, so this isn't needed for correctness yet.
#[allow(dead_code)]
const MIN_STORAGE_VERSION: yubikit::core::Version = yubikit::core::Version(6, 0, 0);

/// Set to demo the STORAGE section with the captured sample dataset
/// instead of attempting a real read — useful until an alpha key with
/// storage support is in hand.
const FAKE_STORAGE_ENV_VAR: &str = "YKMAN_FAKE_STORAGE";

fn print_storage_section(
    dev: &dyn YubiKeyDevice,
    _version: &yubikit::core::Version,
    unicode: bool,
) {
    let info = if std::env::var_os(FAKE_STORAGE_ENV_VAR).is_some() {
        Some(sample_storage_info())
    } else {
        read_device_storage_info(dev).map(|info| storage_summary_from_info(&info))
    };
    let Some(StorageSummary {
        total_bytes,
        apps,
        total_objects,
        free_objects,
    }) = info
    else {
        // No storage data available — e.g. firmware predating this
        // feature, or a non-CCID transport. Nothing to show, same as
        // it's always been for these keys.
        return;
    };
    let used_bytes: u64 = apps.iter().map(|a| a.used_bytes).sum();
    let free_bytes = total_bytes - used_bytes;
    let used_pct = used_bytes as f64 / total_bytes as f64 * 100.0;

    println!();
    println!("{}", color::dim("STORAGE"));

    let used_text = format!(
        "{} of {}  ({})",
        fmt_kb(used_bytes),
        fmt_kb(total_bytes),
        pct_str(used_bytes, total_bytes)
    );
    let used_line = if used_pct >= 95.0 {
        color::red(&used_text)
    } else if used_pct >= 80.0 {
        color::yellow(&used_text)
    } else {
        color::bright(&used_text)
    };
    println!("{}{used_line}", pad_label("Used"));
    println!(
        "{}{}",
        pad_label("Free"),
        color::bright(&fmt_kb(free_bytes))
    );

    // Object slots (headrar) are a separate, finite resource from page
    // space: every object needs both a free slot *and* enough free pages,
    // so the device can be effectively full on slots alone even while
    // `free_bytes` above still shows room. Always shown (not just when
    // critical) so this limit stays a visible, respected parameter rather
    // than hidden inside the byte total.
    let used_objects = total_objects - free_objects;
    let objects_pct = used_objects as f64 / total_objects.max(1) as f64 * 100.0;
    let objects_text = format!(
        "{used_objects} of {total_objects}  ({})",
        pct_str(used_objects as u64, total_objects as u64)
    );
    let objects_line = if free_objects == 0 {
        color::red(&objects_text)
    } else if objects_pct >= 80.0 {
        color::yellow(&objects_text)
    } else {
        color::bright(&objects_text)
    };
    println!("{}{objects_line}", pad_label("Objects"));
    println!();

    // Narrow terminals (< 60 columns): drop the bar, keep the text.
    let wide_enough = terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize >= 60)
        .unwrap_or(true);
    if wide_enough {
        print_bar(&apps, total_bytes, free_bytes, unicode);
        println!();
    }
    print_legend(&apps, total_bytes, free_bytes, unicode);
}

fn print_bar(apps: &[StorageApp], total_bytes: u64, free_bytes: u64, unicode: bool) {
    let (used_ch, free_ch) = if unicode {
        ("\u{2588}", "\u{2591}")
    } else {
        ("#", "-")
    };

    let mut used_cells = 0usize;
    let mut bar = String::new();
    for app in apps {
        // An app can be `is_visible()` (has object slots) while still
        // having zero bytes (fully inline in its header, no pages used) —
        // nothing to draw here since the bar represents byte/page usage,
        // but it still gets a legend row below.
        if app.used_bytes == 0 {
            continue;
        }
        let raw = app.used_bytes as f64 / total_bytes as f64 * BAR_WIDTH as f64;
        let mut cells = raw.round() as usize;
        if cells == 0 {
            cells = 1;
        }
        used_cells += cells;
        bar.push_str(&color::swatch(&used_ch.repeat(cells), app.color));
    }
    let free_cells = BAR_WIDTH.saturating_sub(used_cells);
    if free_bytes > 0 {
        bar.push_str(&color::muted(&free_ch.repeat(free_cells)));
    }
    println!("{bar}");
}

fn print_legend(apps: &[StorageApp], total_bytes: u64, free_bytes: u64, unicode: bool) {
    let block = if unicode { "\u{2588}" } else { "#" };

    // Percentages are allocated together across every visible leaf row
    // plus the trailing "free" row via the largest-remainder method,
    // rather than rounding each row in isolation with `pct_str`, so they
    // always add up to exactly 100% instead of occasionally drifting to
    // 99% or 101%. Group header rows (below) are a combined view of their
    // own children's bytes, so they're deliberately left out of this pool
    // and given their own independently-rounded percentage instead —
    // otherwise the same bytes would be counted twice towards 100%.
    let visible_bytes: Vec<u64> = apps
        .iter()
        .filter(|a| a.is_visible())
        .map(|a| a.used_bytes)
        .chain(std::iter::once(free_bytes))
        .collect();
    let mut percentages = allocate_percentages(&visible_bytes, total_bytes).into_iter();

    // Tracks which group headers (e.g. "PIV") have already been printed,
    // so the first visible child of a group prints a combined header row
    // above it, and later children of the same group don't repeat it.
    let mut printed_groups: std::collections::HashSet<&'static str> =
        std::collections::HashSet::new();
    for app in apps {
        if !app.is_visible() {
            continue;
        }
        let marker = color::swatch(block, app.color);

        if let Some(group) = app.group {
            if printed_groups.insert(group) {
                let (group_bytes, group_objects) = apps
                    .iter()
                    .filter(|a| a.is_visible() && a.group == Some(group))
                    .fold((0u64, 0u32), |(bytes, objects), a| {
                        (bytes + a.used_bytes, objects + a.objects)
                    });
                let name = color::dim(&format!("{:<16}", group));
                let size = color::bright(&format!("{:>12}", fmt_kb(group_bytes)));
                let pct = color::dim(&format!("{:>7}", pct_str(group_bytes, total_bytes)));
                let count = color::dim(&format!("{group_objects} objects"));
                println!("{marker} {name}{size}{pct}   {count}");
            }
            // Children are indented one column under their group header.
            let name = color::dim(&format!("{:<16}", format!(" {}", app.name)));
            let size = color::bright(&format!("{:>12}", fmt_kb(app.used_bytes)));
            let pct_value = percentages.next().unwrap_or_default();
            let pct = color::dim(&format!("{:>7}", pct_value));
            let count = color::dim(&format!("{} {}", app.objects, app.object_label));
            println!("{marker} {name}{size}{pct}   {count}");
            continue;
        }

        let name = color::dim(&format!("{:<16}", app.name));
        let size = color::bright(&format!("{:>12}", fmt_kb(app.used_bytes)));
        let pct_value = percentages.next().unwrap_or_default();
        let pct = color::dim(&format!("{:>7}", pct_value));
        let count = color::dim(&format!("{} {}", app.objects, app.object_label));
        println!("{marker} {name}{size}{pct}   {count}");
    }
    // The free segment keeps a muted colour to visually recede behind the
    // used applications, both in the bar and its legend swatch.
    let marker = color::muted(block);
    let name = color::dim(&format!("{:<16}", "free"));
    let size = color::bright(&format!("{:>12}", fmt_kb(free_bytes)));
    let pct_value = percentages.next().unwrap_or_default();
    let pct = color::dim(&format!("{:>7}", pct_value));
    println!("{marker} {name}{size}{pct}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_status_marks_unsupported_transport_as_not_available() {
        assert!(
            usb_status_cell(Capability::PIV, false, Capability::NONE).contains("Not available")
        );
    }

    #[test]
    fn usb_status_spells_out_enabled_and_disabled() {
        assert!(usb_status_cell(Capability::PIV, true, Capability::PIV).contains("Enabled"));
        assert!(usb_status_cell(Capability::PIV, true, Capability::NONE).contains("Disabled"));
    }

    #[test]
    fn usb_status_marks_fido_ccid_inactive_when_fido2_is_disabled() {
        let enabled_without_fido2 = Capability::FIDOCCID;
        assert!(
            usb_status_cell(Capability::FIDOCCID, true, enabled_without_fido2).contains("Inactive")
        );
        let enabled_with_fido2 = Capability::FIDOCCID | Capability::FIDO2;
        assert!(
            usb_status_cell(Capability::FIDOCCID, true, enabled_with_fido2).contains("Enabled")
        );
    }

    #[test]
    fn nfc_status_marks_fido_ccid_as_not_applicable() {
        assert!(nfc_status_cell(Capability::FIDOCCID, false, Capability::NONE).contains("N/A"));
        assert!(nfc_status_cell(Capability::FIDOCCID, true, Capability::FIDOCCID).contains("N/A"));
    }

    #[test]
    fn storage_requires_firmware_6_0_0_or_above() {
        assert!(yubikit::core::Version(5, 7, 2) < MIN_STORAGE_VERSION);
        assert!(yubikit::core::Version(6, 0, 0) >= MIN_STORAGE_VERSION);
        assert!(yubikit::core::Version(6, 1, 0) >= MIN_STORAGE_VERSION);
        // An unknown/uncertain version reads as 0.0.0 and must also be
        // treated as unsupported.
        assert!(yubikit::core::Version(0, 0, 0) < MIN_STORAGE_VERSION);
    }
}
