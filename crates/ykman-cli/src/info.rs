use anyhow::Result;

use yubikit::core::Transport;
use yubikit::device::YubiKeyDevice;
use yubikit::management::Capability;

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
            Some(true) => "Restricted",
            _ => {
                if info
                    .config
                    .enabled_capabilities
                    .get(&Transport::Nfc)
                    .is_some_and(|c| !c.is_empty())
                {
                    "Enabled"
                } else {
                    "Disabled"
                }
            }
        };
        print_field("NFC transport", nfc_status);
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
        unicode,
    );

    print_storage_section(&info.version, unicode);

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
fn use_unicode() -> bool {
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

/// Glyphs for the enabled/disabled application dots. In colour mode, both
/// are filled since green/red alone conveys the state; without colour, shape
/// carries the distinction instead (filled vs. hollow dot).
fn dot_glyphs(color_on: bool) -> (&'static str, &'static str) {
    if color_on {
        ("\u{25cf}", "\u{25cf}")
    } else {
        ("\u{25cf}", "\u{25cb}")
    }
}

/// Column width for each USB/NFC status cell in the two-transport
/// applications table, including its right-padding. ASCII mode spells out
/// `Enabled`/`Disabled` (matching the original table), so it needs a wider
/// column than the single-character dot used in Unicode mode.
const APP_NAME_WIDTH: usize = 20;
const APP_COL_WIDTH_UNICODE: usize = 6;
const APP_COL_WIDTH_ASCII: usize = 10;

fn app_col_width(unicode: bool) -> usize {
    if unicode {
        APP_COL_WIDTH_UNICODE
    } else {
        APP_COL_WIDTH_ASCII
    }
}

fn print_applications(
    supported: &std::collections::HashMap<Transport, Capability>,
    enabled: &std::collections::HashMap<Transport, Capability>,
    unicode: bool,
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
        // FIDO_CCID is an interface flag, not a user-facing application.
        .filter(|&cap| cap != Capability::FIDOCCID)
        .filter(|&cap| usb_supported.contains(cap) || nfc_supported.contains(cap))
        .collect();

    // Always show a USB column (and an NFC column when the key supports it)
    // with the heading on the same row as the column labels, for
    // consistency between USB-only and NFC-capable keys.
    let col_width = app_col_width(unicode);
    let header = if has_nfc {
        format!(
            "{:<APP_NAME_WIDTH$}{:>col_width$}{:>col_width$}",
            "APPLICATIONS", "USB", "NFC"
        )
    } else {
        format!("{:<APP_NAME_WIDTH$}{:>col_width$}", "APPLICATIONS", "USB")
    };
    println!("{}", color::dim(&header));
    for cap in apps {
        let name = color::bright(&format!("{:<APP_NAME_WIDTH$}", cap.display_name()));
        let usb_cell = dot_cell(
            usb_supported.contains(cap),
            usb_enabled.contains(cap),
            unicode,
        );
        if has_nfc {
            let nfc_cell = dot_cell(
                nfc_supported.contains(cap),
                nfc_enabled.contains(cap),
                unicode,
            );
            println!("{name}{usb_cell}{nfc_cell}");
        } else {
            println!("{name}{usb_cell}");
        }
    }
}

/// Render one USB/NFC status cell: a dim placeholder (`\u{2013}`/`-`) when the
/// capability isn't available on that transport at all, otherwise the
/// enabled/disabled state for that transport. In Unicode mode this is a
/// single coloured dot; in ASCII mode it spells out `Enabled`/`Disabled`,
/// matching the original table.
fn dot_cell(available: bool, is_enabled: bool, unicode: bool) -> String {
    let col_width = app_col_width(unicode);
    if !available {
        let dash = if unicode { "\u{2013}" } else { "-" };
        let pad = " ".repeat(col_width - dash.chars().count());
        return format!("{pad}{}", color::muted(dash));
    }
    if unicode {
        let (dot_enabled, dot_disabled) = dot_glyphs(color::enabled());
        let glyph = if is_enabled {
            color::green(dot_enabled)
        } else {
            color::red(dot_disabled)
        };
        let pad = " ".repeat(col_width - 1);
        format!("{pad}{glyph}")
    } else {
        let (text, colored) = if is_enabled {
            ("Enabled", color::green("Enabled"))
        } else {
            ("Disabled", color::red("Disabled"))
        };
        let pad = " ".repeat(col_width.saturating_sub(text.len()));
        format!("{pad}{colored}")
    }
}

struct StorageApp {
    name: &'static str,
    used_bytes: u64,
    objects: u32,
    object_label: &'static str,
    color: color::Swatch,
}

/// Static placeholder storage data. Firmware 6.x devices use a single
/// dynamic pool with no fixed per-application capacities; there is no API
/// yet to read real usage, so these figures are for UI purposes only.
fn fake_storage() -> (u64, Vec<StorageApp>) {
    let total_bytes = 61440u64; // 60.0 KB
    let apps = vec![
        StorageApp {
            name: "FIDO2",
            used_bytes: 24576,
            objects: 18,
            object_label: "passkeys",
            color: color::Swatch::Red,
        },
        StorageApp {
            name: "PIV",
            used_bytes: 9626,
            objects: 5,
            object_label: "certificates",
            color: color::Swatch::Yellow,
        },
        StorageApp {
            name: "OATH",
            used_bytes: 3994,
            objects: 24,
            object_label: "accounts",
            color: color::Swatch::Green,
        },
        StorageApp {
            name: "OpenPGP",
            used_bytes: 922,
            objects: 3,
            object_label: "keys",
            color: color::Swatch::Blue,
        },
        StorageApp {
            name: "YubiHSM Auth",
            used_bytes: 204,
            objects: 2,
            object_label: "credentials",
            color: color::Swatch::Magenta,
        },
    ];
    (total_bytes, apps)
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

/// Minimum firmware version exposing the STORAGE section.
const MIN_STORAGE_VERSION: yubikit::core::Version = yubikit::core::Version(6, 0, 0);

fn print_storage_section(version: &yubikit::core::Version, unicode: bool) {
    if *version < MIN_STORAGE_VERSION {
        // Storage reporting isn't available on older firmware (and an
        // unknown/uncertain version reads as 0.0.0, which also fails this
        // check, so we don't show placeholder data for it either).
        return;
    }

    let (total_bytes, apps) = fake_storage();
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
    for app in apps {
        if app.used_bytes == 0 {
            continue;
        }
        let marker = color::swatch(block, app.color);
        let name = color::dim(&format!("{:<16}", app.name));
        let size = color::bright(&format!("{:>12}", fmt_kb(app.used_bytes)));
        let pct = color::dim(&format!("{:>7}", pct_str(app.used_bytes, total_bytes)));
        let count = color::dim(&format!("{} {}", app.objects, app.object_label));
        println!("{marker} {name}{size}{pct}   {count}");
    }
    // The free segment keeps a muted colour to visually recede behind the
    // used applications, both in the bar and its legend swatch.
    let marker = color::muted(block);
    let name = color::dim(&format!("{:<16}", "free"));
    let size = color::bright(&format!("{:>12}", fmt_kb(free_bytes)));
    let pct = color::dim(&format!("{:>7}", pct_str(free_bytes, total_bytes)));
    println!("{marker} {name}{size}{pct}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_glyphs_are_filled_for_both_states_when_color_on() {
        assert_eq!(dot_glyphs(true), ("\u{25cf}", "\u{25cf}"));
    }

    #[test]
    fn dot_glyphs_distinguish_state_by_shape_when_color_off() {
        assert_eq!(dot_glyphs(false), ("\u{25cf}", "\u{25cb}"));
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
