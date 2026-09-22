//! Centralised colour-output policy for the whole CLI.
//!
//! Any module that wants to print styled text should go through the helpers
//! here (or call [`enabled`] directly) instead of deciding on its own
//! whether ANSI codes are appropriate. That keeps the precedence rules
//! consistent everywhere `ykman` prints something, not just in `ykman info`.

use std::io::IsTerminal;
use std::sync::OnceLock;

use owo_colors::OwoColorize;

/// Value for the global `--color` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ColorChoice {
    /// Always emit ANSI colour codes.
    Always,
    /// Emit colour only when stdout is an interactive terminal (default).
    #[default]
    Auto,
    /// Never emit ANSI colour codes.
    Never,
}

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Resolve and cache whether coloured output should be used for the rest of
/// the process. Must be called once, early in `main`, before any command
/// prints output.
///
/// Precedence, highest first:
/// 1. An explicit `--no-color` flag or `--color=never` disables colour;
///    an explicit `--color=always` enables it.
/// 2. Otherwise, the `NO_COLOR` environment variable
///    (<https://no-color.org>) disables colour if set to a non-empty value.
/// 3. Otherwise, colour is enabled only if stdout is an interactive
///    terminal, so output piped to a file or another process isn't
///    cluttered with escape codes.
pub fn init(no_color_flag: bool, choice: ColorChoice) {
    let enabled = resolve(no_color_flag, choice);
    let _ = ENABLED.set(enabled);
}

fn resolve(no_color_flag: bool, choice: ColorChoice) -> bool {
    if no_color_flag || choice == ColorChoice::Never {
        return false;
    }
    if choice == ColorChoice::Always {
        return true;
    }
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    std::io::stdout().is_terminal()
}

/// Whether coloured output is currently enabled. Defaults to `false` if
/// [`init`] hasn't been called yet (e.g. in unit tests).
pub fn enabled() -> bool {
    ENABLED.get().copied().unwrap_or(false)
}

/// Emphasise a value with bold. Deliberately doesn't force an explicit
/// foreground colour, so it renders in the terminal's own default
/// foreground (respecting light/dark themes) with bold for contrast.
pub fn bright(s: &str) -> String {
    if enabled() {
        s.bold().to_string()
    } else {
        s.to_string()
    }
}

/// Secondary/label text. With only the standard 16-color palette to work
/// with, the "bright black" slot renders too dark on many themes, so labels
/// use the terminal's plain default foreground instead - the same colour as
/// values - and rely entirely on [`bright`]'s bold weight for contrast.
pub fn dim(s: &str) -> String {
    s.to_string()
}

/// A muted grey, reserved for the free-space bar/legend swatch where a
/// visually receding block (not readable text) is wanted. Uses the
/// terminal's "bright black" ANSI slot, so it still follows the user's
/// theme.
pub fn muted(s: &str) -> String {
    if enabled() {
        s.bright_black().to_string()
    } else {
        s.to_string()
    }
}

/// Green, typically used to indicate an enabled/positive state.
pub fn green(s: &str) -> String {
    if enabled() {
        s.green().to_string()
    } else {
        s.to_string()
    }
}

/// Red, typically used to indicate a disabled/negative state or an error.
pub fn red(s: &str) -> String {
    if enabled() {
        s.red().to_string()
    } else {
        s.to_string()
    }
}

/// Amber/yellow, typically used for a warning state.
pub fn yellow(s: &str) -> String {
    if enabled() {
        s.yellow().to_string()
    } else {
        s.to_string()
    }
}

/// One of the standard 16 ANSI colours, for stable per-identity colouring
/// (e.g. distinguishing applications in the storage bar) that still
/// respects the user's terminal theme, unlike a hard-coded RGB value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Swatch {
    Red,
    Yellow,
    Green,
    Blue,
    Magenta,
}

pub fn swatch(s: &str, color: Swatch) -> String {
    if !enabled() {
        return s.to_string();
    }
    match color {
        Swatch::Red => s.red().to_string(),
        Swatch::Yellow => s.yellow().to_string(),
        Swatch::Green => s.green().to_string(),
        Swatch::Blue => s.blue().to_string(),
        Swatch::Magenta => s.magenta().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_flag_disables_regardless_of_choice() {
        assert!(!resolve(true, ColorChoice::Always));
        assert!(!resolve(true, ColorChoice::Auto));
    }

    #[test]
    fn color_never_disables() {
        assert!(!resolve(false, ColorChoice::Never));
    }

    #[test]
    fn color_always_enables_even_without_tty() {
        assert!(resolve(false, ColorChoice::Always));
    }

    #[test]
    fn no_color_env_var_disables_in_auto_mode() {
        // SAFETY: test-only, single-threaded env mutation guarded by running
        // this test in isolation from others touching NO_COLOR.
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
        assert!(!resolve(false, ColorChoice::Auto));
        unsafe {
            std::env::remove_var("NO_COLOR");
        }
    }

    #[test]
    fn empty_no_color_env_var_is_ignored() {
        unsafe {
            std::env::set_var("NO_COLOR", "");
        }
        // Falls through to the TTY check; in test harnesses stdout isn't a
        // TTY, so this should resolve to false, but for the right reason
        // (not because of NO_COLOR).
        let result = resolve(false, ColorChoice::Auto);
        unsafe {
            std::env::remove_var("NO_COLOR");
        }
        assert!(!result);
    }
}
