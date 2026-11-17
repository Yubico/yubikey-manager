//! Colour policy shared by storage output and clap's help/error output.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    Always,
    #[default]
    Auto,
    Never,
}

static ENABLED: OnceLock<bool> = OnceLock::new();

pub fn init(no_color: bool, choice: ColorChoice) {
    let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    let terminal = std::io::stdout().is_terminal()
        && std::env::var_os("TERM").is_none_or(|value| value != "dumb");
    let _ = ENABLED.set(resolve(no_color, choice, no_color_env, terminal));
}

fn resolve(no_color: bool, choice: ColorChoice, no_color_env: bool, terminal: bool) -> bool {
    !no_color
        && match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => !no_color_env && terminal,
        }
}

// Clap handles --help before the parsed Cli is available.
pub fn help_choice(args: impl IntoIterator<Item = OsString>) -> clap::ColorChoice {
    let mut choice = clap::ColorChoice::Auto;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let value = match arg.to_str() {
            Some("--") => break,
            Some("--no-color") => return clap::ColorChoice::Never,
            Some("--color") => args.next(),
            Some(arg) => arg.strip_prefix("--color=").map(OsString::from),
            None => None,
        };
        choice = match value.as_deref().and_then(|value| value.to_str()) {
            Some("always") => clap::ColorChoice::Always,
            Some("never") => clap::ColorChoice::Never,
            Some("auto") => clap::ColorChoice::Auto,
            _ => choice,
        };
    }
    choice
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Red,
    Yellow,
    Blue,
    Cyan,
    Muted,
}

fn style(text: &str, open: &str, close: &str) -> String {
    if ENABLED.get().copied().unwrap_or(false) {
        format!("\x1b[{open}m{text}\x1b[{close}m")
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str) -> String {
    style(text, "1", "22")
}

pub fn paint(text: &str, tone: Tone) -> String {
    let code = match tone {
        Tone::Red => "31",
        Tone::Yellow => "33",
        Tone::Blue => "34",
        Tone::Cyan => "36",
        Tone::Muted => "90",
    };
    style(text, code, "39")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_flags_override_environment_and_terminal() {
        for no_color_env in [false, true] {
            for terminal in [false, true] {
                assert!(resolve(false, ColorChoice::Always, no_color_env, terminal));
                assert!(!resolve(false, ColorChoice::Never, no_color_env, terminal));
                assert!(!resolve(true, ColorChoice::Always, no_color_env, terminal));
            }
        }
    }

    #[test]
    fn auto_requires_terminal_without_no_color() {
        for no_color_env in [false, true] {
            for terminal in [false, true] {
                assert_eq!(
                    resolve(false, ColorChoice::Auto, no_color_env, terminal),
                    !no_color_env && terminal
                );
            }
        }
    }

    #[test]
    fn help_honours_explicit_colour_and_end_of_options() {
        for (args, expected) in [
            (
                vec!["info", "--color=always", "--help"],
                clap::ColorChoice::Always,
            ),
            (
                vec!["--color", "never", "info", "--help"],
                clap::ColorChoice::Never,
            ),
            (
                vec!["info", "--no-color", "--help"],
                clap::ColorChoice::Never,
            ),
            (vec!["--", "--color=always"], clap::ColorChoice::Auto),
        ] {
            assert_eq!(help_choice(args.into_iter().map(OsString::from)), expected);
        }
    }
}
