use clap::builder::styling::{Style, Styles};
use clap::{Arg, Command};

pub const STYLES: Styles = Styles::styled()
    .header(Style::new().bold())
    .usage(Style::new().bold())
    .literal(Style::new());

const SCP_OPTIONS: &[&str] = &["scp", "scp-ca", "scp-sd", "scp-oce", "scp-password"];
const ADDITIONAL_COMMANDS: &[&str] = &["apdu", "diagnose", "version", "licenses"];

pub fn configure(mut command: Command) -> Command {
    command = command.styles(STYLES);
    command.build();
    finalize(&mut command, true);
    command
}

fn section(output: &mut String, heading: &str, body: &str) {
    let body = body.trim_end();
    if body.is_empty() {
        return;
    }
    if !output.is_empty() {
        output.push_str("\n\n");
    }
    let style = STYLES.get_header();
    output.push_str(&format!(
        "{}{heading}{}\n{body}",
        style.render(),
        style.render_reset()
    ));
}

fn render(command: Command, template: &'static str) -> String {
    command
        .styles(STYLES)
        .help_template(template)
        .render_help()
        .ansi()
        .to_string()
}

fn arguments(command: &Command, template: &'static str, include: impl Fn(&Arg) -> bool) -> String {
    let mut view = Command::new("ykman")
        .version(env!("CARGO_PKG_VERSION"))
        .disable_help_flag(true)
        .disable_version_flag(true)
        .args(command.get_arguments().cloned())
        .groups(command.get_groups().cloned());
    let args: Vec<_> = command.get_arguments().cloned().collect();
    for arg in args {
        let hide = arg.is_hide_set() || !include(&arg);
        view = view.mut_arg(arg.get_id(), |arg| {
            if arg.get_long() == Some("help") {
                return arg.hide(hide).help("Print help");
            }
            // Keep detailed security notes even though -h and --help share a layout.
            let long_help = arg.get_long_help().cloned();
            let arg = arg.hide(hide);
            match long_help {
                Some(help) => arg.help(help),
                None => arg,
            }
        });
    }
    render(view, template)
}

fn commands(command: &Command, include: impl Fn(&Command) -> bool) -> String {
    let view = command.clone().mut_subcommands(|sub| {
        let hide = sub.is_hide_set() || sub.get_name() == "help" || !include(&sub);
        sub.hide(hide)
    });
    render(view, "{subcommands}")
}

fn is_scp(arg: &Arg) -> bool {
    arg.get_long()
        .is_some_and(|name| SCP_OPTIONS.contains(&name))
}

fn is_global(arg: &Arg) -> bool {
    arg.is_global_set() || matches!(arg.get_long(), Some("help" | "version"))
}

fn lowercase_placeholders(usage: &str) -> String {
    let mut output = String::with_capacity(usage.len());
    let mut rest = usage;
    while let Some(start) = rest.find(['[', '<']) {
        output.push_str(&rest[..=start]);
        rest = &rest[start + 1..];
        let end = rest.find(['[', '<', ']', '>']).unwrap_or(rest.len());
        let token = &rest[..end];
        if !token.starts_with('-')
            && token
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
        {
            output.push_str(&token.to_ascii_lowercase());
        } else {
            output.push_str(token);
        }
        rest = &rest[end..];
    }
    output.push_str(rest);
    output
}

fn finalize(command: &mut Command, root: bool) {
    // Render each section from filtered metadata, never by parsing clap's formatted rows.
    let mut output = command
        .get_long_about()
        .or_else(|| command.get_about())
        .map(|about| about.ansi().to_string())
        .unwrap_or_default();
    section(
        &mut output,
        "USAGE",
        &format!(
            "  {}",
            lowercase_placeholders(&render(command.clone(), "{usage}"))
        ),
    );
    section(
        &mut output,
        "ARGUMENTS",
        &arguments(command, "{positionals}", Arg::is_positional),
    );
    section(
        &mut output,
        "COMMANDS",
        &commands(command, |sub| {
            !root || !ADDITIONAL_COMMANDS.contains(&sub.get_name())
        }),
    );
    if root {
        section(
            &mut output,
            "ADDITIONAL COMMANDS",
            &commands(command, |sub| ADDITIONAL_COMMANDS.contains(&sub.get_name())),
        );
    }
    section(
        &mut output,
        "OPTIONS",
        &arguments(command, "{options}", |arg| {
            !arg.is_positional() && !is_global(arg) && !is_scp(arg)
        }),
    );
    section(
        &mut output,
        "SECURE CHANNEL OPTIONS",
        &arguments(command, "{options}", is_scp),
    );
    section(
        &mut output,
        "GLOBAL OPTIONS",
        &arguments(command, "{options}", |arg| {
            !arg.is_positional() && is_global(arg) && !is_scp(arg)
        }),
    );
    if let Some(after) = command.get_after_help() {
        let after = after.ansi().to_string();
        if let Some(examples) = after.strip_prefix("Examples:\n") {
            section(&mut output, "EXAMPLES", examples.trim_start_matches('\n'));
        } else if !after.is_empty() {
            output.push_str("\n\n");
            output.push_str(&after);
        }
    }
    if root {
        section(
            &mut output,
            "LEARN MORE",
            "  Run `ykman <command> --help` for details about a command.\n  Read the manual at https://docs.yubico.com/ykman",
        );
    }
    let taken = std::mem::take(command);
    *command = taken.override_help(output);
    for sub in command.get_subcommands_mut() {
        finalize(sub, false);
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, FromArgMatches};

    use super::{configure, lowercase_placeholders};
    use crate::{Cli, Commands};

    #[test]
    fn usage_only_lowercases_placeholders() {
        assert_eq!(
            lowercase_placeholders("ykman keys [OPTIONS] <PUBLIC-KEY> [<FILE>] [-P|--pin] [-P]"),
            "ykman keys [options] <public-key> [<file>] [-P|--pin] [-P]"
        );
    }

    #[test]
    fn presentation_preserves_command_grammar() {
        fn compare(before: &clap::Command, after: &clap::Command) {
            assert_eq!(before.get_name(), after.get_name());
            let before_args: Vec<_> = before.get_arguments().collect();
            let after_args: Vec<_> = after.get_arguments().collect();
            assert_eq!(before_args.len(), after_args.len());
            for (before, after) in before_args.into_iter().zip(after_args) {
                assert_eq!(format!("{before:?}"), format!("{after:?}"));
            }
            let before_subs: Vec<_> = before.get_subcommands().collect();
            let after_subs: Vec<_> = after.get_subcommands().collect();
            assert_eq!(before_subs.len(), after_subs.len());
            for (before, after) in before_subs.into_iter().zip(after_subs) {
                compare(before, after);
            }
        }
        let mut before = Cli::command();
        before.build();
        compare(&before, &configure(Cli::command()));
    }

    #[test]
    fn utility_commands_parse_without_a_device() {
        for (args, expected) in [
            (vec!["ykman", "diagnose"], "diagnose"),
            (vec!["ykman", "licenses"], "licenses"),
            (vec!["ykman", "version"], "version"),
            (vec!["ykman", "completion", "bash"], "completion"),
        ] {
            let matches = configure(Cli::command())
                .try_get_matches_from(args)
                .unwrap();
            assert_eq!(matches.subcommand_name(), Some(expected));
            let cli = Cli::from_arg_matches(&matches).unwrap();
            assert!(matches!(
                cli.command,
                Some(
                    Commands::Diagnose
                        | Commands::Licenses
                        | Commands::Version
                        | Commands::Completion { .. }
                )
            ));
        }
    }
}
