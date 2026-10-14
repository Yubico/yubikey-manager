use super::*;

#[cfg(test)]
mod tests;

pub(super) const LEVELS: [(&str, &str); 5] = [
    ("error", "Only errors"),
    ("warning", "Warnings and errors"),
    ("info", "General progress information"),
    ("debug", "Detailed internals (default)"),
    (
        "traffic",
        "Everything, including raw APDU traffic (may contain secrets)",
    ),
];
/// Options the shell sets itself (or that make no sense in its UI).
pub(super) const SHELL_MANAGED_OPTS: [&str; 8] = [
    "color",
    "no-color",
    "log-level",
    "log-file",
    "device",
    "version",
    "licenses",
    "diagnose",
];
/// Commands handled by the shell itself (the first three wrap top-level flags).
pub(super) const BUILTINS: [(&str, &str); 17] = [
    ("diagnose", "Run system diagnostics"),
    ("licenses", "Show open source licenses"),
    ("version", "Show the ykman version"),
    (
        "batch",
        "Repeat a command or saved script on one YubiKey after another",
    ),
    ("record", "Record a sequence of commands, then run it"),
    (
        "export",
        "Export generated values as CSV: /export [copy|file]",
    ),
    ("csv", "Use a CSV file for variables: /csv <file>"),
    (
        "secrets",
        "Hide or show secrets in the summary and commands: /secrets [hide|show]",
    ),
    (
        "repeat",
        "Run a command several times: /repeat <n> <command…>",
    ),
    (
        "script",
        "Browse saved scripts, or /script save|run|list|delete",
    ),
    ("clear", "Clear the screen"),
    ("device", "Choose which YubiKey to use (also: ← key)"),
    (
        "copy",
        "Copy the last command (or all) to the clipboard: /copy [all]",
    ),
    (
        "save",
        "Save the last command (or all) to a file: /save [all] [file]",
    ),
    ("log", "Set the log level: /log [level]"),
    ("help", "Show keyboard shortcuts"),
    ("quit", "Exit shell"),
];

pub(super) fn is_builtin(word: &str) -> bool {
    matches!(word, "exit" | "scripts") || BUILTINS.iter().any(|(n, _)| *n == word)
}

/// The word currently being typed, without the leading `/` (empty if the
/// input ends in whitespace).
pub(super) fn current_partial(input: &str) -> &str {
    if input.ends_with(char::is_whitespace) {
        ""
    } else {
        let word = input.rsplit(char::is_whitespace).next().unwrap_or("");
        word.strip_prefix('/').unwrap_or(word)
    }
}

/// Minimal shell-like splitting: whitespace separated, with '...' and "..." quoting.
pub(super) fn split_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut has = false;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    args.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        args.push(cur);
    }
    args
}

/// Parses `ykman list` lines such as `YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 123`.
/// Uses the OS clipboard tool where there is one, else the OSC 52 escape,
/// which most modern terminals (including over SSH) honour.
pub(super) fn copy_to_clipboard(text: &str) -> std::result::Result<(), String> {
    let tool = if cfg!(target_os = "macos") {
        Some("pbcopy")
    } else if cfg!(windows) {
        Some("clip")
    } else {
        None
    };
    if let Some(tool) = tool {
        let child = std::process::Command::new(tool)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if child.wait().is_ok_and(|s| s.success()) {
                return Ok(());
            }
        }
    }
    use base64::Engine;
    if text.len() > 100_000 {
        return Err("too large for the terminal clipboard; use /save".to_string());
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(text);
    let mut out = std::io::stdout();
    write!(out, "\x1b]52;c;{b64}\x07")
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())
}

impl App {
    /// Walks the clap tree along the completed words, returning the deepest
    /// command reached and how many words were consumed.
    pub(super) fn resolve<'a>(&'a self, words: &[&str]) -> (&'a clap::Command, usize) {
        let mut node = &self.tree;
        let mut used = 0;
        for w in words {
            match node.get_subcommands().find(|s| s.get_name() == *w) {
                Some(s) => {
                    node = s;
                    used += 1;
                }
                None => break,
            }
        }
        (node, used)
    }

    pub(super) fn suggestions(&self) -> Vec<Suggestion> {
        let Some(rest) = self.input.buf.strip_prefix('/') else {
            return Vec::new();
        };
        if self.var_prompt().is_some() {
            return Vec::new();
        }
        if self.input.cursor != self.input.len() {
            return Vec::new();
        }
        let trailing_space = rest.ends_with(char::is_whitespace);
        let mut words: Vec<&str> = rest.split_whitespace().collect();
        let mut partial = if trailing_space {
            ""
        } else {
            words.pop().unwrap_or("")
        };
        // A fully typed command group lists its subcommands without waiting for a space.
        if !partial.is_empty()
            && !partial.starts_with('-')
            && !(words.is_empty() && is_builtin(partial))
        {
            let skip = usize::from(words.first() == Some(&"batch"));
            if !words
                .get(skip..)
                .is_some_and(|w| w.first().is_some_and(|f| is_builtin(f)))
            {
                let mut path = words[skip..].to_vec();
                path.push(partial);
                let (node, used) = self.resolve(&path);
                if used == path.len() && node.get_subcommands().any(|c| !c.is_hide_set()) {
                    words.push(partial);
                    partial = "";
                }
            }
        }
        let base = if words.is_empty() {
            "/".to_string()
        } else {
            format!("/{} ", words.join(" "))
        };
        let mut out = Vec::new();
        let mut add = |name: &str, desc: &str| {
            out.push(Suggestion {
                display: format!("{base}{name}"),
                name: name.to_string(),
                desc: desc.to_string(),
            });
        };

        // `${` completes variable names wherever a sequence will expand them.
        if let Some(at) = partial.rfind("${")
            && !partial[at..].contains('}')
        {
            let (before, typed) = (&partial[..at], &partial[at + 2..]);
            let in_repeat = words.first() == Some(&"repeat")
                || self
                    .recording
                    .as_ref()
                    .is_some_and(|r| r.iter().any(|s| s.first().is_some_and(|w| w == "repeat")));
            for (name, desc) in self.variable_suggestions(in_repeat) {
                if name.starts_with(typed) {
                    add(&format!("{before}${{{name}}}"), &desc);
                }
            }
            return out;
        }
        if words == ["copy"] && "all".starts_with(partial) {
            add("all", "The whole session, not just the last command");
            return out;
        }
        if words == ["secrets"] {
            for (name, desc) in [
                ("hide", "Mask secrets in the summary and echoed commands"),
                ("show", "Show secrets again"),
            ] {
                if name.starts_with(partial) {
                    add(name, desc);
                }
            }
            return out;
        }
        if words == ["csv"] {
            if "clear".starts_with(partial) {
                add("clear", "Detach the CSV file");
            }
            for (name, desc) in path_suggestions(partial, Some(&TABLE_EXTS)) {
                add(&name, &desc);
            }
            return out;
        }
        if words == ["export"] || words == ["save"] || words == ["save", "all"] {
            if words != ["save", "all"] && words[0] == "save" && "all".starts_with(partial) {
                add("all", "The whole session, not just the last command");
            }
            if words[0] == "export" && "copy".starts_with(partial) {
                add("copy", "Copy to the clipboard instead");
            }
            // The target is usually a new file, so only offer folders to browse.
            for (name, desc) in path_suggestions(partial, Some(&[])) {
                add(&name, &desc);
            }
            return out;
        }
        if words.first() == Some(&"script") {
            for (name, desc) in self.script_suggestions(&words, partial) {
                add(&name, &desc);
            }
            return out;
        }
        if words == ["help"] && "variables".starts_with(partial) {
            add("variables", "Variables for recorded sequences");
            return out;
        }
        if words == ["log"] {
            for (name, desc) in LEVELS {
                if name.starts_with(partial) {
                    add(name, desc);
                }
            }
            return out;
        }
        // After `/batch` the rest completes like a normal command.
        let off = match words.first() {
            Some(&"batch") => 1,
            Some(&"repeat") if words.len() >= 2 => 2,
            _ => 0,
        };
        if off == 1 && words.len() == 1 {
            if "stop".starts_with(partial) {
                add("stop", "End the batch and show a summary");
            }
            for (name, n, steps) in self.load_script_list() {
                if name.starts_with(partial) {
                    add(&name, &script_desc(n, &steps));
                }
            }
        }
        if off == 0 && words.first().is_some_and(|w| is_builtin(w)) {
            return out;
        }
        let words = &words[off..];
        let (node, used) = self.resolve(words);
        // An option that takes a value is waiting for it: offer the choices, if
        // there are any, instead of the other options.
        if used < words.len()
            && !partial.starts_with('-')
            && let Some(arg) = words.last().and_then(|t| value_option(node, t))
        {
            if is_file_arg(arg) {
                for (name, desc) in path_suggestions(partial, output_exts(arg)) {
                    add(&name, &desc);
                }
                return out;
            }
            for pv in arg.get_possible_values() {
                let name = pv.get_name();
                if !pv.is_hide_set() && name.starts_with(partial) {
                    add(
                        name,
                        &pv.get_help().map(|h| h.to_string()).unwrap_or_default(),
                    );
                }
            }
            return out;
        }
        if !partial.starts_with('-')
            && !node.has_subcommands()
            && let Some(arg) = next_positional(node, &words[used..]).filter(|a| is_file_arg(a))
        {
            for (name, desc) in path_suggestions(partial, output_exts(arg)) {
                add(&name, &desc);
            }
            return out;
        }
        if used < words.len() || partial.starts_with('-') {
            // SCP options apply to every command, so keep them after the specific ones.
            let mut args: Vec<&clap::Arg> = node.get_arguments().collect();
            args.sort_by_key(|a| a.get_long().is_some_and(|l| l.starts_with("scp")));
            let taken = used_options(node, &words[used..]);
            for arg in args {
                let Some(long) = arg
                    .get_long()
                    .filter(|l| !arg.is_hide_set() && !SHELL_MANAGED_OPTS.contains(l))
                else {
                    continue;
                };
                let name = format!("--{long}");
                let repeatable = matches!(arg.get_action(), clap::ArgAction::Append);
                let excluded = (!repeatable && taken.contains(&arg.get_id()))
                    || conflicts_with_used(node, arg, &taken);
                if name.starts_with(partial) && !excluded {
                    add(
                        &name,
                        &arg.get_help().map(|s| s.to_string()).unwrap_or_default(),
                    );
                }
            }
            return out;
        }
        let mut subs: Vec<&clap::Command> = node.get_subcommands().collect();
        if used == 0 {
            subs.sort_by_key(|c| c.get_name() != "info");
        }
        for sub in subs {
            let name = sub.get_name();
            if sub.is_hide_set() || name == "help" || !name.starts_with(partial) {
                continue;
            }
            if self.batch_mode {
                let mut path = words[..used].to_vec();
                path.push(name);
                if !self.batch_possible(&path) {
                    continue;
                }
            }
            add(
                name,
                &sub.get_about().map(|s| s.to_string()).unwrap_or_default(),
            );
        }
        if used == 0 && off == 0 {
            for (name, desc) in BUILTINS {
                if name.starts_with(partial) {
                    add(name, desc);
                }
            }
        }
        out
    }

    /// Variable names that can follow `${`, with a short description.
    fn variable_suggestions(&self, in_repeat: bool) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        if let Some(t) = &self.csv {
            for (i, h) in t.headers.iter().enumerate() {
                let first = t.rows.first().and_then(|r| r.get(i)).cloned();
                let eg = match first {
                    Some(_) if var_secret(h) => "e.g. ••••".to_string(),
                    Some(v) => format!("e.g. {v}"),
                    None => String::new(),
                };
                out.push((h.clone(), format!("CSV column {}", eg).trim().to_string()));
            }
        }
        let steps = self
            .recording
            .as_deref()
            .or(self.last_sequence.as_ref().map(|s| s.steps.as_slice()));
        for n in steps.map(custom_vars).unwrap_or_default() {
            if !out.iter().any(|o| o.0 == n) {
                out.push((n, "your variable".into()));
            }
        }
        let mut builtin = vec![
            ("serial", "serial number of the key"),
            ("version", "firmware version"),
            ("name", "product name"),
            ("round", "batch round number"),
            ("date", "today, YYYY-MM-DD"),
        ];
        if in_repeat {
            builtin.push(("i", "iteration number in /repeat"));
        }
        out.extend(builtin.into_iter().map(|(n, d)| (n.into(), d.into())));
        for (n, d) in [
            ("random", "random letters and digits (8)"),
            ("random:base32", "random OATH secret (32)"),
            ("random:hex", "random hex (32)"),
            ("random:digits", "random digits (6)"),
            ("random:alnum", "random letters and digits (8)"),
        ] {
            out.push((n.into(), d.into()));
        }
        out
    }

    /// Usage hint (positionals, option value) shown as ghost text after a command.
    pub(super) fn arg_hint(&self) -> Option<String> {
        let rest = self.input.buf.strip_prefix('/')?;
        if self.input.cursor != self.input.len() || !rest.ends_with(char::is_whitespace) {
            return None;
        }
        let mut words: Vec<&str> = rest.split_whitespace().collect();
        if words.first() == Some(&"batch") {
            words.remove(0);
        }
        // `/repeat <n> <command…>` hints like the command itself.
        if words.first() == Some(&"repeat") {
            words.drain(..words.len().min(2));
        }
        let first = words.first()?;
        if is_builtin(first) {
            return None;
        }
        let (node, used) = self.resolve(&words);
        let value_name = |a: &clap::Arg| {
            a.get_value_names()
                .and_then(|v| v.first())
                .map_or_else(|| a.get_id().as_str().to_uppercase(), |n| n.to_string())
        };
        if used < words.len() {
            let arg = value_option(node, words.last()?)?;
            return Some(format!("<{}>", value_name(arg)));
        }
        if node.has_subcommands() {
            return None;
        }
        let mut parts: Vec<String> = node
            .get_positionals()
            .map(|a| {
                if a.is_required_set() {
                    format!("<{}>", value_name(a))
                } else {
                    format!("[{}]", value_name(a))
                }
            })
            .collect();
        if node.get_arguments().any(|a| {
            a.get_long()
                .is_some_and(|l| !a.is_hide_set() && !SHELL_MANAGED_OPTS.contains(&l))
        }) {
            parts.push("[--options]".to_string());
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    // ---------- input ----------

    /// History as browsed with Up/Down. Batch mode shows only batch commands,
    /// without the `/batch` prefix that is implied there.
    pub(super) fn visible_history(&self) -> Vec<String> {
        if !self.batch_mode {
            return self.history.clone();
        }
        self.history
            .iter()
            .filter_map(|h| {
                if h.starts_with("/repeat ") {
                    return Some(h.clone());
                }
                h.strip_prefix("/batch ").map(|r| format!("/{}", r.trim()))
            })
            .filter(|h| h.len() > 1)
            .collect()
    }

    pub(super) fn history_step(&mut self, back: bool) {
        let history = self.visible_history();
        if history.is_empty() {
            return;
        }
        let pos = match (self.hist_pos, back) {
            (None, true) => Some(history.len() - 1),
            (Some(p), true) => Some(p.saturating_sub(1)),
            (Some(p), false) if p + 1 < history.len() => Some(p + 1),
            _ => None,
        };
        self.hist_pos = pos;
        let text = pos.map(|p| history[p].clone()).unwrap_or_default();
        self.input.set(text);
    }

    pub(super) fn accept(&mut self, s: &Suggestion) {
        // A folder keeps going; anything else is a finished word.
        let gap = if s.display.ends_with('/') { "" } else { " " };
        self.input.buf = format!("{}{gap}", s.display);
        self.input.cursor = self.input.len();
        self.sel = 0;
    }

    pub(super) fn submit(&mut self) {
        let line = self.input.take();
        self.sel = 0;
        self.hist_pos = None;
        if self.var_prompt().is_some() {
            self.var_answer(&line);
            return;
        }
        let Some(rest) = line.trim().strip_prefix('/') else {
            if !line.trim().is_empty() {
                self.note("Commands start with /. Type / to see what's available.");
            }
            return;
        };
        let mut args = split_args(rest);
        if args.is_empty() {
            return;
        }
        let plain = !is_builtin(&args[0]);
        let line = if self.batch_mode && plain {
            args.insert(0, "batch".to_string());
            format!("/batch {}", rest.trim())
        } else {
            line
        };
        if self.history.last().map(String::as_str) != Some(line.trim()) {
            self.history.push(line.trim().to_string());
        }
        self.persist_command(&args);
        if self.recording.is_some() && plain {
            let skip = usize::from(self.batch_mode);
            self.record_step(&args[skip..]);
            return;
        }
        // A command with ${variables} runs as a one-step sequence.
        if plain && !self.batch_mode && args.iter().any(|w| w.contains("${")) {
            self.repeat_command(&args);
            return;
        }
        match args[0].as_str() {
            "exit" if self.batch_mode => self.leave_batch_mode(),
            "quit" | "exit" => self.quit = true,
            "clear" => {
                self.entries.clear();
                self.toggled.clear();
                self.welcome = false;
                self.scroll = 0;
            }
            "device" => self.open_sidebar(),
            "scripts" => self.open_side(1),
            "help" => self.help(args.get(1).map(String::as_str)),
            "log" => self.set_log_level(args.get(1).map(String::as_str)),
            "copy" => self.copy_output(args.get(1).is_some_and(|a| a == "all")),
            "save" => self.save_output(&args[1..]),
            "record" => self.record_command(),
            "repeat" => self.repeat_command(&args),
            "script" if args.len() == 1 => self.open_side(1),
            "script" => self.script_command(&args[1..]),
            "csv" => self.csv_command(&args[1..]),
            "export" => self.export_command(&args[1..]),
            "secrets" => self.secrets_command(args.get(1).map(String::as_str)),
            "batch" if self.recording.is_some() => {
                self.note("Finish the recording first (Esc).");
            }
            "batch" if args.len() == 1 => self.enter_batch_mode(),
            "batch" => self.batch_command(&args[1..]),
            _ if self.batch.is_some() => {
                self.note("A batch or sequence is active. Use /batch stop to end it first.");
            }
            _ if self.running => self.note("A command is already running."),
            "version" | "licenses" | "diagnose" if args.len() == 1 => {
                let flag = vec![format!("--{}", args[0])];
                self.spawn(line.trim(), flag);
            }
            _ if self.hide_secrets => {
                let shown = masked_step(&args);
                self.spawn(&shown, args);
            }
            _ => self.spawn(line.trim(), args),
        }
    }

    /// `/secrets` shows the state, `/secrets hide|show` changes it.
    pub(super) fn secrets_command(&mut self, arg: Option<&str>) {
        match arg {
            Some("hide") => self.hide_secrets = true,
            Some("show") => self.hide_secrets = false,
            None => {}
            Some(_) => return self.note("usage: /secrets [hide|show]"),
        }
        let state = if self.hide_secrets { "hidden" } else { "shown" };
        self.note(&format!(
            "Secrets are {state} in the summary and in echoed commands (/export still includes them)."
        ));
    }

    /// Remember only the command path (never arguments, which may be secrets).
    pub(super) fn persist_command(&mut self, args: &[String]) {
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        let prefix = if words.first() == Some(&"batch") {
            "batch "
        } else {
            ""
        };
        let rest = &words[prefix.len().min(1)..];
        let repeat = words.first() == Some(&"repeat") && parse_repeat(args).is_ok();
        // `/repeat <n> <command path>`: the count is kept, the arguments are not.
        let rest = if repeat { &words[2..] } else { rest };
        let (node, used) = self.resolve(rest);
        let path = if repeat {
            if used == 0 {
                return;
            }
            format!("repeat {} {}", words[1], rest[..used].join(" "))
        } else if used > 0 {
            let mut path = rest[..used].join(" ");
            if !prefix.is_empty() {
                for tok in safe_batch_args(node, &rest[used..]) {
                    path.push(' ');
                    path.push_str(&tok);
                }
            }
            path
        } else if prefix.is_empty() && is_builtin(words[0]) && !matches!(words[0], "quit" | "exit")
        {
            words[0].to_string()
        } else {
            return;
        };
        let entry = format!("/{prefix}{path}");
        if self.saved.last() != Some(&entry) {
            self.saved.push(entry);
            let excess = self.saved.len().saturating_sub(200);
            self.saved.drain(..excess);
            self.save();
        }
    }

    /// Plain text of the current view for the last command (or the session).
    pub(super) fn export_text(&self, all: bool) -> String {
        let start = if all {
            0
        } else {
            self.entries
                .iter()
                .rposition(|e| e.kind == Kind::Cmd)
                .unwrap_or(0)
        };
        let (logs, out) = (self.tab != 0, self.tab != 2);
        let mut text = String::new();
        let mut push = |kind: Kind, t: &str| {
            let t = if matches!(kind, Kind::Out | Kind::Err) {
                strip_ansi(t)
            } else {
                t.to_string()
            };
            text.push_str(t.trim_end());
            text.push('\n');
        };
        let mut chunks: Vec<(Option<&Entry>, Vec<&Entry>, Vec<&Entry>)> =
            vec![(None, vec![], vec![])];
        for e in &self.entries[start..] {
            match e.kind {
                Kind::Cmd => chunks.push((Some(e), vec![], vec![])),
                Kind::Log => chunks.last_mut().expect("non-empty").1.push(e),
                _ => chunks.last_mut().expect("non-empty").2.push(e),
            }
        }
        for (cmd, log_lines, rest) in chunks {
            if let Some(c) = cmd {
                push(Kind::Cmd, &format!("$ {}", c.text));
            }
            if logs {
                for e in log_lines {
                    push(Kind::Log, &e.text);
                }
            }
            if out {
                for e in rest.into_iter().filter(|e| e.kind != Kind::Note) {
                    push(e.kind, &e.text);
                }
            }
        }
        text
    }

    pub(super) fn copy_output(&mut self, all: bool) {
        let text = self.export_text(all);
        if text.trim().is_empty() {
            self.note("Nothing to copy yet.");
            return;
        }
        let lines = text.lines().count();
        match copy_to_clipboard(&text) {
            Ok(()) => self.note(&format!("Copied {lines} lines to the clipboard.")),
            Err(e) => self.note(&format!("Couldn't copy: {e}")),
        }
    }

    pub(super) fn save_output(&mut self, args: &[String]) {
        let all = args.first().is_some_and(|a| a == "all");
        let file = args.get(usize::from(all));
        let text = self.export_text(all);
        if text.trim().is_empty() {
            self.note("Nothing to save yet.");
            return;
        }
        let path = file.map_or_else(
            || {
                std::path::PathBuf::from(format!(
                    "ykman-shell-{}.txt",
                    chrono::Local::now().format("%Y%m%d-%H%M%S")
                ))
            },
            std::path::PathBuf::from,
        );
        // Private and never overwrites: the output may contain sensitive data.
        let res = create_private_file(&path).and_then(|()| std::fs::write(&path, &text));
        match res {
            Ok(()) => self.note(&format!(
                "Saved {} lines to {}",
                text.lines().count(),
                path.display()
            )),
            Err(e) => self.note(&format!("Couldn't save {}: {e}", path.display())),
        }
    }

    pub(super) fn help(&mut self, topic: Option<&str>) {
        if topic.is_some_and(|t| t.starts_with("var")) {
            return self.help_variables();
        }
        const ROWS: [(&str, &str); 19] = [
            (
                "/",
                "Browse commands; Tab/→ complete, ↑/↓ select, Enter run",
            ),
            ("←", "(empty prompt) choose which YubiKey to use"),
            ("Tab, F1-F3", "Switch between Default, Hybrid and Debug"),
            ("Ctrl+T", "Expand/collapse the log blocks in Hybrid"),
            ("mouse", "Wheel scrolls; click tabs, log headers, devices"),
            (
                "Ctrl+F",
                "Find in the output; Enter next, ↑ previous, Esc close",
            ),
            ("PgUp/PgDn", "Scroll; ↑/↓ browse history"),
            (
                "/copy [all]",
                "Copy the last command (all = whole session) to the clipboard",
            ),
            (
                "/save [all] [file]",
                "Same, to a file (ykman-shell-<time>.txt)",
            ),
            ("", "Follows the current tab: Debug tab = debug log"),
            (
                "/log [level]",
                "Log verbosity: error, warning, info, debug, traffic",
            ),
            (
                "/record",
                "Queue several commands, run once or on every key",
            ),
            (
                "/repeat <n> <cmd…>",
                "Run a command n times (1-100); ${i} = iteration",
            ),
            (
                "/export [copy|file]",
                "Save or copy generated values as CSV",
            ),
            (
                "/csv <file>",
                "Variables from a CSV; one row per key in batch",
            ),
            ("/script", "Browse saved sequences; save, run, list, delete"),
            (
                "/secrets [hide|show]",
                "Mask secrets in the summary and commands",
            ),
            ("/help variables", "Variables: ${serial}, ${random:hex}, …"),
            (
                "Ctrl+C / Esc",
                "Cancel command or prompt / clear input / quit",
            ),
        ];
        for (k, d) in ROWS {
            self.note(&format!("{k:<22}{d}"));
        }
    }

    fn help_variables(&mut self) {
        for l in [
            "Variables work in recorded and saved sequences: write ${name} in a command.",
            "",
            "From the current key (changes per key in a batch):",
            "  ${serial}   serial number           ${version}  firmware version",
            "  ${name}     product name            ${round}    batch round (1, 2, …)",
            "  ${date}     today, YYYY-MM-DD",
            "  ${i}        iteration number inside /repeat",
            "",
            "Random, generated fresh for every key and run:",
            "  ${random:base32:32}   OATH secret (A-Z, 2-7), default length 32",
            "  ${random:hex:32}      hex, default 32",
            "  ${random:digits:6}    digits, default 6",
            "  ${random:alnum:8}     letters and digits, default 8 (also just ${random})",
            "  Lengths are 1-128. The same ${random:…} twice in one run is the same value.",
            "  base32 and hex values are hidden in the command and printed once after the run.",
            "",
            "From a CSV: /csv <file>, then ${column} in a sequence. Batch mode takes one row per",
            "  key (a failed key retries the same row); /repeat all … runs once per row.",
            "",
            "Your own, e.g. ${customer}: asked once before the sequence starts.",
            "  Names containing secret, key, pass, pin, puk, token or code are masked.",
            "  Values are kept in memory only and never saved with a script.",
        ] {
            self.note(l);
        }
        self.note("");
        self.note("Available in this session:");
        let mut any = false;
        if let Some(t) = self.csv.clone() {
            any = true;
            self.note(&format!(
                "  CSV {} ({} row{}):",
                t.name,
                t.rows.len(),
                plural(t.rows.len())
            ));
            for (i, h) in t.headers.iter().enumerate() {
                let first = t
                    .rows
                    .first()
                    .and_then(|r| r.get(i))
                    .cloned()
                    .unwrap_or_default();
                let shown = if var_secret(h) {
                    "••••".into()
                } else {
                    first
                };
                self.note(&format!("    ${{{h}}}  e.g. {shown}"));
            }
        }
        let used: Vec<String> = self
            .recording
            .as_deref()
            .or(self.last_sequence.as_ref().map(|s| s.steps.as_slice()))
            .map(custom_vars)
            .unwrap_or_default()
            .into_iter()
            .filter(|n| !self.csv.as_ref().is_some_and(|t| t.headers.contains(n)))
            .collect();
        if !used.is_empty() {
            any = true;
            let list: Vec<String> = used.iter().map(|n| format!("${{{n}}}")).collect();
            self.note(&format!("  Your own, in the sequence: {}", list.join(", ")));
        }
        if !any {
            self.note("  No CSV attached and no custom variables in use (see /csv).");
        }
    }

    pub(super) fn set_log_level(&mut self, level: Option<&str>) {
        match level.and_then(|l| LEVELS.iter().find(|(n, _)| *n == l)) {
            Some((name, _)) => {
                self.log_level = name;
                self.save();
                self.note(&format!("log level set to {name}"));
                if *name == "traffic" {
                    self.note("Warning: traffic logs may include sensitive data.");
                }
            }
            None => self.note(&format!("usage: /log <level>; current: {}", self.log_level)),
        }
    }

    // ---------- background work ----------
}

/// Batch arguments that are safe to remember: boolean flags and single-digit
/// positionals such as a slot number. Option values may be secrets, so they are dropped.
fn safe_batch_args(node: &clap::Command, args: &[&str]) -> Vec<String> {
    let flag = |a: &clap::Arg| !a.get_action().takes_values();
    args.iter()
        .filter(|tok| {
            if let Some(long) = tok.strip_prefix("--") {
                node.get_arguments()
                    .any(|a| a.get_long() == Some(long) && flag(a))
            } else if let Some(shorts) = tok.strip_prefix('-') {
                !shorts.is_empty()
                    && shorts.chars().all(|c| {
                        node.get_arguments()
                            .any(|a| a.get_short() == Some(c) && flag(a))
                    })
            } else {
                tok.len() == 1 && tok.chars().all(|c| c.is_ascii_digit())
            }
        })
        .map(|t| t.to_string())
        .collect()
}

/// Options already typed on the line, by short or long name (`-x`, `-gG`, `--key=..`).
fn used_options<'a>(node: &'a clap::Command, tokens: &[&str]) -> Vec<&'a clap::Id> {
    let mut used = Vec::new();
    for tok in tokens {
        if let Some(long) = tok.strip_prefix("--") {
            let long = long.split('=').next().unwrap_or(long);
            used.extend(
                node.get_arguments()
                    .filter(|a| a.get_long() == Some(long))
                    .map(|a| a.get_id()),
            );
        } else if let Some(shorts) = tok.strip_prefix('-') {
            for c in shorts.chars() {
                let Some(a) = node.get_arguments().find(|a| a.get_short() == Some(c)) else {
                    break;
                };
                used.push(a.get_id());
                if a.get_action().takes_values() {
                    break;
                }
            }
        }
    }
    used
}

/// Whether `arg` conflicts with an already typed option; clap records each
/// declared conflict on one side only, so check both directions.
fn conflicts_with_used(node: &clap::Command, arg: &clap::Arg, taken: &[&clap::Id]) -> bool {
    node.get_arg_conflicts_with(arg)
        .iter()
        .any(|c| taken.contains(&c.get_id()))
        || taken
            .iter()
            .filter_map(|id| node.get_arguments().find(|a| a.get_id() == *id))
            .filter(|a| !a.is_global_set())
            .any(|t| {
                node.get_arg_conflicts_with(t)
                    .iter()
                    .any(|c| c.get_id() == arg.get_id())
            })
}

/// The option a token names (`--long` or a single `-s`) if it takes a value.
fn value_option<'a>(node: &'a clap::Command, tok: &str) -> Option<&'a clap::Arg> {
    let arg = if let Some(long) = tok.strip_prefix("--") {
        node.get_arguments().find(|a| a.get_long() == Some(long))
    } else {
        let mut chars = tok.strip_prefix('-')?.chars();
        let c = chars.next().filter(|_| chars.next().is_none())?;
        node.get_arguments().find(|a| a.get_short() == Some(c))
    };
    arg.filter(|a| a.get_action().takes_values())
}

/// Output files are new, so only folders are offered; inputs list all files.
fn output_exts(a: &clap::Arg) -> Option<&'static [&'static str]> {
    a.get_id().as_str().contains("output").then_some(&[])
}

const TABLE_EXTS: [&str; 3] = ["csv", "tsv", "txt"];

/// Whether an argument takes a file path (by its name; ykman has no path type).
fn is_file_arg(a: &clap::Arg) -> bool {
    let id = a.get_id().as_str();
    ["file", "path", "output", "input"]
        .iter()
        .any(|k| id.contains(k))
}

/// The positional the next word would fill, given the words typed after the command.
fn next_positional<'a>(node: &'a clap::Command, typed: &[&str]) -> Option<&'a clap::Arg> {
    let mut count = 0;
    let mut skip = false;
    for t in typed {
        if skip {
            skip = false;
        } else if t.starts_with('-') {
            skip = !t.contains('=') && value_option(node, t).is_some();
        } else {
            count += 1;
        }
    }
    node.get_positionals().nth(count)
}

/// CSV files and folders matching a partly typed path, for `/csv`.
fn path_suggestions(typed: &str, exts: Option<&[&str]>) -> Vec<(String, String)> {
    let (dir, prefix) = match typed.rfind('/') {
        Some(i) => (&typed[..=i], &typed[i + 1..]),
        None => ("", typed),
    };
    let real = match dir.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(rest))
            .unwrap_or_else(|| dir.into()),
        None if dir.is_empty() => ".".into(),
        None => dir.into(),
    };
    let mut found: Vec<(bool, String)> = std::fs::read_dir(real)
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let e = e.ok()?;
            let name = e.file_name().into_string().ok()?;
            if !name.starts_with(prefix) || (name.starts_with('.') && !prefix.starts_with('.')) {
                return None;
            }
            let is_dir = e.path().is_dir();
            let ext = std::path::Path::new(&name)
                .extension()
                .map(|x| x.to_string_lossy().to_lowercase());
            (is_dir || exts.is_none_or(|x| ext.as_deref().is_some_and(|e| x.contains(&e))))
                .then_some((is_dir, name))
        })
        .collect();
    found.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase()))
    });
    found.truncate(50);
    found
        .into_iter()
        .map(|(is_dir, name)| {
            let shown = format!("{dir}{name}{}", if is_dir { "/" } else { "" });
            (shown, if is_dir { "folder" } else { "file" }.into())
        })
        .collect()
}
