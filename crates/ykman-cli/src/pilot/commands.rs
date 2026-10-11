use super::*;

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
/// Options the pilot sets itself (or that make no sense in its UI).
pub(super) const PILOT_MANAGED_OPTS: [&str; 8] = [
    "color",
    "no-color",
    "log-level",
    "log-file",
    "device",
    "version",
    "licenses",
    "diagnose",
];
/// Commands handled by the pilot itself (the first three wrap top-level flags).
pub(super) const BUILTINS: [(&str, &str); 11] = [
    ("diagnose", "Run system diagnostics"),
    ("licenses", "Show open source licenses"),
    ("version", "Show the ykman version"),
    ("batch", "Repeat a command on one YubiKey after another"),
    ("clear", "Clear the screen"),
    ("device", "Choose which YubiKey to use (also: ← key)"),
    ("copy", "Copy the last command's output: /copy [all]"),
    ("save", "Save the last command's output: /save [all] [file]"),
    ("log", "Set the log level: /log [level]"),
    ("help", "Show keyboard shortcuts"),
    ("quit", "Exit pilot"),
];

pub(super) fn is_builtin(word: &str) -> bool {
    word == "exit" || BUILTINS.iter().any(|(n, _)| *n == word)
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
        if !partial.is_empty() && !partial.starts_with('-') {
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

        if (words == ["copy"] || words == ["save"]) && "all".starts_with(partial) {
            add("all", "Include the whole session");
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
        let off = usize::from(words.first() == Some(&"batch"));
        if off == 1 && words.len() == 1 && "stop".starts_with(partial) {
            add("stop", "End the batch and show a summary");
        }
        if off == 0 && words.first().is_some_and(|w| is_builtin(w)) {
            return out;
        }
        let words = &words[off..];
        let (node, used) = self.resolve(words);
        if used < words.len() || partial.starts_with('-') {
            // SCP options apply to every command, so keep them after the specific ones.
            let mut args: Vec<&clap::Arg> = node.get_arguments().collect();
            args.sort_by_key(|a| a.get_long().is_some_and(|l| l.starts_with("scp")));
            for arg in args {
                let Some(long) = arg
                    .get_long()
                    .filter(|l| !arg.is_hide_set() && !PILOT_MANAGED_OPTS.contains(l))
                else {
                    continue;
                };
                let name = format!("--{long}");
                if name.starts_with(partial) && !words.contains(&name.as_str()) {
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
            let long = words.last()?.strip_prefix("--")?;
            let arg = node.get_arguments().find(|a| a.get_long() == Some(long))?;
            return arg
                .get_action()
                .takes_values()
                .then(|| format!("<{}>", value_name(arg)));
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
                .is_some_and(|l| !a.is_hide_set() && !PILOT_MANAGED_OPTS.contains(&l))
        }) {
            parts.push("[--options]".to_string());
        }
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    // ---------- input ----------

    pub(super) fn history_step(&mut self, back: bool) {
        if self.history.is_empty() {
            return;
        }
        let pos = match (self.hist_pos, back) {
            (None, true) => Some(self.history.len() - 1),
            (Some(p), true) => Some(p.saturating_sub(1)),
            (Some(p), false) if p + 1 < self.history.len() => Some(p + 1),
            _ => None,
        };
        self.hist_pos = pos;
        let text = pos.map(|p| self.history[p].clone()).unwrap_or_default();
        self.input.set(text);
    }

    pub(super) fn accept(&mut self, s: &Suggestion) {
        self.input.buf = format!("{} ", s.display);
        self.input.cursor = self.input.len();
        self.sel = 0;
    }

    pub(super) fn submit(&mut self) {
        let line = self.input.take();
        self.sel = 0;
        self.hist_pos = None;
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
        let line = if self.batch_mode && !is_builtin(&args[0]) {
            args.insert(0, "batch".to_string());
            format!("/batch {}", rest.trim())
        } else {
            line
        };
        if self.history.last().map(String::as_str) != Some(line.trim()) {
            self.history.push(line.trim().to_string());
        }
        self.persist_command(&args);
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
            "help" => self.help(),
            "log" => self.set_log_level(args.get(1).map(String::as_str)),
            "copy" => self.copy_output(args.get(1).is_some_and(|a| a == "all")),
            "save" => self.save_output(&args[1..]),
            "batch" if args.len() == 1 => self.enter_batch_mode(),
            "batch" => self.batch_command(&args[1..]),
            _ if self.batch.is_some() => {
                self.note("A batch is active. Use /batch stop to end it first.");
            }
            _ if self.running => self.note("A command is already running."),
            "version" | "licenses" | "diagnose" if args.len() == 1 => {
                let flag = vec![format!("--{}", args[0])];
                self.spawn(line.trim(), flag);
            }
            _ => self.spawn(line.trim(), args),
        }
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
        let (node, used) = self.resolve(rest);
        let path = if used > 0 {
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
        let (logs, out) = (self.tab != 2, self.tab != 1);
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
                    "ykman-pilot-{}.txt",
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

    pub(super) fn help(&mut self) {
        for l in [
            "/            browse commands; Tab/→ complete, ↑/↓ select, Enter run",
            "←            (empty prompt) choose which YubiKey to use",
            "Tab, F1-F3   switch between Mixed, Logs and Output",
            "Ctrl+T       expand/collapse the log blocks in the Mixed view",
            "mouse        wheel scrolls; click tabs, log headers and devices",
            "Ctrl+F       find in the output; Enter next, ↑ previous, Esc close",
            "PgUp/PgDn    scroll;  ↑/↓ browse history",
            "/copy [all]  copy the current view of the last command (or all) to the clipboard",
            "/save [all] [file]  save it to a file (default: ykman-pilot-<time>.txt)",
            "/log [level] change log verbosity (error, warning, info, debug, traffic)",
            "Ctrl+C       cancel running command / clear input / quit",
            "Esc          cancel a prompt or clear input",
        ] {
            self.note(l);
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
