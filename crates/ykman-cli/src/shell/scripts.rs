use super::*;
use std::collections::HashMap;

#[cfg(test)]
mod tests;

const BUILTIN_VARS: [&str; 6] = ["serial", "version", "name", "round", "date", "i"];
const MAX_REPEAT: usize = 100;

/// How `${...}` variables are filled in.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Expand {
    /// Placeholders, to validate a step before any key or value is known.
    Check,
    /// Real values, for running.
    Run,
    /// Real values with secret ones hidden, for showing.
    Display,
}

pub(super) fn var_secret(name: &str) -> bool {
    let n = name.to_lowercase();
    ["secret", "key", "pass", "pin", "puk", "token", "code"]
        .iter()
        .any(|s| n.contains(s))
}

pub(super) fn is_random(n: &str) -> bool {
    n == "random" || n.starts_with("random:")
}

const RANDOM_KINDS: [(&str, usize); 4] = [("base32", 32), ("hex", 32), ("digits", 6), ("alnum", 8)];

/// Parses `random[:kind[:length]]` into its kind and length.
pub(super) fn parse_random(name: &str) -> Result<(&'static str, usize), String> {
    let mut parts = name.split(':');
    parts.next();
    let kind = parts.next().unwrap_or("alnum");
    let Some(&(kind, default)) = RANDOM_KINDS.iter().find(|(k, _)| *k == kind) else {
        return Err(format!(
            "unknown random kind '{kind}' (use base32, hex, digits or alnum)"
        ));
    };
    let len = match parts.next() {
        None => default,
        Some(l) => l
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=128).contains(n))
            .ok_or("random length must be 1-128")?,
    };
    if parts.next().is_some() {
        return Err("use ${random:kind:length}".into());
    }
    Ok((kind, len))
}

fn random_string(kind: &str, len: usize) -> String {
    let alphabet: &[u8] = match kind {
        "base32" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "hex" => b"0123456789abcdef",
        "digits" => b"0123456789",
        _ => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    };
    // Reject bytes past the largest multiple of the alphabet size to avoid bias.
    let limit = 256 - 256 % alphabet.len();
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let mut buf = [0u8; 64];
        if getrandom::fill(&mut buf).is_err() {
            break;
        }
        for b in buf {
            if (b as usize) < limit && out.len() < len {
                out.push(alphabet[b as usize % alphabet.len()] as char);
            }
        }
    }
    out
}

/// The distinct, valid `${random…}` names used by a step.
pub(super) fn random_names(step: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in step {
        for (_, _, n) in find_vars(w) {
            if is_random(n) && parse_random(n).is_ok() && !out.iter().any(|x| x == n) {
                out.push(n.to_string());
            }
        }
    }
    out
}

pub(super) fn random_value(name: &str) -> Option<String> {
    let (kind, len) = parse_random(name).ok()?;
    Some(random_string(kind, len))
}

/// base32 and hex values are secrets, hidden in the echoed command.
pub(super) fn random_is_secret(name: &str) -> bool {
    parse_random(name).is_ok_and(|(k, _)| k == "base32" || k == "hex")
}

/// `repeat <count> <command…>`: the count and the command to repeat.
pub(super) fn parse_repeat(args: &[String]) -> Result<(usize, &[String]), String> {
    if args.len() < 3 {
        return Err("usage: /repeat <count> <command…>".into());
    }
    let n = if args[1] == "all" {
        usize::MAX
    } else {
        args[1]
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=MAX_REPEAT).contains(n))
            .ok_or_else(|| format!("the count must be 1-{MAX_REPEAT} (or all, with a CSV)"))?
    };
    if args[2] == "repeat" {
        return Err("repeat can't be nested".into());
    }
    Ok((n, &args[2..]))
}

/// Expand `repeat` steps into one step per iteration (with `${i}` filled in).
/// The flags mark steps that get fresh random values; the rows say which CSV
/// row a step reads (only when a sequence runs once on a single key).
fn unroll(
    steps: &[Vec<String>],
    once: bool,
    csv: Option<&Table>,
) -> (Vec<Vec<String>>, Vec<bool>, Vec<Option<usize>>) {
    let headers = csv.map_or(&[][..], |t| &t.headers[..]);
    let total = csv.map_or(0, |t| t.rows.len());
    let uses = once && steps_use(steps, headers);
    let has_repeat = steps
        .iter()
        .any(|s| s[0] == "repeat" && parse_repeat(s).is_ok());
    let (mut flat, mut fresh, mut rows) = (Vec::new(), Vec::new(), Vec::new());
    let mut pass = |steps: &[Vec<String>], row: Option<usize>, repeats: bool| {
        for s in steps {
            match parse_repeat(s) {
                Ok((n, rest)) if s[0] == "repeat" && repeats => {
                    let n = if n == usize::MAX { total } else { n };
                    for i in 1..=n {
                        flat.push(
                            rest.iter()
                                .map(|w| w.replace("${i}", &i.to_string()))
                                .collect(),
                        );
                        fresh.push(true);
                        rows.push(uses.then_some(i - 1));
                    }
                }
                _ => {
                    flat.push(s.clone());
                    fresh.push(false);
                    rows.push(row);
                }
            }
        }
    };
    if uses && !has_repeat {
        // Without a /repeat, the whole sequence runs once per row.
        for r in 0..total {
            pass(steps, Some(r), false);
        }
    } else {
        pass(steps, uses.then_some(0), true);
    }
    (flat, fresh, rows)
}

/// Commands that restart the key, so the next step must wait for it.
pub(super) fn may_reboot(step: &[String]) -> bool {
    step.first().is_some_and(|w| w == "config") || step.iter().any(|w| w == "reset")
}

/// Calls `f` for each `${name}` in the word, giving its byte range.
pub(super) fn find_vars(word: &str) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = word[from..].find("${") {
        let start = from + i;
        let Some(len) = word[start..].find('}') else {
            break;
        };
        let name = &word[start + 2..start + len];
        let plain = |n: &str| {
            n.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        };
        let ok = if is_random(name) {
            name.split(':')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric()))
        } else {
            plain(name)
        };
        if ok {
            out.push((start, start + len + 1, name));
        }
        from = start + len + 1;
    }
    out
}

/// The custom (non built-in) variable names used by the steps, in order.
pub(super) fn custom_vars(steps: &[Vec<String>]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for w in steps.iter().flatten() {
        for (_, _, n) in find_vars(w) {
            if !BUILTIN_VARS.contains(&n) && !is_random(n) && !names.iter().any(|x| x == n) {
                names.push(n.to_string());
            }
        }
    }
    names
}

/// The most recent recorded sequence, kept for the session so it can be saved later.
pub(super) struct Sequence {
    pub(super) steps: Vec<Vec<String>>,
    pub(super) name: Option<String>,
}

fn scripts_dir() -> Option<std::path::PathBuf> {
    Some(state::state_file()?.parent()?.join("shell-scripts"))
}

/// Completion text for a saved script: a marker, the step count and the first step.
pub(super) fn script_desc(count: usize, steps: &[String]) -> String {
    let first = steps.first().map_or("", String::as_str);
    let more = if count > 1 { "…" } else { "" };
    format!(
        "≡ Saved script · {count} step{} · {first}{more}",
        plural(count)
    )
}

pub(super) fn script_names() -> Vec<String> {
    let mut names: Vec<String> = scripts_dir()
        .and_then(|d| std::fs::read_dir(d).ok())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| valid_name(n))
        .collect();
    names.sort();
    names
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 40
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn quote(w: &str) -> String {
    if !w.is_empty() && !w.contains(char::is_whitespace) && !w.contains(['"', '\'']) {
        w.to_string()
    } else if w.contains('"') {
        format!("'{w}'")
    } else {
        format!("\"{w}\"")
    }
}

fn format_step(s: &[String]) -> String {
    s.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ")
}

const SECRET_FLAGS: [&str; 7] = [
    "key",
    "password",
    "secret",
    "passphrase",
    "pin",
    "puk",
    "code",
];

fn secret_flag(w: &str) -> bool {
    let w = w.to_lowercase();
    w.starts_with('-') && SECRET_FLAGS.iter().any(|s| w.contains(s))
}

/// Whether a clap parameter id (resolved from short or long flags) holds a secret.
fn secret_param(id: &str) -> bool {
    id != "keyboard_layout" && SECRET_FLAGS.iter().any(|s| id.contains(s))
}

/// A step for display, with values that look like secrets hidden.
pub(super) fn masked_step(step: &[String], names: &[Option<String>]) -> String {
    let off = if step.first().is_some_and(|w| w == "repeat") {
        2
    } else {
        0
    };
    let w: Vec<&str> = step.iter().skip(off).map(String::as_str).collect();
    let positional = if w.starts_with(&["oath", "accounts", "add"]) {
        Some(4)
    } else if w.starts_with(&["oath", "accounts", "uri"]) {
        Some(3)
    } else {
        None
    };
    let hide = |s: &str| {
        if s.contains("${") {
            quote(s)
        } else {
            "••••".to_string()
        }
    };
    let mut out = Vec::new();
    let mut hide_next = false;
    for (i, word) in step.iter().enumerate() {
        let by_name = !word.starts_with('-')
            && names
                .get(i)
                .and_then(Option::as_deref)
                .is_some_and(secret_param);
        let shown = if (hide_next || by_name) && !word.starts_with('-') {
            hide(word)
        } else if let Some((flag, value)) = word.split_once('=')
            && secret_flag(flag)
        {
            format!("{flag}={}", hide(value))
        } else if !word.starts_with('-')
            && i.checked_sub(off).is_some()
            && i - off == positional.unwrap_or(usize::MAX)
        {
            hide(word)
        } else {
            quote(word)
        };
        hide_next = secret_flag(word) && !word.contains('=');
        out.push(shown);
    }
    out.join(" ")
}

/// Steps that may carry secrets on the command line.
fn looks_secret(step: &[String]) -> bool {
    let step = match parse_repeat(step) {
        Ok((_, rest)) if step[0] == "repeat" => rest,
        _ => step,
    };
    let flag = step.iter().enumerate().any(|(i, w)| {
        // A variable is asked for at run time, so nothing secret is stored.
        if step.get(i + 1).is_some_and(|n| n.contains("${")) {
            return false;
        }
        secret_flag(w)
    });
    let w: Vec<&str> = step.iter().map(String::as_str).collect();
    flag || w.starts_with(&["otp", "static"])
        || w.starts_with(&["oath", "accounts", "add"])
        || w.starts_with(&["oath", "accounts", "uri"])
}

impl App {
    pub(super) fn new_batch(&self, steps: Vec<Vec<String>>, once: bool, current: u32) -> Batch {
        let csv = self.csv.clone().filter(|t| steps_use(&steps, &t.headers));
        let headers = csv.as_ref().map_or(Vec::new(), |t| t.headers.clone());
        let ask: Vec<String> = custom_vars(&steps)
            .into_iter()
            .filter(|n| !headers.contains(n))
            .collect();
        let (steps, fresh, step_rows) = unroll(&steps, once, csv.as_ref());
        Batch {
            steps,
            fresh,
            step_rows,
            csv,
            row: 0,
            labels: Vec::new(),
            step: 0,
            retries: 0,
            auto_yes: false,
            auto_asked: false,
            once,
            phase: if ask.is_empty() {
                BatchPhase::Confirm
            } else {
                BatchPhase::Vars
            },
            round: 0,
            same_key: false,
            current,
            results: Vec::new(),
            vars: HashMap::new(),
            ask,
            random: HashMap::new(),
        }
    }

    /// The variable being asked for, and whether its value is secret.
    pub(super) fn var_prompt(&self) -> Option<(String, bool)> {
        let b = self.batch.as_ref()?;
        if !matches!(b.phase, BatchPhase::Vars) {
            return None;
        }
        let n = b.ask.first()?;
        Some((n.clone(), var_secret(n)))
    }

    pub(super) fn var_answer(&mut self, value: &str) {
        let value = value.trim();
        let Some((name, secret)) = self.var_prompt() else {
            return;
        };
        if value.is_empty() {
            self.note(&format!("A value for ${{{name}}} is required."));
            return;
        }
        let shown = if secret { "••••" } else { value };
        self.note(&format!("  ${{{name}}} = {shown}"));
        if let Some(b) = self.batch.as_mut() {
            b.vars.insert(name, value.to_string());
            b.ask.remove(0);
            if b.ask.is_empty() {
                b.phase = BatchPhase::Confirm;
            }
        }
    }

    /// Fill in `${name}` variables in a step.
    pub(super) fn expand(&self, step: &[String], mode: Expand) -> Vec<String> {
        let b = self.batch.as_ref();
        let serial = b.map_or(0, |b| b.current);
        let dev = self.devices.iter().find(|d| d.serial == serial);
        let csv_value = |name: &str| -> Option<String> {
            let b = b?;
            let t = b.csv.as_ref()?;
            let col = t.headers.iter().position(|h| h == name)?;
            t.rows.get(current_row(b)?)?.get(col).cloned()
        };
        let value = |name: &str| -> String {
            let check = mode == Expand::Check;
            match name {
                "serial" if check => "1".into(),
                "serial" => serial.to_string(),
                "version" => dev.map_or_else(|| "1".into(), |d| d.version.clone()),
                "name" => dev.map_or_else(|| "YubiKey".into(), |d| d.name.clone()),
                "round" => b.map_or(1, |b| b.round).to_string(),
                _ if is_random(name) => match (mode, b.and_then(|b| b.random.get(name))) {
                    (Expand::Run, Some(v)) => v.clone(),
                    (Expand::Display, Some(v)) => {
                        if random_is_secret(name) {
                            "••••".into()
                        } else {
                            v.clone()
                        }
                    }
                    (Expand::Display, None) => format!("${{{name}}}"),
                    _ => "1".into(),
                },
                "date" => chrono::Local::now().format("%Y-%m-%d").to_string(),
                _ if check => "1".into(),
                _ if csv_value(name).is_some() => {
                    if mode == Expand::Display && var_secret(name) {
                        "••••".into()
                    } else {
                        csv_value(name).unwrap_or_default()
                    }
                }
                _ if mode == Expand::Display && var_secret(name) => "••••".into(),
                _ => b
                    .and_then(|b| b.vars.get(name).cloned())
                    .unwrap_or_else(|| format!("${{{name}}}")),
            }
        };
        step.iter()
            .map(|w| {
                let mut out = String::new();
                let mut last = 0;
                for (s, e, n) in find_vars(w) {
                    out.push_str(&w[last..s]);
                    out.push_str(&value(n));
                    last = e;
                }
                out.push_str(&w[last..]);
                out
            })
            .collect()
    }

    /// Remember a sequence for the session; `name` is set if it came from disk.
    pub(super) fn remember_sequence(&mut self, steps: &[Vec<String>], name: Option<String>) {
        self.last_sequence = Some(Sequence {
            steps: steps.to_vec(),
            name,
        });
    }

    /// A single dim hint after a run, if the sequence has not been saved yet.
    pub(super) fn script_hint(&mut self) {
        let unsaved = self
            .last_sequence
            .as_ref()
            .is_some_and(|s| s.name.is_none());
        let tip = match (unsaved, self.generated.is_empty()) {
            (true, false) => {
                "Tip: /script save <name> keeps this sequence, /export saves the values as CSV."
            }
            (true, true) => "Tip: /script save <name> keeps this sequence for later.",
            (false, false) => "Tip: /export saves the generated values as CSV.",
            (false, true) => return,
        };
        self.note(tip);
    }

    pub(super) fn script_command(&mut self, args: &[String]) {
        match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["show", name] => return self.script_show(name),
            ["rename", old, new] => return self.script_rename(old, new),
            ["rename", ..] => {
                self.note("Usage: /script rename <old-name> <new-name>");
                return;
            }
            _ => {}
        }
        if self.batch.is_some() || self.running || self.recording.is_some() {
            self.note("Finish the current command, batch or recording first.");
            return;
        }
        if args.len() > 2 {
            self.note("Script names can't contain spaces. Use - or _.");
            return;
        }
        let name = args.get(1).map(String::as_str);
        match (args.first().map(String::as_str), name) {
            (Some("save"), Some(n)) => self.script_save(n),
            (Some("run"), Some(n)) => self.script_run(n),
            (Some("delete"), Some(n)) => self.script_delete(n),
            (Some("list"), _) => self.script_list(),
            (Some("last" | "rerun"), _) => match self.last_sequence.as_ref() {
                Some(s) => {
                    let (steps, name) = (s.steps.clone(), s.name.clone());
                    self.start_saved(steps, name);
                }
                None => self.note("No sequence yet. Use /record to make one."),
            },
            _ => self.note(
                "Usage: /script save <name> · run <name> · show <name> · rename <old> <new> · list · delete <name> · last",
            ),
        }
    }

    fn script_list(&mut self) {
        let names = script_names();
        if names.is_empty() {
            self.note("No saved scripts. Record a sequence, then /script save <name>.");
            return;
        }
        self.note(&format!("Saved scripts ({}):", names.len()));
        for n in names {
            let steps = self.load_script(&n).map_or(0, |s| s.len());
            self.note(&format!("  {n}  · {steps} step{}", plural(steps)));
        }
    }

    fn script_save(&mut self, name: &str) {
        if !valid_name(name) {
            self.note("Script names may use letters, digits, - and _ (max 40).");
            return;
        }
        let Some(steps) = self.last_sequence.as_ref().map(|s| s.steps.clone()) else {
            self.note("Nothing to save yet. Use /record to make a sequence.");
            return;
        };
        let Some(dir) = scripts_dir() else {
            self.note("No place to save scripts on this system.");
            return;
        };
        let secret = steps.iter().any(|s| looks_secret(s));
        let confirmed = self.confirm_save.as_deref() == Some(name);
        if secret && !confirmed {
            self.confirm_save = Some(name.to_string());
            self.push(
                Kind::Fail,
                "These steps may contain secrets, which are saved as plain text. \
                 Run the same command again to save anyway."
                    .to_string(),
            );
            return;
        }
        self.confirm_save = None;
        let mut text = String::new();
        for s in &steps {
            text.push_str(&format_step(s));
            text.push('\n');
        }
        let path = dir.join(name);
        let existed = path.exists();
        let result = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&path, text));
        match result {
            Ok(()) => {
                self.note(&format!(
                    "{} script '{name}' ({} step{}).",
                    if existed { "Updated" } else { "Saved" },
                    steps.len(),
                    plural(steps.len())
                ));
                if let Some(s) = self.last_sequence.as_mut() {
                    s.name = Some(name.to_string());
                }
            }
            Err(e) => self.note(&format!("Could not save: {e}")),
        }
    }

    fn script_show(&mut self, name: &str) {
        let Some(steps) = self.load_script(name) else {
            self.note(&format!("No script named '{name}'."));
            return;
        };
        self.note(&format!(
            "Script '{name}' · {} step{}:",
            steps.len(),
            plural(steps.len())
        ));
        for (i, s) in steps.iter().enumerate() {
            self.note(&format!("  {}  {}", i + 1, self.masked(s)));
        }
    }

    fn script_rename(&mut self, old: &str, new: &str) {
        if !valid_name(new) {
            self.note("Script names may use letters, digits, - and _ (max 40).");
            return;
        }
        let Some(dir) = scripts_dir() else {
            self.note("No place to save scripts on this system.");
            return;
        };
        if !valid_name(old) || !dir.join(old).is_file() {
            self.note(&format!("No script named '{old}'."));
        } else if dir.join(new).exists() {
            self.note(&format!("A script named '{new}' already exists."));
        } else if let Err(e) = std::fs::rename(dir.join(old), dir.join(new)) {
            self.note(&format!("Could not rename: {e}"));
        } else {
            self.note(&format!("Renamed script '{old}' to '{new}'."));
            if let Some(s) = self.last_sequence.as_mut()
                && s.name.as_deref() == Some(old)
            {
                s.name = Some(new.to_string());
            }
        }
    }

    fn script_delete(&mut self, name: &str) {
        let removed = valid_name(name)
            && scripts_dir().is_some_and(|d| std::fs::remove_file(d.join(name)).is_ok());
        if removed {
            self.note(&format!("Deleted script '{name}'."));
            if let Some(s) = self.last_sequence.as_mut()
                && s.name.as_deref() == Some(name)
            {
                s.name = None;
            }
        } else {
            self.note(&format!("No script named '{name}'."));
        }
    }

    /// A step for display with secrets hidden, using clap to resolve short flags.
    pub(super) fn masked(&self, step: &[String]) -> String {
        let off = if step.first().is_some_and(|w| w == "repeat") {
            2.min(step.len())
        } else {
            0
        };
        let mut names = vec![None; off];
        names.extend(self.param_names(&step[off..]));
        masked_step(step, &names)
    }

    pub(super) fn load_script_list(&self) -> Vec<(String, usize, Vec<String>)> {
        script_names()
            .into_iter()
            .map(|n| {
                let steps = self.load_script(&n).unwrap_or_default();
                let shown = steps.iter().map(|s| self.masked(s)).collect();
                (n, steps.len(), shown)
            })
            .collect()
    }

    pub(super) fn load_script(&self, name: &str) -> Option<Vec<Vec<String>>> {
        if !valid_name(name) {
            return None;
        }
        let text = std::fs::read_to_string(scripts_dir()?.join(name)).ok()?;
        Some(
            text.lines()
                .map(split_args)
                .filter(|s| !s.is_empty())
                .collect(),
        )
    }

    pub(super) fn script_run(&mut self, name: &str) {
        let Some(steps) = self.load_script(name) else {
            self.note(&format!("No script named '{name}'."));
            return;
        };
        if steps.is_empty() {
            self.note(&format!("Script '{name}' is empty."));
            return;
        }
        for (i, s) in steps.iter().enumerate() {
            if let Err(e) = self.check_step(s) {
                self.note(&format!("Script '{name}' step {}: {e}", i + 1));
                return;
            }
        }
        self.start_saved(steps, Some(name.to_string()));
    }

    fn start_saved(&mut self, steps: Vec<Vec<String>>, name: Option<String>) {
        if !self.sequence_ready(&steps) {
            return;
        }
        self.start_sequence(steps, name);
    }

    pub(super) fn show_steps(&mut self, steps: &[Vec<String>]) {
        for (i, s) in steps.iter().enumerate() {
            self.note(&format!("  {}  {}", i + 1, s.join(" ")));
        }
    }

    pub(super) fn script_suggestions(
        &self,
        words: &[&str],
        partial: &str,
    ) -> Vec<(String, String)> {
        let subs = [
            ("save", "Save the last sequence: /script save <name>"),
            ("run", "Run a saved script"),
            ("show", "Show what a saved script does"),
            (
                "rename",
                "Rename a saved script: /script rename <old> <new>",
            ),
            ("list", "List saved scripts"),
            ("delete", "Delete a saved script"),
            ("last", "Run the last sequence again"),
        ];
        match words {
            ["script"] => subs
                .iter()
                .filter(|(n, _)| n.starts_with(partial))
                .map(|(n, d)| (n.to_string(), d.to_string()))
                .collect(),
            ["script", "run" | "delete" | "show" | "rename"] => self
                .load_script_list()
                .into_iter()
                .filter(|(n, ..)| n.starts_with(partial))
                .map(|(n, count, steps)| {
                    let desc = script_desc(count, &steps);
                    (n, desc)
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}
