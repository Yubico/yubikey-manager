use super::*;

/// Command paths that make sense to repeat on many keys (plus any `reset`).
pub(super) const BATCH_ALLOWED: [&[&str]; 10] = [
    &["otp", "yubiotp"],
    &["otp", "static"],
    &["otp", "chalresp"],
    &["otp", "hotp"],
    &["otp", "ndef"],
    &["otp", "swap"],
    &["config"],
    &["oath", "accounts", "add"],
    &["oath", "accounts", "import"],
    &["oath", "accounts", "uri"],
];
pub(super) const BATCH_POLL: Duration = Duration::from_millis(500);
/// A rebooting key needs a moment before it can be trusted to be back.
const STEP_SETTLE: Duration = Duration::from_millis(1500);
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

pub(super) enum BatchPhase {
    /// Waiting for the user to confirm the first run.
    Confirm,
    Running,
    /// Waiting for the next key; `absent` once the previous one was seen gone.
    Waiting {
        prev: u32,
        absent: bool,
    },
    /// The previous key came back; ask before running on it again.
    SameKey(u32),
    /// Asking for the values of the sequence's variables.
    Vars,
    /// A step finished; wait for the key to be ready before the next one.
    StepWait {
        serial: u32,
        since: Instant,
    },
}

/// Run a sequence of commands (often just one) on one key, or repeat it across
/// keys; every run asks its own prompts.
pub(super) struct Batch {
    pub(super) steps: Vec<Vec<String>>,
    pub(super) step: usize,
    /// Run once on the current key instead of repeating on every key.
    pub(super) once: bool,
    pub(super) phase: BatchPhase,
    pub(super) round: usize,
    /// The current round runs on the same key as the previous one.
    pub(super) same_key: bool,
    /// Serial of the key the current round runs on.
    pub(super) current: u32,
    pub(super) results: Vec<(u32, bool)>,
    /// Values for `${name}` variables, asked once before the first run.
    pub(super) vars: std::collections::HashMap<String, String>,
    /// Variable names still to ask, the first one being asked now.
    pub(super) ask: Vec<String>,
    /// `${random:…}` values generated for the current round.
    pub(super) random: std::collections::HashMap<String, String>,
    /// Steps that came from a `repeat` and so get fresh random values each.
    pub(super) fresh: Vec<bool>,
    /// Generated secret values to print after the round: (step, name, value).
    /// The attached CSV, if the steps use its columns.
    pub(super) csv: Option<Table>,
    /// Batch mode: the CSV row the current round uses.
    pub(super) row: usize,
    /// Run-once mode: the CSV row each step uses.
    pub(super) step_rows: Vec<Option<usize>>,
    /// Per finished round: which row it used (shown in the summary).
    pub(super) labels: Vec<String>,
}

impl App {
    /// Whether the command path is (or leads to) something batch mode accepts.
    pub(super) fn batch_possible(&self, words: &[&str]) -> bool {
        fn has_reset(c: &clap::Command) -> bool {
            c.get_subcommands()
                .any(|s| s.get_name() == "reset" || has_reset(s))
        }
        let (node, used) = self.resolve(words);
        used < words.len()
            || node.get_name() == "reset"
            || BATCH_ALLOWED
                .iter()
                .any(|p| p.starts_with(words) || words.starts_with(p))
            || has_reset(node)
    }

    /// Whether the full command is on the batch allowlist (or any reset).
    pub(super) fn batch_allows(&self, words: &[&str]) -> bool {
        let (_, used) = self.resolve(words);
        let is_reset = used > 0 && words[used - 1] == "reset";
        is_reset || BATCH_ALLOWED.iter().any(|p| words.starts_with(p))
    }

    pub(super) fn enter_batch_mode(&mut self) {
        if self.batch_mode {
            self.note("Already in batch mode.");
        } else {
            self.batch_mode = true;
            self.hist_pos = None;
            self.note("Batch mode: each command you enter repeats on one YubiKey after another.");
        }
    }

    pub(super) fn leave_batch_mode(&mut self) {
        self.batch_mode = false;
        self.hist_pos = None;
        self.note("Left batch mode.");
    }

    pub(super) fn batch_waiting(&self) -> bool {
        self.batch.as_ref().is_some_and(|b| {
            matches!(
                b.phase,
                BatchPhase::Waiting { .. } | BatchPhase::SameKey(_) | BatchPhase::StepWait { .. }
            )
        })
    }

    /// `/batch <command...>` or `/batch stop`.
    pub(super) fn batch_command(&mut self, args: &[String]) {
        if args.first().map(String::as_str) == Some("stop") {
            if self.batch.is_some() {
                self.cancel();
                self.end_batch("Batch stopped");
            } else {
                self.note("No batch is running.");
            }
            return;
        }
        if self.batch.is_some() {
            self.note("A batch is already active. Use /batch stop to end it.");
            return;
        }
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        if !self.batch_allows(&words) {
            self.note(
                "Batch supports OTP programming, OATH account adding, config and reset commands. Example: otp yubiotp 1 -S -g -G",
            );
            return;
        }
        if self.devices.len() != 1 {
            self.note("Batch needs exactly one YubiKey inserted to start.");
            return;
        }
        if self.running {
            self.note("A command is already running.");
            return;
        }
        if words.starts_with(&["otp", "yubiotp"])
            && args.iter().any(|a| {
                ["-P", "-p", "-k", "--public-id", "--private-id", "--key"].contains(&a.as_str())
            })
        {
            self.note(
                "Warning: a fixed public ID, private ID or key is identical on every key. Use -S -g -G to generate per key.",
            );
        }
        let (serial, name) = (self.devices[0].serial, self.devices[0].describe());
        let msg = format!(
            "Batch: /{} on {}. The command runs on every key you insert, so give it all the options it needs.",
            args.join(" "),
            name
        );
        self.note(&msg);
        self.batch = Some(self.new_batch(vec![args.to_vec()], false, serial));
    }

    pub(super) fn begin_round(&mut self, serial: u32) {
        let Some(b) = self.batch.as_mut() else {
            return;
        };
        b.round += 1;
        b.same_key = b.results.iter().any(|r| r.0 == serial);
        b.current = serial;
        b.step = 0;
        b.phase = BatchPhase::Running;
        b.random.clear();
        let (round, n, once) = (b.round, b.steps.len(), b.once);
        let row = b.csv.is_some().then(|| row_label(b, b.row));
        self.device = Some(serial);
        if once {
            let s = if n == 1 { "" } else { "s" };
            self.note(&format!("Running {n} step{s} on YubiKey S/N {serial}"));
        } else {
            let row = row.map_or_else(String::new, |r| format!(" · {r}"));
            self.note(&format!("Batch round {round}: YubiKey S/N {serial}{row}"));
        }
        self.run_step();
    }

    /// Start the current step of the running sequence.
    fn run_step(&mut self) {
        let Some(b) = self.batch.as_ref() else {
            return;
        };
        let (idx, fresh) = (b.step, b.fresh[b.step]);
        let step = b.steps[idx].clone();
        let mut generated: Vec<[String; 4]> = Vec::new();
        let columns = self.param_names(&step);
        if let Some(b) = self.batch.as_mut() {
            for n in random_names(&step) {
                let column = columns
                    .iter()
                    .zip(&step)
                    .find(|(_, w)| find_vars(w).iter().any(|(_, _, v)| *v == n))
                    .and_then(|(c, _)| c.clone())
                    .unwrap_or_else(|| parse_random(&n).map_or(n.clone(), |(k, _)| k.to_string()));
                if (fresh || !b.random.contains_key(&n))
                    && let Some(v) = random_value(&n)
                {
                    let serial = b.current.to_string();
                    let group = if fresh {
                        format!("{}.{}", b.round, idx)
                    } else {
                        b.round.to_string()
                    };
                    let same = |g: &[String; 4]| g[0] == serial && g[1] == group;
                    let taken = |name: &str| {
                        self.generated
                            .iter()
                            .chain(&generated)
                            .any(|g| same(g) && g[2] == name)
                    };
                    let mut name = column.clone();
                    let mut k = 2;
                    while taken(&name) {
                        name = format!("{column}_{k}");
                        k += 1;
                    }
                    generated.push([serial, group, name, v.clone()]);
                    b.random.insert(n, v);
                }
            }
        }
        self.generated.extend(generated);
        let Some(b) = self.batch.as_ref() else {
            return;
        };
        let step = &step;
        let args = self.expand(step, Expand::Run);
        let shown_args = self.expand(step, Expand::Display);
        let (step, n) = (b.step, b.steps.len());
        let shown = if n == 1 && !b.once {
            format!("/batch {}", shown_args.join(" "))
        } else {
            format!("/{}", shown_args.join(" "))
        };
        if n > 1 && !fresh {
            self.note(&format!("Step {}/{n}", step + 1));
        }
        self.spawn(&shown, args);
    }

    /// A command finished: go on to the next step, or complete the round.
    pub(super) fn batch_step_done(&mut self, code: Option<u32>) {
        let Some(b) = self.batch.as_mut() else {
            return;
        };
        if !matches!(b.phase, BatchPhase::Running) {
            return;
        }
        let good = code == Some(0);
        if good && b.step + 1 < b.steps.len() {
            let reboots = may_reboot(&b.steps[b.step]);
            b.step += 1;
            if reboots {
                b.phase = BatchPhase::StepWait {
                    serial: b.current,
                    since: Instant::now(),
                };
            } else {
                self.run_step();
            }
            return;
        }
        self.finish_round(good);
    }

    fn finish_round(&mut self, good: bool) {
        let Some(b) = self.batch.as_mut() else {
            return;
        };
        b.results.push((b.current, good));
        let row_info = (!b.once && b.csv.is_some()).then(|| row_label(b, b.row));
        b.labels.push(row_info.clone().unwrap_or_default());
        let mut exhausted = false;
        if good
            && !b.once
            && let Some(t) = &b.csv
        {
            b.row += 1;
            exhausted = b.row >= t.rows.len();
        }
        let ok = b.results.iter().filter(|r| r.1).count();
        let tally = format!("{ok} ok, {} failed", b.results.len() - ok);
        let (n, step, serial) = (b.steps.len(), b.step + 1, b.current);
        let (once, round_no) = (b.once, b.round);
        let msg = if once {
            match (good, n) {
                (true, 1) => (Kind::Success, format!("Done on S/N {serial}")),
                (true, _) => (Kind::Success, format!("All {n} steps done on S/N {serial}")),
                (false, 1) => (Kind::RoundFail, format!("Failed on S/N {serial}")),
                (false, _) => (
                    Kind::RoundFail,
                    format!("Failed at step {step}/{n} on S/N {serial}"),
                ),
            }
        } else {
            let steps = match (good, n) {
                (_, 1) => String::new(),
                (true, _) => format!(" · {n} steps"),
                (false, _) => format!(" · failed at step {step}/{n}"),
            };
            let steps = match &row_info {
                Some(r) => format!("{steps} · {r}"),
                None => steps,
            };
            let round = b.round;
            if good {
                (
                    Kind::Success,
                    format!("Round {round} done on S/N {serial} · {tally}{steps}"),
                )
            } else {
                (
                    Kind::RoundFail,
                    format!("Round {round} failed on S/N {serial} · {tally}{steps}"),
                )
            }
        };
        if once {
            self.batch = None;
        } else {
            b.phase = BatchPhase::Waiting {
                prev: serial,
                absent: false,
            };
        }
        self.push(msg.0, msg.1);
        self.show_generated(serial, round_no);
        if once {
            self.script_hint();
        } else if exhausted {
            self.end_batch("Batch finished: every CSV row is done");
        }
    }

    /// Give up on a step whose key never came back.
    pub(super) fn batch_tick(&mut self) {
        let Some(Batch {
            phase: BatchPhase::StepWait { serial, since },
            ..
        }) = self.batch.as_ref()
        else {
            return;
        };
        if since.elapsed() > STEP_TIMEOUT {
            let serial = *serial;
            self.push(
                Kind::Fail,
                format!("YubiKey S/N {serial} did not come back in time."),
            );
            self.finish_round(false);
        }
    }

    /// Enter on the confirmation: begin the first run.
    pub(super) fn confirm_start(&mut self) {
        let once = self.batch.as_ref().is_some_and(|b| b.once);
        let serial = if once {
            self.active_device()
        } else {
            match self.devices.as_slice() {
                [d] => Some(d.serial),
                _ => None,
            }
        };
        match serial {
            Some(s) => self.begin_round(s),
            None => self.end_batch("Batch cancelled (the YubiKey changed)"),
        }
    }

    pub(super) fn end_batch(&mut self, title: &str) {
        let Some(b) = self.batch.take() else {
            return;
        };
        if b.once {
            self.note(&title.replace("Batch", "Sequence"));
            return;
        }
        let ok = b.results.iter().filter(|r| r.1).count();
        let failed = b.results.len() - ok;
        self.note(&format!("{title}: {ok} succeeded, {failed} failed"));
        for (i, (serial, good)) in b.results.iter().enumerate() {
            let row = b.labels.get(i).filter(|l| !l.is_empty());
            let row = row.map_or_else(String::new, |l| format!("  {l}"));
            self.note(&format!(
                "  {} S/N {serial}{row}",
                if *good { "✓" } else { "✗" }
            ));
        }
        if b.steps.len() > 1 {
            self.script_hint();
        }
    }

    /// Called with a fresh device list: start the next round on a new key.
    pub(super) fn batch_devices(&mut self) {
        let Some(b) = self.batch.as_mut() else {
            return;
        };
        let serials: Vec<u32> = self.devices.iter().map(|d| d.serial).collect();
        match (&mut b.phase, serials.as_slice()) {
            (BatchPhase::Waiting { absent, .. }, []) => *absent = true,
            (BatchPhase::Waiting { prev, .. }, [s]) if s != prev => {
                let s = *s;
                self.next_key(s);
            }
            (BatchPhase::Waiting { prev, absent: true }, [s]) if s == prev => {
                let s = *s;
                b.phase = BatchPhase::SameKey(s);
                self.note(&format!(
                    "YubiKey S/N {s} was already programmed in this batch."
                ));
            }
            (BatchPhase::StepWait { serial, since }, list)
                if since.elapsed() >= STEP_SETTLE && list.contains(serial) =>
            {
                b.phase = BatchPhase::Running;
                self.run_step();
            }
            (BatchPhase::SameKey(s), []) => {
                let s = *s;
                b.phase = BatchPhase::Waiting {
                    prev: s,
                    absent: true,
                };
            }
            (BatchPhase::SameKey(prev), [s]) if s != prev => {
                let s = *s;
                self.next_key(s);
            }
            _ => {}
        }
    }

    /// Start a round on a new key, or pause if it was already programmed in this batch.
    pub(super) fn next_key(&mut self, serial: u32) {
        let Some(b) = self.batch.as_mut() else {
            return;
        };
        if b.results.iter().any(|r| r.0 == serial) {
            b.phase = BatchPhase::SameKey(serial);
            self.note(&format!(
                "YubiKey S/N {serial} was already programmed in this batch."
            ));
        } else {
            self.begin_round(serial);
        }
    }

    /// Short status-bar text while the batch waits for the user.
    pub(super) fn batch_wait_msg(&self) -> Option<&'static str> {
        match self.batch.as_ref()?.phase {
            BatchPhase::Confirm => Some("waiting for confirmation"),
            BatchPhase::SameKey(_) => Some("same YubiKey, waiting for your decision"),
            BatchPhase::Waiting { .. } if self.devices.len() > 1 => {
                Some("waiting for a single YubiKey")
            }
            BatchPhase::Waiting { .. } => Some("waiting for the next YubiKey"),
            BatchPhase::StepWait { .. } => Some("waiting for the YubiKey to come back"),
            BatchPhase::Vars => None,
            BatchPhase::Running => None,
        }
    }

    pub(super) fn batch_label(&self) -> Option<String> {
        let b = self.batch.as_ref()?;
        let ok = b.results.iter().filter(|r| r.1).count();
        let tally = if b.once {
            "Sequence".to_string()
        } else {
            format!("Batch {ok} ok, {} failed", b.results.len() - ok)
        };
        let n = b.steps.len();
        let mut progress = if n > 1 {
            format!(" · step {}/{n}", b.step + 1)
        } else {
            String::new()
        };
        if let Some(t) = b.csv.as_ref().filter(|_| !b.once) {
            let row = b.row.min(t.rows.len() - 1);
            progress.push_str(&format!(" · {}", row_label(b, row)));
        }
        Some(match b.phase {
            BatchPhase::Vars => format!(
                "Enter a value for ${{{}}} (Esc to cancel)",
                b.ask.first().map_or("", String::as_str)
            ),
            BatchPhase::Confirm if b.once => {
                format!("Press Enter to run {n} step{}, Esc to cancel", plural(n))
            }
            BatchPhase::Confirm => format!(
                "Press Enter to start the batch ({n} step{}), Esc to cancel",
                plural(n)
            ),
            BatchPhase::Running if b.same_key => format!(
                "{tally} · round {} running{progress} · warning: this YubiKey was already used in this batch",
                b.round
            ),
            BatchPhase::Running if b.once => format!("{tally} running{progress}"),
            BatchPhase::Running => format!("{tally} · round {} running{progress}", b.round),
            BatchPhase::StepWait { .. } => {
                format!("{tally}{progress} · waiting for the YubiKey to come back (Esc to stop)")
            }
            BatchPhase::SameKey(s) => format!(
                "S/N {s} was already used in this batch · Enter to run anyway, or insert a different key (Esc to finish)"
            ),
            BatchPhase::Waiting { .. } if self.devices.len() > 1 => {
                format!("{tally} · leave only one YubiKey inserted")
            }
            BatchPhase::Waiting { .. } => {
                format!("{tally} · insert the next YubiKey (Esc to finish)")
            }
        })
    }

    /// `/repeat <n> <command…>`: queue it while recording, else run it as a sequence.
    pub(super) fn repeat_command(&mut self, args: &[String]) {
        if self.recording.is_some() {
            self.record_step(args);
        } else if self.batch.is_some() || self.running {
            self.note("Finish the running command or batch first.");
        } else if let Err(e) = self.check_step(args) {
            self.note(&format!("Not repeated: {e}"));
        } else if self.sequence_ready(&[args.to_vec()]) {
            self.start_sequence(vec![args.to_vec()], None);
        }
    }

    /// Start recording, or finish the recording in progress.
    pub(super) fn record_command(&mut self) {
        if self.recording.is_some() {
            self.finish_recording();
        } else if self.batch.is_some() || self.running {
            self.note("Finish the running command or batch first.");
        } else {
            self.recording = Some(Vec::new());
            self.note(if self.batch_mode {
                "Recording: enter the commands to run on every key. Esc to finish."
            } else {
                "Recording: enter commands to queue them. Variables like ${serial} work (/help variables). Esc to finish."
            });
        }
    }

    /// Whether a command can be a step here; the error is a short reason.
    pub(super) fn check_step(&self, args: &[String]) -> Result<(), String> {
        if args.first().is_some_and(|w| w == "repeat") {
            let (_, rest) = parse_repeat(args)?;
            return self.check_step(rest);
        }
        for w in args {
            for (_, _, n) in find_vars(w) {
                if is_random(n) {
                    parse_random(n)?;
                }
            }
        }
        let expanded = self.expand(args, Expand::Check);
        let words: Vec<&str> = expanded.iter().map(String::as_str).collect();
        if self.batch_mode && !self.batch_allows(&words) {
            return Err(
                "batch supports OTP programming, OATH account adding, config and reset commands."
                    .into(),
            );
        }
        let parsed = self
            .tree
            .clone()
            .try_get_matches_from(std::iter::once("ykman").chain(words.iter().copied()));
        if let Err(e) = parsed {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                return Err("help and version can't be part of a sequence.".into());
            }
            let text = e.render().to_string();
            return Err(text
                .lines()
                .map(|l| l.trim().trim_start_matches("error: "))
                .find(|l| !l.is_empty())
                .unwrap_or("invalid command")
                .to_string());
        }
        Ok(())
    }

    /// For each word of a step, the name of the command parameter it fills
    /// (e.g. `name`, `secret`, `password`), if clap can tell.
    pub(super) fn param_names(&self, step: &[String]) -> Vec<Option<String>> {
        let expanded = self.expand(step, Expand::Check);
        let mut names = vec![None; step.len()];
        let Ok(mut m) = self.tree.clone().try_get_matches_from(
            std::iter::once("ykman").chain(expanded.iter().map(String::as_str)),
        ) else {
            return names;
        };
        let mut offset = 0;
        loop {
            for id in m.ids().map(|i| i.as_str().to_string()).collect::<Vec<_>>() {
                if m.value_source(&id) != Some(clap::parser::ValueSource::CommandLine) {
                    continue;
                }
                for i in m.indices_of(&id).into_iter().flatten() {
                    // Indices count from the start of this subcommand's own arguments.
                    if let Some(slot) = (offset + i).checked_sub(1).and_then(|i| names.get_mut(i)) {
                        slot.get_or_insert_with(|| id.clone());
                    }
                }
            }
            match m.remove_subcommand() {
                Some((name, sub)) => {
                    offset += expanded
                        .iter()
                        .skip(offset)
                        .position(|w| *w == name)
                        .map_or(0, |p| p + 1);
                    m = sub;
                }
                None => break,
            }
        }
        names
    }

    /// Queue a command (without the implicit `batch` prefix) if it would be accepted.
    pub(super) fn record_step(&mut self, args: &[String]) {
        if let Err(e) = self.check_step(args) {
            self.note(&format!("Not added: {e}"));
            return;
        }
        let Some(steps) = self.recording.as_mut() else {
            return;
        };
        steps.push(args.to_vec());
    }

    /// Esc: stop recording and ask for confirmation to run what was queued.
    pub(super) fn finish_recording(&mut self) {
        let Some(steps) = self.recording.as_ref() else {
            return;
        };
        if steps.is_empty() {
            self.recording = None;
            self.note("Recording cancelled: no commands were added.");
            return;
        }
        let queued = self.recording.clone().unwrap_or_default();
        if !self.sequence_ready(&queued) {
            return;
        }
        let steps = self.recording.take().unwrap_or_default();
        self.start_sequence(steps, None);
    }

    /// Whether a YubiKey is in place to run a sequence now.
    pub(super) fn sequence_ready(&mut self, steps: &[Vec<String>]) -> bool {
        if let Some(p) = self.csv_problem(steps) {
            self.note(&p);
            false
        } else if self.batch_mode && self.devices.len() != 1 {
            self.note("Batch needs exactly one YubiKey inserted to start.");
            false
        } else if !self.batch_mode && self.active_device().is_none() {
            self.note("Insert a YubiKey to run the sequence.");
            false
        } else {
            true
        }
    }

    /// List the steps and ask for confirmation before running them.
    pub(super) fn start_sequence(&mut self, steps: Vec<Vec<String>>, name: Option<String>) {
        let what = name
            .as_ref()
            .map_or_else(String::new, |n| format!(" '{n}'"));
        self.note(&format!(
            "Sequence{what}: {} step{}",
            steps.len(),
            plural(steps.len())
        ));
        self.show_steps(&steps);
        if let Some(t) = self.csv.as_ref().filter(|t| steps_use(&steps, &t.headers)) {
            let what = if self.batch_mode {
                "one row per key"
            } else {
                "rows by /repeat, or one pass per row"
            };
            self.note(&format!("  CSV {}: {} rows, {what}", t.name, t.rows.len()));
        }
        self.remember_sequence(&steps, name);
        let serial = self.active_device().unwrap_or_default();
        let once = !self.batch_mode;
        self.generated.clear();
        self.batch = Some(self.new_batch(steps, once, serial));
    }

    // ---------- prompts ----------
}

pub(super) fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
