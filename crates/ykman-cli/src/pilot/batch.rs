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
}

/// Repeat one command across keys, replaying the first run's answers.
pub(super) struct Batch {
    pub(super) args: Vec<String>,
    pub(super) shown: String,
    pub(super) phase: BatchPhase,
    pub(super) round: usize,
    /// The current round runs on the same key as the previous one.
    pub(super) same_key: bool,
    /// Serial of the key the current round runs on.
    pub(super) current: u32,
    pub(super) results: Vec<(u32, bool)>,
    /// (normalised prompt, reply) recorded during round 1; memory only.
    pub(super) answers: Vec<(String, String)>,
    pub(super) used: Vec<bool>,
}

/// Prompt text without digits, so prompts that mention a serial still match.
pub(super) fn norm_prompt(p: &str) -> String {
    strip_ansi(p)
        .trim()
        .chars()
        .filter(|c| !c.is_ascii_digit())
        .collect()
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
        self.batch
            .as_ref()
            .is_some_and(|b| matches!(b.phase, BatchPhase::Waiting { .. } | BatchPhase::SameKey(_)))
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
        let (node, used) = self.resolve(&words);
        let force = node
            .get_arguments()
            .find(|a| a.get_long() == Some("force"))
            .filter(|a| {
                !args
                    .iter()
                    .any(|x| x == "--force" || a.get_short().is_some_and(|c| x == &format!("-{c}")))
            })
            .is_some();
        let is_reset = used > 0 && words[used - 1] == "reset";
        if !is_reset && !BATCH_ALLOWED.iter().any(|p| words.starts_with(p)) {
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
            "Batch: /{} on {}.{} Answers from the first run are repeated on every key.",
            args.join(" "),
            name,
            if force { " Runs with --force." } else { "" }
        );
        self.note(&msg);
        let mut run_args = args.to_vec();
        if force {
            run_args.push("--force".to_string());
        }
        self.batch = Some(Batch {
            args: run_args,
            shown: format!("/batch {}", args.join(" ")),
            phase: BatchPhase::Confirm,
            round: 0,
            same_key: false,
            current: serial,
            results: Vec::new(),
            answers: Vec::new(),
            used: Vec::new(),
        });
    }

    pub(super) fn begin_round(&mut self, serial: u32) {
        let Some(b) = self.batch.as_mut() else {
            return;
        };
        b.round += 1;
        b.same_key = b.results.iter().any(|r| r.0 == serial);
        b.current = serial;
        b.phase = BatchPhase::Running;
        b.used = vec![false; b.answers.len()];
        let (shown, args, round) = (b.shown.clone(), b.args.clone(), b.round);
        self.device = Some(serial);
        self.note(&format!("Batch round {round}: YubiKey S/N {serial}"));
        self.spawn(&shown, args);
    }

    pub(super) fn end_batch(&mut self, title: &str) {
        let Some(b) = self.batch.take() else {
            return;
        };
        let ok = b.results.iter().filter(|r| r.1).count();
        let failed = b.results.len() - ok;
        self.note(&format!("{title}: {ok} succeeded, {failed} failed"));
        for (serial, good) in b.results {
            self.note(&format!("  {} S/N {serial}", if good { "✓" } else { "✗" }));
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

    /// Answer prompts of later rounds with the replies recorded in round 1.
    pub(super) fn auto_reply(&mut self) {
        let Some(b) = self.batch.as_ref() else {
            return;
        };
        if b.round < 2 || !matches!(b.phase, BatchPhase::Running) {
            return;
        }
        let Some(raw) = self.prompt().map(str::to_string) else {
            return;
        };
        let norm = norm_prompt(&raw);
        let Some(b) = self.batch.as_mut() else {
            return;
        };
        let Some(i) = (0..b.answers.len()).find(|&i| !b.used[i] && b.answers[i].0 == norm) else {
            return;
        };
        b.used[i] = true;
        let reply = b.answers[i].1.clone();
        let secret = self.secret_prompt(&raw);
        self.send_reply(&reply, secret);
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
            BatchPhase::Running => None,
        }
    }

    pub(super) fn batch_label(&self) -> Option<String> {
        let b = self.batch.as_ref()?;
        let ok = b.results.iter().filter(|r| r.1).count();
        let tally = format!("Batch {ok} ok, {} failed", b.results.len() - ok);
        Some(match b.phase {
            BatchPhase::Confirm => "Press Enter to start the batch, Esc to cancel".into(),
            BatchPhase::Running if b.same_key => format!(
                "{tally} · round {} running · warning: this YubiKey was already used in this batch",
                b.round
            ),
            BatchPhase::Running => format!("{tally} · round {} running", b.round),
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

    // ---------- prompts ----------
}
