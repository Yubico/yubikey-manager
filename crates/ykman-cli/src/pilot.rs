//! `ykman --pilot`: an interactive TUI front-end for the regular CLI.
//!
//! The pilot never calls into command implementations directly. Every command
//! is executed by re-invoking this same binary as a child process, so the CLI
//! behaves exactly as it does outside the pilot:
//!
//! * stdout/stdin run through a pseudo-terminal, so output is line-buffered and
//!   coloured, and prompts (PIN, confirmations) work and are shown inline;
//! * logs are written by the child to a private temp file (`--log-file`) and
//!   tailed, which keeps them separate from the output.

use anyhow::{Context, Result};
use portable_pty::{ChildKiller, CommandBuilder, PtySize, native_pty_system};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use std::io::{Read, Write};
use std::process::{Command as Proc, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

const TABS: [&str; 3] = ["Mixed", "Logs", "Output"];
const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
const LEVELS: [(&str, &str); 5] = [
    ("error", "Only errors"),
    ("warning", "Warnings and errors"),
    ("info", "General progress information"),
    ("debug", "Detailed internals (default)"),
    (
        "traffic",
        "Everything, including raw APDU traffic (may contain secrets)",
    ),
];
const DEVICE_POLL: Duration = Duration::from_secs(5);
const PROMPT_DELAY: Duration = Duration::from_millis(200);
const POPUP_ROWS: usize = 8;
// Colours come from the terminal's own palette so the pilot follows the
// user's theme; "dim" text uses the DIM attribute on the default foreground.
const ACCENT: Color = Color::Green;
const TEXT: Color = Color::Reset;
const WARN: Color = Color::Yellow;
const ERROR: Color = Color::Red;
const OUTPUT_MARK: Color = Color::Blue;
const ON_ACCENT: Color = Color::Black;
const BAND: Color = Color::Indexed(235);
const SELECTED: Color = Color::Indexed(238);
const TAB_BG: Color = Color::Indexed(237);

fn dim() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

fn ansi_color(n: u8) -> Color {
    Color::Indexed(n)
}

static RUN_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Cmd,
    Out,
    Err,
    Log,
    Note,
}

struct Entry {
    kind: Kind,
    text: String,
}

enum Msg {
    Line(Kind, String),
    /// Unterminated trailing output of the child (possibly a prompt).
    Partial(String),
    Done(Option<u32>),
    Devices(Vec<Device>),
}

#[derive(Clone)]
struct Device {
    serial: u32,
    name: String,
    version: String,
}

impl Device {
    fn describe(&self) -> String {
        format!("{}  S/N: {}  F/W: {}", self.name, self.serial, self.version)
    }
}

struct Suggestion {
    /// Label shown in the popup.
    display: String,
    /// Text that replaces the word being typed when accepted.
    name: String,
    desc: String,
}

/// A single-line text editor.
#[derive(Default)]
struct Editor {
    buf: String,
    /// Cursor position in chars.
    cursor: usize,
}

impl Editor {
    fn byte_at(&self, chars: usize) -> usize {
        self.buf
            .char_indices()
            .nth(chars)
            .map_or(self.buf.len(), |(i, _)| i)
    }
    fn len(&self) -> usize {
        self.buf.chars().count()
    }
    fn set(&mut self, s: String) {
        self.cursor = s.chars().count();
        self.buf = s;
    }
    fn take(&mut self) -> String {
        self.cursor = 0;
        std::mem::take(&mut self.buf)
    }
    fn insert(&mut self, c: char) {
        let i = self.byte_at(self.cursor);
        self.buf.insert(i, c);
        self.cursor += 1;
    }
    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            let i = self.byte_at(self.cursor);
            self.buf.remove(i);
        }
    }
    fn delete(&mut self) {
        if self.cursor < self.len() {
            let i = self.byte_at(self.cursor);
            self.buf.remove(i);
        }
    }
    fn delete_word(&mut self) {
        while self.cursor > 0 && self.char_before().is_whitespace() {
            self.backspace();
        }
        while self.cursor > 0 && !self.char_before().is_whitespace() {
            self.backspace();
        }
    }
    fn char_before(&self) -> char {
        self.buf[..self.byte_at(self.cursor)]
            .chars()
            .next_back()
            .unwrap_or(' ')
    }
    fn kill_to_start(&mut self) {
        let i = self.byte_at(self.cursor);
        self.buf.drain(..i);
        self.cursor = 0;
    }
    fn kill_to_end(&mut self) {
        let i = self.byte_at(self.cursor);
        self.buf.truncate(i);
    }
    /// Handles common editing keys; returns whether the key was consumed.
    fn on_key(&mut self, key: &KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.len(),
            KeyCode::Char('u') if ctrl => self.kill_to_start(),
            KeyCode::Char('k') if ctrl => self.kill_to_end(),
            KeyCode::Char('w') if ctrl => self.delete_word(),
            KeyCode::Char(c) if !ctrl => self.insert(c),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.len(),
            _ => return false,
        }
        true
    }
}

struct App {
    tree: clap::Command,
    entries: Vec<Entry>,
    welcome: bool,
    scanned: bool,
    /// Prompt text whose echoed copy should be dropped from the output.
    skip_echo: Option<String>,
    tab: usize,
    input: Editor,
    history: Vec<String>,
    hist_pos: Option<usize>,
    sel: usize,
    scroll: usize,
    running: bool,
    partial: String,
    partial_since: Instant,
    writer: Option<Box<dyn Write + Send>>,
    killer: Option<Box<dyn ChildKiller + Send + Sync>>,
    log_level: &'static str,
    logs_expanded: bool,
    sidebar: bool,
    side_state: ListState,
    devices: Vec<Device>,
    device: Option<u32>,
    body_width: u16,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    tick: usize,
    last_poll: Instant,
    polling: bool,
    quit: bool,
}

pub fn run(tree: clap::Command) -> Result<()> {
    let mut terminal = ratatui::init();
    let res = App::new(tree).main_loop(&mut terminal);
    ratatui::restore();
    res
}

impl App {
    fn new(tree: clap::Command) -> Self {
        let (tx, rx) = mpsc::channel();
        let mut app = App {
            tree,
            entries: Vec::new(),
            welcome: true,
            scanned: false,
            skip_echo: None,
            tab: 0,
            input: Editor::default(),
            history: Vec::new(),
            hist_pos: None,
            sel: 0,
            scroll: 0,
            running: false,
            partial: String::new(),
            partial_since: Instant::now(),
            writer: None,
            killer: None,
            log_level: "debug",
            logs_expanded: true,
            sidebar: false,
            side_state: ListState::default(),
            devices: Vec::new(),
            device: None,
            body_width: 80,
            tx,
            rx,
            tick: 0,
            last_poll: Instant::now(),
            polling: false,
            quit: false,
        };
        app.refresh_devices();
        app
    }

    fn note(&mut self, text: &str) {
        self.push(Kind::Note, text.to_string());
    }

    fn push(&mut self, kind: Kind, text: String) {
        self.entries.push(Entry { kind, text });
    }

    fn main_loop(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(60))? {
                match event::read()? {
                    Event::Key(key) if key.kind != KeyEventKind::Release => self.on_key(key),
                    Event::Paste(text) => {
                        for c in text.chars().filter(|c| !c.is_control()) {
                            self.input.insert(c);
                        }
                    }
                    _ => {}
                }
            }
            self.tick = self.tick.wrapping_add(1);
            while let Ok(msg) = self.rx.try_recv() {
                self.on_msg(msg);
            }
            if !self.running && !self.polling && self.last_poll.elapsed() > DEVICE_POLL {
                self.refresh_devices();
            }
        }
        if let Some(k) = self.killer.as_mut() {
            let _ = k.kill();
        }
        Ok(())
    }

    fn on_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Line(kind, text) => {
                if kind == Kind::Out {
                    self.partial.clear();
                    if self
                        .skip_echo
                        .take_if(|p| strip_ansi(&text).trim() == p.as_str())
                        .is_some()
                    {
                        return;
                    }
                }
                self.push(kind, text);
            }
            Msg::Partial(text) => {
                if text != self.partial {
                    self.partial = text;
                    self.partial_since = Instant::now();
                }
            }
            Msg::Done(code) => {
                self.running = false;
                self.skip_echo = None;
                self.writer = None;
                self.killer = None;
                self.partial.clear();
                match code {
                    Some(0) => {}
                    Some(c) => self.note(&format!("exited with code {c}")),
                    None => self.note("terminated"),
                }
            }
            Msg::Devices(list) => {
                self.polling = false;
                self.last_poll = Instant::now();
                let before = self.active_device();
                if let Some(serial) = self.device
                    && !list.iter().any(|d| d.serial == serial)
                {
                    self.device = None;
                    let msg = match self.devices.iter().find(|d| d.serial == serial) {
                        Some(d) => format!("Removed {}", d.describe()),
                        None => format!("YubiKey {serial} was removed."),
                    };
                    self.note(&msg);
                }
                self.devices = list;
                self.announce_device_change(before);
                if !self.scanned {
                    self.scanned = true;
                    let n = self.devices.len();
                    if n > 1 {
                        self.note(&format!(
                            "{n} YubiKeys detected. Using the first one; press ← to choose another."
                        ));
                    }
                }
            }
        }
    }

    // ---------- prompts ----------

    /// The prompt text if the running command is waiting for input.
    fn prompt(&self) -> Option<&str> {
        let text = self.partial.trim_end_matches('\r');
        let last = text.chars().next_back()?;
        (self.running
            && self.writer.is_some()
            && self.partial_since.elapsed() > PROMPT_DELAY
            && (last.is_whitespace() || ":?]>".contains(last)))
        .then_some(text)
    }

    fn prompt_is_secret(prompt: &str) -> bool {
        let p = prompt.to_lowercase();
        [
            "pin",
            "puk",
            "password",
            "passphrase",
            "secret",
            "key",
            "code",
        ]
        .iter()
        .any(|w| p.contains(w))
            && !p.contains("[y/n]")
    }

    fn on_prompt_key(&mut self, key: KeyEvent, secret: bool) {
        match key.code {
            KeyCode::Enter => {
                let reply = self.input.take();
                if secret {
                    let prompt = strip_ansi(&self.partial);
                    self.skip_echo = Some(prompt.trim().to_string());
                }
                if let Some(w) = self.writer.as_mut() {
                    let _ = w.write_all(format!("{reply}\r").as_bytes());
                    let _ = w.flush();
                }
                self.partial.clear();
                self.partial_since = Instant::now();
            }
            KeyCode::Esc => self.cancel(),
            _ => {
                self.input.on_key(&key);
            }
        }
    }

    fn cancel(&mut self) {
        if let Some(k) = self.killer.as_mut() {
            let _ = k.kill();
            self.note("cancelled");
        }
    }

    // ---------- command tree ----------

    /// Walks the clap tree along the completed words, returning the deepest
    /// command reached and how many words were consumed.
    fn resolve<'a>(&'a self, words: &[&str]) -> (&'a clap::Command, usize) {
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

    fn suggestions(&self) -> Vec<Suggestion> {
        let Some(rest) = self.input.buf.strip_prefix('/') else {
            return Vec::new();
        };
        if self.input.cursor != self.input.len() {
            return Vec::new();
        }
        let trailing_space = rest.ends_with(char::is_whitespace);
        let mut words: Vec<&str> = rest.split_whitespace().collect();
        let partial = if trailing_space {
            ""
        } else {
            words.pop().unwrap_or("")
        };
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

        if words == ["log"] {
            for (name, desc) in LEVELS {
                if name.starts_with(partial) {
                    add(name, desc);
                }
            }
            return out;
        }
        if words
            .first()
            .is_some_and(|w| matches!(*w, "clear" | "device" | "help" | "quit" | "exit" | "log"))
        {
            return out;
        }
        let (node, used) = self.resolve(&words);
        if used < words.len() || partial.starts_with('-') {
            for arg in node.get_arguments() {
                let Some(long) = arg.get_long().filter(|_| !arg.is_hide_set()) else {
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
        if used == 0 {
            for (name, desc) in [
                ("clear", "Clear the screen"),
                ("device", "Choose which YubiKey to use (also: ← key)"),
                ("log", "Set the log level: /log [level]"),
                ("help", "Show keyboard shortcuts"),
                ("quit", "Exit pilot"),
            ] {
                if name.starts_with(partial) {
                    add(name, desc);
                }
            }
        }
        for sub in node.get_subcommands() {
            let name = sub.get_name();
            if sub.is_hide_set() || name == "help" || !name.starts_with(partial) {
                continue;
            }
            add(
                name,
                &sub.get_about().map(|s| s.to_string()).unwrap_or_default(),
            );
        }
        out
    }

    // ---------- input ----------

    fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            if self.running {
                self.cancel();
            } else if !self.input.buf.is_empty() {
                self.input.take();
            } else {
                self.quit = true;
            }
            return;
        }
        if ctrl && key.code == KeyCode::Char('d') && self.input.buf.is_empty() {
            self.quit = true;
            return;
        }
        if ctrl && key.code == KeyCode::Char('t') {
            self.logs_expanded = !self.logs_expanded;
            return;
        }
        if self.sidebar {
            self.on_sidebar_key(key);
            return;
        }
        if let Some(prompt) = self.prompt() {
            let secret = Self::prompt_is_secret(prompt);
            self.on_prompt_key(key, secret);
            return;
        }
        let sugg = self.suggestions();
        let popup = !sugg.is_empty();
        if popup {
            self.sel = self.sel.min(sugg.len() - 1);
        }
        match key.code {
            KeyCode::Esc => {
                self.input.take();
                self.hist_pos = None;
                self.sel = 0;
            }
            KeyCode::Left if self.input.buf.is_empty() => self.open_sidebar(),
            KeyCode::F(n) if (1..=3).contains(&n) => self.tab = n as usize - 1,
            KeyCode::Tab if popup => self.accept(&sugg[self.sel]),
            KeyCode::Right if popup && self.input.cursor == self.input.len() => {
                self.accept(&sugg[self.sel]);
            }
            KeyCode::Tab if self.input.buf.is_empty() => self.tab = (self.tab + 1) % TABS.len(),
            KeyCode::BackTab => self.tab = (self.tab + TABS.len() - 1) % TABS.len(),
            KeyCode::Up if popup => self.sel = (self.sel + sugg.len() - 1) % sugg.len(),
            KeyCode::Down if popup => self.sel = (self.sel + 1) % sugg.len(),
            KeyCode::Up => self.history_step(true),
            KeyCode::Down => self.history_step(false),
            KeyCode::PageUp => self.scroll += 10,
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Enter => {
                let partial = current_partial(&self.input.buf);
                if popup && sugg[self.sel].name != partial {
                    self.accept(&sugg[self.sel]);
                } else {
                    self.submit();
                }
            }
            _ => {
                if self.input.on_key(&key) {
                    self.sel = 0;
                }
            }
        }
    }

    fn history_step(&mut self, back: bool) {
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

    fn accept(&mut self, s: &Suggestion) {
        let keep = self.input.buf.len() - current_partial(&self.input.buf).len();
        self.input.buf.truncate(keep);
        self.input.buf.push_str(&s.name);
        self.input.buf.push(' ');
        self.input.cursor = self.input.len();
        self.sel = 0;
    }

    /// The YubiKey commands run against: the user's pick if it is still
    /// connected, otherwise the first one found.
    fn active_device(&self) -> Option<u32> {
        self.device
            .filter(|s| self.devices.iter().any(|d| d.serial == *s))
            .or_else(|| self.devices.first().map(|d| d.serial))
    }

    /// Note the newly active key if it differs from `before`.
    fn announce_device_change(&mut self, before: Option<u32>) {
        let now = self.active_device();
        if now == before || (before.is_none() && self.welcome) {
            return;
        }
        if let Some(d) = now.and_then(|s| self.devices.iter().find(|d| d.serial == s)) {
            let verb = if before.is_some() {
                "Switched to"
            } else {
                "Using"
            };
            let msg = format!("{verb} {}", d.describe());
            self.note(&msg);
        }
    }

    fn open_sidebar(&mut self) {
        self.sidebar = true;
        self.refresh_devices();
        let idx = self
            .active_device()
            .and_then(|s| self.devices.iter().position(|d| d.serial == s))
            .unwrap_or(0);
        self.side_state.select(Some(idx));
    }

    fn on_sidebar_key(&mut self, key: KeyEvent) {
        let count = self.devices.len();
        let cur = self
            .side_state
            .selected()
            .unwrap_or(0)
            .min(count.max(1) - 1);
        match key.code {
            KeyCode::Esc | KeyCode::Right | KeyCode::Left => self.sidebar = false,
            KeyCode::Up if count > 0 => self.side_state.select(Some((cur + count - 1) % count)),
            KeyCode::Down if count > 0 => self.side_state.select(Some((cur + 1) % count)),
            KeyCode::Enter => {
                let before = self.active_device();
                if let Some(d) = self.devices.get(cur) {
                    self.device = Some(d.serial);
                }
                self.announce_device_change(before);
                self.sidebar = false;
            }
            _ => {}
        }
    }

    fn submit(&mut self) {
        let line = self.input.take();
        self.sel = 0;
        self.hist_pos = None;
        let Some(rest) = line.trim().strip_prefix('/') else {
            if !line.trim().is_empty() {
                self.note("Commands start with /. Type / to see what's available.");
            }
            return;
        };
        let args = split_args(rest);
        if args.is_empty() {
            return;
        }
        self.history.push(line.trim().to_string());
        match args[0].as_str() {
            "quit" | "exit" => self.quit = true,
            "clear" => {
                self.entries.clear();
                self.welcome = false;
                self.scroll = 0;
            }
            "device" => self.open_sidebar(),
            "help" => self.help(),
            "log" => self.set_log_level(args.get(1).map(String::as_str)),
            _ if self.running => self.note("A command is already running."),
            _ => self.spawn(line.trim(), args),
        }
    }

    fn help(&mut self) {
        for l in [
            "/            browse commands; Tab/→ complete, ↑/↓ select, Enter run",
            "←            (empty prompt) choose which YubiKey to use",
            "Tab, F1-F3   switch between Mixed, Logs and Output",
            "Ctrl+T       expand/collapse the log blocks in the Mixed view",
            "PgUp/PgDn    scroll;  ↑/↓ browse history",
            "/log [level] change log verbosity (error, warning, info, debug, traffic)",
            "Ctrl+C       cancel running command / clear input / quit",
            "Esc          cancel a prompt or clear input",
        ] {
            self.note(l);
        }
    }

    fn set_log_level(&mut self, level: Option<&str>) {
        match level.and_then(|l| LEVELS.iter().find(|(n, _)| *n == l)) {
            Some((name, _)) => {
                self.log_level = name;
                self.note(&format!("log level set to {name}"));
                if *name == "traffic" {
                    self.note("Warning: traffic logs may include sensitive data.");
                }
            }
            None => self.note(&format!("usage: /log <level>; current: {}", self.log_level)),
        }
    }

    // ---------- background work ----------

    fn refresh_devices(&mut self) {
        self.polling = true;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let devices = Proc::new(exe())
                .arg("list")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .map(|o| parse_devices(&String::from_utf8_lossy(&o.stdout)))
                .unwrap_or_default();
            let _ = tx.send(Msg::Devices(devices));
        });
    }

    fn spawn(&mut self, shown: &str, args: Vec<String>) {
        self.scroll = 0;
        self.push(Kind::Cmd, shown.to_string());
        if let Err(e) = self.try_spawn(args) {
            self.push(Kind::Err, format!("failed to start: {e:#}"));
        }
    }

    fn try_spawn(&mut self, args: Vec<String>) -> Result<()> {
        let log_path = std::env::temp_dir().join(format!(
            "ykman-pilot-{}-{}.log",
            std::process::id(),
            RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_file(&log_path).context("creating log file")?;

        let mut cmd = CommandBuilder::new(exe());
        cmd.args(["--log-level", self.log_level, "--log-file"]);
        cmd.arg(&log_path);
        let own_device = args.iter().any(|a| a == "-d" || a == "--device");
        if let Some(serial) = self.active_device()
            && args[0] != "list"
            && !own_device
        {
            cmd.args(["--device", &serial.to_string()]);
        }
        cmd.args(&args);

        let pair = native_pty_system().openpty(PtySize {
            rows: 24,
            cols: self.body_width.max(40),
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut child = match pair.slave.spawn_command(cmd) {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_file(&log_path);
                return Err(e);
            }
        };
        drop(pair.slave);
        let reader = pair.master.try_clone_reader()?;
        self.writer = Some(pair.master.take_writer()?);
        self.killer = Some(child.clone_killer());
        self.running = true;
        self.partial.clear();

        let tx = self.tx.clone();
        let out = std::thread::spawn(move || pump_pty(reader, tx));

        let stop = Arc::new(AtomicBool::new(false));
        let tail = {
            let (stop, tx, path) = (stop.clone(), self.tx.clone(), log_path.clone());
            std::thread::spawn(move || tail_log(&path, &stop, &tx))
        };

        let tx = self.tx.clone();
        let master = pair.master;
        std::thread::spawn(move || {
            let code = child.wait().ok().map(|s| s.exit_code());
            drop(master);
            let _ = out.join();
            stop.store(true, Ordering::Relaxed);
            let _ = tail.join();
            let _ = std::fs::remove_file(&log_path);
            let _ = tx.send(Msg::Done(code));
        });
        Ok(())
    }

    // ---------- drawing ----------

    fn draw(&mut self, f: &mut Frame) {
        let mut area = f.area();
        // The device panel spans the full height; everything else sits to its right.
        if self.sidebar {
            let w = 37.min(area.width.saturating_sub(10));
            let side = Rect::new(area.x + 1, area.y, w.saturating_sub(1), area.height);
            self.draw_sidebar(f, side);
            area = Rect::new(area.x + w, area.y, area.width - w, area.height);
        }
        let rows = Layout::vertical([
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);
        // One column of padding on both sides, except for the full-width input band.
        let pad = |r: Rect| Rect::new(r.x + 1, r.y, r.width.saturating_sub(2), r.height);
        let top = if self.sidebar {
            Rect::new(
                rows[0].x + 1,
                rows[0].y,
                rows[0].width.saturating_sub(1),
                rows[0].height,
            )
        } else {
            pad(rows[0])
        };
        let main = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(3),
        ])
        .split(top);

        let mut tab_spans = Vec::new();
        for (i, t) in TABS.iter().enumerate() {
            let style = if i == self.tab {
                Style::new()
                    .fg(ON_ACCENT)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                dim().bg(TAB_BG)
            };
            tab_spans.push(Span::styled(format!(" {t} "), style));
            tab_spans.push(Span::raw(" "));
        }
        f.render_widget(Paragraph::new(Line::from(tab_spans)), main[0]);

        self.body_width = main[2].width.saturating_sub(2);
        self.draw_log(f, main[2]);
        self.draw_input(f, rows[1]);
        self.draw_status(f, pad(rows[2]));
        self.draw_popup(f, rows[1]);
    }

    fn draw_sidebar(&mut self, f: &mut Frame, area: Rect) {
        let active = self.active_device();
        let mut items: Vec<ListItem> = self
            .devices
            .iter()
            .map(|d| {
                let mark = if active == Some(d.serial) { "●" } else { " " };
                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(format!(" {mark} "), Style::new().fg(ACCENT)),
                        Span::styled(d.name.clone(), Style::new().add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(Span::styled(
                        format!("   S/N: {}  F/W: {}", d.serial, d.version),
                        dim(),
                    )),
                ])
            })
            .collect();
        if items.is_empty() {
            items.push(ListItem::new(Span::styled("  Insert a YubiKey", dim())));
        }
        let list = List::new(items)
            .block(
                ratatui::widgets::Block::new()
                    .borders(ratatui::widgets::Borders::RIGHT)
                    .border_style(dim())
                    .padding(ratatui::widgets::Padding::new(0, 1, 2, 0)),
            )
            .highlight_style(Style::new().bg(SELECTED));
        f.render_stateful_widget(list, area, &mut self.side_state);
    }

    fn draw_log(&mut self, f: &mut Frame, area: Rect) {
        let width = area.width.saturating_sub(2).max(1) as usize;
        let mut lines: Vec<Line> = Vec::new();
        let live = (!self.partial.is_empty() && self.prompt().is_none()).then(|| Entry {
            kind: Kind::Out,
            text: self.partial.clone(),
        });
        // Group entries per command run so logs can precede the output.
        struct Run<'a> {
            cmd: Option<&'a Entry>,
            logs: Vec<&'a Entry>,
            rest: Vec<&'a Entry>,
        }
        let mut runs = vec![Run {
            cmd: None,
            logs: Vec::new(),
            rest: Vec::new(),
        }];
        for e in self.entries.iter().chain(live.as_ref()) {
            match e.kind {
                Kind::Cmd => runs.push(Run {
                    cmd: Some(e),
                    logs: Vec::new(),
                    rest: Vec::new(),
                }),
                Kind::Log => runs.last_mut().expect("non-empty").logs.push(e),
                _ => runs.last_mut().expect("non-empty").rest.push(e),
            }
        }
        if self.welcome {
            self.welcome_lines(width, &mut lines);
        }
        let mixed = self.tab == 0;
        let show_out = self.tab != 1;
        let show_logs = self.tab != 2;
        let last_run = runs.len() - 1;
        let mut prev: Option<u8> = None;
        let mut gap = |lines: &mut Vec<Line<'static>>, group: u8| {
            if prev.is_some_and(|p| p != group) {
                lines.push(Line::from(""));
            }
            prev = Some(group);
        };
        for (n, run) in runs.iter().enumerate() {
            if let Some(cmd) = run.cmd {
                gap(&mut lines, 0);
                render_entry(cmd, width, &mut lines);
            }
            if show_logs && !run.logs.is_empty() {
                gap(&mut lines, 1);
                if mixed && !self.logs_expanded {
                    let live_run = self.running && n == last_run;
                    let last = run.logs.last().map_or("", |e| e.text.as_str());
                    lines.push(log_summary(
                        run.logs.len(),
                        last,
                        live_run,
                        self.tick,
                        width,
                    ));
                } else {
                    if mixed {
                        lines.push(Line::from(Span::styled(
                            "▼ Logs (Ctrl+T to collapse)",
                            dim().add_modifier(Modifier::ITALIC),
                        )));
                    }
                    for e in &run.logs {
                        render_entry(e, width, &mut lines);
                    }
                }
            }
            let mut marked = false;
            for e in &run.rest {
                let is_out = matches!(e.kind, Kind::Out | Kind::Err);
                if is_out && !show_out {
                    continue;
                }
                gap(&mut lines, if is_out { 2 } else { 3 });
                let start = lines.len();
                render_entry(e, width, &mut lines);
                if is_out && !marked {
                    marked = true;
                    lines[start].spans[0] = Span::styled("● ", Style::new().fg(OUTPUT_MARK));
                }
            }
        }
        let h = area.height as usize;
        let max_scroll = lines.len().saturating_sub(h);
        self.scroll = self.scroll.min(max_scroll);
        let start = lines.len().saturating_sub(h + self.scroll);
        let shown: Vec<Line> = lines.into_iter().skip(start).take(h).collect();
        f.render_widget(Paragraph::new(shown), area);
    }

    fn welcome_lines(&self, width: usize, lines: &mut Vec<Line<'static>>) {
        let device = match self
            .active_device()
            .and_then(|s| self.devices.iter().find(|d| d.serial == s))
        {
            Some(d) => Line::from(vec![
                Span::styled("● ", Style::new().fg(ACCENT)),
                Span::styled(
                    format!("{} ({})", d.name, d.version),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  S/N: {}", d.serial), dim()),
            ]),
            None => Line::from(vec![
                Span::styled("○ ", Style::new().fg(WARN)),
                Span::styled(
                    "No YubiKey detected. Insert one to get started.",
                    Style::new().fg(WARN),
                ),
            ]),
        };
        let body = vec![
            Line::from(vec![
                Span::styled(
                    "ykman ",
                    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(env!("CARGO_PKG_VERSION"), dim()),
            ]),
            Line::from(Span::styled(
                "Configure your YubiKey via the command line.",
                dim(),
            )),
            Line::from(""),
            device,
        ];
        let inner = body
            .iter()
            .map(Line::width)
            .max()
            .unwrap_or(0)
            .max(40)
            .min(width.saturating_sub(4).max(1));
        let border = dim();
        lines.push(Line::from(Span::styled(
            format!("╭{}╮", "─".repeat(inner + 2)),
            border,
        )));
        for l in body {
            let pad = inner.saturating_sub(l.width());
            let mut spans = vec![Span::styled("│ ", border)];
            spans.extend(l.spans);
            spans.push(Span::raw(" ".repeat(pad)));
            spans.push(Span::styled(" │", border));
            lines.push(Line::from(spans));
        }
        lines.push(Line::from(Span::styled(
            format!("╰{}╯", "─".repeat(inner + 2)),
            border,
        )));
        lines.push(Line::from(""));
        let mut tips: Vec<(&str, &str)> = vec![
            ("/", "browse commands"),
            ("←", "switch YubiKey"),
            ("Ctrl+T", "toggle logs"),
            ("/help", "all keys"),
        ];
        if self.active_device().is_some() {
            tips.insert(1, ("/info", "see what your key supports"));
        }
        for (k, d) in tips {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{k:<8}"), Style::new().fg(ACCENT)),
                Span::styled(d, dim()),
            ]));
        }
        lines.push(Line::from(""));
    }

    fn draw_input(&self, f: &mut Frame, area: Rect) {
        let band = Style::new().bg(BAND);
        f.render_widget(Block::new().style(band), area);
        let row = Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), 1);

        let (label, text, ghost) = match self.prompt() {
            Some(prompt) => {
                let prompt = strip_ansi(prompt);
                let shown = if Self::prompt_is_secret(&prompt) {
                    "•".repeat(self.input.len())
                } else {
                    self.input.buf.clone()
                };
                (prompt, shown, String::new())
            }
            None => {
                let sugg = self.suggestions();
                let partial = current_partial(&self.input.buf);
                let ghost = sugg
                    .get(self.sel.min(sugg.len().saturating_sub(1)))
                    .and_then(|s| s.name.strip_prefix(partial))
                    .unwrap_or("")
                    .to_string();
                ("❯ ".to_string(), self.input.buf.clone(), ghost)
            }
        };
        let mut spans = vec![Span::styled(
            label.clone(),
            Style::new().fg(ACCENT).bg(BAND),
        )];
        if text.is_empty() && ghost.is_empty() && self.prompt().is_none() {
            spans.push(Span::styled("Type / for commands", dim().bg(BAND)));
        }
        spans.push(Span::styled(text, band));
        spans.push(Span::styled(ghost, dim().bg(BAND)));
        f.render_widget(Paragraph::new(Line::from(spans)).style(band), row);
        if !self.sidebar {
            let x = row.x + label.chars().count() as u16 + self.input.cursor as u16;
            f.set_cursor_position((x.min(row.right().saturating_sub(1)), row.y));
        }
    }

    fn draw_status(&self, f: &mut Frame, area: Rect) {
        let left = if self.running {
            let msg = if self.prompt().is_some() {
                "waiting for input"
            } else {
                "running…"
            };
            vec![Span::styled(
                format!("{} {msg}", SPINNER[self.tick / 2 % SPINNER.len()]),
                Style::new().fg(WARN),
            )]
        } else {
            vec![
                Span::styled("←", dim().add_modifier(Modifier::BOLD)),
                Span::styled(" devices", dim()),
            ]
        };
        let mut spans = left;
        spans.extend([
            Span::styled(" · ", dim()),
            Span::styled("tab", dim().add_modifier(Modifier::BOLD)),
            Span::styled(" next tab · ", dim()),
            Span::styled("/help", dim().add_modifier(Modifier::BOLD)),
            Span::styled(" show help", dim()),
        ]);
        f.render_widget(Paragraph::new(Line::from(spans)), area);

        let dev = match self.active_device() {
            Some(s) => match self.devices.iter().find(|d| d.serial == s) {
                Some(d) => format!("{} ({})", d.name, d.version),
                None => format!("YubiKey {s}"),
            },
            None => "no YubiKey detected".to_string(),
        };
        let right = Line::from(Span::styled(
            format!("{dev} · log: {}", self.log_level),
            dim(),
        ))
        .right_aligned();
        f.render_widget(Paragraph::new(right), area);
    }

    fn draw_popup(&self, f: &mut Frame, input_area: Rect) {
        let sugg = self.suggestions();
        if sugg.is_empty() || self.sidebar || self.prompt().is_some() {
            return;
        }
        let h = (sugg.len().min(POPUP_ROWS) as u16).min(input_area.y);
        if h == 0 {
            return;
        }
        let area = Rect::new(input_area.x, input_area.y - h, input_area.width, h);
        let name_w = sugg
            .iter()
            .map(|s| s.display.chars().count())
            .max()
            .unwrap_or(0)
            + 3;
        let sel = self.sel.min(sugg.len() - 1);
        let items: Vec<ListItem> = sugg
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let is_sel = i == sel;
                let name_style = if is_sel {
                    Style::new().fg(TEXT).add_modifier(Modifier::BOLD)
                } else {
                    Style::new().fg(TEXT)
                };
                let desc_style = if is_sel { Style::new() } else { dim() };
                ListItem::new(Line::from(vec![
                    Span::raw(" "),
                    Span::styled(if is_sel { "❯ " } else { "  " }, Style::new().fg(ACCENT)),
                    Span::styled(format!("{:<name_w$}", s.display), name_style),
                    Span::styled(s.desc.clone(), desc_style),
                ]))
            })
            .collect();
        let mut state = ListState::default().with_selected(Some(sel));
        f.render_widget(Clear, area);
        f.render_stateful_widget(
            List::new(items).highlight_style(Style::new().bg(SELECTED)),
            area,
            &mut state,
        );
    }
}

// ---------- child output plumbing ----------

/// Reads the pty, emitting complete lines plus the unterminated remainder.
fn pump_pty(mut reader: Box<dyn Read + Send>, tx: Sender<Msg>) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buf[..n]);
        while let Some(i) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=i).collect();
            let text = String::from_utf8_lossy(&line[..i])
                .trim_end_matches('\r')
                .to_string();
            let _ = tx.send(Msg::Line(Kind::Out, text));
        }
        let _ = tx.send(Msg::Partial(String::from_utf8_lossy(&pending).into_owned()));
    }
    if !pending.is_empty() {
        let _ = tx.send(Msg::Line(
            Kind::Out,
            String::from_utf8_lossy(&pending).into_owned(),
        ));
    }
}

/// Follows the child's log file, emitting each completed line.
fn tail_log(path: &std::path::Path, stop: &AtomicBool, tx: &Sender<Msg>) {
    use std::io::{Seek, SeekFrom};
    let mut pos = 0u64;
    let mut pending = String::new();
    loop {
        let finished = stop.load(Ordering::Relaxed);
        if let Ok(mut file) = std::fs::File::open(path)
            && file.seek(SeekFrom::Start(pos)).is_ok()
        {
            let mut chunk = Vec::new();
            if let Ok(n) = file.read_to_end(&mut chunk) {
                pos += n as u64;
                pending.push_str(&String::from_utf8_lossy(&chunk));
            }
        }
        while let Some(i) = pending.find('\n') {
            let line: String = pending.drain(..=i).collect();
            let _ = tx.send(Msg::Line(Kind::Log, line.trim_end().to_string()));
        }
        if finished {
            if !pending.trim().is_empty() {
                let _ = tx.send(Msg::Line(Kind::Log, pending.trim_end().to_string()));
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}

fn create_private_file(path: &std::path::Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map(|_| ())
}

// ---------- rendering helpers ----------

/// One-line stand-in for a collapsed block of log lines.
fn log_summary(count: usize, last: &str, live: bool, tick: usize, width: usize) -> Line<'static> {
    let dim = dim();
    let head = if live {
        format!("{} Working…", SPINNER[tick / 2 % SPINNER.len()])
    } else {
        format!("▶ {count} log lines")
    };
    let used = head.chars().count() + 2;
    let tail: String = last.chars().take(width.saturating_sub(used + 24)).collect();
    let hint = if live { "" } else { " (Ctrl+T to expand)" };
    Line::from(vec![
        Span::styled(head, dim.add_modifier(Modifier::ITALIC)),
        Span::styled(format!("{hint}  {tail}"), dim),
    ])
}

fn render_entry(e: &Entry, width: usize, lines: &mut Vec<Line<'static>>) {
    let pstyle_cmd = Style::new().fg(ACCENT);
    let (prefix, base) = match e.kind {
        Kind::Cmd => ("● ", Style::new().add_modifier(Modifier::BOLD)),
        Kind::Out => ("  ", Style::new()),
        Kind::Err => ("  ", Style::new().fg(ERROR)),
        Kind::Log => ("│ ", dim()),
        Kind::Note => ("  ", Style::new().fg(WARN).add_modifier(Modifier::ITALIC)),
    };
    let cells = if matches!(e.kind, Kind::Out | Kind::Err) {
        parse_ansi(&e.text, base)
    } else {
        e.text
            .chars()
            .filter(|c| !c.is_control())
            .map(|c| (c, base))
            .collect()
    };
    let chunk = width.saturating_sub(2).max(1);
    if cells.is_empty() {
        lines.push(Line::from(Span::styled(
            prefix,
            if e.kind == Kind::Cmd {
                pstyle_cmd
            } else {
                base
            },
        )));
        return;
    }
    for (i, part) in cells.chunks(chunk).enumerate() {
        let mut spans = vec![Span::styled(
            if i == 0 || e.kind == Kind::Log {
                prefix
            } else {
                "  "
            },
            if e.kind == Kind::Cmd {
                pstyle_cmd
            } else {
                base
            },
        )];
        let mut run = String::new();
        let mut run_style = part[0].1;
        for (c, st) in part {
            if *st != run_style {
                spans.push(Span::styled(std::mem::take(&mut run), run_style));
                run_style = *st;
            }
            run.push(*c);
        }
        spans.push(Span::styled(run, run_style));
        lines.push(Line::from(spans));
    }
}

/// Converts text with ANSI SGR codes into styled chars. Other escape
/// sequences are dropped, and a carriage return discards the text before it.
fn parse_ansi(text: &str, base: Style) -> Vec<(char, Style)> {
    let mut out: Vec<(char, Style)> = Vec::new();
    let mut style = base;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    let mut params = String::new();
                    let mut fin = ' ';
                    for n in chars.by_ref() {
                        if ('@'..='~').contains(&n) {
                            fin = n;
                            break;
                        }
                        params.push(n);
                    }
                    if fin == 'm' {
                        style = apply_sgr(&params, style, base);
                    }
                } else {
                    chars.next();
                }
            }
            '\r' => out.clear(),
            '\t' => out.extend(std::iter::repeat_n((' ', style), 4)),
            c if c.is_control() => {}
            c => out.push((c, style)),
        }
    }
    out
}

fn apply_sgr(params: &str, mut style: Style, base: Style) -> Style {
    let nums: Vec<u16> = params
        .split([';', ':'])
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    let mut i = 0;
    while i < nums.len() {
        match nums[i] {
            0 => style = base,
            1 => style = style.add_modifier(Modifier::BOLD),
            2 => style = style.add_modifier(Modifier::DIM),
            3 => style = style.add_modifier(Modifier::ITALIC),
            4 => style = style.add_modifier(Modifier::UNDERLINED),
            22 => style = style.remove_modifier(Modifier::BOLD | Modifier::DIM),
            23 => style = style.remove_modifier(Modifier::ITALIC),
            24 => style = style.remove_modifier(Modifier::UNDERLINED),
            n @ 30..=37 => style = style.fg(ansi_color((n - 30) as u8)),
            n @ 90..=97 => style = style.fg(ansi_color((n - 90 + 8) as u8)),
            n @ 40..=47 => style = style.bg(ansi_color((n - 40) as u8)),
            n @ 100..=107 => style = style.bg(ansi_color((n - 100 + 8) as u8)),
            39 => style.fg = base.fg,
            49 => style.bg = base.bg,
            n @ (38 | 48) => {
                let color = match nums.get(i + 1) {
                    Some(5) if i + 2 < nums.len() => {
                        i += 2;
                        Some(ansi_color(nums[i] as u8))
                    }
                    Some(2) if i + 4 < nums.len() => {
                        i += 4;
                        Some(Color::Rgb(
                            nums[i - 2] as u8,
                            nums[i - 1] as u8,
                            nums[i] as u8,
                        ))
                    }
                    _ => None,
                };
                if let Some(c) = color {
                    style = if n == 38 { style.fg(c) } else { style.bg(c) };
                }
            }
            _ => {}
        }
        i += 1;
    }
    style
}

fn strip_ansi(text: &str) -> String {
    parse_ansi(text, Style::new())
        .into_iter()
        .map(|(c, _)| c)
        .collect()
}

// ---------- misc helpers ----------

fn exe() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| "ykman".into())
}

/// The word currently being typed, without the leading `/` (empty if the
/// input ends in whitespace).
fn current_partial(input: &str) -> &str {
    if input.ends_with(char::is_whitespace) {
        ""
    } else {
        let word = input.rsplit(char::is_whitespace).next().unwrap_or("");
        word.strip_prefix('/').unwrap_or(word)
    }
}

/// Minimal shell-like splitting: whitespace separated, with '...' and "..." quoting.
fn split_args(s: &str) -> Vec<String> {
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
fn parse_devices(stdout: &str) -> Vec<Device> {
    stdout
        .lines()
        .filter_map(|line| {
            let (head, serial) = line.rsplit_once("Serial:")?;
            let serial = serial.trim().parse().ok()?;
            let (name, rest) = head.split_once('(')?;
            let version = rest.split_once(')')?.0;
            Some(Device {
                serial,
                name: name.trim().to_string(),
                version: version.to_string(),
            })
        })
        .collect()
}
