use anyhow::{Context, Result};
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};
use ratatui::{DefaultTerminal, Frame};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod batch;
mod commands;
mod runner;
mod state;
mod ui;

use self::batch::*;
use self::commands::*;
use self::runner::*;
use self::state::*;
use self::ui::*;

const DEVICE_POLL: Duration = Duration::from_secs(5);
const PROMPT_DELAY: Duration = Duration::from_millis(200);
const MAX_ENTRIES: usize = 20_000;
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Cmd,
    Out,
    Err,
    Log,
    Note,
    /// A command that exited with an error.
    Fail,
    /// A batch round that completed successfully.
    Success,
    /// A batch round that failed.
    RoundFail,
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
        format!("{} ({})  S/N: {}", self.name, self.version, self.serial)
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

/// Incremental find in the log view (Ctrl+F).
struct Search {
    query: String,
    idx: usize,
    total: usize,
    jump: bool,
}

/// Clickable regions recorded while drawing, in screen coordinates.
#[derive(Default)]
struct Hits {
    tabs: Vec<(Rect, usize)>,
    toggles: Vec<(Rect, usize)>,
    side_items: Rect,
    log: Rect,
}

struct App {
    tree: clap::Command,
    entries: Vec<Entry>,
    welcome: bool,
    scanned: bool,
    /// Prompt text whose echoed copy should be dropped from the output.
    skip_echo: Option<String>,
    tab: usize,
    /// Tab last written to the state file.
    saved_tab: usize,
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
    master: Option<Arc<Mutex<Box<dyn MasterPty + Send>>>>,
    /// Selected answer of a yes/no prompt; `None` means the prompt's default.
    yn_sel: Option<usize>,
    /// Commands persisted across sessions (command path only, never arguments).
    saved: Vec<String>,
    log_level: &'static str,
    logs_expanded: bool,
    /// Runs whose log block differs from the global expanded/collapsed default.
    toggled: HashSet<usize>,
    hits: Hits,
    search: Option<Search>,
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
    batch: Option<Batch>,
    /// Batch mode: typed commands are repeated on key after key.
    batch_mode: bool,
    quit: bool,
}

pub fn run(tree: clap::Command) -> Result<()> {
    let mut terminal = ratatui::init();
    if let Some((bg, fg)) = query_terminal_colors() {
        let _ = SHADES.set(shades_from(bg, fg));
    }
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = ratatui::crossterm::execute!(std::io::stdout(), DisableMouseCapture);
        prev_hook(info);
    }));
    let _ = ratatui::crossterm::execute!(std::io::stdout(), EnableMouseCapture);
    let res = App::new(tree).main_loop(&mut terminal);
    let _ = ratatui::crossterm::execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    res
}

impl App {
    fn new(mut tree: clap::Command) -> Self {
        // Building resolves conflict declarations in both directions.
        tree.build();
        let (tx, rx) = mpsc::channel();
        let mut app = App {
            tree,
            entries: Vec::new(),
            welcome: true,
            scanned: false,
            skip_echo: None,
            tab: 0,
            saved_tab: 0,
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
            master: None,
            yn_sel: None,
            saved: Vec::new(),
            log_level: "debug",
            logs_expanded: true,
            toggled: HashSet::new(),
            hits: Hits::default(),
            search: None,
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
            batch: None,
            batch_mode: false,
            quit: false,
        };
        let state = load_state();
        if let Some(level) = state.level {
            app.log_level = level;
        }
        app.tab = state.tab;
        app.saved_tab = state.tab;
        app.history = state.history.clone();
        app.saved = state.history;
        app.refresh_devices();
        app
    }

    fn note(&mut self, text: &str) {
        self.push(Kind::Note, text.to_string());
    }

    fn push(&mut self, kind: Kind, text: String) {
        // Bound memory; run indices shift when old entries are dropped.
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.drain(..MAX_ENTRIES / 10);
            self.toggled.clear();
        }
        self.entries.push(Entry { kind, text });
    }

    fn main_loop(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        let mut dirty = true;
        while !self.quit {
            if dirty || self.running || self.batch_wait_msg().is_some() {
                terminal.draw(|f| self.draw(f))?;
                dirty = false;
            }
            let wait = if self.running { 60 } else { 200 };
            if event::poll(Duration::from_millis(wait))? {
                dirty = true;
                match event::read()? {
                    Event::Key(key) if key.kind != KeyEventKind::Release => self.on_key(key),
                    Event::Mouse(m) => self.on_mouse(m),
                    Event::Paste(text) => {
                        for c in text.chars().filter(|c| !c.is_control()) {
                            self.input.insert(c);
                        }
                    }
                    _ => {}
                }
            }
            if self.tab != self.saved_tab {
                self.save();
            }
            self.tick = self.tick.wrapping_add(1);
            while let Ok(msg) = self.rx.try_recv() {
                dirty = true;
                self.on_msg(msg);
            }
            let interval = if self.batch_waiting() {
                BATCH_POLL
            } else {
                DEVICE_POLL
            };
            if !self.running && !self.polling && self.last_poll.elapsed() > interval {
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
                self.master = None;
                self.yn_sel = None;
                self.writer = None;
                self.killer = None;
                self.partial.clear();
                let mut round_msg = None;
                if let Some(b) = self.batch.as_mut()
                    && matches!(b.phase, BatchPhase::Running)
                {
                    let good = code == Some(0);
                    b.results.push((b.current, good));
                    let ok = b.results.iter().filter(|r| r.1).count();
                    let tally = format!("{ok} ok, {} failed", b.results.len() - ok);
                    round_msg = Some(if good {
                        (
                            Kind::Success,
                            format!("Round {} done on S/N {} · {tally}", b.round, b.current),
                        )
                    } else {
                        (
                            Kind::RoundFail,
                            format!("Round {} failed on S/N {} · {tally}", b.round, b.current),
                        )
                    });
                    b.phase = BatchPhase::Waiting {
                        prev: b.current,
                        absent: false,
                    };
                }
                match code {
                    Some(0) => {}
                    Some(c) => self.push(Kind::Fail, format!("exited with code {c}")),
                    None => self.note("terminated"),
                }
                if let Some((kind, text)) = round_msg {
                    self.push(kind, text);
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
                }
                // The batch has its own progress messages.
                if self.scanned && self.batch.is_none() {
                    let gone: Vec<String> = self
                        .devices
                        .iter()
                        .filter(|d| !list.iter().any(|n| n.serial == d.serial))
                        .map(|d| format!("Removed {}", d.describe()))
                        .collect();
                    let new: Vec<String> = list
                        .iter()
                        .filter(|n| !self.devices.iter().any(|d| d.serial == n.serial))
                        .map(|d| format!("Inserted {}", d.describe()))
                        .collect();
                    for msg in gone.into_iter().chain(new) {
                        self.note(&msg);
                    }
                }
                self.devices = list;
                // Keep the first key found as the active one so a changing
                // list order (e.g. with NFC readers) cannot switch it.
                if self.device.is_none() {
                    self.device = self.devices.first().map(|d| d.serial);
                }
                self.announce_device_change(before);
                self.batch_devices();
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

    // ---------- batch mode ----------

    fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            if self.running {
                self.cancel();
            } else if !self.input.buf.is_empty() {
                self.input.take();
            } else if self.batch.is_some() {
                self.end_batch("Batch finished");
            } else if self.batch_mode {
                self.leave_batch_mode();
            } else {
                self.quit = true;
            }
            return;
        }
        if ctrl && key.code == KeyCode::Char('d') && self.input.buf.is_empty() {
            self.quit = true;
            return;
        }
        if !self.running && self.input.buf.is_empty() && !self.sidebar {
            let confirming = self
                .batch
                .as_ref()
                .is_some_and(|b| matches!(b.phase, BatchPhase::Confirm));
            let same = self.batch.as_ref().and_then(|b| match b.phase {
                BatchPhase::SameKey(s) => Some(s),
                _ => None,
            });
            match key.code {
                KeyCode::Enter if same.is_some() => {
                    if let Some(s) = same {
                        self.begin_round(s);
                    }
                    return;
                }
                KeyCode::Enter if confirming => {
                    if let [d] = self.devices.as_slice() {
                        let serial = d.serial;
                        self.begin_round(serial);
                    } else {
                        self.end_batch("Batch cancelled (the YubiKey changed)");
                    }
                    return;
                }
                KeyCode::Esc if self.batch.is_none() && self.batch_mode => {
                    self.leave_batch_mode();
                    return;
                }
                KeyCode::Esc if self.batch.is_some() => {
                    self.end_batch(if confirming {
                        "Batch cancelled"
                    } else {
                        "Batch finished"
                    });
                    return;
                }
                _ => {}
            }
        }
        if ctrl && key.code == KeyCode::Char('t') {
            self.logs_expanded = !self.logs_expanded;
            self.toggled.clear();
            return;
        }
        if self.search.is_some() {
            self.on_search_key(key);
            return;
        }
        if ctrl && key.code == KeyCode::Char('f') && !self.sidebar && self.prompt().is_none() {
            self.search = Some(Search {
                query: String::new(),
                idx: 0,
                total: 0,
                jump: false,
            });
            return;
        }
        if self.sidebar {
            self.on_sidebar_key(key);
            return;
        }
        if let Some(prompt) = self.prompt().map(str::to_string) {
            if self.is_choice(&prompt) {
                self.on_yes_no_key(key, &prompt);
            } else {
                let secret = self.secret_prompt(&prompt);
                self.on_prompt_key(key, secret);
            }
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
            KeyCode::Up if popup && self.hist_pos.is_none() => {
                self.sel = (self.sel + sugg.len() - 1) % sugg.len()
            }
            KeyCode::Down if popup && self.hist_pos.is_none() => {
                self.sel = (self.sel + 1) % sugg.len()
            }
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
                    self.hist_pos = None;
                }
            }
        }
    }

    fn on_search_key(&mut self, key: KeyEvent) {
        let Some(sr) = self.search.as_mut() else {
            return;
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let step = |sr: &mut Search, back: bool| {
            if sr.total > 0 {
                sr.idx = if back {
                    (sr.idx + sr.total - 1) % sr.total
                } else {
                    (sr.idx + 1) % sr.total
                };
                sr.jump = true;
            }
        };
        match key.code {
            KeyCode::Esc => self.search = None,
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => step(sr, true),
            KeyCode::Enter | KeyCode::Down => step(sr, false),
            KeyCode::Up => step(sr, true),
            KeyCode::Backspace => {
                sr.query.pop();
                sr.idx = 0;
                sr.jump = true;
            }
            KeyCode::Char('u') if ctrl => {
                sr.query.clear();
                sr.idx = 0;
            }
            KeyCode::Char(c) if !ctrl => {
                sr.query.push(c);
                sr.idx = 0;
                sr.jump = true;
            }
            KeyCode::PageUp => self.scroll += 10,
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            _ => {}
        }
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
        // Inserting the first key is already announced as "Inserted".
        if now == before || before.is_none() {
            return;
        }
        if let Some(d) = now.and_then(|s| self.devices.iter().find(|d| d.serial == s)) {
            let msg = format!("Switched to {}", d.describe());
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
            KeyCode::Enter => self.choose_device(cur),
            _ => {}
        }
    }

    fn choose_device(&mut self, idx: usize) {
        let before = self.active_device();
        if let Some(d) = self.devices.get(idx) {
            self.device = Some(d.serial);
        }
        self.announce_device_change(before);
        self.sidebar = false;
    }

    fn on_mouse(&mut self, m: MouseEvent) {
        let (x, y) = (m.column, m.row);
        let inside = |r: Rect| x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height;
        match m.kind {
            MouseEventKind::ScrollUp => self.scroll += 3,
            MouseEventKind::ScrollDown => self.scroll = self.scroll.saturating_sub(3),
            MouseEventKind::Down(MouseButton::Left) => {
                if self.sidebar && inside(self.hits.side_items) {
                    let row = (y - self.hits.side_items.y) as usize / 3 + self.side_state.offset();
                    if row < self.devices.len() {
                        self.side_state.select(Some(row));
                        self.choose_device(row);
                    }
                } else if let Some(&(_, t)) = self.hits.tabs.iter().find(|(r, _)| inside(*r)) {
                    self.tab = t;
                } else if let Some(&(_, n)) = self.hits.toggles.iter().find(|(r, _)| inside(*r))
                    && !self.toggled.remove(&n)
                {
                    self.toggled.insert(n);
                }
            }
            _ => {}
        }
    }

    fn logs_collapsed(&self, run: usize) -> bool {
        !self.logs_expanded != self.toggled.contains(&run)
    }
}
