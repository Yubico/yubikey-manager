use super::*;

pub(super) const TABS: [&str; 3] = ["Default", "Hybrid", "Debug"];
pub(super) const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
pub(super) const LOGO: [&str; 6] = [
    "       _                          ",
    " _   _| | ___ __ ___   __ _ _ __  ",
    "| | | | |/ / \'_ ` _ \\ / _` | \'_ \\ ",
    "| |_| |   <| | | | | | (_| | | | |",
    " \\__, |_|\\_\\_| |_| |_|\\__,_|_| |_|",
    " |___/                            ",
];

/// Recent commands shown while browsing history with Up/Down.
pub(super) const HISTORY_ROWS: usize = POPUP_ROWS;
pub(super) const POPUP_ROWS: usize = 6;
// Colours come from the terminal's own palette so the shell follows the
// user's theme; "dim" text uses the DIM attribute on the default foreground.
const ACCENT: Color = Color::Green;
const BATCH_ACCENT: Color = Color::LightBlue;
static THEME: AtomicU8 = AtomicU8::new(0);
const RECORD_ACCENT: Color = Color::Magenta;

/// Primary colour: cyan while in batch mode so the mode is obvious.
pub(super) fn accent() -> Color {
    match THEME.load(Ordering::Relaxed) {
        2 => RECORD_ACCENT,
        1 => BATCH_ACCENT,
        _ => ACCENT,
    }
}
pub(super) const TEXT: Color = Color::Reset;
pub(super) const WARN: Color = Color::Yellow;
pub(super) const ERROR: Color = Color::Red;
pub(super) const OUTPUT_MARK: Color = Color::Green;
pub(super) const CMD_MARK: Color = Color::Blue;
pub(super) const ON_ACCENT: Color = Color::Black;

/// Background shades (input band, tab chip, selection), derived from the
/// terminal's own background colour when it reports one.
pub(super) static SHADES: std::sync::OnceLock<[Color; 3]> = std::sync::OnceLock::new();
pub(super) const FALLBACK_SHADES: [Color; 3] = [
    Color::Indexed(235),
    Color::Indexed(237),
    Color::Indexed(238),
];

pub(super) fn band_bg() -> Color {
    SHADES.get().unwrap_or(&FALLBACK_SHADES)[0]
}
pub(super) fn tab_bg() -> Color {
    SHADES.get().unwrap_or(&FALLBACK_SHADES)[1]
}
pub(super) fn selected() -> Color {
    SHADES.get().unwrap_or(&FALLBACK_SHADES)[2]
}

pub(super) type Rgb = (u8, u8, u8);

/// Blend the background towards the theme's foreground colour (or the
/// opposite extreme when unknown), so the shades stay tinted by the theme.
pub(super) fn shades_from(bg: Rgb, fg: Option<Rgb>) -> [Color; 3] {
    let lum =
        |c: Rgb| (0.299 * f64::from(c.0) + 0.587 * f64::from(c.1) + 0.114 * f64::from(c.2)) / 255.0;
    let target = match fg {
        Some(fg) if (lum(fg) - lum(bg)).abs() > 0.3 => fg,
        _ if lum(bg) < 0.5 => (255, 255, 255),
        _ => (0, 0, 0),
    };
    let mix = |k: f64| {
        let m = |b: u8, t: u8| (f64::from(b) + (f64::from(t) - f64::from(b)) * k).round() as u8;
        Color::Rgb(m(bg.0, target.0), m(bg.1, target.1), m(bg.2, target.2))
    };
    [mix(0.07), mix(0.12), mix(0.18)]
}

/// Ask the terminal for its foreground and background colours (OSC 10/11). A
/// DA1 request is sent right after so terminals that ignore OSC still answer
/// and we never hang.
#[cfg(unix)]
pub(super) fn query_terminal_colors() -> Option<(Rgb, Option<Rgb>)> {
    let mut out = std::io::stdout();
    out.write_all(b"\x1b]10;?\x1b\\\x1b]11;?\x1b\\\x1b[c")
        .ok()?;
    out.flush().ok()?;
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut buf = Vec::new();
    while Instant::now() < deadline {
        let mut fds = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `fds` is a valid pollfd and we pass a count of 1.
        if unsafe { libc::poll(&mut fds, 1, 50) } <= 0 {
            continue;
        }
        let mut chunk = [0u8; 256];
        // SAFETY: `chunk` is a valid writable buffer of the given length.
        let n = unsafe { libc::read(0, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n <= 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
        if buf.windows(3).any(|w| w == b"\x1b[?") && buf.last() == Some(&b'c') {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let parse = |s: &str| -> Option<Rgb> {
        let mut parts = s.split('/');
        let mut chan = || {
            let p = parts.next()?;
            let hex: String = p.chars().take_while(char::is_ascii_hexdigit).collect();
            let max = 16f64.powi(hex.len() as i32) - 1.0;
            let v = u32::from_str_radix(&hex, 16).ok()?;
            Some((f64::from(v) / max * 255.0).round() as u8)
        };
        Some((chan()?, chan()?, chan()?))
    };
    // Replies arrive in request order: foreground first, then background.
    let mut found = text.split("rgb:").skip(1).map(parse);
    match (found.next()?, found.next()) {
        (fg, Some(Some(bg))) => Some((bg, fg)),
        (Some(bg), None) => Some((bg, None)),
        _ => None,
    }
}

#[cfg(not(unix))]
pub(super) fn query_terminal_colors() -> Option<(Rgb, Option<Rgb>)> {
    None
}

pub(super) fn dim() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

pub(super) fn ansi_color(n: u8) -> Color {
    Color::Indexed(n)
}

/// One-line stand-in for a collapsed block of log lines.
pub(super) fn log_summary(
    count: usize,
    last: &str,
    live: bool,
    tick: usize,
    width: usize,
) -> Line<'static> {
    let dim = dim();
    let head = if live {
        format!("{} Working…", SPINNER[tick / 2 % SPINNER.len()])
    } else {
        format!("▶ {count} log lines")
    };
    let used = head.chars().count() + 2;
    let tail: String = last.chars().take(width.saturating_sub(used + 24)).collect();
    let hint = if live { "" } else { " (click to expand)" };
    Line::from(vec![
        Span::styled(head, dim.add_modifier(Modifier::ITALIC)),
        Span::styled(format!("{hint}  {tail}"), dim),
    ])
}

/// A row filled with a half block in the selection colour, for vertical padding.
/// Keys that work in the sidebar, per tab (YubiKeys, Scripts).
const SIDEBAR_KEYS: [&[(&str, &str)]; 2] = [
    &[("Enter", "select"), ("Tab", "scripts")],
    &[
        ("Enter", "run"),
        ("Space", "expand"),
        ("r", "rename"),
        ("d", "delete"),
        ("Tab", "devices"),
    ],
];

/// The sidebar keys as dim lines, wrapped to `width` columns.
fn sidebar_hint(tab: usize, width: usize) -> Vec<Line<'static>> {
    let bold = dim().add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut cur: Vec<Span<'static>> = Vec::new();
    let mut used = 0;
    for (key, what) in SIDEBAR_KEYS[tab] {
        let w = key.chars().count() + what.chars().count() + 1;
        if used > 0 && used + 3 + w > width {
            lines.push(Line::from(std::mem::take(&mut cur)));
            used = 0;
        }
        if used > 0 {
            cur.push(Span::styled(" · ", dim()));
            used += 3;
        }
        cur.push(Span::styled(*key, bold));
        cur.push(Span::styled(format!(" {what}"), dim()));
        used += w;
    }
    lines.push(Line::from(cur));
    lines
}

pub(super) fn half_edge(c: char, width: usize) -> Line<'static> {
    Line::from(Span::styled(
        c.to_string().repeat(width),
        Style::new().fg(selected()).bg(Color::Reset),
    ))
}

pub(super) fn render_entry(e: &Entry, width: usize, lines: &mut Vec<Line<'static>>) {
    let pstyle_cmd = Style::new().fg(CMD_MARK);
    let (prefix, base) = match e.kind {
        Kind::Cmd => ("❯ ", Style::new().add_modifier(Modifier::BOLD)),
        Kind::Out => ("  ", Style::new()),
        Kind::Err => ("  ", Style::new().fg(ERROR)),
        Kind::Log => ("│ ", dim()),
        Kind::Fail => ("  ", Style::new().fg(ERROR)),
        Kind::Success => (
            "✓ ",
            Style::new().fg(OUTPUT_MARK).add_modifier(Modifier::BOLD),
        ),
        Kind::RoundFail => ("✗ ", Style::new().fg(ERROR).add_modifier(Modifier::BOLD)),
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
pub(super) fn parse_ansi(text: &str, base: Style) -> Vec<(char, Style)> {
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

pub(super) fn apply_sgr(params: &str, mut style: Style, base: Style) -> Style {
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

pub(super) fn strip_ansi(text: &str) -> String {
    parse_ansi(text, Style::new())
        .into_iter()
        .map(|(c, _)| c)
        .collect()
}

/// Char ranges of case-insensitive matches of `q` in a rendered line.
pub(super) fn find_in_line(line: &Line, q: &[char]) -> Vec<usize> {
    let text: Vec<char> = line
        .spans
        .iter()
        .flat_map(|s| s.content.chars())
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect();
    if q.is_empty() || text.len() < q.len() {
        return Vec::new();
    }
    (0..=text.len() - q.len())
        .filter(|&i| text[i..i + q.len()] == *q)
        .collect()
}

pub(super) fn highlight_line(line: &Line, q: &[char], style: Style) -> Line<'static> {
    let starts = find_in_line(line, q);
    let mut cells: Vec<(char, Style)> = line
        .spans
        .iter()
        .flat_map(|s| s.content.chars().map(|c| (c, line.style.patch(s.style))))
        .collect();
    for st in starts {
        for cell in &mut cells[st..st + q.len()] {
            cell.1 = cell.1.patch(style);
        }
    }
    let mut spans: Vec<Span<'static>> = Vec::new();
    for (c, st) in cells {
        match spans.last_mut() {
            Some(last) if last.style == st => last.content.to_mut().push(c),
            _ => spans.push(Span::styled(c.to_string(), st)),
        }
    }
    Line::from(spans)
}

impl App {
    pub(super) fn draw(&mut self, f: &mut Frame) {
        let theme = if self.recording.is_some() {
            2
        } else {
            u8::from(self.batch_mode || self.batch.is_some())
        };
        THEME.store(theme, Ordering::Relaxed);
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
        self.hits.tabs.clear();
        let mut x = main[0].x;
        for (i, t) in TABS.iter().enumerate() {
            let style = if i == self.tab {
                Style::new()
                    .fg(ON_ACCENT)
                    .bg(accent())
                    .add_modifier(Modifier::BOLD)
            } else {
                dim().bg(tab_bg())
            };
            let w = t.chars().count() as u16 + 2;
            self.hits.tabs.push((Rect::new(x, main[0].y, w, 1), i));
            x += w + 1;
            tab_spans.push(Span::styled(format!(" {t} "), style));
            tab_spans.push(Span::raw(" "));
        }
        f.render_widget(Paragraph::new(Line::from(tab_spans)), main[0]);

        self.body_width = main[2].width.saturating_sub(2);
        self.draw_log(f, main[2]);
        self.draw_input(f, rows[1]);
        self.draw_status(f, pad(rows[2]));
        self.draw_script_panel(f, rows[1]);
        self.draw_popup(f, rows[1]);
    }

    pub(super) fn draw_sidebar(&mut self, f: &mut Frame, area: Rect) {
        let w = area.width.saturating_sub(2) as usize;
        f.render_widget(
            ratatui::widgets::Block::new()
                .borders(ratatui::widgets::Borders::RIGHT)
                .border_style(dim()),
            area,
        );
        self.hits.side_tabs.clear();
        let mut x = area.x + 1;
        let mut head = Vec::new();
        for (i, t) in ["YubiKeys", "Scripts"].iter().enumerate() {
            let style = if i == self.side_tab {
                Style::new()
                    .fg(ON_ACCENT)
                    .bg(accent())
                    .add_modifier(Modifier::BOLD)
            } else {
                dim().bg(tab_bg())
            };
            let tw = t.len() as u16 + 2;
            self.hits.side_tabs.push((Rect::new(x, area.y, tw, 1), i));
            head.push(Span::styled(format!(" {t} "), style));
            head.push(Span::raw(" "));
            x += tw + 1;
        }
        f.render_widget(
            Paragraph::new(Line::from(head)),
            Rect::new(area.x + 1, area.y, area.width.saturating_sub(3), 1),
        );
        let hint_w = area.width.saturating_sub(3);
        let hint = sidebar_hint(self.side_tab, hint_w as usize);
        let hint_h = (hint.len() as u16).min(area.height.saturating_sub(3));
        f.render_widget(
            Paragraph::new(hint),
            Rect::new(area.x + 1, area.y + 2, hint_w, hint_h),
        );
        let top = 2 + hint_h + 1;
        let area = Rect::new(
            area.x,
            area.y + top,
            area.width,
            area.height.saturating_sub(top),
        );
        let chosen = self.side_state.selected();
        let mut items: Vec<ListItem> = if self.side_tab == 1 {
            self.script_items(chosen, w)
        } else {
            self.device_items(self.active_device(), chosen, w)
        };
        if items.is_empty() {
            let msg = if self.side_tab == 1 {
                "  No saved scripts yet."
            } else {
                "  Insert a YubiKey"
            };
            items.push(ListItem::new(Span::styled(msg, dim())));
        }
        let list = List::new(items).block(
            ratatui::widgets::Block::new()
                .borders(ratatui::widgets::Borders::RIGHT)
                .border_style(dim())
                .padding(ratatui::widgets::Padding::new(0, 1, 1, 0)),
        );
        self.hits.side_items = Rect::new(
            area.x,
            area.y + 1,
            area.width.saturating_sub(2),
            area.height.saturating_sub(1),
        );
        f.render_stateful_widget(list, area, &mut self.side_state);
        if chosen == Some(0) && self.side_state.offset() == 0 && area.height > 0 {
            let edge = Rect::new(area.x, area.y, area.width.saturating_sub(2), 1);
            f.render_widget(Paragraph::new(half_edge('▄', w)), edge);
        }
    }

    fn script_items(&self, chosen: Option<usize>, w: usize) -> Vec<ListItem<'static>> {
        self.scripts
            .iter()
            .enumerate()
            .map(|(i, (name, n, steps))| {
                let is_sel = chosen == Some(i);
                let fill = if is_sel {
                    Style::new().bg(selected())
                } else {
                    Style::new()
                };
                let room = w.saturating_sub(5);
                let fit = |text: String| {
                    if text.chars().count() > room {
                        text.chars()
                            .take(room.saturating_sub(1))
                            .collect::<String>()
                            + "…"
                    } else {
                        text
                    }
                };
                let open = self.script_open == Some(i);
                let mut body: Vec<Line<'static>> = Vec::new();
                if open {
                    for (k, s) in steps.iter().take(MAX_OPEN_STEPS).enumerate() {
                        body.push(
                            Line::from(Span::styled(fit(format!("{} {s}", k + 1)), dim()))
                                .style(fill),
                        );
                    }
                    if steps.len() > MAX_OPEN_STEPS {
                        let more = steps.len() - MAX_OPEN_STEPS;
                        body.push(
                            Line::from(Span::styled(format!("… +{more} more"), dim())).style(fill),
                        );
                    }
                }
                if body.is_empty() {
                    let first = steps.first().cloned().unwrap_or_default();
                    body.push(Line::from(Span::styled(fit(first), dim())).style(fill));
                }
                for line in &mut body {
                    line.spans.insert(0, Span::raw("   "));
                }
                let mut lines = vec![
                    Line::from(vec![
                        Span::raw("   "),
                        Span::styled(name.clone(), Style::new().add_modifier(Modifier::BOLD)),
                        Span::styled(format!("  {n} step{}", plural(*n)), dim()),
                    ])
                    .style(fill),
                ];
                lines.extend(body);
                lines.push(if is_sel {
                    half_edge('▀', w)
                } else if chosen == Some(i + 1) {
                    half_edge('▄', w)
                } else {
                    Line::from("")
                });
                ListItem::new(lines)
            })
            .collect()
    }

    fn device_items(
        &self,
        active: Option<u32>,
        chosen: Option<usize>,
        w: usize,
    ) -> Vec<ListItem<'static>> {
        self.devices
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let mark = if active == Some(d.serial) { "●" } else { " " };
                let is_sel = chosen == Some(i);
                let fill = if is_sel {
                    Style::new().bg(selected())
                } else {
                    Style::new()
                };
                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(format!(" {mark} "), Style::new().fg(accent())),
                        Span::styled(d.name.clone(), Style::new().add_modifier(Modifier::BOLD)),
                    ])
                    .style(fill),
                    Line::from(Span::styled(
                        if d.serial == NO_SERIAL {
                            format!("   F/W: {}", d.version)
                        } else {
                            format!("   S/N: {}  F/W: {}", d.serial, d.version)
                        },
                        dim(),
                    ))
                    .style(fill),
                    if is_sel {
                        half_edge('▀', w)
                    } else if chosen == Some(i + 1) {
                        half_edge('▄', w)
                    } else {
                        Line::from("")
                    },
                ])
            })
            .collect()
    }

    pub(super) fn draw_log(&mut self, f: &mut Frame, area: Rect) {
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
        let mixed = self.tab == 1;
        let show_out = self.tab != 2;
        let show_logs = self.tab != 0;
        let last_run = runs.len() - 1;
        let mut toggle_lines: Vec<(usize, usize)> = Vec::new();
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
                if mixed {
                    toggle_lines.push((lines.len(), n));
                }
                if mixed && self.logs_collapsed(n) {
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
                            "▼ Logs (click to collapse)",
                            dim().add_modifier(Modifier::ITALIC),
                        )));
                    }
                    for e in &run.logs {
                        render_entry(e, width, &mut lines);
                    }
                }
            }
            // The Debug tab is the raw log: no output, notes or batch messages.
            if !show_out {
                continue;
            }
            let failed = run.rest.iter().any(|e| e.kind == Kind::Fail);
            // The red marker and the command's own error already say it failed;
            // keep the exit code only when there is nothing else to show.
            let has_output = run
                .rest
                .iter()
                .any(|e| matches!(e.kind, Kind::Out | Kind::Err));
            let mut marked = false;
            for e in &run.rest {
                if has_output && e.kind == Kind::Fail && e.text.starts_with("exited with code") {
                    continue;
                }
                let is_out = matches!(e.kind, Kind::Out | Kind::Err | Kind::Fail);
                if is_out && !show_out {
                    continue;
                }
                let group = match e.kind {
                    _ if is_out => 2,
                    Kind::Success | Kind::RoundFail => 4,
                    _ => 3,
                };
                gap(&mut lines, group);
                let start = lines.len();
                render_entry(e, width, &mut lines);
                if is_out && !marked {
                    marked = true;
                    let color = if failed { ERROR } else { OUTPUT_MARK };
                    lines[start].spans[0] = Span::styled("● ", Style::new().fg(color));
                }
            }
        }
        let h = area.height as usize;
        if let Some(sr) = self.search.as_mut()
            && !sr.query.is_empty()
        {
            let q: Vec<char> = sr.query.to_lowercase().chars().collect();
            let hits: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| !find_in_line(l, &q).is_empty())
                .map(|(i, _)| i)
                .collect();
            sr.total = hits.len();
            sr.idx = sr.idx.min(hits.len().saturating_sub(1));
            if sr.jump && !hits.is_empty() {
                let start = hits[sr.idx].saturating_sub(h / 2);
                self.scroll = lines.len().saturating_sub(h).saturating_sub(start);
            }
            sr.jump = false;
            for (n, &i) in hits.iter().enumerate() {
                let style = if n == sr.idx {
                    Style::new()
                        .fg(ON_ACCENT)
                        .bg(WARN)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::new().bg(selected())
                };
                lines[i] = highlight_line(&lines[i], &q, style);
            }
        } else if let Some(sr) = self.search.as_mut() {
            sr.total = 0;
        }
        let max_scroll = lines.len().saturating_sub(h);
        self.scroll = self.scroll.min(max_scroll);
        let start = lines.len().saturating_sub(h + self.scroll);
        let shown: Vec<Line> = lines.into_iter().skip(start).take(h).collect();
        f.render_widget(Paragraph::new(shown), area);

        self.hits.log = area;
        self.hits.toggles = toggle_lines
            .into_iter()
            .filter(|(i, _)| *i >= start && *i < start + h)
            .map(|(i, n)| {
                (
                    Rect::new(area.x, area.y + (i - start) as u16, area.width, 1),
                    n,
                )
            })
            .collect();
        if max_scroll > 0 {
            let mut state = ScrollbarState::new(max_scroll).position(max_scroll - self.scroll);
            f.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None)
                    .style(dim()),
                area,
                &mut state,
            );
        }
    }

    pub(super) fn welcome_lines(&self, width: usize, lines: &mut Vec<Line<'static>>) {
        let device = match self
            .active_device()
            .and_then(|s| self.devices.iter().find(|d| d.serial == s))
        {
            Some(d) => Line::from(vec![
                Span::styled("● ", Style::new().fg(accent())),
                Span::styled(
                    format!("{} ({})", d.name, d.version),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    if d.serial == NO_SERIAL {
                        String::new()
                    } else {
                        format!("  S/N: {}", d.serial)
                    },
                    dim(),
                ),
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
                    Style::new().fg(accent()).add_modifier(Modifier::BOLD),
                ),
                Span::styled(env!("CARGO_PKG_VERSION"), dim()),
                Span::styled(" · ", dim()),
                Span::styled("shell mode", Style::new().fg(WARN)),
            ]),
            Line::from(Span::styled(
                "Configure your YubiKey via the command line.",
                dim(),
            )),
            Line::from(""),
            device,
        ];
        let text_w = body.iter().map(Line::width).max().unwrap_or(0);
        let logo_w = LOGO.iter().map(|l| l.chars().count()).max().unwrap_or(0);
        let avail = width.saturating_sub(4).max(1);
        let body = if logo_w + 5 + text_w <= avail {
            let top = (LOGO.len() - body.len()) / 2;
            let mut rows = Vec::new();
            for (i, art) in LOGO.iter().enumerate() {
                let mut spans = vec![
                    Span::styled(format!("{art:<logo_w$}"), Style::new().fg(accent())),
                    Span::styled(" │ ", dim()),
                ];
                if let Some(l) = i.checked_sub(top).and_then(|j| body.get(j)) {
                    spans.extend(l.spans.clone());
                }
                rows.push(Line::from(spans));
            }
            rows
        } else {
            body
        };
        let inner = body
            .iter()
            .map(Line::width)
            .max()
            .unwrap_or(0)
            .max(40)
            .min(avail);
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
        let tips = [
            ("/", "browse commands"),
            ("←", "switch YubiKey"),
            ("Ctrl+T", "toggle logs"),
            ("Ctrl+F", "find in output"),
            ("/info", "show general information"),
            ("/help", "show help"),
        ];
        for (k, d) in tips {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{k:<8}"), Style::new().fg(accent())),
                Span::styled(d, dim()),
            ]));
        }
        lines.push(Line::from(""));
    }

    pub(super) fn draw_input(&self, f: &mut Frame, area: Rect) {
        let band = Style::new().bg(band_bg());
        f.render_widget(Block::new().style(band), area);
        // Half-block edges make the band look half a row shorter top and bottom.
        if area.height >= 3 {
            let edge = Style::new().fg(band_bg()).bg(Color::Reset);
            let w = area.width as usize;
            let top = Rect::new(area.x, area.y, area.width, 1);
            let bottom = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
            f.render_widget(Paragraph::new(Span::styled("▄".repeat(w), edge)), top);
            f.render_widget(Paragraph::new(Span::styled("▀".repeat(w), edge)), bottom);
        }
        let row = Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), 1);

        let searching = self.search.as_ref().map(|s| s.query.clone());
        let (label, text, ghost) = match self.prompt() {
            _ if searching.is_some() => (
                "Find: ".to_string(),
                searching.clone().unwrap_or_default(),
                String::new(),
            ),
            Some(prompt) => {
                let prompt = strip_ansi(prompt);
                let shown = if self.secret_prompt(&prompt) {
                    "•".repeat(self.input.len())
                } else {
                    self.input.buf.clone()
                };
                let hint = if self.is_choice(&prompt) {
                    "  ↑/↓ choose · Enter confirm".to_string()
                } else {
                    String::new()
                };
                (prompt, shown, hint)
            }
            None if self.var_prompt().is_some() => {
                let (name, secret) = self.var_prompt().unwrap_or_default();
                let shown = if secret {
                    "•".repeat(self.input.len())
                } else {
                    self.input.buf.clone()
                };
                (format!("{name} ❯ "), shown, String::new())
            }
            None => {
                let sugg = self.suggestions();
                let partial = current_partial(&self.input.buf);
                let ghost = sugg
                    .get(self.sel.min(sugg.len().saturating_sub(1)))
                    .and_then(|s| s.name.strip_prefix(partial))
                    .unwrap_or("")
                    .to_string();
                let ghost = if ghost.is_empty() && sugg.is_empty() {
                    self.arg_hint().unwrap_or_default()
                } else {
                    ghost
                };
                let mark = match (self.recording.is_some(), self.batch_mode) {
                    (true, true) => "batch rec ❯ ",
                    (true, false) => "rec ❯ ",
                    (false, true) => "batch ❯ ",
                    (false, false) => "❯ ",
                };
                (mark.to_string(), self.input.buf.clone(), ghost)
            }
        };
        let mut spans = vec![Span::styled(
            label.clone(),
            Style::new().fg(accent()).bg(band_bg()),
        )];
        if text.is_empty() && ghost.is_empty() && self.prompt().is_none() && searching.is_none() {
            match self.batch_label() {
                Some(hint) => spans.push(Span::styled(
                    hint,
                    Style::new().add_modifier(Modifier::BOLD).bg(band_bg()),
                )),
                None => {
                    let hint = if self.recording.is_some() {
                        "Type / to add a command · Esc to finish"
                    } else if self.batch_mode {
                        "Type / to pick a command to repeat on many keys · Esc to leave"
                    } else {
                        "Type / for commands"
                    };
                    spans.push(Span::styled(hint, dim().bg(band_bg())));
                }
            }
        }
        spans.push(Span::styled(text, band));
        spans.push(Span::styled(ghost, dim().bg(band_bg())));
        f.render_widget(Paragraph::new(Line::from(spans)).style(band), row);
        let choosing = self.prompt().is_some_and(|p| self.is_choice(p));
        if !self.sidebar && !choosing {
            let col = searching
                .as_ref()
                .map_or(self.input.cursor, |q| q.chars().count());
            let x = row.x + label.chars().count() as u16 + col as u16;
            f.set_cursor_position((x.min(row.right().saturating_sub(1)), row.y));
        }
    }

    pub(super) fn draw_status(&self, f: &mut Frame, area: Rect) {
        let left = if let Some(sr) = &self.search {
            let pos = if sr.total == 0 {
                "no matches".to_string()
            } else {
                format!("{}/{}", sr.idx + 1, sr.total)
            };
            vec![
                Span::styled(format!("find: {pos}"), Style::new().fg(WARN)),
                Span::styled(" · ", dim()),
                Span::styled("Enter", dim().add_modifier(Modifier::BOLD)),
                Span::styled(" next · ", dim()),
                Span::styled("↑", dim().add_modifier(Modifier::BOLD)),
                Span::styled(" previous · ", dim()),
                Span::styled("Esc", dim().add_modifier(Modifier::BOLD)),
                Span::styled(" close", dim()),
            ]
        } else if self.running || self.batch_wait_msg().is_some() {
            let msg = if self.prompt().is_some() {
                "waiting for input"
            } else {
                self.batch_wait_msg().unwrap_or("running…")
            };
            vec![Span::styled(
                format!("{} {msg}", SPINNER[self.tick / 2 % SPINNER.len()]),
                Style::new().fg(WARN),
            )]
        } else {
            vec![
                Span::styled("←", dim().add_modifier(Modifier::BOLD)),
                Span::styled(" devices & scripts", dim()),
            ]
        };
        let bold = dim().add_modifier(Modifier::BOLD);
        let full = {
            let mut v = left.clone();
            v.extend([
                Span::styled(" · ", dim()),
                Span::styled("tab", bold),
                Span::styled(" next tab · ", dim()),
                Span::styled("/help", bold),
                Span::styled(" show help", dim()),
            ]);
            v
        };
        let short = {
            let mut v = left.clone();
            v.extend([Span::styled(" · ", dim()), Span::styled("/help", bold)]);
            v
        };

        let dev = match self.active_device() {
            Some(s) => match self.devices.iter().find(|d| d.serial == s) {
                Some(d) => format!("{} ({})", d.name, d.version),
                None => format!("YubiKey {s}"),
            },
            None => "no YubiKey detected".to_string(),
        };
        let total = area.width as usize;
        let mut right = format!("{dev} · log: {}", self.log_level);
        if right.chars().count() + 12 > total {
            right = dev;
        }
        let rw = right.chars().count();
        let avail = total.saturating_sub(rw + 2);
        let width = |v: &[Span]| v.iter().map(Span::width).sum::<usize>();
        let spans = if self.search.is_some() {
            left
        } else {
            [full, short, left]
                .into_iter()
                .find(|v| width(v) <= avail)
                .unwrap_or_default()
        };
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        let right = Line::from(Span::styled(right, dim())).right_aligned();
        f.render_widget(Paragraph::new(right), area);
    }

    pub(super) fn draw_yes_no(&self, f: &mut Frame, input_area: Rect, prompt: &str) {
        let h = 2u16.min(input_area.y);
        if h == 0 {
            return;
        }
        let area = Rect::new(input_area.x, input_area.y - h, input_area.width, h);
        let cur = self.yn_choice(prompt);
        let items: Vec<ListItem> = [("Yes", "y"), ("No", "n")]
            .iter()
            .enumerate()
            .map(|(i, (name, key))| {
                let is_sel = i == cur;
                ListItem::new(Line::from(vec![
                    Span::raw(" "),
                    Span::styled(if is_sel { "❯ " } else { "  " }, Style::new().fg(accent())),
                    Span::styled(
                        format!("{name:<6}"),
                        if is_sel {
                            Style::new().add_modifier(Modifier::BOLD)
                        } else {
                            Style::new()
                        },
                    ),
                    Span::styled(format!("press {key}"), dim()),
                ]))
            })
            .collect();
        let mut state = ListState::default().with_selected(Some(cur));
        f.render_widget(Clear, area);
        f.render_stateful_widget(
            List::new(items).highlight_style(Style::new().bg(selected())),
            area,
            &mut state,
        );
    }

    /// Numbered overview of the commands queued by `/record`, above the input.
    pub(super) fn draw_script_panel(&self, f: &mut Frame, input_area: Rect) {
        let Some(steps) = self.recording.as_ref() else {
            return;
        };
        if self.sidebar
            || self.prompt().is_some()
            || self.hist_pos.is_some()
            || !self.suggestions().is_empty()
        {
            return;
        }
        let max = 6;
        let hidden = steps.len().saturating_sub(max);
        let width = input_area.width.saturating_sub(4) as usize;
        let n = steps.len();
        let mut lines = vec![Line::from(vec![
            Span::styled(
                "● Recording",
                Style::new().fg(accent()).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" · {n} step{}", if n == 1 { "" } else { "s" }),
                dim(),
            ),
        ])];
        if hidden > 0 {
            lines.push(Line::from(Span::styled(
                format!("  … {hidden} earlier"),
                dim(),
            )));
        }
        for (i, s) in steps.iter().enumerate().skip(hidden) {
            let mut text = s.join(" ");
            let room = width.saturating_sub(6);
            if text.chars().count() > room {
                text = text
                    .chars()
                    .take(room.saturating_sub(1))
                    .collect::<String>()
                    + "…";
            }
            lines.push(Line::from(vec![
                Span::styled(format!("{:>3}  ", i + 1), Style::new().fg(accent())),
                Span::raw(text),
            ]));
        }
        lines.push(Line::from(Span::styled(
            "Enter add · Backspace remove last · Esc finish",
            dim(),
        )));
        let h = (lines.len() as u16).min(input_area.y);
        if h == 0 {
            return;
        }
        let skip = lines.len() - h as usize;
        let area = Rect::new(
            input_area.x + 2,
            input_area.y - h,
            input_area.width.saturating_sub(4),
            h,
        );
        f.render_widget(Clear, area);
        f.render_widget(Paragraph::new(lines.split_off(skip)), area);
    }

    pub(super) fn draw_popup(&self, f: &mut Frame, input_area: Rect) {
        if let Some(prompt) = self.prompt()
            && self.is_choice(prompt)
            && !self.sidebar
        {
            self.draw_yes_no(f, input_area, prompt);
            return;
        }
        let history = self.visible_history();
        let (sugg, sel) = match self.hist_pos {
            Some(pos) if pos < history.len() => {
                let n = history.len();
                let size = n.min(HISTORY_ROWS);
                let start = pos.min(n - size);
                let items = history[start..start + size]
                    .iter()
                    .map(|h| Suggestion {
                        display: h.clone(),
                        name: h.clone(),
                        desc: String::new(),
                    })
                    .collect();
                (items, pos - start)
            }
            _ => (self.suggestions(), self.sel),
        };
        if sugg.is_empty() || self.sidebar || self.prompt().is_some() {
            return;
        }
        let h = (POPUP_ROWS as u16).min(input_area.y);
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
        let sel = sel.min(sugg.len() - 1);
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
                    Span::styled(if is_sel { "❯ " } else { "  " }, Style::new().fg(accent())),
                    Span::styled(format!("{:<name_w$}", s.display), name_style),
                    Span::styled(s.desc.clone(), desc_style),
                ]))
            })
            .collect();
        let mut state = ListState::default().with_selected(Some(sel));
        f.render_widget(Clear, area);
        f.render_stateful_widget(
            List::new(items).highlight_style(Style::new().bg(selected())),
            area,
            &mut state,
        );
    }
}
