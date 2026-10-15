//! Multi-step progress display for interactive flows (e.g. FIDO reset).
//!
//! Shows a `Status:` line above a bar split into one segment per step.
//! On a terminal the two lines are redrawn in place; otherwise each update
//! is appended as a single plain line, so piped output stays readable.
//!
//! In live mode a background thread animates the bar: completed steps fill
//! in quickly rather than jumping. Nothing is delayed for the sake of
//! animation, except that `finish`/`fail` wait for the short (~200 ms)
//! fill-in to complete.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::color;

const MAX_BAR_WIDTH: usize = 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tone {
    Normal,
    Failure,
}

const TICK: Duration = Duration::from_millis(40);
/// Ticks a segment takes to fill in.
const FILL_TICKS: usize = 5;

fn bar_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| (w.0 as usize).saturating_sub(2))
        .unwrap_or(MAX_BAR_WIDTH)
        .clamp(10, MAX_BAR_WIDTH)
}

/// Renders `cells` bar cells with the first `filled` in the "done" style.
fn render_cells(cells: usize, filled: usize, unicode: bool, styled: bool) -> String {
    let (full, empty) = if unicode {
        ("\u{2588}", "\u{2591}")
    } else {
        ("#", "-")
    };
    let paint = |ch: &str, f: fn(&str) -> String| if styled { f(ch) } else { ch.to_string() };
    (0..cells)
        .map(|i| {
            if i < filled {
                paint(full, color::green)
            } else {
                paint(empty, color::muted)
            }
        })
        .collect()
}

fn segment_width(total: usize, width: usize) -> usize {
    (width / total.max(1)).max(1)
}

/// Renders the bar: `done` of `total` segments filled, as one continuous bar.
#[cfg(test)]
fn render_bar(total: usize, done: usize, width: usize, unicode: bool, styled: bool) -> String {
    let seg = segment_width(total, width);
    render_cells(seg * total.max(1), seg * done, unicode, styled)
}

fn render_status(status: &str, tone: Tone) -> String {
    let text = format!("Status: {status}");
    match tone {
        Tone::Normal => text,
        Tone::Failure => color::red(&text),
    }
}

/// Plain one-line form used when output isn't a terminal.
fn render_plain(total: usize, done: usize, status: &str, unicode: bool) -> String {
    let (full, empty) = if unicode {
        ("\u{2588}", "\u{2591}")
    } else {
        ("#", "-")
    };
    let bar: String = (0..total)
        .map(|i| if i < done { full } else { empty })
        .collect();
    format!("[{bar}] {done}/{total} {status}")
}

struct State {
    target_done: usize,
    status: String,
    tone: Tone,
    /// Cells currently shown as filled (trails the target while animating).
    shown: usize,
    drawn: usize,
    started: bool,
    running: bool,
    /// Final state; the thread exits once `shown` reaches the target.
    settled: bool,
}

struct Inner {
    total: usize,
    unicode: bool,
    live: bool,
    stop: AtomicBool,
    state: Mutex<State>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Draws the current state in place. Returns whether anything is still
    /// animating.
    fn redraw(&self, st: &mut State) -> bool {
        let width = bar_width();
        let seg = segment_width(self.total, width);
        let cells = seg * self.total;
        let target = (seg * st.target_done).min(cells);
        if st.shown < target {
            st.shown = (st.shown + seg.div_ceil(FILL_TICKS)).min(target);
        } else {
            st.shown = target;
        }
        let filling = st.shown < target;

        let mut err = std::io::stderr().lock();
        if st.drawn > 0 {
            let _ = write!(err, "\x1b[{}A", st.drawn);
        }
        let _ = writeln!(err, "\x1b[2K{}", render_status(&st.status, st.tone));
        let bar = render_cells(cells, st.shown, self.unicode, true);
        let _ = writeln!(err, "\x1b[2K{bar}");
        let _ = err.flush();
        st.drawn = 2;
        filling
    }
}

pub struct StepProgress {
    inner: Arc<Inner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl StepProgress {
    pub fn new(total: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                total,
                unicode: crate::info::use_unicode(),
                live: std::io::stderr().is_terminal() && color::enabled(),
                stop: AtomicBool::new(false),
                state: Mutex::new(State {
                    target_done: 0,
                    status: String::new(),
                    tone: Tone::Normal,
                    shown: 0,
                    drawn: 0,
                    started: false,
                    running: false,
                    settled: false,
                }),
            }),
            thread: Mutex::new(None),
        }
    }

    /// Show `status` with `done` completed segments.
    pub fn update(&self, done: usize, status: &str) {
        self.draw(done, status, Tone::Normal, false);
    }

    pub fn finish(&self, status: &str) {
        self.draw(self.inner.total, status, Tone::Normal, true);
    }

    /// Mark the flow as failed, keeping the bar where it stopped.
    pub fn fail(&self, done: usize, status: &str) {
        self.draw(done, status, Tone::Failure, true);
    }

    fn draw(&self, done: usize, status: &str, tone: Tone, settle: bool) {
        let inner = &self.inner;
        if !inner.live {
            let mut err = std::io::stderr().lock();
            if !inner.lock().started {
                let _ = writeln!(err);
                inner.lock().started = true;
            }
            let _ = writeln!(
                err,
                "{}",
                render_plain(inner.total, done, status, inner.unicode)
            );
            return;
        }
        let busy = {
            let mut st = inner.lock();
            if !st.started {
                st.started = true;
                eprintln!();
                // First draw shows its position immediately.
                let seg = segment_width(inner.total, bar_width());
                st.shown = seg * done;
            }
            st.target_done = done;
            st.status = status.to_string();
            st.tone = tone;
            st.settled = settle;
            inner.redraw(&mut st)
        };
        if busy {
            self.ensure_thread();
        }
        if settle {
            self.join();
        }
    }

    /// Starts the animation thread unless one is already running. The thread
    /// exits as soon as nothing is animating and is restarted on demand.
    fn ensure_thread(&self) {
        {
            let mut st = self.inner.lock();
            if st.running {
                return;
            }
            st.running = true;
        }
        let inner = Arc::clone(&self.inner);
        let handle = std::thread::spawn(move || {
            while !inner.stop.load(Ordering::Relaxed) {
                std::thread::sleep(TICK);
                let mut st = inner.lock();
                if !inner.redraw(&mut st) {
                    st.running = false;
                    break;
                }
            }
        });
        *self.thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    /// Wait for the animation thread to finish drawing the final state.
    fn join(&self) {
        let handle = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = handle {
            let _ = h.join();
        }
    }
}

impl Drop for StepProgress {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        let handle = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = handle {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_fills_completed_segments() {
        assert_eq!(render_bar(2, 0, 10, false, false), "----------");
        assert_eq!(render_bar(2, 1, 10, false, false), "#####-----");
        assert_eq!(render_bar(2, 2, 10, false, false), "##########");
    }

    #[test]
    fn bar_unicode() {
        assert_eq!(
            render_bar(2, 1, 6, true, false),
            "\u{2588}\u{2588}\u{2588}\u{2591}\u{2591}\u{2591}"
        );
    }

    #[test]
    fn plain_line_format() {
        assert_eq!(
            render_plain(2, 1, "Reinsert your YubiKey", false),
            "[#-] 1/2 Reinsert your YubiKey"
        );
        assert_eq!(
            render_plain(2, 2, "done", true),
            "[\u{2588}\u{2588}] 2/2 done"
        );
    }

    #[test]
    fn status_without_color_is_plain() {
        assert_eq!(render_status("x", Tone::Failure), "Status: x");
    }
}
