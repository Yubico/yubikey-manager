use super::*;

pub(super) static RUN_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Reads the pty, emitting complete lines plus the unterminated remainder.
pub(super) fn pump_pty(mut reader: Box<dyn Read + Send>, tx: Sender<Msg>) {
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
pub(super) fn tail_log(path: &std::path::Path, stop: &AtomicBool, tx: &Sender<Msg>) {
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

pub(super) fn create_private_file(path: &std::path::Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map(|_| ())
}

pub(super) fn exe() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| "ykman".into())
}

impl App {
    /// The prompt text if the running command is waiting for input.
    pub(super) fn prompt(&self) -> Option<&str> {
        let text = self.partial.trim_end_matches('\r');
        let last = text.chars().next_back()?;
        (self.running
            && self.writer.is_some()
            && self.partial_since.elapsed() > PROMPT_DELAY
            && (last.is_whitespace() || ":?]>".contains(last)))
        .then_some(text)
    }

    pub(super) fn prompt_is_secret(prompt: &str) -> bool {
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

    /// Whether the prompt hides its input. On Unix the pty's echo flag is
    /// authoritative; elsewhere (or if unavailable) we guess from the text.
    pub(super) fn secret_prompt(&self, prompt: &str) -> bool {
        #[cfg(unix)]
        if let Some(m) = &self.master
            && let Ok(m) = m.lock()
            && let Some(t) = m.get_termios()
        {
            return t.local_flags.bits() & libc::ECHO == 0;
        }
        Self::prompt_is_secret(prompt)
    }

    /// A visible y/n question, answered through the Yes/No list.
    pub(super) fn is_choice(&self, prompt: &str) -> bool {
        Self::is_yes_no(prompt) && !self.secret_prompt(prompt)
    }

    pub(super) fn is_yes_no(prompt: &str) -> bool {
        let p = prompt.to_lowercase();
        p.contains("[y/n]") || p.contains("(y/n)")
    }

    /// Index into [Yes, No]; destructive-by-default prompts start on "No".
    pub(super) fn yn_choice(&self, prompt: &str) -> usize {
        self.yn_sel
            .unwrap_or(usize::from(!prompt.contains("[Y/n]")))
    }

    pub(super) fn send_reply(&mut self, reply: &str, secret: bool) {
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
        self.yn_sel = None;
    }

    pub(super) fn on_yes_no_key(&mut self, key: KeyEvent, prompt: &str) {
        let cur = self.yn_choice(prompt);
        match key.code {
            KeyCode::Char('y' | 'Y') => self.send_reply("y", false),
            KeyCode::Char('n' | 'N') => self.send_reply("n", false),
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                self.yn_sel = Some(1 - cur);
            }
            KeyCode::Enter => self.send_reply(if cur == 0 { "y" } else { "n" }, false),
            KeyCode::Esc => self.cancel(),
            _ => {}
        }
    }

    pub(super) fn on_prompt_key(&mut self, key: KeyEvent, secret: bool) {
        match key.code {
            KeyCode::Enter => {
                let reply = self.input.take();
                self.send_reply(&reply, secret);
            }
            KeyCode::Esc => self.cancel(),
            _ => {
                self.input.on_key(&key);
            }
        }
    }

    pub(super) fn cancel(&mut self) {
        if let Some(k) = self.killer.as_mut() {
            let _ = k.kill();
            self.note("cancelled");
        }
    }

    pub(super) fn spawn(&mut self, shown: &str, args: Vec<String>) {
        self.scroll = 0;
        self.push(Kind::Cmd, shown.to_string());
        if let Err(e) = self.try_spawn(args) {
            self.push(Kind::Err, format!("failed to start: {e:#}"));
        }
    }

    pub(super) fn try_spawn(&mut self, args: Vec<String>) -> Result<()> {
        let log_path = std::env::temp_dir().join(format!(
            "ykman-pilot-{}-{}.log",
            std::process::id(),
            RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_file(&log_path).context("creating log file")?;
        super::state::wait_for_poll();

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
        let master = Arc::new(Mutex::new(pair.master));
        self.master = Some(master.clone());
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
}
