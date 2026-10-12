use super::*;

const MAX_ROWS: usize = 10_000;

/// A CSV file attached for the session: the header names become variables.
#[derive(Clone)]
pub(super) struct Table {
    pub(super) name: String,
    pub(super) headers: Vec<String>,
    pub(super) rows: Vec<Vec<String>>,
}

/// Splits CSV text into records, honouring quotes and `""` escapes.
fn parse_records(text: &str, delim: char) -> Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut chars = text.chars().peekable();
    let mut line = 1;
    let end_record = |record: &mut Vec<String>, field: &mut String, records: &mut Vec<_>| {
        record.push(std::mem::take(field));
        if record.iter().any(|f| !f.trim().is_empty()) {
            records.push(std::mem::take(record));
        } else {
            record.clear();
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' if quoted => quoted = false,
            '"' if field.is_empty() && !was_quoted => {
                quoted = true;
                was_quoted = true;
            }
            _ if quoted => {
                if c == '\n' {
                    line += 1;
                }
                field.push(c);
            }
            c if c == delim => {
                record.push(std::mem::take(&mut field));
                was_quoted = false;
            }
            '\r' => {}
            '\n' => {
                line += 1;
                end_record(&mut record, &mut field, &mut records);
                was_quoted = false;
            }
            _ => field.push(c),
        }
    }
    if quoted {
        return Err(format!("unterminated quote (started before line {line})"));
    }
    end_record(&mut record, &mut field, &mut records);
    Ok(records)
}

fn valid_header(h: &str) -> bool {
    h.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(super) fn parse_table(name: &str, text: &str) -> Result<Table, String> {
    let text = text.trim_start_matches('\u{feff}');
    let first = text.lines().next().unwrap_or("");
    // Spreadsheet exports use ; or tab depending on locale.
    let delim = [',', ';', '\t']
        .into_iter()
        .max_by_key(|d| first.matches(*d).count())
        .filter(|d| first.contains(*d))
        .unwrap_or(',');
    let mut records = parse_records(text, delim)?;
    if records.len() < 2 {
        return Err("needs a header row and at least one data row".into());
    }
    let headers: Vec<String> = records
        .remove(0)
        .into_iter()
        .map(|h| h.trim().to_string())
        .collect();
    if let Some(bad) = headers.iter().find(|h| !valid_header(h)) {
        return Err(format!(
            "column name '{bad}' can't be a variable (use letters, digits and _, starting with a letter)"
        ));
    }
    if let Some(i) = headers
        .iter()
        .enumerate()
        .find_map(|(i, h)| headers[..i].contains(h).then_some(i))
    {
        return Err(format!("column '{}' appears twice", headers[i]));
    }
    if records.len() > MAX_ROWS {
        return Err(format!("too many rows (max {MAX_ROWS})"));
    }
    if let Some((i, r)) = records
        .iter()
        .enumerate()
        .find(|(_, r)| r.len() != headers.len())
    {
        return Err(format!(
            "row {} has {} fields, expected {}",
            i + 1,
            r.len(),
            headers.len()
        ));
    }
    Ok(Table {
        name: name.to_string(),
        headers,
        rows: records,
    })
}

impl App {
    /// `/csv <file>` attaches a file, `/csv clear` detaches it, `/csv` shows it.
    pub(super) fn csv_command(&mut self, args: &[String]) {
        if self.batch.is_some() || self.running || self.recording.is_some() {
            self.note("Finish the current command, batch or recording first.");
            return;
        }
        match args {
            [] => match &self.csv {
                Some(t) => {
                    let msg = format!(
                        "{}: {} rows · columns {}",
                        t.name,
                        t.rows.len(),
                        t.headers.join(", ")
                    );
                    self.note(&msg);
                }
                None => self
                    .note("No CSV attached. Use /csv <file>; the header row names the variables."),
            },
            [a] if a == "clear" => {
                self.csv = None;
                self.note("CSV detached.");
            }
            [path] => {
                let expanded = match path.strip_prefix("~/") {
                    Some(rest) => std::env::var_os("HOME")
                        .map(|h| std::path::PathBuf::from(h).join(rest))
                        .unwrap_or_else(|| path.into()),
                    None => path.into(),
                };
                let name = expanded
                    .file_name()
                    .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned());
                let result = std::fs::read_to_string(&expanded)
                    .map_err(|e| e.to_string())
                    .and_then(|t| parse_table(&name, &t));
                match result {
                    Ok(t) => {
                        self.note(&format!(
                            "Attached {}: {} row{} · columns {}",
                            t.name,
                            t.rows.len(),
                            plural(t.rows.len()),
                            t.headers.join(", ")
                        ));
                        self.note(
                            "Use ${column} in a sequence. In batch mode each key takes the next row.",
                        );
                        self.csv = Some(t);
                    }
                    Err(e) => self.note(&format!("Could not use {path}: {e}")),
                }
            }
            _ => self.note("Usage: /csv <file> · /csv clear · /csv"),
        }
    }

    /// Why the sequence can't start with the attached CSV, if it can't.
    pub(super) fn csv_problem(&self, steps: &[Vec<String>]) -> Option<String> {
        for s in steps {
            let Ok((n, rest)) = parse_repeat(s) else {
                continue;
            };
            if s[0] != "repeat" {
                continue;
            }
            match &self.csv {
                None if n == usize::MAX => {
                    return Some("repeat all needs a CSV: /csv <file>".into());
                }
                Some(t)
                    if n != usize::MAX
                        && n > t.rows.len()
                        && steps_use(&[rest.to_vec()], &t.headers) =>
                {
                    return Some(format!(
                        "repeat {n} needs {n} rows but {} has {}",
                        t.name,
                        t.rows.len()
                    ));
                }
                _ => {}
            }
        }
        None
    }
}

pub(super) fn steps_use(steps: &[Vec<String>], headers: &[String]) -> bool {
    steps.iter().flatten().any(|w| {
        find_vars(w)
            .iter()
            .any(|(_, _, n)| headers.iter().any(|h| h == n))
    })
}

/// The row a step reads its CSV columns from.
pub(super) fn current_row(b: &Batch) -> Option<usize> {
    b.csv.as_ref()?;
    if b.once {
        b.step_rows.get(b.step).copied().flatten()
    } else {
        Some(b.row)
    }
}

/// `row 3/20 (alice)`, using the first column unless it looks secret.
pub(super) fn row_label(b: &Batch, row: usize) -> String {
    let Some(t) = &b.csv else {
        return String::new();
    };
    let who = t
        .headers
        .first()
        .filter(|h| !var_secret(h))
        .and_then(|_| t.rows.get(row)?.first())
        .map_or_else(String::new, |v| format!(" ({v})"));
    format!("row {}/{}{who}", row + 1, t.rows.len())
}

fn csv_field(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

/// Generated values as one row per key and iteration, one column per variable.
fn generated_rows(entries: &[[String; 4]]) -> (Vec<String>, Vec<(String, Vec<String>)>) {
    let mut names: Vec<String> = Vec::new();
    let mut rows: Vec<(&str, &str, Vec<(&str, &str)>)> = Vec::new();
    for [serial, group, name, value] in entries {
        if !names.contains(name) {
            names.push(name.clone());
        }
        match rows.iter_mut().find(|r| r.0 == serial && r.1 == group) {
            Some(r) => r.2.push((name, value)),
            None => rows.push((serial, group, vec![(name, value)])),
        }
    }
    let rows = rows
        .into_iter()
        .map(|(serial, _, vals)| {
            let cells = names
                .iter()
                .map(|n| {
                    vals.iter()
                        .find(|v| v.0 == n)
                        .map_or(String::new(), |v| v.1.to_string())
                })
                .collect();
            (serial.to_string(), cells)
        })
        .collect();
    (names, rows)
}

impl App {
    /// Show what a round generated, so the values can be written down or checked.
    pub(super) fn show_generated(&mut self, serial: u32, round: usize) {
        let (s, r) = (serial.to_string(), round.to_string());
        let mine: Vec<[String; 4]> = self
            .generated
            .iter()
            .filter(|g| g[0] == s && (g[1] == r || g[1].starts_with(&format!("{r}."))))
            .cloned()
            .collect();
        if mine.is_empty() {
            return;
        }
        let (names, rows) = generated_rows(&mine);
        if let [(_, cells)] = rows.as_slice() {
            let w = names.iter().map(|n| n.chars().count()).max().unwrap_or(0);
            for (n, c) in names.iter().zip(cells) {
                self.note(&format!("  {n:<w$}  {c}"));
            }
            return;
        }
        let widths: Vec<usize> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                rows.iter()
                    .map(|r| r.1[i].chars().count())
                    .chain([n.chars().count()])
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let line = |cells: &[String]| {
            let padded: Vec<String> = cells
                .iter()
                .zip(&widths)
                .map(|(c, w)| format!("{c:<w$}"))
                .collect();
            format!("  {}", padded.join("  ").trim_end())
        };
        self.note(&line(&names));
        for (_, cells) in &rows {
            self.note(&line(cells));
        }
    }

    /// `/export` saves, `/export copy` copies, `/export <file>` saves to a file.
    pub(super) fn export_command(&mut self, args: &[String]) {
        if self.generated.is_empty() {
            self.note("No generated values yet. Run a sequence that uses ${random…} first.");
            return;
        }
        let (names, rows) = generated_rows(&self.generated);
        let mut text = format!(
            "serial,{}\n",
            names
                .iter()
                .map(|h| csv_field(h))
                .collect::<Vec<_>>()
                .join(",")
        );
        for (serial, cells) in &rows {
            let cells: Vec<String> = cells.iter().map(|c| csv_field(c)).collect();
            text.push_str(&format!("{},{}\n", csv_field(serial), cells.join(",")));
        }
        let n = rows.len();
        if args.first().is_some_and(|a| a == "copy") {
            match copy_to_clipboard(&text) {
                Ok(()) => self.note(&format!("Copied {n} row{} as CSV.", plural(n))),
                Err(e) => self.note(&format!("Couldn't copy: {e}")),
            }
            return;
        }
        let path = args.first().map_or_else(
            || {
                std::path::PathBuf::from(format!(
                    "ykman-pilot-values-{}.csv",
                    chrono::Local::now().format("%Y%m%d-%H%M%S")
                ))
            },
            std::path::PathBuf::from,
        );
        // Private and never overwrites: the values include secrets.
        let res = create_private_file(&path).and_then(|()| std::fs::write(&path, &text));
        match res {
            Ok(()) => self.note(&format!(
                "Saved {n} row{} to {} (contains secrets)",
                plural(n),
                path.display()
            )),
            Err(e) => self.note(&format!("Couldn't save {}: {e}", path.display())),
        }
    }
}
