use serde_json::Value;

use crate::util::CliError;

/// Pretty-print a JSON value in the style of Python ykman's `pretty_print()`.
///
/// - Objects: keys left-aligned with aligned values; nested objects/arrays
///   get their own indented block.
/// - Arrays: each element printed recursively.
/// - Scalars: printed directly (null → "None", bool → "True"/"False").
fn pretty_print(value: &Value, level: usize) -> Vec<String> {
    let indent = "  ".repeat(level);
    match value {
        Value::Array(arr) => {
            let mut lines = Vec::new();
            for v in arr {
                lines.extend(pretty_print(v, level));
            }
            lines
        }
        Value::Object(map) => {
            // First pass: compute max key width for single-line entries
            let mut entries: Vec<(&str, Vec<String>, bool)> = Vec::new();
            let mut max_key_len: usize = 0;
            for (k, v) in map {
                let p = pretty_print(v, level + 1);
                let multiline = p.len() > 1 || matches!(v, Value::Object(_) | Value::Array(_));
                if !multiline {
                    max_key_len = max_key_len.max(k.len());
                }
                entries.push((k, p, multiline));
            }
            let pad = indent.len() + max_key_len + 1; // +1 for ':'

            let mut lines = Vec::new();
            for (k, p, multiline) in entries {
                let k_line = format!("{indent}{k}:");
                if multiline {
                    lines.push(k_line);
                    lines.extend(p);
                    if lines.last().map(|l| !l.is_empty()).unwrap_or(false) {
                        lines.push(String::new());
                    }
                } else {
                    let padded = format!("{k_line:<pad$}");
                    let val = p.first().map(|s| s.trim_start()).unwrap_or("");
                    lines.push(format!("{padded} {val}"));
                }
            }
            lines
        }
        Value::Null => vec![format!("{indent}None")],
        Value::Bool(b) => vec![format!("{indent}{}", if *b { "True" } else { "False" })],
        Value::Number(n) => vec![format!("{indent}{n}")],
        Value::String(s) => vec![format!("{indent}{s}")],
    }
}

pub fn run_diagnose() -> Result<(), CliError> {
    let report = ykman_cli::diagnostics::run_diagnostics();
    let json = serde_json::to_value(&report).unwrap();
    for line in pretty_print(&json, 0) {
        println!("{line}");
    }
    println!();
    println!("End of diagnostics");
    Ok(())
}
