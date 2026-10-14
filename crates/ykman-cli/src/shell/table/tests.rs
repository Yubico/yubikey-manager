use super::*;

fn s(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

#[test]
fn parses_a_simple_table() {
    let t = parse_table("x.csv", "name,secret\nA,111\nB,222\n").unwrap();
    assert_eq!(t.name, "x.csv");
    assert_eq!(t.headers, ["name", "secret"]);
    assert_eq!(t.rows, [s(&["A", "111"]), s(&["B", "222"])]);
}

#[test]
fn detects_the_delimiter() {
    let semi = parse_table("x", "a;b\n1;2\n").unwrap();
    assert_eq!(semi.rows, [s(&["1", "2"])]);
    let tab = parse_table("x", "a\tb\n1\t2\n").unwrap();
    assert_eq!(tab.headers, ["a", "b"]);
    assert_eq!(tab.rows, [s(&["1", "2"])]);
}

#[test]
fn handles_bom_crlf_and_blank_lines() {
    let t = parse_table("x", "\u{feff}a,b\r\n1,2\r\n\r\n3,4\r\n").unwrap();
    assert_eq!(t.headers, ["a", "b"]);
    assert_eq!(t.rows, [s(&["1", "2"]), s(&["3", "4"])]);
}

#[test]
fn quoted_fields() {
    let t = parse_table("x", "a,b\n\"x,y\",\"say \"\"hi\"\"\"\n\"multi\nline\",z\n").unwrap();
    assert_eq!(t.rows[0], s(&["x,y", "say \"hi\""]));
    assert_eq!(t.rows[1], s(&["multi\nline", "z"]));
}

#[test]
fn empty_fields_are_kept() {
    let t = parse_table("x", "a,b,c\n1,,3\n").unwrap();
    assert_eq!(t.rows[0], s(&["1", "", "3"]));
}

#[test]
fn rejects_bad_tables() {
    assert!(parse_table("x", "").is_err());
    assert!(parse_table("x", "a,b\n").is_err());
    assert!(parse_table("x", "1bad,b\n1,2\n").is_err());
    assert!(parse_table("x", "a b,c\n1,2\n").is_err());
    assert!(
        parse_table("x", "a,a\n1,2\n")
            .unwrap_err()
            .contains("twice")
    );
    assert!(parse_table("x", "a,b\n1\n").unwrap_err().contains("row 1"));
    assert!(
        parse_table("x", "a,b\n\"1,2\n")
            .unwrap_err()
            .contains("quote")
    );
}

#[test]
fn rejects_too_many_rows() {
    let mut text = String::from("a\n");
    for i in 0..=MAX_ROWS {
        text.push_str(&format!("{i}\n"));
    }
    assert!(parse_table("x", &text).unwrap_err().contains("too many"));
}

#[test]
fn header_names() {
    assert!(valid_header("name"));
    assert!(valid_header("_x1"));
    assert!(!valid_header(""));
    assert!(!valid_header("1x"));
    assert!(!valid_header("a-b"));
}

#[test]
fn steps_use_only_matching_headers() {
    let steps = vec![s(&["oath", "accounts", "add", "${name}", "x"])];
    assert!(steps_use(&steps, &s(&["name"])));
    assert!(!steps_use(&steps, &s(&["other"])));
    assert!(!steps_use(&steps, &[]));
}

#[test]
fn csv_fields_are_quoted_when_needed() {
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
}

#[test]
fn csv_export_parses_back() {
    let original = s(&["plain", "a,b", "say \"hi\"", "two\nlines"]);
    let line = original
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    let t = parse_table("x", &format!("a,b,c,d\n{line}\n")).unwrap();
    assert_eq!(t.rows[0], original);
}

fn entry(serial: &str, group: &str, name: &str, value: &str) -> [String; 4] {
    [serial, group, name, value].map(String::from)
}

#[test]
fn generated_values_become_one_row_per_key_and_round() {
    let entries = vec![
        entry("100", "1", "key", "AAA"),
        entry("100", "1", "pid", "11"),
        entry("200", "1", "key", "BBB"),
        entry("200", "1", "pid", "22"),
    ];
    let (names, rows) = generated_rows(&entries);
    assert_eq!(names, ["key", "pid"]);
    assert_eq!(
        rows,
        [
            ("100".to_string(), s(&["AAA", "11"])),
            ("200".to_string(), s(&["BBB", "22"])),
        ]
    );
}

#[test]
fn generated_rows_leave_gaps_empty() {
    let entries = vec![
        entry("100", "1", "key", "AAA"),
        entry("100", "2", "pid", "11"),
    ];
    let (names, rows) = generated_rows(&entries);
    assert_eq!(names, ["key", "pid"]);
    assert_eq!(rows[0].1, s(&["AAA", ""]));
    assert_eq!(rows[1].1, s(&["", "11"]));
}

#[test]
fn generated_rows_of_nothing() {
    let (names, rows) = generated_rows(&[]);
    assert!(names.is_empty());
    assert!(rows.is_empty());
}

#[test]
fn hidden_secrets_are_masked_in_the_summary() {
    let secrets: std::collections::HashSet<String> = ["s3cr3t".to_string()].into();
    assert_eq!(masked_cell(true, &secrets, "s3cr3t"), "••••");
    assert_eq!(masked_cell(true, &secrets, "public"), "public");
    assert_eq!(masked_cell(false, &secrets, "s3cr3t"), "s3cr3t");
}
