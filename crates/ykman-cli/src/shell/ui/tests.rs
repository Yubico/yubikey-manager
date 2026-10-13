use super::*;

#[test]
fn strips_colour_codes() {
    assert_eq!(strip_ansi("\x1b[31mred\x1b[0m plain"), "red plain");
    assert_eq!(strip_ansi("\x1b[1;32mok\x1b[m"), "ok");
}

#[test]
fn plain_text_is_unchanged() {
    assert_eq!(strip_ansi("hello world"), "hello world");
    assert_eq!(strip_ansi(""), "");
}

#[test]
fn legend_wraps_within_the_width() {
    for tab in 0..2 {
        for width in [12, 20, 30, 60] {
            for line in sidebar_hint(tab, width) {
                let w: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
                // A single entry wider than the panel can't be split.
                assert!(w <= width.max(16), "tab {tab} width {width}: {w}");
            }
        }
    }
}

#[test]
fn legend_never_loses_a_key() {
    for (tab, keys) in SIDEBAR_KEYS.iter().enumerate() {
        let text: String = sidebar_hint(tab, 20)
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        for (key, what) in keys.iter() {
            assert!(text.contains(key) && text.contains(what), "{key} {what}");
        }
    }
}
