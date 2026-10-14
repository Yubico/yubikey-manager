use super::*;

fn s(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

#[test]
fn secret_variable_names() {
    assert!(var_secret("pin"));
    assert!(var_secret("NewPassword"));
    assert!(var_secret("api_token"));
    assert!(!var_secret("serial"));
    assert!(!var_secret("label"));
}

#[test]
fn random_defaults_and_kinds() {
    assert_eq!(parse_random("random"), Ok(("alnum", 8)));
    assert_eq!(parse_random("random:hex"), Ok(("hex", 32)));
    assert_eq!(parse_random("random:base32"), Ok(("base32", 32)));
    assert_eq!(parse_random("random:digits"), Ok(("digits", 6)));
    assert_eq!(parse_random("random:digits:4"), Ok(("digits", 4)));
}

#[test]
fn random_rejects_bad_input() {
    assert!(parse_random("random:nope").is_err());
    assert!(parse_random("random:hex:0").is_err());
    assert!(parse_random("random:hex:129").is_err());
    assert!(parse_random("random:hex:x").is_err());
    assert!(parse_random("random:hex:4:5").is_err());
}

#[test]
fn random_values_match_their_alphabet_and_length() {
    let hex = random_value("random:hex:40").unwrap();
    assert_eq!(hex.len(), 40);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

    let digits = random_value("random:digits:12").unwrap();
    assert_eq!(digits.len(), 12);
    assert!(digits.chars().all(|c| c.is_ascii_digit()));

    let b32 = random_value("random:base32").unwrap();
    assert!(
        b32.chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
    );

    assert!(random_value("random:bogus").is_none());
}

#[test]
fn random_secrets_are_base32_and_hex_only() {
    assert!(random_is_secret("random:hex"));
    assert!(random_is_secret("random:base32:16"));
    assert!(!random_is_secret("random:digits"));
    assert!(!random_is_secret("random"));
}

#[test]
fn random_names_are_distinct_and_valid() {
    let step = s(&[
        "a",
        "${random:hex}",
        "${random:hex}",
        "${random:digits:4}",
        "${random:bad}",
    ]);
    assert_eq!(random_names(&step), ["random:hex", "random:digits:4"]);
}

#[test]
fn repeat_parsing() {
    let args = s(&["repeat", "3", "otp", "info"]);
    let (n, rest) = parse_repeat(&args).unwrap();
    assert_eq!(n, 3);
    assert_eq!(rest, &s(&["otp", "info"])[..]);

    assert_eq!(
        parse_repeat(&s(&["repeat", "all", "otp", "info"]))
            .unwrap()
            .0,
        usize::MAX
    );
    assert!(parse_repeat(&s(&["repeat", "3"])).is_err());
    assert!(parse_repeat(&s(&["repeat", "0", "otp", "info"])).is_err());
    assert!(parse_repeat(&s(&["repeat", "101", "otp", "info"])).is_err());
    assert!(parse_repeat(&s(&["repeat", "x", "otp", "info"])).is_err());
    assert!(parse_repeat(&s(&["repeat", "2", "repeat", "2", "info"])).is_err());
}

#[test]
fn unroll_repeat_fills_in_the_counter() {
    let steps = vec![s(&[
        "repeat", "3", "oath", "accounts", "add", "acct${i}", "ABC",
    ])];
    let (flat, fresh, rows) = unroll(&steps, false, None);
    assert_eq!(flat.len(), 3);
    assert_eq!(flat[0][3], "acct1");
    assert_eq!(flat[2][3], "acct3");
    assert_eq!(fresh, [true, true, true]);
    assert_eq!(rows, [None, None, None]);
}

#[test]
fn unroll_keeps_plain_steps() {
    let steps = vec![s(&["otp", "info"]), s(&["piv", "info"])];
    let (flat, fresh, rows) = unroll(&steps, true, None);
    assert_eq!(flat, steps);
    assert_eq!(fresh, [false, false]);
    assert_eq!(rows, [None, None]);
}

fn table() -> Table {
    Table {
        name: "t.csv".into(),
        headers: s(&["name"]),
        rows: vec![s(&["a"]), s(&["b"]), s(&["c"])],
    }
}

#[test]
fn unroll_runs_the_sequence_once_per_csv_row() {
    let steps = vec![s(&["oath", "accounts", "add", "${name}", "ABC"])];
    let t = table();
    let (flat, _, rows) = unroll(&steps, true, Some(&t));
    assert_eq!(flat.len(), 3);
    assert_eq!(rows, [Some(0), Some(1), Some(2)]);
}

#[test]
fn unroll_repeat_all_follows_the_csv() {
    let steps = vec![s(&[
        "repeat", "all", "oath", "accounts", "add", "${name}", "ABC",
    ])];
    let t = table();
    let (flat, fresh, rows) = unroll(&steps, true, Some(&t));
    assert_eq!(flat.len(), 3);
    assert_eq!(fresh, [true, true, true]);
    assert_eq!(rows, [Some(0), Some(1), Some(2)]);
}

#[test]
fn unroll_ignores_the_csv_when_not_used() {
    let steps = vec![s(&["otp", "info"])];
    let t = table();
    let (flat, _, rows) = unroll(&steps, true, Some(&t));
    assert_eq!(flat.len(), 1);
    assert_eq!(rows, [None]);
}

#[test]
fn reboot_commands() {
    assert!(may_reboot(&s(&["config", "usb", "--disable", "OTP"])));
    assert!(may_reboot(&s(&["oath", "reset"])));
    assert!(!may_reboot(&s(&["oath", "accounts", "list"])));
    assert!(!may_reboot(&[]));
}

#[test]
fn finds_variables_with_their_ranges() {
    let word = "x${serial}y${random:hex:8}";
    let found = find_vars(word);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0], (1, 10, "serial"));
    assert_eq!(&word[found[1].0..found[1].1], "${random:hex:8}");
    assert_eq!(found[1].2, "random:hex:8");
}

#[test]
fn ignores_malformed_variables() {
    assert!(find_vars("${1bad}").is_empty());
    assert!(find_vars("${}").is_empty());
    assert!(find_vars("${open").is_empty());
    assert!(find_vars("$name").is_empty());
    assert!(find_vars("${a b}").is_empty());
    assert!(find_vars("${random::x}").is_empty());
}

#[test]
fn custom_variables_skip_builtins_and_random() {
    let steps = vec![
        s(&["a", "${serial}", "${label}"]),
        s(&["b", "${random}", "${label}", "${pin}", "${i}"]),
    ];
    assert_eq!(custom_vars(&steps), ["label", "pin"]);
}

#[test]
fn script_names() {
    assert!(valid_name("provision-1_a"));
    assert!(!valid_name(""));
    assert!(!valid_name("has space"));
    assert!(!valid_name("../escape"));
    assert!(!valid_name("a/b"));
    assert!(!valid_name(&"x".repeat(41)));
    assert!(valid_name(&"x".repeat(40)));
}

#[test]
fn quoting_round_trips_through_split_args() {
    for step in [
        s(&["otp", "info"]),
        s(&["oath", "accounts", "add", "My Label", "ABC"]),
        s(&["a", "say \"hi\"", "it's"]),
        s(&["a", ""]),
    ] {
        let text = format_step(&step);
        let back = split_args(&text);
        // A word with both quote kinds can't be represented; skip it.
        if step.iter().any(|w| w.contains('"') && w.contains('\'')) {
            continue;
        }
        assert_eq!(back, step, "{text}");
    }
}

#[test]
fn secret_flags() {
    assert!(secret_flag("--key"));
    assert!(secret_flag("--new-pin"));
    assert!(secret_flag("--Password"));
    assert!(!secret_flag("--name"));
    assert!(!secret_flag("key"));
}

#[test]
fn masks_the_value_after_a_secret_flag() {
    assert_eq!(
        masked_step(&s(&["otp", "yubiotp", "1", "--key", "abc123"])),
        "otp yubiotp 1 --key ••••"
    );
    assert_eq!(
        masked_step(&s(&["piv", "access", "--pin=123456"])),
        "piv access --pin=••••"
    );
}

#[test]
fn masks_secret_positionals_for_oath() {
    assert_eq!(
        masked_step(&s(&["oath", "accounts", "add", "Acme", "JBSWY3DP"])),
        "oath accounts add Acme ••••"
    );
    assert_eq!(
        masked_step(&s(&[
            "oath",
            "accounts",
            "uri",
            "otpauth://totp/x?secret=A"
        ])),
        "oath accounts uri ••••"
    );
    assert_eq!(
        masked_step(&s(&[
            "repeat", "3", "oath", "accounts", "add", "A", "SECRET"
        ])),
        "repeat 3 oath accounts add A ••••"
    );
}

#[test]
fn leaves_variables_visible_when_masking() {
    assert_eq!(
        masked_step(&s(&["otp", "yubiotp", "1", "--key", "${key}"])),
        "otp yubiotp 1 --key ${key}"
    );
}

#[test]
fn masking_leaves_ordinary_steps_alone() {
    assert_eq!(masked_step(&s(&["oath", "info"])), "oath info");
    assert_eq!(
        masked_step(&s(&["oath", "accounts", "add", "My Label", "x"])),
        "oath accounts add \"My Label\" ••••"
    );
}

#[test]
fn secret_looking_steps() {
    assert!(looks_secret(&s(&["otp", "yubiotp", "1", "--key", "abc"])));
    assert!(looks_secret(&s(&["otp", "static", "1", "abc"])));
    assert!(looks_secret(&s(&["oath", "accounts", "add", "A", "B"])));
    assert!(looks_secret(&s(&[
        "repeat", "2", "oath", "accounts", "uri", "u"
    ])));
    assert!(!looks_secret(&s(&["oath", "info"])));
    // A variable is asked for at run time, so nothing secret is stored.
    assert!(!looks_secret(&s(&[
        "otp", "yubiotp", "1", "--key", "${key}"
    ])));
}
