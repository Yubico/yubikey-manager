use super::*;
use clap::{Arg, ArgAction, Command};

#[test]
fn splits_on_whitespace() {
    assert_eq!(split_args("otp info"), ["otp", "info"]);
    assert_eq!(split_args("  a   b  "), ["a", "b"]);
    assert!(split_args("").is_empty());
    assert!(split_args("   ").is_empty());
}

#[test]
fn splits_with_quotes() {
    assert_eq!(split_args("a 'b c' \"d e\""), ["a", "b c", "d e"]);
    assert_eq!(split_args("say \"it's\""), ["say", "it's"]);
    assert_eq!(split_args("a '' b"), ["a", "", "b"]);
    assert_eq!(split_args("pre\"fix ed\"post"), ["prefix edpost"]);
}

#[test]
fn unterminated_quote_takes_the_rest() {
    assert_eq!(split_args("a \"b c"), ["a", "b c"]);
}

#[test]
fn partial_word_being_typed() {
    assert_eq!(current_partial("/oa"), "oa");
    assert_eq!(current_partial("oath acc"), "acc");
    assert_eq!(current_partial("oath "), "");
    assert_eq!(current_partial(""), "");
    assert_eq!(current_partial("oath --for"), "--for");
}

#[test]
fn builtin_words() {
    assert!(is_builtin("help"));
    assert!(is_builtin("exit"));
    assert!(is_builtin("scripts"));
    assert!(!is_builtin("oath"));
    assert!(!is_builtin(""));
}

#[test]
fn builtins_are_unique() {
    let mut names: Vec<&str> = BUILTINS.iter().map(|(n, _)| *n).collect();
    names.sort();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before);
}

fn node() -> Command {
    Command::new("x")
        .arg(
            Arg::new("force")
                .long("force")
                .short('f')
                .action(ArgAction::SetTrue),
        )
        .arg(Arg::new("all").short('a').action(ArgAction::SetTrue))
        .arg(
            Arg::new("key")
                .long("key")
                .short('k')
                .action(ArgAction::Set),
        )
}

#[test]
fn keeps_only_flags_and_small_numbers() {
    let node = node();
    let args = ["--force", "--key", "abc", "1", "-f"];
    assert_eq!(safe_batch_args(&node, &args), ["--force", "1", "-f"]);
}

#[test]
fn drops_values_that_could_be_secrets() {
    let node = node();
    assert!(safe_batch_args(&node, &["--key=abc"]).is_empty());
    assert!(safe_batch_args(&node, &["12", "123456"]).is_empty());
    assert!(safe_batch_args(&node, &["-k"]).is_empty());
}

#[test]
fn combined_short_flags_need_every_letter_to_be_a_flag() {
    let node = node();
    assert_eq!(safe_batch_args(&node, &["-fa"]), ["-fa"]);
    assert!(safe_batch_args(&node, &["-fk"]).is_empty());
    assert!(safe_batch_args(&node, &["-"]).is_empty());
}

#[test]
fn unknown_flags_are_dropped() {
    let node = node();
    assert!(safe_batch_args(&node, &["--nope", "-z"]).is_empty());
}
