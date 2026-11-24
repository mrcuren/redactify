//! CLI argument handling: a mistake in the flags must never make the CLI
//! scan some other text than the input and report it clean. Every usage
//! error exits 2 with nothing on stdout; `--` ends the options (POSIX
//! utility syntax guideline 10), so a TEXT that starts with `-` stays
//! expressible.

use std::process::Command;

const PII: &str = "TCKN 12345678950";

/// Runs the CLI and returns (exit code, stdout, stderr).
fn run_cli<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_redactify"))
        .args(args)
        .env_remove("REDACTIFY_POLICY")
        .output()
        .expect("binary runs");
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
        String::from_utf8(out.stderr).expect("utf-8 stderr"),
    )
}

fn assert_usage_error(args: &[&str], stderr_mentions: &str) {
    let (code, stdout, stderr) = run_cli(args);
    assert_eq!(
        code,
        Some(2),
        "{args:?}: stdout {stdout:?} stderr {stderr:?}"
    );
    assert!(stdout.is_empty(), "{args:?}: {stdout}");
    assert!(stderr.contains(stderr_mentions), "{args:?}: {stderr}");
    assert!(
        !stderr.contains("12345678950"),
        "{args:?} echoed the text: {stderr}"
    );
}

#[test]
fn an_unknown_flag_is_refused_wherever_it_stands() {
    // a misspelled mode flag is not scanned as the text ("No PII found.")
    assert_usage_error(&["--sanitise", PII], "--sanitise");
    // and an unknown flag after the mode does not take the place of the text
    assert_usage_error(&["--guard", "--verbose", PII], "--verbose");
    assert_usage_error(&[PII, "-x"], "-x");
}

#[test]
fn more_than_one_text_is_refused() {
    // unquoted words would otherwise scan the first word only
    assert_usage_error(&["TCKN", "12345678950"], "one TEXT");
    assert_usage_error(&["--sanitize", "a", "b"], "one TEXT");
    assert_usage_error(&["-", PII], "one TEXT");
}

#[test]
fn two_different_modes_are_refused() {
    assert_usage_error(&["--guard", "--sanitize", PII], "--sanitize");
}

#[test]
fn value_flags_without_a_value_are_refused() {
    for flag in ["--target", "-t", "--locale", "-l"] {
        assert_usage_error(&["--guard", flag], flag);
    }
}

#[test]
fn stream_and_fpr_monitor_take_no_text() {
    assert_usage_error(&["--stream", PII], "--stream");
    assert_usage_error(&["--fpr-monitor", PII], "--fpr-monitor");
}

#[test]
fn double_dash_ends_the_options() {
    let (code, stdout, stderr) = run_cli(&["--sanitize", "--json", "--", "-x TCKN 12345678950"]);
    assert_eq!(code, Some(0), "{stdout} {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON value");
    assert_eq!(v["text"], "-x TCKN [TCKN]");
    // a flag name after `--` is text, not a flag
    let (code, stdout, _) = run_cli(&["--", "--guard"]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("No PII found."), "{stdout}");
}

#[test]
fn flags_may_follow_the_text() {
    let (code, stdout, stderr) = run_cli(&[PII, "--sanitize", "--json"]);
    assert_eq!(code, Some(0), "{stdout} {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON value");
    assert_eq!(v["text"], "TCKN [TCKN]");
}

#[cfg(any(windows, unix))]
#[test]
fn a_non_unicode_argument_is_refused_without_echoing_it() {
    #[cfg(windows)]
    let arg = {
        use std::os::windows::ffi::OsStringExt;
        // "TCKN 12345678950" followed by an unpaired surrogate
        let mut wide: Vec<u16> = PII.encode_utf16().collect();
        wide.push(0xD800);
        std::ffi::OsString::from_wide(&wide)
    };
    #[cfg(unix)]
    let arg = {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = PII.as_bytes().to_vec();
        bytes.push(0xFF);
        std::ffi::OsString::from_vec(bytes)
    };
    let (code, stdout, stderr) = run_cli(&[arg]);
    assert_eq!(code, Some(2), "stdout {stdout:?} stderr {stderr:?}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.contains("12345678950"), "argument echoed: {stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn a_closed_stdout_keeps_the_decision_exit_code() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_redactify"))
        .args(["--guard", "-"])
        .env_remove("REDACTIFY_POLICY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary runs");
    // the reader leaves before any output (`redactify --guard - | grep -q x`)
    drop(child.stdout.take());
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin
        .write_all(b"AKIAIOSFODNN7EXAMPLE")
        .expect("stdin write");
    drop(stdin);
    let out = child.wait_with_output().expect("binary exits");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Block exits 1, never a printing panic's 101
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
