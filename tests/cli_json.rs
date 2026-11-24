//! CLI JSON output tests: exercise the real binary (CARGO_BIN_EXE) in every
//! mode that supports `--json`, asserting the responses are valid JSON with
//! the documented fields. Complements the REST API tests: same detailed
//! format, different transport.
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_redactify"))
}

fn run_json(args: &[&str]) -> serde_json::Value {
    let out = bin().args(args).output().expect("binary runs");
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout is not a single JSON value ({e}): {stdout:?}");
    })
}

#[test]
fn cli_detect_json() {
    let v = run_json(&["--json", "TCKN 12345678950 ve mail a@b.com"]);
    let ents = v["entities"].as_array().unwrap();
    assert!(ents
        .iter()
        .any(|e| e["type"] == "TCKN" && e["score"] == 1.0));
    assert!(ents.iter().any(|e| e["type"] == "EMAIL"));
}

#[test]
fn cli_guard_json_blocks_and_reports() {
    let out = bin()
        .args(["--guard", "--json", "bkz http://169.254.169.254/meta"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "Block exits 1");
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8(out.stdout).unwrap().trim()).unwrap();
    assert_eq!(v["action"], "Block");
    assert!(v["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["category"] == "DANGEROUS_URL"));
}

#[test]
fn cli_sanitize_json_masks() {
    let v = run_json(&["--sanitize", "--json", "TCKN 12345678950 gitti"]);
    assert_eq!(v["action"], "Mask");
    assert!(v["text"].as_str().unwrap().contains("[TCKN]"));
    assert!(v["pii_found"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("TCKN")));
}

#[test]
fn cli_sanitize_json_model_output_encodes() {
    let v = run_json(&["--sanitize", "--json", "--target", "model-output", "5 < 10"]);
    assert!(v["text"].as_str().unwrap().contains("5 &lt; 10"));
}

#[test]
fn cli_encode_json() {
    let v = run_json(&["--encode", "--json", "a < b"]);
    assert_eq!(v["encoded"], "a &lt; b");
}

#[test]
fn cli_vault_json_round_trip() {
    let v = run_json(&["--vault", "--json", "TCKN 12345678950 arayin"]);
    // pseudonymized hides the raw value; restored round-trips it back
    let anon = v["pseudonymized"].as_str().unwrap();
    assert!(
        !anon.contains("12345678950"),
        "pseudonymized leaked PII: {anon}"
    );
    assert_eq!(v["restored"], "TCKN 12345678950 arayin");
    assert!(!v["entries"].as_array().unwrap().is_empty());
}

#[test]
fn cli_locale_filter_excludes_other_locale() {
    // SSN is en; a tr-only scan must not report it
    let tr = run_json(&["--json", "--locale", "tr", "SSN 536-90-6292 gitti"]);
    assert_eq!(tr["entities"].as_array().unwrap().len(), 0);
    let en = run_json(&["--json", "--locale", "en", "SSN 536-90-6292 gitti"]);
    assert!(en["entities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "SSN"));
}

// ------------------------------------------------------------ --stream

#[test]
fn cli_stream_masks_as_lines_complete() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = bin()
        .arg("--stream")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary spawns");
    {
        let stdin = child.stdin.as_mut().unwrap();
        // chunk boundary INSIDE the line, mid-identifier: the line is only
        // processed when complete, so the entity is found whole
        stdin.write_all(b"TCKN 12345678").unwrap();
        stdin.write_all(b"950 gecerli\n").unwrap();
        stdin.write_all(b"ikinci satir\n").unwrap();
    } // drop closes stdin
    let out = child.wait_with_output().expect("child exits");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "TCKN [TCKN] gecerli\nikinci satir\n"
    );
    assert!(out.status.success(), "no block expected");
}

#[test]
fn cli_stream_block_stops_forwarding_and_exits_one() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = bin()
        .arg("--stream")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary spawns");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"guvenli satir\n").unwrap();
        stdin
            .write_all(b"bkz http://169.254.169.254/meta\n")
            .unwrap();
        stdin.write_all(b"bu satir ulasmamali\n").unwrap();
    }
    let out = child.wait_with_output().expect("child exits");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout, "guvenli satir\n");
    assert_eq!(out.status.code(), Some(1), "block exits 1");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("blocked"), "{stderr}");
}

#[test]
fn cli_stream_json_emits_ndjson_events() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = bin()
        .args(["--stream", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary spawns");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"TCKN 12345678950\n").unwrap();
    }
    let out = child.wait_with_output().expect("child exits");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let events: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();
    assert_eq!(events.len(), 1, "{stdout}");
    assert_eq!(events[0]["type"], "segment");
    assert_eq!(events[0]["text"], "TCKN [TCKN]\n");
    assert!(out.status.success());
}

// -------------------------------------------------------- stdin, --locale

/// Runs the binary with `args`, feeding `stdin`; returns (exit code,
/// stdout, stderr).
fn run_with_stdin(args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary spawns");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("child exits");
    (
        out.status.code(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn cli_dash_reads_the_text_from_stdin() {
    // detect: `-` is stdin, not the text "-"
    let (code, stdout, _) = run_with_stdin(&["--json", "-"], "TCKN 12345678950");
    assert_eq!(code, Some(0));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["input"], "TCKN 12345678950");
    assert_eq!(v["entities"][0]["type"], "TCKN");
    // the guard modes too
    let (code, stdout, _) = run_with_stdin(&["--sanitize", "--json", "-"], "SSN 536-90-6292 gitti");
    assert_eq!(code, Some(0));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["text"], "SSN [SSN] gitti");
}

#[test]
fn cli_guard_honors_the_locale_flag() {
    // the uk pack is opt-in: without it the NHS number is plain text
    let (code, stdout, _) = run_with_stdin(&["--guard", "--json", "nhs 9434765870"], "");
    assert_eq!(code, Some(0));
    let plain: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(plain["action"], "Allow");
    let (code, stdout, _) = run_with_stdin(
        &["--guard", "--locale", "uk", "--json", "nhs 9434765870"],
        "",
    );
    assert_eq!(code, Some(0));
    let uk: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(uk["action"], "Mask");
    assert_eq!(uk["pii_found"], serde_json::json!(["UK_NHS"]));
}

#[test]
fn cli_sanitize_vault_stream_and_detect_honor_the_locale_flag() {
    let v = run_json(&["--sanitize", "-l", "uk", "--json", "nhs 9434765870"]);
    assert_eq!(v["text"], "nhs [UK_NHS]");
    let v = run_json(&["--vault", "-l", "uk", "--json", "nhs 9434765870"]);
    assert_eq!(v["pseudonymized"], "nhs [UK_NHS_1]");
    assert_eq!(v["restored"], "nhs 9434765870");
    let (code, stdout, _) = run_with_stdin(&["--stream", "-l", "uk"], "nhs 9434765870\n");
    assert_eq!(code, Some(0));
    assert_eq!(stdout, "nhs [UK_NHS]\n");
    // human detect output: the masked line comes from the same detector
    // as the table (not with the default tr+en set)
    let (code, stdout, _) = run_with_stdin(&["-l", "uk", "nhs 9434765870"], "");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("UK_NHS"), "{stdout}");
    assert_eq!(stdout.lines().last(), Some("nhs [UK_NHS]"), "{stdout}");
}

#[test]
fn cli_fpr_monitor_parses_its_pacing_flags() {
    let (code, _, stderr) = run_with_stdin(
        &[
            "--fpr-monitor",
            "--interval-secs",
            "0",
            "--max-iterations",
            "1",
        ],
        "",
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("max 1 iterations"), "{stderr}");
    assert!(stderr.contains("iter 1/1"), "{stderr}");
    assert!(stderr.contains("PASSED"), "{stderr}");
    for bad in [
        &["--fpr-monitor", "--max-iterations", "0"][..],
        &["--fpr-monitor", "--interval-secs", "soon"][..],
        &["--fpr-monitor", "--max-iterations"][..],
    ] {
        let (code, _, stderr) = run_with_stdin(bad, "");
        assert_eq!(code, Some(2), "{bad:?}: {stderr}");
        assert!(stderr.contains("error"), "{stderr}");
    }
}

#[test]
fn cli_usage_documents_every_flag_and_locale() {
    let (code, stdout, _) = run_with_stdin(&["--help"], "");
    assert_eq!(code, Some(0));
    for needle in [
        "--policy",
        "--fpr-monitor",
        "--interval-secs",
        "--max-iterations",
        "[TEXT | -]",
        "tool_response",
    ] {
        assert!(stdout.contains(needle), "usage lacks {needle}: {stdout}");
    }
    // the --locale paragraph lists every locale pack
    let start = stdout.find("--locale").expect("--locale documented");
    let end = start
        + stdout[start..]
            .find("--policy")
            .expect("--policy after --locale");
    let words: Vec<&str> = stdout[start..end]
        .split(|c: char| !c.is_ascii_alphanumeric())
        .collect();
    for locale in redactify::SUPPORTED_LOCALES {
        assert!(words.contains(locale), "usage lacks locale {locale}");
    }
}
