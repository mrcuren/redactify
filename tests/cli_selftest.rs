//! `redactify selftest`, `--probe` and the dry-run CLI paths: statuses,
//! latencies, rule ids and actions are printed, probe values never.
#![cfg(feature = "config")]

use std::io::Write;
use std::process::{Command, Stdio};

/// The synthetic values of the selftest probes (must never be printed).
const PROBE_VALUES: &[&str] = &[
    "12345678950",
    "TR330006100519786457841326",
    "4111 1111 1111 1111",
    "0532 123 45 67",
    "ali@example.com",
    "Ahmet",
    "AKIAIOSFODNN7EXAMPLE",
];

/// Runs the CLI (with `policy` as the TOML policy when given) and returns
/// (exit code, stdout, stderr).
fn run(args: &[&str], policy: Option<&str>, stdin: &str) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_redactify"));
    cmd.args(args).env_remove("REDACTIFY_POLICY");
    let file = policy.map(|toml| {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "redactify-selftest-{}-{n}.toml",
            std::process::id()
        ));
        std::fs::write(&path, toml).expect("policy file");
        path
    });
    if let Some(path) = &file {
        cmd.env("REDACTIFY_POLICY", path);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("stdin write");
    let out = child.wait_with_output().expect("binary exits");
    if let Some(path) = file {
        let _ = std::fs::remove_file(path);
    }
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("utf-8"),
        String::from_utf8(out.stderr).expect("utf-8"),
    )
}

fn assert_no_values(out: &str) {
    for v in PROBE_VALUES {
        assert!(!out.contains(v), "printed {v:?}: {out}");
    }
}

#[test]
fn selftest_passes_on_the_built_in_policy() {
    for args in [&["selftest"][..], &["--selftest"][..]] {
        let (code, out, err) = run(args, None, "");
        assert_eq!(code, Some(0), "{out}{err}");
        assert!(
            out.contains("7 probes: 7 passed, 0 failed, 0 skipped"),
            "{out}"
        );
        for name in [
            "TCKN",
            "IBAN",
            "CREDIT_CARD",
            "PHONE",
            "EMAIL",
            "NAME",
            "SECRET",
        ] {
            assert!(
                out.lines()
                    .any(|l| l.starts_with("PASS") && l.contains(name)),
                "{name}: {out}"
            );
        }
        assert!(out.contains(" us"), "latency is printed: {out}");
        assert_no_values(&out);
        assert_no_values(&err);
    }
}

#[test]
fn selftest_fails_with_exit_1_when_the_policy_breaks_a_probe() {
    // a relevance rule that downgrades every e-mail after "mail": the
    // e-mail probe is not masked
    let policy = "schema_version = \"0.4\"\n[[relevance.rules]]\nentity_types = [\"EMAIL\"]\ncue_any = [\"mail\"]\n";
    let (code, out, _) = run(&["selftest"], Some(policy), "");
    assert_eq!(code, Some(1), "{out}");
    assert!(
        out.lines()
            .any(|l| l.starts_with("FAIL") && l.contains("EMAIL")),
        "{out}"
    );
    assert_no_values(&out);
}

#[test]
fn selftest_follows_the_entity_actions_and_locales() {
    let policy = "schema_version = \"0.4\"\nlocales = [\"en\"]\n[entities]\nEMAIL = \"ignore\"\nIBAN = \"block\"\nCREDIT_CARD = \"log\"\n";
    let (code, out, err) = run(&["selftest", "--json"], Some(policy), "");
    assert_eq!(code, Some(0), "{out}{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("JSON");
    let status = |name: &str| {
        v["probes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["probe"] == name)
            .map(|p| {
                (
                    p["status"].as_str().unwrap().to_owned(),
                    p["action"].as_str().unwrap().to_owned(),
                )
            })
            .unwrap()
    };
    assert_eq!(status("EMAIL"), ("skip".into(), "IGNORE".into()));
    assert_eq!(status("IBAN"), ("pass".into(), "BLOCK".into()));
    assert_eq!(status("CREDIT_CARD"), ("pass".into(), "LOG".into()));
    assert_eq!(status("TCKN").0, "skip", "tr is not selected");
    assert_no_values(&out);
}

#[test]
fn selftest_takes_no_text() {
    let (code, _, err) = run(&["--selftest", "hello"], None, "");
    assert_eq!(code, Some(2), "{err}");
    // the word itself stays expressible as a TEXT after `--`
    let (code, out, _) = run(&["--", "selftest"], None, "");
    assert_eq!(code, Some(0));
    assert!(out.contains("No PII found."), "{out}");
}

#[test]
fn probe_prints_types_offsets_rule_ids_and_actions_never_values() {
    let policy = "schema_version = \"0.4\"\n[entities]\nTCKN = \"block\"\n";
    let text = "TCKN 12345678950, mail ali@example.com";
    let (code, out, _) = run(&["--probe", text], Some(policy), "");
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("TCKN") && out.contains("BLOCK") && out.contains("rule tr::tckn"),
        "{out}"
    );
    assert!(
        out.contains("EMAIL") && out.contains("rule generic::email"),
        "{out}"
    );
    assert!(out.contains("ACTION:      Block"), "{out}");
    assert_no_values(&out);
    let (code, out, _) = run(&["--probe", "--json", "-"], None, text);
    assert_eq!(code, Some(0));
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("JSON");
    assert_eq!(v["entities"][0]["start"], 5);
    assert_eq!(v["entities"][0]["source"], "rule tr::tckn");
    assert_no_values(&out);
}

#[test]
fn dry_run_guard_exits_0_and_the_stream_echoes_its_input() {
    let policy = "schema_version = \"0.4\"\ndry_run = true\n";
    let (code, out, _) = run(&["--guard", "key AKIAIOSFODNN7EXAMPLE"], Some(policy), "");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("dry run (not enforced): would Block"), "{out}");
    let input = "hello\nkey AKIAIOSFODNN7EXAMPLE\nTCKN 12345678950\n";
    let (code, out, err) = run(&["--stream"], Some(policy), input);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, input, "shadow mode passes the input unchanged");
    assert!(err.contains("dry run (not enforced): would block"), "{err}");
    assert!(!err.contains("AKIAIOSFODNN7EXAMPLE"));
}
