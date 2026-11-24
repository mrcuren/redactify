//! Secrets corpus gate: every positive vector in `data/secrets_corpus.jsonl`
//! must fire its vendor at (at least) the expected tier, and every negative
//! vector must produce zero secret spans. The corpus and the two-source
//! notes live in `data/secrets_corpus.SOURCES.md` (repo evidence rule).

use std::path::PathBuf;

use redactify::guard::find_secret_spans;
use redactify::policy::{guard_all, sanitize, GuardAction, GuardTarget};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/secrets_corpus.jsonl")
}

struct Row {
    text: String,
    expect: Vec<(String, f32)>,
}

fn load() -> Vec<Row> {
    let raw = std::fs::read_to_string(corpus_path()).expect("corpus file readable");
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("valid jsonl line");
            let text = v["text"].as_str().expect("text field").to_owned();
            let expect = v["expect"]
                .as_array()
                .expect("expect array")
                .iter()
                .map(|e| {
                    (
                        e["vendor"].as_str().expect("vendor").to_owned(),
                        e["min_score"].as_f64().expect("min_score") as f32,
                    )
                })
                .collect();
            Row { text, expect }
        })
        .collect()
}

#[test]
fn positives_fire_their_vendor_at_tier() {
    let rows = load();
    let positives = rows.iter().filter(|r| !r.expect.is_empty()).count();
    assert!(positives >= 25, "corpus shrank: {positives} positives");
    let mut hits = 0usize;
    for row in rows.iter().filter(|r| !r.expect.is_empty()) {
        let spans = find_secret_spans(&row.text);
        for (vendor, min_score) in &row.expect {
            let found = spans
                .iter()
                .any(|s| s.vendor == vendor && s.score >= *min_score - f32::EPSILON);
            if found {
                hits += 1;
            } else {
                panic!(
                    "missed {vendor} (min {min_score}) in: {}\nspans: {:?}",
                    row.text, spans
                );
            }
        }
    }
    // acceptance gate: 100% on this curated set (>= 95% was the floor)
    assert_eq!(hits, rows.iter().map(|r| r.expect.len()).sum::<usize>());
}

#[test]
fn negatives_stay_silent() {
    for row in load().into_iter().filter(|r| r.expect.is_empty()) {
        let spans = find_secret_spans(&row.text);
        assert!(
            spans.is_empty(),
            "benign fired: {} -> {:?}",
            row.text,
            spans
        );
    }
}

/// A base64-wrapped key is the same leak: the guard pipeline decodes the
/// payload layer and blocks (QUtJQUlPU0ZPRE5ON0VYQU1QTEU= is
/// base64("AKIAIOSFODNN7EXAMPLE"), verified with an external tool).
#[test]
fn base64_wrapped_key_blocks_in_guard() {
    let d = guard_all("payload QUtJQUlPU0ZPRE5ON0VYQU1QTEU= gonderiliyor");
    assert_eq!(d.action, GuardAction::Block);
}

/// Vendor-tier secrets block under the default policy and never survive a
/// sanitize round trip (Block included).
#[test]
fn secrets_never_survive_sanitize() {
    let r = sanitize(
        "AKIAIOSFODNN7EXAMPLE ve normal metin",
        &GuardTarget::UserPrompt,
    );
    assert_eq!(r.decision.action, GuardAction::Block);
    assert!(!r.text.contains("N7EXAMPLE"));
    assert!(r.text.contains("[SECRET:AWS_ACCESS_KEY]"));
}

/// Twilio Account SID and API Key SID follow the vendor schema
/// (`[0-9a-fA-F]{32}`); both `SK` key forms carry one `TWILIO_KEY` label at 0.9.
#[test]
fn twilio_sids_follow_the_vendor_schema_with_one_key_label() {
    for (text, vendor) in [
        ("sid AC0123456789abcdef0123456789abcdef", "TWILIO_SID"),
        ("sid AC0123456789ABCDEF0123456789ABCDEF", "TWILIO_SID"),
        ("key SK0123456789abcdef0123456789abcdef", "TWILIO_KEY"),
        ("key SK0123456789ABCDEF0123456789ABCDEF", "TWILIO_KEY"),
    ] {
        let spans = find_secret_spans(text);
        assert_eq!(spans.len(), 1, "{text}: {spans:?}");
        assert_eq!(spans[0].vendor, vendor, "{text}");
        assert!((spans[0].score - 0.9).abs() < 1e-6, "{text}");
    }
    // no other Twilio key label
    assert!(find_secret_spans("SK0123456789abcdef0123456789abcdef")
        .iter()
        .all(|s| s.vendor != "TWILIO_TOKEN"));
}
