//! Custom rules from the TOML policy (schema 0.3, `[[custom_rules]]`):
//! the Docker / REST deployment adds its own identifiers without Rust code.
//! Every rule is compiled when the file is parsed (fail-closed), and every
//! guard that carries the policy applies the rules.
#![cfg(feature = "config")]

use redactify::policy::{ConfigError, Policy, StreamingGuard};
use redactify::{Guard, GuardAction, GuardTarget};

const POLICY: &str = r#"
schema_version = "0.3"

[[custom_rules]]
label = "EMPLOYEE_ID"
pattern = '\bE\d{6}\b'

[[custom_rules]]
label = "PROJECT_CODENAME"
words = ["Falcon", "Nightjar"]

[[custom_rules]]
label = "TICKET_ID"
pattern = '\bT-\d{4}\b'
cues = ["ticket", "bilet"]
score = 0.9
"#;

fn policy() -> Policy {
    Policy::from_toml(POLICY).expect("valid policy")
}

#[test]
fn guards_with_the_policy_apply_its_custom_rules() {
    let p = policy();
    let guard = Guard::new(GuardTarget::UserPrompt).with_policy(Some(&p));
    let r = guard.sanitize("personel E123456 Falcon projesinde, ticket T-1234");
    assert_eq!(
        r.decision.action,
        GuardAction::Mask,
        "{}",
        r.decision.rationale
    );
    assert_eq!(
        r.text,
        "personel [EMPLOYEE_ID] [PROJECT_CODENAME] projesinde, ticket [TICKET_ID]"
    );
    // the cue-gated rule needs its cue
    assert_eq!(guard.sanitize("T-9999 notu").text, "T-9999 notu");
    let found = guard.detector().detect("bilet T-1234");
    assert_eq!(found[0].kind.as_str(), "TICKET_ID");
    assert_eq!(found[0].score, 0.9);
}

#[test]
fn custom_rules_need_schema_0_3() {
    let old = POLICY.replace("\"0.3\"", "\"0.2\"");
    assert!(matches!(
        Policy::from_toml(&old),
        Err(ConfigError::CustomRulesNeedSchema03)
    ));
    // 0.4 (entity actions) keeps custom rules; the gate moves to 0.5
    assert!(Policy::from_toml(&POLICY.replace("\"0.3\"", "\"0.4\"")).is_ok());
    assert!(matches!(
        Policy::from_toml("schema_version = \"0.5\""),
        Err(ConfigError::SchemaVersion(_))
    ));
    // a 0.3 file without custom rules is fine
    assert!(Policy::from_toml("schema_version = \"0.3\"").is_ok());
}

#[test]
fn invalid_custom_rules_refuse_the_file() {
    let cases = [
        // pattern does not compile
        ("label = \"BAD\"\npattern = '(unclosed'", 0),
        // neither pattern nor words / both
        ("label = \"NONE\"", 0),
        ("label = \"BOTH\"\npattern = 'x'\nwords = [\"y\"]", 0),
        // not a label shape / score outside 0..=1
        ("label = \"lower\"\npattern = 'x'", 0),
        ("label = \"SCORE\"\npattern = 'x'\nscore = 1.5", 0),
    ];
    for (rule, index) in cases {
        let text = format!("schema_version = \"0.3\"\n[[custom_rules]]\n{rule}\n");
        match Policy::from_toml(&text) {
            Err(ConfigError::CustomRule(e)) => assert_eq!(e.index, index, "{rule}"),
            other => panic!("{rule}: expected a custom rule error, got {other:?}"),
        }
    }
    // unknown fields are refused like everywhere in the schema
    let text =
        "schema_version = \"0.3\"\n[[custom_rules]]\nlabel = \"X\"\npattern = 'x'\nboost = 1\n";
    assert!(matches!(Policy::from_toml(text), Err(ConfigError::Toml(_))));
}

#[test]
fn the_streaming_guard_with_the_policy_matches_batch() {
    let p = policy();
    let text = "satir bir E123456\nikinci satir Nightjar ve ticket T-1234\n";
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_policy(Some(&p))
        .sanitize(text);
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(policy());
    let mut out = String::new();
    for chunk in text.split_inclusive(' ') {
        for ev in sg.push(chunk) {
            out.push_str(ev.as_segment().expect("no Block").0);
        }
    }
    for ev in sg.finish() {
        out.push_str(ev.as_segment().expect("no Block").0);
    }
    assert_eq!(out, batch.text);
    assert!(out.contains("[PROJECT_CODENAME]"), "{out}");
}

#[test]
fn equal_files_give_equal_policies() {
    assert_eq!(policy(), policy());
    assert_ne!(policy(), Policy::default());
}

#[cfg(feature = "api")]
#[test]
fn the_rest_server_policy_applies_custom_rules_on_every_endpoint() {
    use redactify::api::{handle_request_with, ApiState};
    let state = ApiState::default().with_policy(policy());
    for (path, body) in [
        ("/v1/sanitize", r#"{"text":"personel E123456"}"#),
        ("/v1/redact", r#"{"text":"personel E123456"}"#),
        ("/v1/detect", r#"{"text":"personel E123456"}"#),
        ("/v1/json/redact", r#"{"json":{"note":"personel E123456"}}"#),
        (
            "/v1/stream/sanitize",
            r#"{"chunks":["personel E123456\n"]}"#,
        ),
    ] {
        let r = handle_request_with(&state, "POST", path, body);
        assert_eq!(r.status, 200, "{path}: {}", r.body);
        assert!(r.body.contains("EMPLOYEE_ID"), "{path}: {}", r.body);
        assert!(!r.body.contains("E123456"), "{path}: {}", r.body);
    }
}

#[cfg(feature = "serde")]
#[test]
fn a_policy_round_trips_through_serde_with_working_rules() {
    let p = policy();
    let json = serde_json::to_string(&p).expect("serialize");
    let back: Policy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, p);
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(Some(&back))
        .sanitize("E123456");
    assert_eq!(r.text, "[EMPLOYEE_ID]");
}
