//! Per-entity actions (MASK / BLOCK / LOG / IGNORE) of the policy: the
//! library decision and transformation, the TOML `[entities]` table, the
//! REST surfaces (sanitize, guard, detect, LiteLLM, stream) and how the
//! actions compose with relevance rules and guard signals.
#![cfg(all(feature = "api", feature = "config"))]

use redactify::api::{handle_request_with, ApiState};
use redactify::policy::{
    ConfigError, EntityAction, GuardAction, Policy, RelevanceRule, StreamingGuard,
};
use redactify::{Detector, EntityType, Guard, GuardTarget};
use serde_json::Value;

const TCKN: &str = "12345678950";

fn policy(entities: &str) -> Policy {
    Policy::from_toml(&format!(
        "schema_version = \"0.4\"\n[entities]\n{entities}\n"
    ))
    .expect("policy parses")
}

fn post(state: &ApiState, path: &str, body: &Value) -> (u16, Value) {
    let r = handle_request_with(state, "POST", path, &body.to_string());
    (r.status, serde_json::from_str(&r.body).expect("JSON body"))
}

#[test]
fn block_type_blocks_with_a_content_free_rationale() {
    let p = policy("TCKN = \"block\"");
    let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&p);
    let d = guard.decide(&format!("TCKN {TCKN} and mail a@b.com"));
    assert_eq!(d.action, GuardAction::Block);
    assert!(
        d.rationale.contains("configured BLOCK: TCKN"),
        "{}",
        d.rationale
    );
    assert!(!d.rationale.contains(TCKN));
    // the other types keep their default (mask) in the counts
    let counts: Vec<(EntityType, EntityAction, usize)> = d
        .entity_counts
        .iter()
        .map(|c| (c.kind, c.action, c.count))
        .collect();
    assert_eq!(
        counts,
        [
            (EntityType::Tckn, EntityAction::Block, 1),
            (EntityType::Email, EntityAction::Mask, 1)
        ]
    );
    // a fullwidth spelling (normalized view only) blocks too
    let d = guard.decide("TCKN \u{FF11}2345678950");
    assert_eq!(d.action, GuardAction::Block);
}

#[test]
fn log_type_is_counted_and_left_unmasked() {
    let p = policy("EMAIL = \"log\"");
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&p)
        .sanitize(&format!("mail a@b.com, TCKN {TCKN}"));
    assert_eq!(r.decision.action, GuardAction::Log);
    assert_eq!(r.text, "mail a@b.com, TCKN [TCKN]");
    assert_eq!(r.decision.mask_summary, ["TCKN"]);
    assert!(r.decision.rationale.contains("configured LOG"));
    // a log-only text logs, nothing else changes
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&p)
        .sanitize("mail a@b.com");
    assert_eq!(
        (r.decision.action, r.text.as_str()),
        (GuardAction::Log, "mail a@b.com")
    );
}

#[test]
fn ignore_type_is_never_detected_and_hides_nothing() {
    let p = policy("EMAIL = \"ignore\"");
    let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&p);
    let r = guard.sanitize(&format!("mail a@b.com, TCKN {TCKN}"));
    assert_eq!(r.decision.action, GuardAction::Mask);
    assert_eq!(r.text, "mail a@b.com, TCKN [TCKN]");
    assert!(r
        .decision
        .entity_counts
        .iter()
        .all(|c| c.kind != EntityType::Email));
    // mask_all (the loggable rendering) and the detector agree
    assert_eq!(guard.mask_all("mail a@b.com"), "mail a@b.com");
    assert!(guard.detector().detect("mail a@b.com").is_empty());

    // an ignored winner does not hide the overlapping candidate it beat
    let text = "see https://example.com/?u=ali@example.com";
    let plain: Vec<EntityType> = Detector::new()
        .detect(text)
        .iter()
        .map(|e| e.kind)
        .collect();
    let ignoring_url: Vec<EntityType> = Detector::new()
        .with_ignored_types(&[EntityType::Url])
        .detect(text)
        .iter()
        .map(|e| e.kind)
        .collect();
    assert!(!ignoring_url.contains(&EntityType::Url), "{ignoring_url:?}");
    if plain == [EntityType::Url] {
        assert_eq!(ignoring_url, [EntityType::Email]);
    }
}

#[test]
fn no_actions_means_no_change() {
    let text = format!("TCKN {TCKN}, mail a@b.com, http://169.254.169.254/x");
    let plain = Guard::new(GuardTarget::UserPrompt).sanitize(&text);
    let p = Policy::default();
    let with = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&p)
        .sanitize(&text);
    assert_eq!(plain, with);
    // an explicit MASK equals the default too
    let p = policy("TCKN = \"mask\"");
    let explicit = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&p)
        .sanitize(&text);
    assert_eq!(plain.text, explicit.text);
    assert_eq!(plain.decision.action, explicit.decision.action);
    // REST bodies stay byte-identical without entity actions
    let body = serde_json::json!({ "text": text });
    let a = handle_request_with(
        &ApiState::default(),
        "POST",
        "/v1/sanitize",
        &body.to_string(),
    );
    let b = handle_request_with(
        &ApiState::default().with_policy(Policy::default()),
        "POST",
        "/v1/sanitize",
        &body.to_string(),
    );
    assert_eq!(a.body, b.body);
    assert!(!a.body.contains("\"entities\""));
}

#[test]
fn relevance_downgrade_wins_over_the_entity_action() {
    let p = policy("PHONE = \"block\"").with_relevance(RelevanceRule {
        entity_types: vec![EntityType::Phone],
        cue_any: vec!["call me at".into()],
        cue_all: vec![],
        window: 64,
    });
    let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&p);
    let d = guard.decide("call me at 0532 123 45 67");
    assert_ne!(d.action, GuardAction::Block, "{}", d.rationale);
    assert_eq!(d.relevance_downgraded.len(), 1);
    assert_eq!(
        guard.decide("tel 0532 123 45 67").action,
        GuardAction::Block
    );
}

#[test]
fn signals_still_block_whatever_the_entity_actions() {
    let p = policy("EMAIL = \"log\"\nTCKN = \"ignore\"");
    let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&p);
    let r = guard.sanitize("mail a@b.com key AKIAIOSFODNN7EXAMPLE");
    assert_eq!(r.decision.action, GuardAction::Block);
    assert!(
        r.decision.rationale.contains("configured LOG"),
        "{}",
        r.decision.rationale
    );
    assert!(!r.text.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn toml_entities_table_is_validated() {
    let p = policy("TCKN = \"BLOCK\"\nEMAIL = \"Log\"\nURL = \"ignore\"\nPHONE = \"mask\"");
    assert_eq!(p.entity_actions.len(), 4);
    assert_eq!(
        p.entity_actions.action_for(EntityType::Url),
        EntityAction::Ignore
    );
    let err =
        Policy::from_toml("schema_version = \"0.4\"\n[entities]\nTCKN = \"drop\"\n").unwrap_err();
    assert!(
        matches!(&err, ConfigError::UnknownEntityAction { label } if label == "TCKN"),
        "{err}"
    );
    assert!(!err.to_string().contains("drop"));
    let err = Policy::from_toml("schema_version = \"0.4\"\n[entities]\nNOT_A_TYPE = \"block\"\n")
        .unwrap_err();
    assert!(matches!(err, ConfigError::UnknownEntityType(_)), "{err}");
    for old in ["0.1", "0.2", "0.3"] {
        let err = Policy::from_toml(&format!(
            "schema_version = \"{old}\"\n[entities]\nTCKN = \"block\"\n"
        ))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::NeedsSchema04("[entities]")),
            "{err}"
        );
        let err = Policy::from_toml(&format!("schema_version = \"{old}\"\ndry_run = true\n"))
            .unwrap_err();
        assert!(
            matches!(err, ConfigError::NeedsSchema04("dry_run")),
            "{err}"
        );
    }
    // a custom label registered by a custom rule of the same file
    let p = Policy::from_toml(
        "schema_version = \"0.4\"\n[[custom_rules]]\nlabel = \"OPS_STAFF_ID\"\npattern = '\\bS\\d{6}\\b'\n[entities]\nOPS_STAFF_ID = \"block\"\n",
    )
    .expect("custom label action");
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&p)
        .decide("staff S123456");
    assert_eq!(d.action, GuardAction::Block, "{}", d.rationale);
    assert!(d.rationale.contains("OPS_STAFF_ID"));
}

#[test]
fn rest_sanitize_guard_and_detect_honour_the_server_policy() {
    let state = ApiState::default().with_policy(policy(
        "TCKN = \"block\"\nEMAIL = \"log\"\nURL = \"ignore\"",
    ));
    let (s, v) = post(
        &state,
        "/v1/sanitize",
        &serde_json::json!({ "text": format!("TCKN {TCKN}") }),
    );
    assert_eq!(s, 200);
    assert_eq!(v["action"], "Block");
    assert!(!v.to_string().contains(TCKN), "{v}");
    assert_eq!(v["entities"][0]["type"], "TCKN");
    assert_eq!(v["entities"][0]["action"], "BLOCK");
    assert_eq!(v["entities"][0]["count"], 1);

    let (_, v) = post(
        &state,
        "/v1/sanitize",
        &serde_json::json!({ "text": "mail a@b.com" }),
    );
    assert_eq!(
        (v["action"].as_str(), v["text"].as_str()),
        (Some("Log"), Some("mail a@b.com"))
    );

    let (_, v) = post(
        &state,
        "/v1/guard",
        &serde_json::json!({ "text": "mail a@b.com" }),
    );
    assert_eq!(v["entities"][0]["action"], "LOG");

    // IGNORE reaches the detection endpoints; BLOCK and LOG types are
    // still reported and masked there (no decision)
    let (_, v) = post(
        &state,
        "/v1/redact",
        &serde_json::json!({ "text": format!("https://example.org mail a@b.com TCKN {TCKN}") }),
    );
    assert_eq!(
        v["redacted"],
        "https://example.org mail [EMAIL] TCKN [TCKN]"
    );
}

#[test]
fn litellm_endpoint_answers_blocked_for_a_block_type() {
    let state = ApiState::default().with_policy(policy("TCKN = \"block\""));
    let (s, v) = post(
        &state,
        "/beta/litellm_basic_guardrail_api",
        &serde_json::json!({ "texts": [format!("my TCKN {TCKN}")], "input_type": "request" }),
    );
    assert_eq!(s, 200);
    assert_eq!(v["action"], "BLOCKED", "{v}");
    assert!(!v.to_string().contains(TCKN));
}

#[test]
fn streaming_guard_honours_the_actions() {
    let block = policy("TCKN = \"block\"");
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(block);
    let mut events = sg.push("hello\nTCKN ");
    events.extend(sg.push(&format!("{TCKN}\nmore\n")));
    events.extend(sg.finish());
    let blocked = events.iter().any(|e| {
        matches!(e, redactify::policy::GuardEvent::Block { rationale }
            if rationale.contains("configured BLOCK: TCKN") && !rationale.contains(TCKN))
    });
    assert!(blocked, "{events:?}");

    let log = policy("EMAIL = \"log\"\nURL = \"ignore\"");
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(log.clone());
    let text = format!("mail a@b.com, TCKN {TCKN}, https://example.org\n");
    let mut out = String::new();
    for ev in sg.push(&text).into_iter().chain(sg.finish()) {
        if let Some((seg, _)) = ev.as_segment() {
            out.push_str(seg);
        }
    }
    // batch parity
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&log)
        .sanitize(&text);
    assert_eq!(out, batch.text);
    assert_eq!(out, "mail a@b.com, TCKN [TCKN], https://example.org\n");
}

#[test]
fn streaming_guard_lets_relevance_win_over_block_like_the_batch() {
    let p = policy("PHONE = \"block\"").with_relevance(RelevanceRule {
        entity_types: vec![EntityType::Phone],
        cue_any: vec!["call me at".into()],
        cue_all: vec![],
        window: 64,
    });
    for (text, blocks) in [
        ("call me at 0532 123 45 67\n", false),
        ("tel 0532 123 45 67\n", true),
    ] {
        let batch = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&p)
            .decide(text);
        assert_eq!(batch.action == GuardAction::Block, blocks, "{text}");
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(p.clone());
        let events: Vec<_> = sg.push(text).into_iter().chain(sg.finish()).collect();
        let streamed = events
            .iter()
            .any(|e| matches!(e, redactify::policy::GuardEvent::Block { .. }));
        assert_eq!(streamed, blocks, "{text}: {events:?}");
    }
}
