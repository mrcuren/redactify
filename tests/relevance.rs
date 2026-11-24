//! Opt-in relevance rules: context-cue masking downgrades.
//!
//! Contract under test:
//! 1. An EMPTY relevance policy is a byte-identical no-op (golden parity).
//! 2. A matching rule keeps the cued entity in the text while other PII
//!    stays masked - in the decision AND in the sanitized output.
//! 3. Downgrades never soften danger signals (Block verdicts unchanged).
//! 4. Streaming with a relevance policy matches batch output (context
//!    windows are line-scoped in both: a cue on another line never counts).
//! 5. TOML (schema 0.2) parses rules and fails closed on malformed ones.
//! 6. The measured test set (`data/relevance_testset.jsonl`, provenance in
//!    its `.SOURCES.md`) holds row by row.

use redactify::policy::{GuardAction, GuardTarget, Policy, RelevanceRule, StreamingGuard};
use redactify::{EntityType, Guard};

fn phone_rule() -> RelevanceRule {
    RelevanceRule {
        entity_types: vec![EntityType::Phone],
        cue_any: vec!["call me at".into(), "reach me at".into()],
        cue_all: vec![],
        window: 64,
    }
}

fn policy_for_family(rule: &str) -> Policy {
    match rule {
        "phone_contact" => Policy::default().with_relevance(RelevanceRule {
            entity_types: vec![EntityType::Phone],
            cue_any: vec!["call me at".into(), "reach me at".into(), "ara beni".into()],
            cue_all: vec![],
            window: 64,
        }),
        "email_contact" => Policy::default().with_relevance(RelevanceRule {
            entity_types: vec![EntityType::Email],
            cue_any: vec!["contact:".into()],
            cue_all: vec![],
            window: 64,
        }),
        other => panic!("unknown rule family {other}"),
    }
}

#[test]
fn cue_less_rule_never_fires_even_via_struct_construction() {
    // pub fields bypass RelevanceRule::new's guard; an empty-cue rule must
    // not unmask anything wholesale
    let rule = RelevanceRule {
        entity_types: vec![EntityType::Phone],
        cue_any: vec![],
        cue_all: vec![],
        window: 64,
    };
    let policy = Policy::default().with_relevance(rule);
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize("call me at 0505 186 48 37");
    assert!(
        r.text.contains("[PHONE]"),
        "cue-less rule must never downgrade: {}",
        r.text
    );
    assert!(r.decision.relevance_downgraded.is_empty());
}

#[test]
fn testset_expectations_hold_row_by_row() {
    let data = std::fs::read_to_string("data/relevance_testset.jsonl")
        .expect("data/relevance_testset.jsonl (run from repo root)");
    let mut rows = 0usize;
    for line in data.lines().filter(|l| !l.trim().is_empty()) {
        rows += 1;
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let text = v["text"].as_str().unwrap();
        let policy = policy_for_family(v["rule"].as_str().unwrap());
        let r = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&policy)
            .sanitize(text);
        for stay in v["expect_stay"].as_array().unwrap() {
            let stay = stay.as_str().unwrap();
            assert!(
                r.text.contains(stay),
                "expected {stay:?} to stay in {text:?} -> {:?}",
                r.text
            );
        }
        for mask in v["expect_masked"].as_array().unwrap() {
            let mask = mask.as_str().unwrap();
            assert!(
                r.text.contains(mask),
                "expected {mask:?} in output of {text:?} -> {:?}",
                r.text
            );
        }
        let want = v["expect_action"].as_str().unwrap();
        assert_eq!(
            r.decision.action.to_string(),
            want,
            "action mismatch on {text:?}"
        );
    }
    assert_eq!(rows, 12, "test set row count is part of the contract");
}

#[test]
fn empty_relevance_policy_is_a_byte_identical_noop() {
    let text = "call me at 0505 186 48 37, TCKN 12345678950";
    let stock = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&Policy::default())
        .decide(text);
    let empty = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&Policy {
            relevance: Default::default(),
            ..Policy::default()
        })
        .decide(text);
    assert_eq!(stock, empty);

    let s1 = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&Policy::default())
        .sanitize(text);
    let s2 = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&Policy {
            relevance: Default::default(),
            ..Policy::default()
        })
        .sanitize(text);
    assert_eq!(s1.text, s2.text);
    assert_eq!(s1.decision, s2.decision);
}

#[test]
fn cued_phone_stays_and_other_pii_stays_masked() {
    let text = "call me at 0505 186 48 37, TCKN 12345678950";
    let policy = Policy::default().with_relevance(phone_rule());
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(text);
    assert!(
        r.text.contains("0505 186 48 37"),
        "cued phone must stay: {}",
        r.text
    );
    assert!(
        r.text.contains("[TCKN]"),
        "uncued TCKN must be masked: {}",
        r.text
    );
    assert!(
        !r.text.contains("[PHONE]"),
        "no phone mask expected: {}",
        r.text
    );
    // decision: the phone is downgraded (reported, span-only), mask summary
    // still names TCKN
    assert!(r.decision.mask_summary.contains(&"TCKN"));
    assert!(!r.decision.mask_summary.contains(&"PHONE"));
    assert_eq!(r.decision.relevance_downgraded.len(), 1);
    let d = &r.decision.relevance_downgraded[0];
    assert_eq!(d.kind, EntityType::Phone);
    assert!(r.decision.rationale.contains("relevance downgraded"));
}

#[test]
fn phone_without_cue_is_masked_as_before() {
    let text = "the number 0505 186 48 37 leaked";
    let policy = Policy::default().with_relevance(phone_rule());
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(text);
    assert!(
        r.text.contains("[PHONE]"),
        "uncued phone must be masked: {}",
        r.text
    );
    assert!(r.decision.relevance_downgraded.is_empty());
}

#[test]
fn downgrades_never_soften_block_verdicts() {
    // SQL injection + cued phone: Block stays Block; the Block branch keeps
    // raw text by contract (caller decides), and the API re-masks for
    // loggability - relevance is not consulted there (conservative).
    let text = "call me at 0505 186 48 37; SELECT * FROM users; --";
    let stock = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&Policy::default())
        .decide(text);
    let with_rule = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&Policy::default().with_relevance(phone_rule()))
        .decide(text);
    assert_eq!(stock.action, GuardAction::Block);
    assert_eq!(with_rule.action, GuardAction::Block);
}

#[test]
fn decision_never_echoes_downgraded_values() {
    let text = "call me at 0505 186 48 37";
    let policy = Policy::default().with_relevance(phone_rule());
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .decide(text);
    // DowngradedSpan is {kind, start, end}: the raw value must not appear
    // anywhere on the decision.
    assert!(!format!("{:?}", d).contains("0505 186 48 37"));
    assert_eq!(d.relevance_downgraded[0].kind, EntityType::Phone);
}

#[test]
fn streaming_with_relevance_matches_batch() {
    let text = "call me at 0505 186 48 37,\nsecond line TCKN 12345678950\n";
    let policy = Policy::default().with_relevance(phone_rule());
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(text);

    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(policy);
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(7) {
        let s = std::str::from_utf8(chunk).unwrap();
        for ev in sg.push(s) {
            if let Some((seg, _)) = ev.as_segment() {
                out.push_str(seg);
            }
        }
    }
    for ev in sg.finish() {
        if let Some((seg, _)) = ev.as_segment() {
            out.push_str(seg);
        }
    }
    assert_eq!(
        out, batch.text,
        "streamed relevance output must equal batch"
    );
    assert!(out.contains("0505 186 48 37"));
    assert!(out.contains("[TCKN]"));
}

#[test]
fn cue_in_previously_emitted_prefix_still_counts_in_streaming() {
    // split BEFORE the entity so the cue lands in the already-emitted
    // prefix; the full-line partition must still see it
    let policy = Policy::default().with_relevance(phone_rule());
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(policy);
    let mut out = String::new();
    for ev in sg.push("call me at ") {
        if let Some((seg, _)) = ev.as_segment() {
            out.push_str(seg);
        }
    }
    for ev in sg.push("0505 186 48 37\n") {
        if let Some((seg, _)) = ev.as_segment() {
            out.push_str(seg);
        }
    }
    for ev in sg.finish() {
        if let Some((seg, _)) = ev.as_segment() {
            out.push_str(seg);
        }
    }
    assert!(
        out.contains("0505 186 48 37"),
        "prefix cue must downgrade: {out}"
    );
}

/// Streams `text` split at byte `at` (a char boundary) and concatenates the
/// emitted segments; `None` when the stream blocked.
fn stream_split(policy: &Policy, text: &str, at: usize) -> Option<String> {
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(policy.clone());
    let mut out = String::new();
    let mut events = sg.push(&text[..at]);
    events.extend(sg.push(&text[at..]));
    events.extend(sg.finish());
    for ev in events {
        out.push_str(ev.as_segment()?.0);
    }
    Some(out)
}

#[test]
fn cue_on_another_line_never_downgrades_in_batch_or_stream() {
    // line-scoped windows: the first cue is within 64 bytes of the first
    // phone, but on the previous line
    let policy = Policy::default().with_relevance(phone_rule());
    let text = "call me at\n0505 186 48 37\nreach me at 0505 186 48 37\n";
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(text);
    assert_eq!(
        batch.text,
        "call me at\n[PHONE]\nreach me at 0505 186 48 37\n"
    );
    assert_eq!(batch.decision.relevance_downgraded.len(), 1);
    for at in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
        assert_eq!(
            stream_split(&policy, text, at).as_deref(),
            Some(batch.text.as_str()),
            "split {at}"
        );
    }
}

#[test]
fn relevance_rules_disable_intra_line_early_emission() {
    // a long newline-free line: early emission would mask the cued phone
    // in a prefix before the line's relevance context is complete; with a
    // relevance rule the line is held until it completes
    let policy = Policy::default().with_relevance(phone_rule());
    let text = format!(
        "call me at 0505 186 48 37 {}",
        "and some more words ".repeat(12)
    );
    assert!(text.len() > 192 && !text.contains('\n'));
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(&text);
    assert!(batch.text.contains("0505 186 48 37"), "{}", batch.text);
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(policy.clone());
    assert!(sg.push(&text).is_empty(), "no early segment expected");
    for at in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
        assert_eq!(
            stream_split(&policy, &text, at).as_deref(),
            Some(batch.text.as_str()),
            "split {at}"
        );
    }
}

#[cfg(feature = "api")]
mod api_exposure {
    use super::*;
    use redactify::policy::RelevancePolicy;

    #[test]
    fn api_guard_response_carries_relevance_downgraded() {
        let policy = Policy {
            relevance: RelevancePolicy {
                rules: vec![phone_rule()],
            },
            ..Policy::default()
        };
        let state = redactify::api::ApiState::default().with_policy(policy);
        let resp = redactify::api::handle_request_with(
            &state,
            "POST",
            "/v1/guard",
            r#"{"text": "call me at 0505 186 48 37"}"#,
        );
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        let rd = body["relevance_downgraded"].as_array().unwrap();
        assert_eq!(rd.len(), 1);
        assert_eq!(rd[0]["type"], "PHONE");
        // spans only - the raw value must not appear anywhere
        assert!(!resp.body.contains("0505 186 48 37"));
    }
}

#[cfg(feature = "config")]
mod toml_config {
    use super::*;
    use redactify::policy::ConfigError;

    #[test]
    fn schema_02_parses_relevance_rules() {
        let p = Policy::from_toml(
            r#"
            schema_version = "0.2"
            block_at = 0.6

            [[relevance.rules]]
            entity_types = ["PHONE", "EMAIL"]
            cue_any = ["call me at", "reach me at"]
            window = 64

            [[relevance.rules]]
            entity_types = ["NAME"]
            cue_all = ["resume", "attached"]
            "#,
        )
        .unwrap();
        assert_eq!(p.relevance.rules.len(), 2);
        assert_eq!(
            p.relevance.rules[0].entity_types,
            vec![EntityType::Phone, EntityType::Email]
        );
        assert_eq!(p.relevance.rules[0].window, 64);
        assert!(p.relevance.rules[1].cue_all.contains(&"resume".to_owned()));
        // default window when omitted
        assert_eq!(
            p.relevance.rules[1].window,
            redactify::policy::DEFAULT_WINDOW
        );

        // behavior: the parsed rule downgrades
        let r = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&p)
            .sanitize("call me at 0505 186 48 37");
        assert!(r.text.contains("0505 186 48 37"));
    }

    #[test]
    fn schema_01_files_keep_parsing_without_relevance() {
        let p = Policy::from_toml(
            r#"
            schema_version = "0.1"
            block_at = 0.5
            "#,
        )
        .unwrap();
        assert_eq!(p.block_at, 0.5);
        assert!(p.relevance.is_empty());
    }

    #[test]
    fn schema_05_is_rejected() {
        // 0.4 (entity actions) is the newest schema; the next minor refuses
        let err = Policy::from_toml("schema_version = \"0.5\"").unwrap_err();
        assert!(matches!(err, ConfigError::SchemaVersion(_)));
    }

    #[test]
    fn unknown_entity_type_fails_closed() {
        let err = Policy::from_toml(
            r#"
            schema_version = "0.2"
            [[relevance.rules]]
            entity_types = ["PHONEE"]
            cue_any = ["x"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownEntityType(s) if s == "PHONEE"));
    }

    #[test]
    fn cueless_rule_fails_closed() {
        let err = Policy::from_toml(
            r#"
            schema_version = "0.2"
            [[relevance.rules]]
            entity_types = ["PHONE"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::RelevanceRuleWithoutCues(_)));
    }

    #[test]
    fn empty_entity_types_fails_closed() {
        let err = Policy::from_toml(
            r#"
            schema_version = "0.2"
            [[relevance.rules]]
            entity_types = []
            cue_any = ["x"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::EmptyEntityTypes));
    }
}
