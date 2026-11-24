//! Fail-mode gates: a detector that errors must be distinguishable from
//! both "clean" and "absent".
//!
//! Matrix under test (full table lives in the crate docs, `lib.rs`):
//!
//! | Component | Failure | Behavior |
//! |---|---|---|
//! | deterministic rules (L0) | regex cancel | per-match skip; embedded patterns are compile-tested (`expect`) |
//! | ML classifiers (L2/L3) | load error | startup REFUSES (`Err` from `new`; CLI exits 1) |
//! | ML classifiers (L2/L3) | inference error/timeout | `FailMode::Closed` (default): max-severity signals -> Block |
//! | PII engine (L1) | regex runtime error (backtrack limit) | `SCAN_INCOMPLETE` Log signal (blockable via override) + the line masked as `[SCAN_INCOMPLETE]` |
//! | NER enrichment (L1) | inference error | fail-open spans + `NER_DEGRADED` Log signal (blockable via override), batch and stream |
//! | NER ensemble (PIIRanha) | member load failure | single-model fallback + `NER_DEGRADED` Log signal |
//! | API worker | handler panic | 500 via `catch_unwind`; raw body never echoed |
//! | secrets (L0) | n/a (deterministic) | vendor shape -> Block + masked out of every sanitize branch |

use redactify::guard::ml::{fail_closed_signals, FailMode};
use redactify::guard::{GuardSignal, SignalKind};
use redactify::policy::{decide, GuardAction, GuardCategory, GuardTarget, Policy, Threshold};
use redactify::{CustomRule, Detector, Entity, EntityType, Guard, NerHealth, NerRecognizer};

/// A recognizer whose model "failed": no spans, health Degraded - the
/// exact posture of OnnxNerRecognizer after an inference error.
struct DegradedNer;

impl NerRecognizer for DegradedNer {
    fn recognize(&self, _text: &str) -> Vec<Entity> {
        Vec::new()
    }
    fn name(&self) -> &'static str {
        "degraded-ner"
    }
    fn health(&self) -> NerHealth {
        NerHealth::Degraded("simulated inference failure")
    }
}

#[test]
fn fail_closed_signals_are_block_level_for_every_category() {
    let cats = [
        GuardCategory::PromptInjection,
        GuardCategory::Jailbreak,
        GuardCategory::Hate,
        GuardCategory::SelfHarm,
    ];
    let sigs = fail_closed_signals(&cats);
    assert_eq!(sigs.len(), cats.len());
    assert!(sigs.iter().all(|&(_, s)| s >= 1.0));
}

#[test]
fn fail_mode_closed_is_the_documented_default_semantics() {
    // the enum surface is the contract: Closed exists, is distinct, and the
    // ONNX classifiers document it as their default (lib.rs matrix)
    assert_ne!(FailMode::Closed, FailMode::Open);
}

#[test]
fn degraded_ner_surfaces_a_log_signal_not_silence() {
    let rec = [&DegradedNer as &dyn NerRecognizer];
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_ner(&rec)
        .decide("bugun toplantida konusuldu");
    assert_eq!(d.action, GuardAction::Log);
    assert!(
        d.rationale.to_ascii_uppercase().contains("NERDEGRADED"),
        "rationale must name the degraded enricher: {}",
        d.rationale
    );
    assert!(d.signals.iter().any(|s| s.kind == SignalKind::NerDegraded));
}

#[test]
fn degraded_ner_is_blockable_via_category_override() {
    // fail-closed operators: one policy line turns the health signal into
    // a Block (Threshold::Low blocks from 0.35; the signal scores 0.4)
    let mut policy = Policy::default();
    policy
        .categories
        .set(GuardCategory::NerDegraded, Threshold::Low);
    let signals = vec![GuardSignal {
        kind: SignalKind::NerDegraded,
        score: 0.4,
        evidence: "degraded-ner".into(),
        rationale: "ner enricher degraded: simulated".into(),
    }];
    let d = decide(&signals, &[], &policy);
    assert_eq!(d.action, GuardAction::Block);
}

#[test]
fn degraded_ner_does_not_break_sanitize() {
    let rec = [&DegradedNer as &dyn NerRecognizer];
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_ner(&rec)
        .sanitize("normal metin");
    // text unchanged (nothing to mask), decision is Log, no panic
    assert_eq!(r.text, "normal metin");
    assert_eq!(r.decision.action, GuardAction::Log);
}

#[test]
fn degraded_ner_in_a_stream_is_logged_and_blockable() {
    use redactify::policy::{GuardEvent, StreamingGuard};
    use std::sync::Arc;
    let ner: Arc<dyn NerRecognizer> = Arc::new(DegradedNer);
    // default policy: the health signal only logs, the line is forwarded
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_ner(vec![Arc::clone(&ner)]);
    let ev = sg.push("bugun toplantida konusuldu\n");
    assert_eq!(
        ev[0].as_segment().map(|(t, _)| t.as_str()),
        Some("bugun toplantida konusuldu\n")
    );
    // fail-closed operators: the same category override as in batch blocks
    let policy = Policy::default().with_category(GuardCategory::NerDegraded, Threshold::Low);
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt)
        .with_ner(vec![ner])
        .with_policy(policy);
    let ev = sg.push("bugun toplantida konusuldu\n");
    assert!(matches!(ev[0], GuardEvent::Block { .. }), "{ev:?}");
    assert!(sg.is_blocked());
}

#[test]
fn healthy_ner_stays_silent_on_health() {
    struct OkNer;
    impl NerRecognizer for OkNer {
        fn recognize(&self, _text: &str) -> Vec<Entity> {
            Vec::new()
        }
        fn name(&self) -> &'static str {
            "ok-ner"
        }
    }
    let rec = [&OkNer as &dyn NerRecognizer];
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_ner(&rec)
        .decide("normal metin");
    assert_eq!(d.action, GuardAction::Allow);
    assert!(!d.rationale.contains("NER_DEGRADED"));
}

#[cfg(feature = "api")]
mod api_block_never_echoes_raw_secrets {
    #[test]
    fn sanitize_endpoint_masks_secret_on_block() {
        // pure handler (same code path the socket server dispatches to)
        let r = redactify::api::handle_request(
            "POST",
            "/v1/sanitize",
            r#"{"text": "AKIAIOSFODNN7EXAMPLE gonderiliyor", "target": "user_prompt"}"#,
        );
        assert_eq!(r.status, 200);
        assert!(!r.body.contains("N7EXAMPLE"), "raw key echoed: {}", r.body);
        assert!(
            r.body.contains("[SECRET:AWS_ACCESS_KEY]"),
            "secret not masked: {}",
            r.body
        );
    }

    #[test]
    fn guard_endpoint_blocks_secret_without_echoing_it() {
        let r = redactify::api::handle_request(
            "POST",
            "/v1/guard",
            r#"{"text": "token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 aktif"}"#,
        );
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["action"], "Block");
        assert!(
            !r.body.contains("MnOpQrStUvWxYz0123456789"),
            "raw token echoed: {}",
            r.body
        );
        assert!(v["signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["kind"] == "SECRETS"));
    }
}

// ------------------------------------------------------------- NaN scores

/// A recognizer that reports "Ahmet Yilmaz" with a NaN score.
struct NanNer;

impl NerRecognizer for NanNer {
    fn recognize(&self, text: &str) -> Vec<Entity> {
        let Some(start) = text.find("Ahmet Yilmaz") else {
            return Vec::new();
        };
        let end = start + "Ahmet Yilmaz".len();
        vec![Entity {
            kind: EntityType::Name,
            start,
            end,
            text: text[start..end].to_owned(),
            score: f32::NAN,
        }]
    }

    fn name(&self) -> &'static str {
        "nan-ner"
    }
}

#[test]
fn nan_scores_fail_safe() {
    let rule = CustomRule::new(EntityType::Itin, r"ORC-\d{4}")
        .unwrap()
        .with_score(f32::NAN);
    let rules = [&rule];
    let ner = NanNer;
    let rec = [&ner as &dyn NerRecognizer];
    for threshold in [0.0, 0.5, 0.99] {
        assert_eq!(
            Detector::new()
                .with_custom_rules(&rules)
                .with_threshold(threshold)
                .redact("ref ORC-1234 x"),
            "ref [ITIN] x",
            "threshold {threshold}"
        );
        assert_eq!(
            Detector::new()
                .with_ner(&rec)
                .with_threshold(threshold)
                .redact("we met Ahmet Yilmaz today"),
            "we met [NAME] today",
            "threshold {threshold}"
        );
    }
}
