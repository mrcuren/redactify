//! Serde round-trip tests for the optional `serde` feature.
//!
//! - Round-trip (Serialize + Deserialize): data/config types consumers may
//!   persist or exchange (`Entity`, `Policy`, `GuardSignal`, ...).
//! - Serialize-only smoke: `Decision`, `SanitizeResult`, `AuditRecord` and
//!   `ToolVerdict` carry `&'static str` labels that `Deserialize` cannot
//!   produce (no `'static` data from borrowed input); each type documents
//!   this on its definition.
//! - Log-safe output: `GuardEvent` (Serialize-only) carries segment
//!   entities as `{kind, start, end, score}` without the raw value, and a
//!   blocked `SanitizeResult` serializes its raw-PII text as `null`.
//! - Label stability: enums serialize to their canonical labels
//!   (`EntityType::Tckn` -> `"TCKN"`, `GuardCategory::SqlInjection` ->
//!   `"SQL_INJECTION"`, `GuardTarget::ToolResponse` -> `"tool_response"`),
//!   matching `as_str()` / `FromStr` spellings used by the REST API and CLI.

#![cfg(feature = "serde")]

use std::str::FromStr;

use redactify::guard::rules::sql_risk;
use redactify::guard::tools::{ToolCall, ToolContract, ToolVerdict};
use redactify::guard::{AuditRecord, GuardCategory, GuardSignal};
use redactify::policy::{
    decide, sanitize, GuardAction, GuardEvent, GuardTarget, Policy, Severity, Threshold,
};
use redactify::{detect, Entity, EntityType};

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json::to_string(value).expect("serializes");
    serde_json::from_str(&json).expect("deserializes")
}

#[test]
fn entity_roundtrips_byte_identical() {
    let entities = detect("TCKN 12345678950, e-posta: a@b.com");
    assert!(!entities.is_empty());
    for e in &entities {
        assert_eq!(&roundtrip(e), e);
    }
}

#[test]
fn entity_type_serializes_to_canonical_label() {
    // canonical labels must match EntityType::as_str (API/CLI spellings)
    for (variant, label) in [
        (EntityType::Tckn, "TCKN"),
        (EntityType::CreditCard, "CREDIT_CARD"),
        (EntityType::UsPassport, "US_PASSPORT"),
        (EntityType::DeTaxId, "DE_TAX_ID"),
    ] {
        assert_eq!(
            serde_json::to_string(&variant).unwrap(),
            format!("\"{label}\"")
        );
        let back: EntityType = serde_json::from_str(&format!("\"{label}\"")).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn policy_with_overrides_roundtrips() {
    let policy = Policy::default()
        .with_category(GuardCategory::SqlInjection, Threshold::High)
        .with_category(GuardCategory::DangerousUrl, Threshold::None);
    let back = roundtrip(&policy);
    assert_eq!(back, policy);
    assert_eq!(
        back.categories.get(GuardCategory::SqlInjection),
        Some(Threshold::High)
    );
}

#[test]
fn severity_and_threshold_use_band_labels() {
    assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"HIGH\"");
    assert_eq!(
        serde_json::to_string(&Threshold::Medium).unwrap(),
        "\"MEDIUM\""
    );
    let back: Severity = serde_json::from_str("\"LOW\"").unwrap();
    assert_eq!(back, Severity::Low);
}

#[test]
fn guard_target_matches_from_str_spelling() {
    // serde form == the FromStr canonical spelling (user_prompt, ...)
    assert_eq!(
        serde_json::to_string(&GuardTarget::ToolResponse).unwrap(),
        "\"tool_response\""
    );
    let back: GuardTarget = serde_json::from_str("\"model_output\"").unwrap();
    assert_eq!(back, GuardTarget::from_str("model_output").unwrap());
}

#[test]
fn guard_signal_roundtrips_with_category_labels() {
    let signal = sql_risk("1' OR '1'='1").expect("matches");
    assert_eq!(&roundtrip(&signal), &signal);
    // SignalKind label matches GuardCategory label spelling
    assert_eq!(
        serde_json::to_string(&signal.kind).unwrap(),
        "\"SQL_INJECTION\""
    );
}

#[test]
fn guard_verdict_roundtrips() {
    // a verdict as the policy core produces it (`GuardVerdict` is
    // `#[non_exhaustive]`: only the library constructs one)
    let signal = sql_risk("1' OR '1'='1").expect("matches");
    let decision = decide(std::slice::from_ref(&signal), &[], &Policy::default());
    let verdict = decision.verdicts.first().expect("a verdict").clone();
    assert_eq!(verdict.category, GuardCategory::SqlInjection);
    assert_eq!(&roundtrip(&verdict), &verdict);
}

#[test]
fn guard_event_serializes_spans_without_raw_values() {
    let segment = GuardEvent::Segment {
        text: "TCKN [TCKN] masked line\n".to_owned(),
        entities: vec![Entity {
            kind: EntityType::Tckn,
            start: 5,
            end: 16,
            text: "12345678950".to_owned(),
            score: 1.0,
        }],
    };
    let json: serde_json::Value = serde_json::to_value(&segment).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "Segment": {
                "text": "TCKN [TCKN] masked line\n",
                "entities": [{"kind": "TCKN", "start": 5, "end": 16, "score": 1.0}]
            }
        })
    );
    // the raw value never rides along with the masked segment
    assert!(!json.to_string().contains("12345678950"), "{json}");

    let block = GuardEvent::Block {
        rationale: "sql injection".to_owned(),
    };
    assert_eq!(
        serde_json::to_value(&block).unwrap(),
        serde_json::json!({"Block": {"rationale": "sql injection"}})
    );
}

#[test]
fn streamed_events_serialize_log_safe() {
    use redactify::policy::StreamingGuard;
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
    let mut events = sg.push("TCKN 12345678950 ve mail ali@ornek.com\n");
    events.extend(sg.finish());
    let json = serde_json::to_string(&events).unwrap();
    assert!(json.contains("\"TCKN\""), "{json}");
    assert!(!json.contains("12345678950"), "{json}");
    assert!(!json.contains("ali@ornek.com"), "{json}");
}

#[test]
fn tool_call_and_contract_roundtrip() {
    let call = ToolCall::new("search", r#"{"q":"a"}"#);
    assert_eq!(&roundtrip(&call), &call);

    let contract = ToolContract::new(&["search", "calculator"])
        .with_global_max(3)
        .with_repeat_tolerance(1);
    let back = roundtrip(&contract);
    // ToolContract does not derive PartialEq (the denied-arg-pattern Regex
    // is not comparable); verify the serializable fields survived the round
    // trip by checking the contract's observable behavior
    assert!(back.allows("search"));
    assert!(back.allows("calculator"));
    assert!(!back.allows("unknown_tool"));
}

#[test]
fn decision_and_sanitize_result_serialize() {
    let result = sanitize("TCKN 12345678950", &GuardTarget::UserPrompt);
    let json = serde_json::to_string(&result).expect("SanitizeResult serializes");
    assert!(json.contains("\"TCKN\""), "labels in {json}");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["text"], "TCKN [TCKN]");
    let _ = serde_json::to_string(&result.decision).expect("Decision serializes");
}

#[test]
fn blocked_sanitize_result_withholds_its_raw_text() {
    // Block keeps the PII raw in memory (the caller owns the decision), so
    // the serialized form must not carry that text
    let result = sanitize(
        "bkz http://169.254.169.254/meta TCKN 12345678950",
        &GuardTarget::UserPrompt,
    );
    assert_eq!(result.decision.action, GuardAction::Block);
    assert!(result.text.contains("12345678950"));
    let v = serde_json::to_value(&result).unwrap();
    assert!(v["text"].is_null(), "{v}");
    assert_eq!(v["decision"]["action"], "Block");
    assert!(!v.to_string().contains("12345678950"), "{v}");
}

#[test]
fn audit_record_and_tool_verdict_serialize() {
    let record = AuditRecord::from_parts(
        "req-1",
        "L1",
        GuardCategory::SqlInjection,
        0.9,
        GuardAction::Block,
        "rule fired".to_owned(),
    );
    let json = serde_json::to_string(&record).expect("AuditRecord serializes");
    assert!(json.contains("\"SQL_INJECTION\""), "labels in {json}");

    assert_eq!(
        serde_json::to_string(&ToolVerdict::Allow).unwrap(),
        "\"Allow\""
    );
    // externally-tagged newtype variant (serde default, round-trippable)
    assert_eq!(
        serde_json::to_string(&ToolVerdict::Deny("LOOP")).unwrap(),
        "{\"Deny\":\"LOOP\"}"
    );
}

#[test]
fn guard_signal_in_typed_slot_deserializes() {
    // a JSON GuardSignal (as persisted from a Decision) parses back
    let signal = sql_risk("1' OR '1'='1").expect("matches");
    let json = serde_json::to_string(&signal).unwrap();
    let back: GuardSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back, signal);
}

#[test]
fn serde_labels_match_canonical_str_on_irregular_variants() {
    // plain SCREAMING_SNAKE_CASE would produce "NO_SQL_INJECTION" (both
    // guard enums) and "PESEL" (EntityType), diverging from the canonical
    // as_str()/FromStr labels that the REST API and the TOML parser use;
    // the explicit renames keep every output path on one label.
    use redactify::guard::{GuardCategory, SignalKind};

    assert_eq!(
        serde_json::to_string(&SignalKind::NoSqlInjection).unwrap(),
        "\"NOSQL_INJECTION\""
    );
    assert_eq!(
        serde_json::to_string(&GuardCategory::NoSqlInjection).unwrap(),
        "\"NOSQL_INJECTION\""
    );
    assert_eq!(SignalKind::NoSqlInjection.as_str(), "NOSQL_INJECTION");
    assert_eq!(GuardCategory::NoSqlInjection.as_str(), "NOSQL_INJECTION");
    assert_eq!(
        serde_json::to_string(&redactify::EntityType::Pesel).unwrap(),
        "\"PL_PESEL\""
    );
    assert_eq!(redactify::EntityType::Pesel.as_str(), "PL_PESEL");
    // FromStr accepts the canonical label
    use std::str::FromStr;
    assert_eq!(
        redactify::EntityType::from_str("PL_PESEL").unwrap(),
        redactify::EntityType::Pesel
    );
}
