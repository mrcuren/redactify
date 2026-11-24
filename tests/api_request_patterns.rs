//! Per-request custom patterns (`patterns`): linear-time regular
//! expressions, bounded, never echoed, with a label that must already exist.
#![cfg(feature = "api")]

use std::time::{Duration, Instant};

use redactify::api::handle_request;
use serde_json::{json, Value};

fn post(path: &str, body: &Value) -> (u16, Value) {
    let r = handle_request("POST", path, &body.to_string());
    (r.status, serde_json::from_str(&r.body).unwrap())
}

fn redacted(body: Value) -> String {
    let (status, v) = post("/v1/redact", &body);
    assert_eq!(status, 200, "{v}");
    v["redacted"].as_str().unwrap().to_owned()
}

fn bad_patterns(patterns: Value) -> Value {
    let (status, v) = post("/v1/redact", &json!({"text": "a", "patterns": patterns}));
    assert_eq!(status, 400, "{patterns}: {v}");
    assert_eq!(v["error"]["code"], "bad_patterns", "{patterns}: {v}");
    v
}

#[test]
fn a_pattern_masks_its_matches_under_the_fixed_default_label() {
    let out = redacted(
        json!({"text": "emp E123456 and E654321 ok", "patterns": [{"pattern": r"\bE\d{6}\b"}]}),
    );
    assert_eq!(out, "emp [CUSTOM_PATTERN] and [CUSTOM_PATTERN] ok");
}

#[test]
fn detect_reports_type_and_offsets_without_the_value() {
    let (status, v) = post(
        "/v1/detect",
        &json!({"text": "emp E123456 ok", "patterns": [{"pattern": r"\bE\d{6}\b"}]}),
    );
    assert_eq!(status, 200);
    let e = &v["entities"][0];
    assert_eq!(e["type"], "CUSTOM_PATTERN");
    assert_eq!(
        (e["start"].as_u64(), e["end"].as_u64()),
        (Some(4), Some(11))
    );
    assert!(!e.to_string().contains("E123456"));
}

#[test]
fn label_may_name_a_known_entity_type() {
    let out = redacted(
        json!({"text": "ref ZZ-4455-X ok", "patterns": [{"pattern": r"ZZ-\d{4}-X", "label": "ITIN"}]}),
    );
    assert_eq!(out, "ref [ITIN] ok");
}

#[test]
fn an_unknown_label_is_refused_and_never_registered() {
    for _ in 0..2 {
        let v = bad_patterns(json!([{"pattern": r"ZZ-\d{4}", "label": "BRAND_NEW_LABEL_X"}]));
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("patterns[0].label"));
    }
    assert!("BRAND_NEW_LABEL_X"
        .parse::<redactify::EntityType>()
        .is_err());
}

#[test]
fn cues_gate_the_match_and_score_feeds_the_threshold() {
    let p = json!([{"pattern": r"\b\d{6}\b", "cues": ["ticket"]}]);
    assert_eq!(
        redacted(json!({"text": "ticket 482913", "patterns": p})),
        "ticket [CUSTOM_PATTERN]"
    );
    assert_eq!(
        redacted(json!({"text": "order 482913", "patterns": p})),
        "order 482913"
    );
    let low = json!([{"pattern": r"\bE\d{6}\b", "score": 0.5}]);
    assert_eq!(
        redacted(json!({"text": "E123456", "patterns": low, "threshold": 0.9})),
        "E123456"
    );
    assert_eq!(
        redacted(json!({"text": "E123456", "patterns": low, "threshold": 0.4})),
        "[CUSTOM_PATTERN]"
    );
}

#[test]
fn patterns_combine_with_words_mask_and_apply_on_every_text_endpoint() {
    let body = json!({
        "text": "E123456 and Phoenix",
        "patterns": [{"pattern": r"\bE\d{6}\b"}],
        "words": ["Phoenix"],
        "mask": {"style": "template", "template": "<{type}>"},
    });
    assert_eq!(redacted(body.clone()), "<CUSTOM_PATTERN> and <CUSTOM_WORD>");
    let (_, v) = post("/v1/guard", &body);
    assert_eq!(v["action"], "Mask");
    let (_, v) = post("/v1/sanitize", &body);
    assert_eq!(v["text"], "<CUSTOM_PATTERN> and <CUSTOM_WORD>");
    let (_, v) = post("/v1/vault/pseudonymize", &body);
    assert_eq!(v["count"], 2);
    assert!(!v["pseudonymized"].as_str().unwrap().contains("E123456"));
    let (_, v) = post(
        "/v1/batch/redact",
        &json!({"texts": ["E123456", "none"], "patterns": [{"pattern": r"\bE\d{6}\b"}]}),
    );
    assert_eq!(v["results"][0]["redacted"], "[CUSTOM_PATTERN]");
    assert_eq!(v["results"][1]["redacted"], "none");
    let (_, v) = post(
        "/v1/json/redact",
        &json!({"json": {"k": "E123456"}, "patterns": [{"pattern": r"\bE\d{6}\b"}]}),
    );
    assert_eq!(v["redacted"]["k"], "[CUSTOM_PATTERN]");
}

#[test]
fn up_to_sixteen_patterns_are_accepted_and_seventeen_are_not() {
    let many = |n: usize| -> Value {
        Value::Array(
            (0..n)
                .map(|i| json!({"pattern": format!("QQ{i:02}-\\d{{3}}")}))
                .collect(),
        )
    };
    assert_eq!(
        redacted(json!({"text": "QQ03-123", "patterns": many(16)})),
        "[CUSTOM_PATTERN]"
    );
    bad_patterns(many(17));
}

#[test]
fn malformed_patterns_are_400_and_never_echo_values() {
    for patterns in [
        json!("SECRETVALUE"),
        json!({"pattern": "SECRETVALUE"}),
        json!(["SECRETVALUE"]),
        json!([{}]),
        json!([{"pattern": 5}]),
        json!([{"pattern": "SECRETVALUE", "extra": 1}]),
        json!([{"pattern": "SECRETVALUE(?=x)"}]),
        json!([{"pattern": "SECRETVALUE(\\w)\\1"}]),
        json!([{"pattern": "SECRETVALUE["}]),
        json!([{"pattern": "a?"}]),
        json!([{"pattern": "x".repeat(257)}]),
        json!([{"pattern": "SECRETVALUE\\d{3}", "cues": "ticket"}]),
        json!([{"pattern": "SECRETVALUE\\d{3}", "cues": [1]}]),
        json!([{"pattern": "SECRETVALUE\\d{3}", "cues": vec!["c"; 17]}]),
        json!([{"pattern": "SECRETVALUE\\d{3}", "cues": ["x".repeat(65)]}]),
        json!([{"pattern": "SECRETVALUE\\d{3}", "score": 1.5}]),
        json!([{"pattern": "SECRETVALUE\\d{3}", "score": "high"}]),
        json!([{"pattern": "SECRETVALUE\\d{3}", "label": 3}]),
        json!([{"pattern": "(\\w{100}){100}"}]),
    ] {
        let v = bad_patterns(patterns.clone());
        assert!(!v.to_string().contains("SECRETVALUE"), "{patterns}: {v}");
    }
}

#[test]
fn a_catastrophic_pattern_cannot_stall_the_server() {
    let text = format!("{}!", "a".repeat(200_000));
    let start = Instant::now();
    let (status, v) = post(
        "/v1/redact",
        &json!({"text": text, "patterns": [{"pattern": "(a+)+bcd"}]}),
    );
    assert_eq!(status, 200, "{v}");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(v["redacted"].as_str().unwrap().len(), 200_001);
}
