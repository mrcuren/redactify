//! REST API tests: the pure handler (no sockets) plus one real HTTP
//! round-trip through tiny_http over a localhost socket.
#![cfg(feature = "api")]

mod common;

use redactify::api::handle_request;

// ------------------------------------------------------------ pure handler

#[test]
fn health_reports_version() {
    let r = handle_request("GET", "/health", "");
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn guard_returns_detailed_decision() {
    let r = handle_request(
        "POST",
        "/v1/guard",
        r#"{"text":"TCKN 12345678950 ve bkz http://169.254.169.254/meta"}"#,
    );
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["action"], "Block");
    assert!(v["rationale"].as_str().unwrap().contains("block line"));
    // detailed format: signals + verdicts + PII spans all present
    assert!(v["signals"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["kind"] == "DANGEROUS_URL"));
    assert!(v["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["category"] == "DANGEROUS_URL" && x["severity"] == "HIGH"));
    let pii = v["pii"].as_array().unwrap();
    assert!(pii.iter().any(|e| e["type"] == "TCKN" && e["score"] == 1.0));
    // privacy: the raw TCKN value must NOT be echoed anywhere in the response
    assert!(!r.body.contains("12345678950"));
}

#[test]
fn guard_target_tool_response_is_stricter() {
    let borderline = r#"{"text":"bkz: http://10.0.0.5/internal","target":"tool_response"}"#;
    let tool = handle_request("POST", "/v1/guard", borderline);
    let user = handle_request(
        "POST",
        "/v1/guard",
        r#"{"text":"bkz: http://10.0.0.5/internal"}"#,
    );
    let tv: serde_json::Value = serde_json::from_str(&tool.body).unwrap();
    let uv: serde_json::Value = serde_json::from_str(&user.body).unwrap();
    assert_eq!(tv["action"], "Block"); // tool policy blocks at 0.5
    assert_eq!(uv["action"], "Block"); // RFC1918 also blocks for user prompts
                                       // and a bad target name is a 400
    let bad = handle_request("POST", "/v1/guard", r#"{"text":"x","target":"nope"}"#);
    assert_eq!(bad.status, 400);
    assert!(bad.body.contains("bad_target"));
}

#[test]
fn detect_supports_locales_and_threshold() {
    let r = handle_request(
        "POST",
        "/v1/detect",
        r#"{"text":"SSN 536-90-6292 ve plaka 34 ABC 123"}"#,
    );
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let types: Vec<&str> = v["entities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["type"].as_str())
        .collect();
    assert!(types.contains(&"SSN"), "types: {types:?}");
    assert!(types.contains(&"PLAKA"), "types: {types:?}");
    assert!(v["redacted"].as_str().unwrap().contains("[SSN]"));

    // threshold filter drops the bare plate (0.85 < 0.9) but keeps the cued one
    let r = handle_request(
        "POST",
        "/v1/detect",
        r#"{"text":"plaka 34 ABC 123 gitti, 06 PKR 34 yolda","threshold":0.9}"#,
    );
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["count"], 1, "body: {}", r.body);

    // en-only locale filter drops the Turkish plate
    let r = handle_request(
        "POST",
        "/v1/detect",
        r#"{"text":"SSN 536-90-6292 ve 34 ABC 123","locales":["en"]}"#,
    );
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["count"], 1);
}

#[test]
fn sanitize_returns_text_with_decision() {
    let r = handle_request(
        "POST",
        "/v1/sanitize",
        r#"{"text":"TCKN 12345678950, x < y","target":"model_output"}"#,
    );
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["action"], "Mask");
    let text = v["text"].as_str().unwrap();
    assert!(text.contains("[TCKN]"));
    assert!(
        text.contains("x &lt; y"),
        "html-encoded output expected: {text}"
    );
}

#[test]
fn redact_endpoint_masks() {
    let r = handle_request("POST", "/v1/redact", r#"{"text":"mail a@b.com"}"#);
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["redacted"], "mail [EMAIL]");
}

#[test]
fn errors_are_structured() {
    let bad_json = handle_request("POST", "/v1/guard", "not json");
    assert_eq!(bad_json.status, 400);
    assert!(bad_json.body.contains("bad_json"));

    let missing = handle_request("POST", "/v1/guard", r#"{"nope":1}"#);
    assert_eq!(missing.status, 400);
    assert!(missing.body.contains("missing_field"));

    let not_found = handle_request("GET", "/v2/other", "");
    assert_eq!(not_found.status, 404);
    assert!(not_found.body.contains("unknown_path"));

    let wrong_method = handle_request("GET", "/v1/guard", "");
    assert_eq!(wrong_method.status, 405);

    // 1 MiB cap
    let big = format!("{{\"text\":\"{}\"}}", "x".repeat(redactify::api::MAX_BODY));
    let too_big = handle_request("POST", "/v1/redact", &big);
    assert_eq!(too_big.status, 413);
}

// ------------------------------------------------- JSON documents and batches

fn body_json(r: &redactify::api::ApiResponse) -> serde_json::Value {
    serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("bad JSON {e}: {}", r.body))
}

#[test]
fn json_redact_masks_leaves_and_reports_pointers() {
    let r = handle_request(
        "POST",
        "/v1/json/redact",
        r#"{"json":{"customer":{"vergi_no":"1234567890","note":"mail a@b.com"},"tags":["ok","TCKN 12345678950"]}}"#,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let v = body_json(&r);
    assert_eq!(
        v["redacted"],
        serde_json::json!({
            "customer": {"vergi_no": "[VKN]", "note": "mail [EMAIL]"},
            "tags": ["ok", "TCKN [TCKN]"]
        })
    );
    let findings: Vec<(&str, &str, &str)> = v["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| {
            (
                f["pointer"].as_str().expect("pointer"),
                f["kind"].as_str().expect("kind"),
                f["type"].as_str().expect("type"),
            )
        })
        .collect();
    assert_eq!(
        findings,
        [
            ("/customer/note", "PII", "EMAIL"),
            ("/customer/vergi_no", "PII", "VKN"),
            ("/tags/1", "PII", "TCKN"),
        ]
    );
    assert_eq!(v["complete"], true);
    assert!(!r.body.contains("12345678950"), "{}", r.body);
    assert!(!r.body.contains("a@b.com"), "{}", r.body);
}

#[test]
fn json_redact_reports_secrets_and_scans_numbers_on_request() {
    let r = handle_request(
        "POST",
        "/v1/json/redact",
        r#"{"json":{"aws":"AKIAIOSFODNN7EXAMPLE","tckn":12345678950},"numeric_leaves":true}"#,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let v = body_json(&r);
    assert_eq!(v["redacted"]["aws"], "[SECRET:AWS_ACCESS_KEY]");
    assert_eq!(v["redacted"]["tckn"], "[TCKN]");
    let kinds: Vec<(&str, &str)> = v["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| (f["kind"].as_str().unwrap(), f["type"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, [("SECRET", "AWS_ACCESS_KEY"), ("PII", "TCKN")]);
}

#[test]
fn json_redact_requires_the_json_field() {
    let r = handle_request("POST", "/v1/json/redact", r#"{"text":"TCKN 12345678950"}"#);
    assert_eq!(r.status, 400);
    assert_eq!(body_json(&r)["error"]["code"], "missing_field");
}

const BATCH_TEXTS: [&str; 3] = [
    "TCKN 12345678950 ve mail a@b.com",
    "temiz bir metin",
    "kart 4111 1111 1111 1111",
];

/// The `texts` array of a batch request plus extra top-level fields.
fn batch_body(extra: &str) -> String {
    let texts = serde_json::to_string(&BATCH_TEXTS).unwrap();
    format!(r#"{{"texts":{texts}{extra}}}"#)
}

#[test]
fn batch_endpoints_match_the_single_text_endpoints() {
    for (batch, single, extra) in [
        (
            "/v1/batch/detect",
            "/v1/detect",
            r#","locales":["tr","en"]"#,
        ),
        ("/v1/batch/redact", "/v1/redact", ""),
        (
            "/v1/batch/sanitize",
            "/v1/sanitize",
            r#","target":"tool_response""#,
        ),
    ] {
        let r = handle_request("POST", batch, &batch_body(extra));
        assert_eq!(r.status, 200, "{batch}: {}", r.body);
        let v = body_json(&r);
        let results = v["results"].as_array().expect("results");
        assert_eq!(v["count"], BATCH_TEXTS.len(), "{batch}");
        assert_eq!(results.len(), BATCH_TEXTS.len(), "{batch}");
        for (text, got) in BATCH_TEXTS.iter().zip(results) {
            let one = serde_json::json!({"text": text}).to_string();
            let one = format!("{}{extra}}}", &one[..one.len() - 1]);
            let want = body_json(&handle_request("POST", single, &one));
            assert_eq!(got, &want, "{batch} vs {single} for {text:?}");
        }
    }
}

#[test]
fn batch_rejects_missing_or_non_string_texts() {
    let r = handle_request("POST", "/v1/batch/redact", r#"{"text":"x"}"#);
    assert_eq!(r.status, 400);
    assert_eq!(body_json(&r)["error"]["code"], "missing_field");
    let r = handle_request("POST", "/v1/batch/redact", r#"{"texts":["ok",7]}"#);
    assert_eq!(r.status, 400);
    let v = body_json(&r);
    assert_eq!(v["error"]["code"], "bad_texts");
    assert!(v["error"]["message"].as_str().unwrap().contains("texts[1]"));
}

#[test]
fn new_endpoints_are_listed_and_reject_get() {
    let index = body_json(&handle_request("GET", "/", ""));
    let listed: Vec<&str> = index["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap())
        .collect();
    for p in [
        "/v1/json/redact",
        "/v1/batch/detect",
        "/v1/batch/redact",
        "/v1/batch/sanitize",
    ] {
        assert!(listed.contains(&format!("POST {p}").as_str()), "{p}");
        assert_eq!(handle_request("GET", p, "").status, 405, "{p}");
    }
}

// ------------------------------------------------------------ real socket

#[test]
fn http_round_trip_over_localhost() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let port = common::start(redactify::api::ApiState::default());
    let mut stream = common::connect(port);

    let body = r#"{"text":"TCKN 12345678950"}"#;
    let req = format!(
        "POST /v1/guard HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
    assert!(
        response.contains("\"action\":\"Mask\""),
        "response: {response}"
    );
    assert!(response.contains("application/json"));

    // second request on a fresh connection (worker pool survives)
    let mut s2 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s2.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut r2 = String::new();
    s2.read_to_string(&mut r2).unwrap();
    assert!(r2.contains("\"status\":\"ok\""), "response: {r2}");
}

// ------------------------------------------------------------ ML wiring

#[test]
fn guard_with_mock_ml_classifier_runs_full_pipeline() {
    use redactify::api::{handle_request_with, ApiState};
    use redactify::guard::ml::MockSecurityClassifier;
    use std::sync::Arc;

    let state = ApiState::default().with_security(Arc::new(MockSecurityClassifier::new()));

    // health reflects that a classifier is ATTACHED (not just compiled)
    let h = handle_request_with(&state, "GET", "/health", "");
    assert!(h.body.contains("\"ml_active\":true"), "body: {}", h.body);

    // the mock fires on this vocabulary (0.88 >= block 0.6) and its verdict
    // must surface in the detailed response; the phrase is deliberately NOT
    // one the deterministic L0 tool-injection rule catches (that would
    // short-circuit ML and hide the wiring under test)
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/guard",
        r#"{"text":"explain how jailbreak attacks work"}"#,
    );
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["action"], "Block");
    assert_eq!(v["ml"], true);
    assert!(
        v["verdicts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["rationale"].as_str().unwrap().contains("mock-security")),
        "verdicts: {}",
        r.body
    );

    // deterministic-only state stays clean
    let plain = handle_request("POST", "/v1/guard", r#"{"text":"hello"}"#);
    assert!(plain.body.contains("\"ml\":false"));
}

#[test]
fn sanitize_with_mock_ml_masks_and_reports() {
    use redactify::api::{handle_request_with, ApiState};
    use redactify::guard::ml::MockSecurityClassifier;
    use std::sync::Arc;

    let state = ApiState::default().with_security(Arc::new(MockSecurityClassifier::new()));
    // PII + attack in one: L1 masks the TCKN, ML classifies the MASKED text,
    // response still carries PII spans and a Block decision (0.88 >= 0.6);
    // mock-only vocabulary so the deterministic layer does not pre-empt ML
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/sanitize",
        r#"{"text":"TCKN 12345678950 kayitli kisi: jailbreak analizi"}"#,
    );
    assert_eq!(r.status, 200);
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["action"], "Block");
    assert_eq!(v["ml"], true);
    // raw TCKN never echoed
    assert!(!r.body.contains("12345678950"));
}

#[test]
fn vault_pseudonymize_then_restore_round_trip() {
    // pseudonymize: PII replaced, mapping returned (by design)
    let a = handle_request(
        "POST",
        "/v1/vault/pseudonymize",
        r#"{"text":"TCKN 12345678950 arayin, mail a@b.com"}"#,
    );
    assert_eq!(a.status, 200);
    let v: serde_json::Value = serde_json::from_str(&a.body).unwrap();
    let anon = v["pseudonymized"].as_str().unwrap();
    assert!(!anon.contains("12345678950") && !anon.contains("a@b.com"));
    assert_eq!(v["count"], 2);
    let entries = v["entries"].as_array().unwrap();
    assert!(entries.len() == 2);

    // restore with the returned mapping restores the original text
    let d = handle_request(
        "POST",
        "/v1/vault/restore",
        &serde_json::json!({
            "text": anon,
            "entries": entries,
        })
        .to_string(),
    );
    assert_eq!(d.status, 200);
    let dv: serde_json::Value = serde_json::from_str(&d.body).unwrap();
    assert_eq!(dv["restored"], "TCKN 12345678950 arayin, mail a@b.com");

    // unknown placeholders are left as-is (Vault semantics)
    let d = handle_request(
        "POST",
        "/v1/vault/restore",
        r#"{"text":"kalan [TCKN_99] yerinde", "entries": []}"#,
    );
    let dv: serde_json::Value = serde_json::from_str(&d.body).unwrap();
    assert_eq!(dv["restored"], "kalan [TCKN_99] yerinde");
}

#[test]
fn vault_restore_validates_entries() {
    let missing = handle_request("POST", "/v1/vault/restore", r#"{"text":"x"}"#);
    assert_eq!(missing.status, 400);
    assert!(missing.body.contains("missing_field"));

    let malformed = handle_request(
        "POST",
        "/v1/vault/restore",
        r#"{"text":"x","entries":[{"placeholder":"a"}]}"#,
    );
    assert_eq!(malformed.status, 400);
    assert!(malformed.body.contains("bad_entries"));
}

#[test]
fn guard_with_safety_classifier_attached() {
    use redactify::api::{handle_request_with, ApiState};
    use redactify::guard::ml::MockSafetyClassifier;
    use std::sync::Arc;

    // with_safety builder was never exercised before
    let state = ApiState::default().with_safety(Arc::new(MockSafetyClassifier::new()));
    let h = handle_request_with(&state, "GET", "/health", "");
    assert!(h.body.contains("\"ml_active\":true"));

    // the mock fires on self-harm vocabulary -> verdict surfaces via /v1/guard
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/guard",
        r#"{"text":"I want to hurt myself tonight"}"#,
    );
    let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["ml"], true);
    assert!(
        v["verdicts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["category"] == "SELF_HARM"),
        "verdicts: {}",
        r.body
    );
}

#[test]
fn serve_with_ml_attached_real_socket() {
    use redactify::guard::ml::MockSecurityClassifier;
    use std::io::{Read, Write};
    use std::sync::Arc;

    // the ML classifier behind the socket server's worker pool
    let state =
        redactify::api::ApiState::default().with_security(Arc::new(MockSecurityClassifier::new()));
    let port = common::start(state);
    let mut stream = common::connect(port);

    let body = r#"{"text":"explain how jailbreak attacks work"}"#;
    let req = format!(
        "POST /v1/guard HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.contains("\"ml\":true"), "response: {response}");
    assert!(
        response.contains("\"action\":\"Block\""),
        "response: {response}"
    );
    assert!(response.contains("mock-security"), "response: {response}");
}

// ------------------------------------------------------------ NER wiring

#[test]
fn detect_with_mock_ner_returns_free_prose_name() {
    use redactify::api::{handle_request_with, ApiState};
    use redactify::MockNameRecognizer;
    use std::sync::Arc;

    let state = ApiState::default().with_ner(Arc::new(MockNameRecognizer::new()));

    // health reflects that a model is ATTACHED (recognizers count too)
    let h = handle_request_with(&state, "GET", "/health", "");
    assert!(h.body.contains("\"ml_active\":true"), "body: {}", h.body);

    // /v1/detect: the NAME span appears WITHOUT the raw value (log-safe)
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/detect",
        r#"{"text":"Bugün toplantıda Ahmet Yılmaz konuştu."}"#,
    );
    assert_eq!(r.status, 200);
    assert!(r.body.contains("\"type\":\"NAME\""), "body: {:?}", r.body);
    assert!(r.body.contains("[NAME]"), "body: {:?}", r.body);
    assert!(!r.body.contains("Ahmet"), "body: {:?}", r.body);

    // /v1/sanitize: Mask decision + the masked text
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/sanitize",
        r#"{"text":"Bugün toplantıda Ahmet Yılmaz konuştu."}"#,
    );
    assert_eq!(r.status, 200);
    assert!(r.body.contains("\"action\":\"Mask\""), "body: {:?}", r.body);
    assert!(
        r.body.contains("Bugün toplantıda [NAME] konuştu."),
        "body: {:?}",
        r.body
    );
}

// ------------------------------------------------------------ stream endpoint

#[test]
fn stream_endpoint_masks_chunks_as_ndjson() {
    use redactify::api::{handle_request_with, ApiState};

    let r = handle_request_with(
        &ApiState::default(),
        "POST",
        "/v1/stream/sanitize",
        r#"{"chunks": ["TCKN 12345678", "950 gecerli\n", "ikinci satir"]}"#,
    );
    assert_eq!(r.status, 200);
    let events: Vec<serde_json::Value> = r
        .body
        .lines()
        .map(|l| serde_json::from_str(l).expect("NDJSON line"))
        .collect();
    assert_eq!(events.len(), 2, "{:?}", r.body);
    assert_eq!(events[0]["type"], "segment");
    assert_eq!(events[0]["text"], "TCKN [TCKN] gecerli\n");
    let ents = events[0]["entities"].as_array().unwrap();
    assert_eq!(ents[0]["type"], "TCKN");
    assert!(!r.body.contains("12345678950"), "raw value never echoed");
    assert_eq!(events[1]["type"], "segment");
    assert_eq!(events[1]["text"], "ikinci satir");
}

#[test]
fn stream_endpoint_block_stops_events() {
    use redactify::api::{handle_request_with, ApiState};

    let r = handle_request_with(
        &ApiState::default(),
        "POST",
        "/v1/stream/sanitize",
        r#"{"chunks": ["guvenli\n", "http://169.254.169.254/meta\n", "ulasmaz\n"]}"#,
    );
    assert_eq!(r.status, 200);
    let events: Vec<serde_json::Value> = r
        .body
        .lines()
        .map(|l| serde_json::from_str(l).expect("NDJSON line"))
        .collect();
    assert_eq!(events.len(), 2, "{:?}", r.body);
    assert_eq!(events[0]["type"], "segment");
    assert_eq!(events[1]["type"], "block");
    assert!(events[1]["rationale"].as_str().unwrap().contains("0.95"));
}

#[test]
fn stream_endpoint_validates_request() {
    let r = handle_request("POST", "/v1/stream/sanitize", r#"{"text": "x"}"#);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("missing_field"), "{}", r.body);
    let r = handle_request("POST", "/v1/stream/sanitize", r#"{"chunks": [1, 2]}"#);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("bad_chunks"), "{}", r.body);
    let r = handle_request("GET", "/v1/stream/sanitize", "");
    assert_eq!(r.status, 405);
}

// --------------------------------------------- stream endpoint == batch

#[test]
fn stream_endpoint_accepts_ndjson_input() {
    // raw NDJSON body: one JSON string per line, each line = one chunk
    // (the natural dump shape for a streaming client)
    let body = "\"TCKN 12345678\"\n\"950 gecerli\\n\"\n\"ikinci satir\"\n";
    let r = handle_request("POST", "/v1/stream/sanitize", body);
    assert_eq!(r.status, 200, "{}", r.body);
    let events: Vec<serde_json::Value> = r
        .body
        .lines()
        .map(|l| serde_json::from_str(l).expect("NDJSON line"))
        .collect();
    assert_eq!(events.len(), 2, "{:?}", r.body);
    assert_eq!(events[0]["text"], "TCKN [TCKN] gecerli\n");
    assert!(!r.body.contains("12345678950"));
}

#[test]
fn stream_endpoint_rejects_malformed_ndjson() {
    // a line that is not a JSON string is a 400, not a panic
    let r = handle_request("POST", "/v1/stream/sanitize", "\"good chunk\"\nnot json\n");
    assert_eq!(r.status, 400);
    assert!(r.body.contains("bad_json"), "{}", r.body);
    // empty body is also rejected
    let r = handle_request("POST", "/v1/stream/sanitize", "  \n \n");
    assert_eq!(r.status, 400);
}

#[test]
fn stream_endpoint_body_cap_is_enforced() {
    use redactify::api::MAX_BODY;
    // the 1 MiB cap applies to the stream endpoint like everywhere else
    let mut big = String::from("\"");
    for _ in 0..(MAX_BODY + 16) {
        big.push('x');
    }
    big.push('"');
    let r = handle_request("POST", "/v1/stream/sanitize", &big);
    assert_eq!(r.status, 413, "expected 413, got {}", r.status);
    assert!(r.body.contains("payload_too_large"));
}

#[test]
fn chunked_body_over_cap_is_rejected_with_413() {
    // A chunked request carries no Content-Length, so the early
    // body_length() fast path cannot judge it; the bounded (take) read
    // must reject the oversized decoded body on every endpoint.
    use redactify::api::MAX_BODY;
    use std::io::{Read, Write};

    let port = common::start(redactify::api::ApiState::default());
    let mut stream = common::connect(port);

    stream
        .write_all(
            b"POST /v1/guard HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    // exactly one byte over the cap: the take(MAX_BODY + 1) read swallows it
    // and the post-read check fires without the client racing a huge send
    let chunk = "a".repeat(MAX_BODY + 1);
    let frame = format!("{:x}\r\n{}\r\n0\r\n\r\n", chunk.len(), chunk);
    stream.write_all(frame.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 413"), "response: {response}");
    assert!(
        response.contains("payload_too_large"),
        "response: {response}"
    );
}

#[test]
fn stream_endpoint_chunked_equals_batch_response() {
    // split-and-rejoin over the stream ENDPOINT equals the BATCH
    // endpoint's sanitized text, across several texts and every split point
    const TEXTS: &[&str] = &[
        "TCKN 12345678950 gecerli",
        "mail a@b.com ve SSN 536-90-6292",
        "IBAN GB82 WEST 1234 5698 7654 32 burada",
        "temiz metin sadece",
    ];
    for text in TEXTS {
        let batch = handle_request(
            "POST",
            "/v1/sanitize",
            &format!("{{\"text\":{}}}", serde_json::to_string(text).unwrap()),
        );
        assert_eq!(batch.status, 200);
        let bv: serde_json::Value = serde_json::from_str(&batch.body).unwrap();
        // Mask for PII texts, Allow for the clean text - either way the
        // batch `text` field is the reference the stream must reproduce
        let expected = bv["text"].as_str().unwrap().to_owned();

        for i in 0..=text.len() {
            if !text.is_char_boundary(i) {
                continue;
            }
            let (a, b) = (&text[..i], &text[i..]);
            let body = serde_json::json!({ "chunks": [a, b] }).to_string();
            let r = handle_request("POST", "/v1/stream/sanitize", &body);
            assert_eq!(r.status, 200, "{}", r.body);
            let mut joined = String::new();
            for line in r.body.lines() {
                let ev: serde_json::Value = serde_json::from_str(line).unwrap();
                if ev["type"] == "segment" {
                    joined.push_str(ev["text"].as_str().unwrap());
                }
            }
            assert_eq!(joined, expected, "text {text:?} split at {i}");
        }
    }
}

#[test]
fn stream_endpoint_live_socket_round_trip_equals_batch() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // `post` opens a fresh connection per request (the worker pool keeps
    // serving)
    let port = common::start(redactify::api::ApiState::default());

    let post = |path: &str, body: &str| -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut response = String::new();
        s.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        response.split_once("\r\n\r\n").unwrap().1.to_owned()
    };

    // streaming request over a REAL socket, NDJSON input split mid-identifier
    let stream_body = "\"TCKN 12345678\"\n\"950 gecerli\\n\"\n\"ikinci\"\n";
    let ndjson_out = post("/v1/stream/sanitize", stream_body);
    let mut joined = String::new();
    for line in ndjson_out.lines() {
        let ev: serde_json::Value = serde_json::from_str(line).expect("live NDJSON line");
        if ev["type"] == "segment" {
            joined.push_str(ev["text"].as_str().unwrap());
        }
    }

    // batch request over the same live server
    let batch_body = r#"{"text":"TCKN 12345678950 gecerli\nikinci"}"#;
    let batch_out = post("/v1/sanitize", batch_body);
    let bv: serde_json::Value = serde_json::from_str(&batch_out).unwrap();
    let expected = bv["text"].as_str().unwrap();

    assert_eq!(joined, expected, "live stream == live batch");
    assert!(
        !ndjson_out.contains("12345678950"),
        "no raw PII in live response"
    );
}

// ------------------------------------------------------- audit middleware

#[test]
fn audit_disabled_by_default_api_behaves_same() {
    // audit OFF (default): responses are byte-identical to the no-audit path
    use redactify::api::{handle_request_with, ApiState};
    let state = ApiState::default();
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/guard",
        r#"{"text":"TCKN 12345678950"}"#,
    );
    assert_eq!(r.status, 200);
    assert!(r.body.contains("\"action\":\"Mask\""));
    // no audit header/field leaks into the response
    assert!(!r.body.contains("audit"), "{}", r.body);
}

#[test]
fn audit_enabled_produces_chained_log() {
    use redactify::api::{handle_request_with, ApiState};
    use std::sync::{Arc, Mutex};

    let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let buf2 = Arc::clone(&buf);

    let state = ApiState::default().with_audit_sink(Box::new(move |record| {
        // simulate the ChainedAuditSink append path
        let mut b = buf2.lock().unwrap();
        b.extend_from_slice(record.to_json().as_bytes());
        b.push(b'\n');
    }));

    let r = handle_request_with(
        &state,
        "POST",
        "/v1/guard",
        r#"{"text":"TCKN 12345678950"}"#,
    );
    assert_eq!(r.status, 200);

    // the sink was invoked: the shared buffer has audit JSON
    let log = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(!log.is_empty(), "audit log must not be empty");
    assert!(log.contains("\"guard\""), "structured record: {log}");
    assert!(log.contains("\"action\""), "{log}");
    assert!(!log.contains("12345678950"), "no raw PII in audit: {log}");
}

mod api_policy_locales {

    /// The /v1/sanitize masking transform runs with the policy's
    /// default_locales, like the decision; with the RAW request locales
    /// (usually empty -> tr+en) locale-pack entities would stay raw in the
    /// response body.
    #[test]
    fn sanitize_masks_with_policy_default_locales_not_request_ones() {
        let policy = redactify::policy::Policy {
            default_locales: vec!["uk".to_owned()],
            ..redactify::policy::Policy::default()
        };
        let state = redactify::api::ApiState::default().with_policy(policy);
        // no request `locales` field: the policy's uk pack must drive BOTH
        // the decision and the masking
        let resp = redactify::api::handle_request_with(
            &state,
            "POST",
            "/v1/sanitize",
            r#"{"text": "nhs 9434765870 record"}"#,
        );
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(body["action"], "Mask");
        assert!(
            body["text"].as_str().unwrap().contains("[UK_NHS]"),
            "policy-default locales must mask locale-pack entities: {}",
            body["text"]
        );
        assert!(!resp.body.contains("9434765870"), "raw value leaked");
    }

    /// A single-line NDJSON body (one JSON string) is also valid buffered
    /// JSON as a SCALAR: it must still reach the NDJSON fallback instead of
    /// a spurious missing_field.
    #[test]
    fn single_line_ndjson_chunk_is_accepted() {
        let resp =
            redactify::api::handle_request("POST", "/v1/stream/sanitize", "\"nhs 9434765870\"");
        assert_eq!(resp.status, 200, "body: {}", resp.body);
        assert!(
            resp.body.contains("\"type\":\"segment\""),
            "body: {}",
            resp.body
        );
    }
}

/// The /v1/detect `threshold` parameter filters the `entities` array AND
/// stays consistent with the `redacted` preview (the API-level contract of
/// the engine-level threshold).
#[test]
fn detect_threshold_filters_entities_and_redacted_consistently() {
    let body = r#"{"text": "TCKN 12345678950 ve mail a@b.com", "threshold": 0.9}"#;
    let resp = handle_request("POST", "/v1/detect", body);
    assert_eq!(resp.status, 200, "{}", resp.body);
    let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    let types: Vec<&str> = v["entities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        vec!["TCKN"],
        "email (0.85) must be filtered: {types:?}"
    );
    let redacted = v["redacted"].as_str().unwrap();
    assert!(
        redacted.contains("[TCKN]"),
        "strong entity masked: {redacted}"
    );
    assert!(
        redacted.contains("a@b.com"),
        "weak entity stays visible: {redacted}"
    );
    // without threshold: both surface and both mask
    let resp = handle_request(
        "POST",
        "/v1/detect",
        r#"{"text": "TCKN 12345678950 ve mail a@b.com"}"#,
    );
    let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(v["count"].as_u64().unwrap(), 2);
    assert!(v["redacted"].as_str().unwrap().contains("[EMAIL]"));
}

// ----------------------------------------------- one semantics per operation

/// The body of a successful JSON response.
fn json_body(r: &redactify::api::ApiResponse) -> serde_json::Value {
    assert_eq!(r.status, 200, "{}", r.body);
    serde_json::from_str(&r.body).expect("JSON body")
}

#[test]
fn detect_and_redact_ignore_stays_normalization_aware() {
    // an allowlist must not switch the endpoints to a raw-text-only path:
    // the zero-width-scattered TCKN is allowlisted through its plain
    // spelling; the second TCKN is still found and masked.
    let body = serde_json::json!({
        "text": "TCKN 1\u{200B}2345678950 ve 10000000146",
        "ignore": ["12345678950"]
    })
    .to_string();
    let v = json_body(&handle_request("POST", "/v1/detect", &body));
    assert_eq!(v["count"], 1, "{v}");
    assert_eq!(v["entities"][0]["type"], "TCKN");
    assert_eq!(v["redacted"], "TCKN 1\u{200B}2345678950 ve [TCKN]");
    let r = json_body(&handle_request("POST", "/v1/redact", &body));
    assert_eq!(r["redacted"], "TCKN 1\u{200B}2345678950 ve [TCKN]");

    // without the allowlist both TCKNs mask (normalization on)
    let body = serde_json::json!({"text": "TCKN 1\u{200B}2345678950 ve 10000000146"}).to_string();
    let r = json_body(&handle_request("POST", "/v1/redact", &body));
    assert_eq!(r["redacted"], "TCKN [TCKN] ve [TCKN]");
}

#[test]
fn detect_threshold_does_not_depend_on_ignore() {
    // the threshold has ONE meaning (inside overlap resolution),
    // with or without an allowlist
    let with_ignore = json_body(&handle_request(
        "POST",
        "/v1/detect",
        r#"{"text":"TCKN 12345678950 ve mail a@b.com","threshold":0.9,"ignore":["nothing"]}"#,
    ));
    let without = json_body(&handle_request(
        "POST",
        "/v1/detect",
        r#"{"text":"TCKN 12345678950 ve mail a@b.com","threshold":0.9}"#,
    ));
    assert_eq!(with_ignore, without);
    assert_eq!(without["count"], 1);
}

#[test]
fn redact_output_masks_secrets_first_then_pii() {
    let body = r#"{"text":"key AKIAIOSFODNN7EXAMPLE ve TCKN 12345678950"}"#;
    let r = json_body(&handle_request("POST", "/v1/redact", body));
    assert_eq!(
        r["redacted"], "key [SECRET:AWS_ACCESS_KEY] ve TCKN [TCKN]",
        "{r}"
    );
    // the detect preview is the same rendering (loggable)
    let d = json_body(&handle_request("POST", "/v1/detect", body));
    assert_eq!(d["redacted"], r["redacted"]);
    assert!(!d.to_string().contains("N7EXAMPLE"));
}

#[test]
fn sanitize_block_remask_covers_fullwidth_tckn_and_secret() {
    let text = "AKIAIOSFODNN7EXAMPLE TCKN \u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}";
    let body = serde_json::json!({ "text": text }).to_string();
    let v = json_body(&handle_request("POST", "/v1/sanitize", &body));
    assert_eq!(v["action"], "Block", "{v}");
    assert_eq!(v["text"], "[SECRET:AWS_ACCESS_KEY] TCKN [TCKN]");
    // model_output: the re-mask is HTML-encoded too
    let body =
        serde_json::json!({ "text": format!("{text} <b>"), "target": "model_output" }).to_string();
    let v = json_body(&handle_request("POST", "/v1/sanitize", &body));
    assert_eq!(v["action"], "Block", "{v}");
    assert_eq!(v["text"], "[SECRET:AWS_ACCESS_KEY] TCKN [TCKN] &lt;b&gt;");
}

#[test]
fn detect_explain_reports_sources_without_raw_values() {
    let fullwidth =
        "\u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}";
    let body = serde_json::json!({
        "text": format!("TCKN 12345678950, plaka 34 ABC 123, eski {fullwidth}"),
        "explain": true
    })
    .to_string();
    let r = handle_request("POST", "/v1/detect", &body);
    let v = json_body(&r);
    let ents = v["entities"].as_array().unwrap();
    assert_eq!(ents.len(), 3, "{v}");
    let tckn = &ents[0]["explain"];
    assert_eq!(
        tckn["source"],
        serde_json::json!({"kind": "RULE", "id": "tr::tckn"})
    );
    assert_eq!(tckn["validator_passed"], true);
    assert_eq!(tckn["view"], "RAW");
    assert_eq!(tckn["score"], ents[0]["score"]);
    let plate = &ents[1]["explain"];
    assert_eq!(plate["source"]["id"], "tr::plaka");
    assert_eq!(plate["cue"], "plaka");
    assert!(plate["score"].as_f64() > plate["base_score"].as_f64());
    assert_eq!(ents[2]["explain"]["view"], "NORMALIZED");
    // never the raw values
    assert!(!r.body.contains("12345678950"), "{}", r.body);
    assert!(!r.body.contains("34 ABC 123"), "{}", r.body);
    assert!(!r.body.contains(fullwidth), "{}", r.body);
    // without the flag: no explain objects (the response shape is unchanged by the explain option)
    let plain = json_body(&handle_request(
        "POST",
        "/v1/detect",
        r#"{"text":"TCKN 12345678950"}"#,
    ));
    assert!(plain["entities"][0].get("explain").is_none());
}

#[test]
fn detect_explain_names_the_ner_recognizer() {
    use redactify::api::{handle_request_with, ApiState};
    use std::sync::Arc;

    let state = ApiState::default().with_ner(Arc::new(redactify::MockNameRecognizer::new()));
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/detect",
        r#"{"text":"we met Jean Dupont today","explain":true}"#,
    );
    let v = json_body(&r);
    assert_eq!(
        v["entities"][0]["explain"]["source"],
        serde_json::json!({"kind": "NER", "name": "mock-ner"})
    );
    assert!(!r.body.contains("Jean"), "{}", r.body);
}

#[test]
fn vault_endpoints_share_the_detector_and_the_restore_rules() {
    // pseudonymize: normalization-aware + locales
    let body = serde_json::json!({
        "text": "TCKN 1\u{200B}2345678950, nhs 9434765870",
        "locales": ["tr", "uk"]
    })
    .to_string();
    let v = json_body(&handle_request("POST", "/v1/vault/pseudonymize", &body));
    assert_eq!(v["pseudonymized"], "TCKN [TCKN_1], nhs [UK_NHS_1]", "{v}");
    // restore: bracketed placeholders accepted
    let d = json_body(&handle_request(
        "POST",
        "/v1/vault/restore",
        r#"{"text":"TCKN [TCKN_1]","entries":[{"placeholder":"[TCKN_1]","original":"12345678950"}]}"#,
    ));
    assert_eq!(d["restored"], "TCKN 12345678950");
    // restore: the entry table is capped
    let entries: Vec<serde_json::Value> = (0..=redactify::MAX_VAULT_ENTRIES)
        .map(|i| serde_json::json!({"placeholder": format!("X_{i}"), "original": "v"}))
        .collect();
    let body = serde_json::json!({"text": "[X_1]", "entries": entries}).to_string();
    let r = handle_request("POST", "/v1/vault/restore", &body);
    assert_eq!(r.status, 413, "{}", r.body);
    assert!(r.body.contains("too_many_entries"), "{}", r.body);
}

#[test]
fn policy_default_locales_drive_detect_redact_and_vault() {
    use redactify::api::{handle_request_with, ApiState};

    let state = ApiState::default().with_policy(redactify::policy::Policy {
        default_locales: vec!["uk".to_owned()],
        ..redactify::policy::Policy::default()
    });
    let body = r#"{"text":"nhs 9434765870"}"#;
    let d = json_body(&handle_request_with(&state, "POST", "/v1/detect", body));
    assert_eq!(d["entities"][0]["type"], "UK_NHS");
    let r = json_body(&handle_request_with(&state, "POST", "/v1/redact", body));
    assert_eq!(r["redacted"], "nhs [UK_NHS]");
    let a = json_body(&handle_request_with(
        &state,
        "POST",
        "/v1/vault/pseudonymize",
        body,
    ));
    assert_eq!(a["pseudonymized"], "nhs [UK_NHS_1]");
    // an explicit request list wins over the policy default
    let r = json_body(&handle_request_with(
        &state,
        "POST",
        "/v1/redact",
        r#"{"text":"nhs 9434765870","locales":["tr"]}"#,
    ));
    assert_eq!(r["redacted"], "nhs 9434765870");
}

// ------------------------------------------------------------- tool guard

#[test]
fn tool_check_allows_and_denies_without_echoing_arguments() {
    let contract = serde_json::json!({
        "allowed": ["search", "shell"],
        "denied_arg_patterns": {"shell": "rm\\s+-rf"}
    });
    let check = |history: serde_json::Value, call: serde_json::Value| {
        let body =
            serde_json::json!({"contract": contract, "history": history, "call": call}).to_string();
        let r = handle_request("POST", "/v1/tool/check", &body);
        assert!(!r.body.contains("secret-arg"), "args echoed: {}", r.body);
        assert!(!r.body.contains("rm -rf"), "args echoed: {}", r.body);
        json_body(&r)
    };
    let allow = check(
        serde_json::json!([]),
        serde_json::json!({"tool": "search", "args": {"q": "secret-arg"}}),
    );
    assert_eq!(
        allow,
        serde_json::json!({"verdict": "allow", "code": "ALLOW"})
    );
    let not_listed = check(
        serde_json::json!([]),
        serde_json::json!({"tool": "delete_db", "args": "secret-arg"}),
    );
    assert_eq!(
        not_listed,
        serde_json::json!({"verdict": "deny", "code": "NOT_ALLOWLISTED"})
    );
    let pattern = check(
        serde_json::json!([]),
        serde_json::json!({"tool": "shell", "args": "rm -rf /"}),
    );
    assert_eq!(pattern["code"], "ARG_PATTERN");
    // loop: the third identical call (key order is not part of the identity)
    let same = serde_json::json!({"tool": "search", "args": {"a": 1, "q": "secret-arg"}});
    let reordered = serde_json::json!({"tool": "search", "args": {"q": "secret-arg", "a": 1}});
    let lp = check(serde_json::json!([same, reordered]), same.clone());
    assert_eq!(lp, serde_json::json!({"verdict": "deny", "code": "LOOP"}));
    // history is optional
    let r = handle_request(
        "POST",
        "/v1/tool/check",
        r#"{"contract":{"allowed":["search"]},"call":{"tool":"search"}}"#,
    );
    assert_eq!(json_body(&r)["verdict"], "allow");
}

#[test]
fn tool_check_validates_and_caps_the_request() {
    let bad_contract = handle_request(
        "POST",
        "/v1/tool/check",
        r#"{"contract":{"allowed":["a"],"global_maxx":1},"call":{"tool":"a"}}"#,
    );
    assert_eq!(bad_contract.status, 400);
    assert!(
        bad_contract.body.contains("bad_contract"),
        "{}",
        bad_contract.body
    );
    assert!(
        bad_contract.body.contains("global_maxx"),
        "{}",
        bad_contract.body
    );

    let missing_call = handle_request("POST", "/v1/tool/check", r#"{"contract":{"allowed":[]}}"#);
    assert_eq!(missing_call.status, 400);
    assert!(missing_call.body.contains("missing_field"));

    let bad_history = handle_request(
        "POST",
        "/v1/tool/check",
        r#"{"contract":{"allowed":["a"]},"history":[{"tool":"a"},{"tool":7}],"call":{"tool":"a"}}"#,
    );
    assert_eq!(bad_history.status, 400);
    assert!(
        bad_history.body.contains("history[1]"),
        "{}",
        bad_history.body
    );

    let history: Vec<serde_json::Value> = (0..=redactify::api::MAX_TOOL_HISTORY)
        .map(|_| serde_json::json!({"tool": "a"}))
        .collect();
    let body = serde_json::json!({
        "contract": {"allowed": ["a"]},
        "history": history,
        "call": {"tool": "a"}
    })
    .to_string();
    let capped = handle_request("POST", "/v1/tool/check", &body);
    assert_eq!(capped.status, 413, "{}", capped.body);
    assert!(capped.body.contains("history_too_long"), "{}", capped.body);

    // routed like every POST endpoint
    assert_eq!(handle_request("GET", "/v1/tool/check", "").status, 405);
    let index = json_body(&handle_request("GET", "/", ""));
    assert!(index["endpoints"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("POST /v1/tool/check")));
}

// -------------------------------------------------------------- /health

#[test]
fn health_reports_model_health_per_slot() {
    use redactify::api::{handle_request_with, ApiState};
    use redactify::guard::category::GuardCategory;
    use redactify::guard::ml::{MlClassifier, MlHealth, MockSecurityClassifier};
    use std::sync::Arc;

    struct Degraded;
    impl MlClassifier for Degraded {
        fn classify(&self, _: &str) -> Vec<(GuardCategory, f32)> {
            Vec::new()
        }
        fn name(&self) -> &'static str {
            "degraded-mock"
        }
        fn health(&self) -> MlHealth {
            MlHealth::Degraded("inference timed out".to_owned())
        }
    }

    let plain = json_body(&handle_request("GET", "/health", ""));
    assert_eq!(plain["status"], "ok");
    assert_eq!(plain["ml_active"], false);
    assert_eq!(
        plain["ml_health"],
        serde_json::json!({"security": null, "safety": null, "ner": null})
    );

    let healthy = ApiState::default()
        .with_security(Arc::new(MockSecurityClassifier::new()))
        .with_ner(Arc::new(redactify::MockNameRecognizer::new()));
    let v = json_body(&handle_request_with(&healthy, "GET", "/health", ""));
    assert_eq!(v["status"], "ok");
    assert_eq!(
        v["ml_health"]["security"],
        serde_json::json!({"status": "ok"})
    );
    assert_eq!(v["ml_health"]["ner"], serde_json::json!({"status": "ok"}));
    assert!(v["ml_health"]["safety"].is_null());

    let degraded = ApiState::default().with_safety(Arc::new(Degraded));
    let v = json_body(&handle_request_with(&degraded, "GET", "/health", ""));
    assert_eq!(v["status"], "degraded");
    assert_eq!(
        v["ml_health"]["safety"],
        serde_json::json!({"status": "degraded", "reason": "inference timed out"})
    );
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
}

// -------------------------------------------------------------- audit

/// Audit records collected by a test sink, as parsed JSON.
type Records = std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>;

/// A state whose audit sink collects every record.
fn audited_state() -> (redactify::api::ApiState, Records) {
    use std::sync::{Arc, Mutex};
    let records: Records = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&records);
    let state = redactify::api::ApiState::default().with_audit_sink(Box::new(move |rec| {
        let v = serde_json::from_str(&rec.to_json()).expect("record JSON");
        sink.lock().unwrap().push(v);
    }));
    (state, records)
}

#[test]
fn audit_covers_sanitize_and_stream_blocks_with_request_ids() {
    use redactify::api::handle_request_with;

    let (state, records) = audited_state();
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/sanitize",
        r#"{"text":"TCKN 12345678950","request_id":"req-42"}"#,
    );
    assert_eq!(r.status, 200);
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/stream/sanitize",
        r#"{"chunks":["guvenli\n","bkz http://169.254.169.254/meta\n"],"request_id":"stream 7"}"#,
    );
    assert_eq!(r.status, 200);
    // a stream without a Block emits no record
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/stream/sanitize",
        r#"{"chunks":["temiz satir\n"]}"#,
    );
    assert_eq!(r.status, 200);
    // no request_id: a generated per-process id
    let r = handle_request_with(&state, "POST", "/v1/guard", r#"{"text":"merhaba"}"#);
    assert_eq!(r.status, 200);

    let recs = records.lock().unwrap().clone();
    assert_eq!(recs.len(), 3, "{recs:?}");
    assert_eq!(recs[0]["request_id"], "req-42");
    assert_eq!(recs[0]["action"], "Mask");
    assert_eq!(recs[0]["layer"], "L0+L1");
    assert_eq!(recs[0]["guard"], "DECISION");
    assert_eq!(recs[1]["request_id"], "stream 7");
    assert_eq!(recs[1]["action"], "Block");
    assert!(recs[1]["rationale"].as_str().unwrap().contains("0.95"));
    assert!(recs[2]["request_id"].as_str().unwrap().starts_with("api-"));
    assert_eq!(recs[2]["action"], "Allow");
    // content-free
    let all = serde_json::to_string(&recs).unwrap();
    assert!(
        !all.contains("12345678950") && !all.contains("169.254"),
        "{all}"
    );
}

#[test]
fn audit_layer_names_the_ml_layers_and_request_ids_are_validated() {
    use redactify::api::handle_request_with;
    use redactify::guard::ml::MockSecurityClassifier;
    use std::sync::Arc;

    let (state, records) = audited_state();
    let state = state.with_security(Arc::new(MockSecurityClassifier::new()));
    let r = handle_request_with(&state, "POST", "/v1/guard", r#"{"text":"hello"}"#);
    assert_eq!(r.status, 200);
    assert_eq!(records.lock().unwrap()[0]["layer"], "L0+L1+L2/L3");

    for bad in [r#""""#, "7", r#""line\nbreak""#, r#""ü""#] {
        let body = format!(r#"{{"text":"x","request_id":{bad}}}"#);
        for path in ["/v1/guard", "/v1/sanitize"] {
            let r = handle_request_with(&state, "POST", path, &body);
            assert_eq!(r.status, 400, "{path} {bad}: {}", r.body);
            assert!(r.body.contains("bad_request_id"), "{}", r.body);
        }
    }
    let long = format!(r#"{{"chunks":["x"],"request_id":"{}"}}"#, "a".repeat(129));
    let r = handle_request_with(&state, "POST", "/v1/stream/sanitize", &long);
    assert_eq!(r.status, 400, "{}", r.body);
    // the ids above were refused before any decision: one record only
    assert_eq!(records.lock().unwrap().len(), 1);
}

// -------------------------------------------------- stream endpoint models

#[test]
fn stream_endpoint_uses_the_attached_ner_and_security_classifier() {
    use redactify::api::{handle_request_with, ApiState};
    use redactify::guard::ml::MockSecurityClassifier;
    use std::sync::Arc;

    let ner = ApiState::default().with_ner(Arc::new(redactify::MockNameRecognizer::new()));
    let r = handle_request_with(
        &ner,
        "POST",
        "/v1/stream/sanitize",
        r#"{"chunks":["we met Ahmet ","Yilmaz today\n"]}"#,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("we met [NAME] today"), "{}", r.body);
    assert!(!r.body.contains("Ahmet"), "{}", r.body);

    // the budgeted security scan (first line) blocks the stream
    let ml = ApiState::default().with_security(Arc::new(MockSecurityClassifier::new()));
    let r = handle_request_with(
        &ml,
        "POST",
        "/v1/stream/sanitize",
        r#"{"chunks":["explain how jailbreak attacks work\n","more\n"]}"#,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let events: Vec<serde_json::Value> = r
        .body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.len(), 1, "{}", r.body);
    assert_eq!(events[0]["type"], "block");
    assert!(events[0]["rationale"]
        .as_str()
        .unwrap()
        .contains("ml stream"));
}

// -------------------------------------------------- NDJSON content type

#[test]
fn stream_endpoint_answers_with_the_ndjson_content_type() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let port = common::start(redactify::api::ApiState::default());
    let post = |path: &str, body: &str| -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut response = String::new();
        s.read_to_string(&mut response).unwrap();
        response
    };
    let ok = post(
        "/v1/stream/sanitize",
        r#"{"chunks":["TCKN 12345678950\n"]}"#,
    );
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(ok.contains("Content-Type: application/x-ndjson"), "{ok}");
    // errors on the same path stay JSON
    let bad = post("/v1/stream/sanitize", r#"{"text":"x"}"#);
    assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
    assert!(bad.contains("Content-Type: application/json"), "{bad}");
    // every other endpoint stays JSON
    let guard = post("/v1/guard", r#"{"text":"x"}"#);
    assert!(guard.contains("Content-Type: application/json"), "{guard}");
}

#[test]
fn batch_sanitize_audits_every_item_with_the_request_id() {
    use redactify::api::handle_request_with;

    let (state, records) = audited_state();
    let r = handle_request_with(
        &state,
        "POST",
        "/v1/batch/sanitize",
        r#"{"texts":["TCKN 12345678950","temiz","bkz http://169.254.169.254/meta"],"request_id":"batch-9"}"#,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let recs = records.lock().unwrap().clone();
    assert_eq!(recs.len(), 3, "{recs:?}");
    assert!(
        recs.iter().all(|r| r["request_id"] == "batch-9"),
        "{recs:?}"
    );
    let actions: Vec<&str> = recs.iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["Mask", "Allow", "Block"]);
    let log = serde_json::to_string(&recs).unwrap();
    assert!(!log.contains("12345678950"), "{log}");
}

#[test]
fn every_text_endpoint_honors_the_ignore_allowlist() {
    let text = "Destek: 0532 123 45 67, TCKN 12345678950";
    let ignore = r#""ignore":["0532 123 45 67"]"#;
    for (path, body) in [
        ("/v1/sanitize", format!(r#"{{"text":"{text}",{ignore}}}"#)),
        ("/v1/redact", format!(r#"{{"text":"{text}",{ignore}}}"#)),
        (
            "/v1/batch/sanitize",
            format!(r#"{{"texts":["{text}"],{ignore}}}"#),
        ),
        (
            "/v1/stream/sanitize",
            format!(r#"{{"chunks":["{text}\n"],{ignore}}}"#),
        ),
    ] {
        let r = handle_request("POST", path, &body);
        assert_eq!(r.status, 200, "{path}: {}", r.body);
        assert!(r.body.contains("0532 123 45 67"), "{path}: {}", r.body);
        assert!(!r.body.contains("12345678950"), "{path}: {}", r.body);
    }
    // the vault keeps the allowlisted value in the text (its mapping holds
    // the originals by design, so the TCKN is in `entries`)
    let r = handle_request(
        "POST",
        "/v1/vault/pseudonymize",
        &format!(r#"{{"text":"{text}",{ignore}}}"#),
    );
    assert_eq!(
        body_json(&r)["pseudonymized"],
        "Destek: 0532 123 45 67, TCKN [TCKN_1]"
    );
    // the guard decision reports no PHONE span for the allowlisted value
    let r = handle_request(
        "POST",
        "/v1/guard",
        &format!(r#"{{"text":"{text}",{ignore}}}"#),
    );
    let v = body_json(&r);
    let types: Vec<&str> = v["pii"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["TCKN"], "{}", r.body);
}
