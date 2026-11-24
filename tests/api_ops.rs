//! REST operations features: dry-run (shadow) mode, `GET /metrics`, the
//! configurable body limit (413), and decisions in the audit sink.
#![cfg(all(feature = "api", feature = "config"))]

mod common;

use std::sync::{Arc, Mutex};

use common::{send, start};
use redactify::api::{handle_request_with, serve_with, ApiState, BearerToken};
use redactify::guard::audit::AuditRecord;
use redactify::policy::Policy;
use serde_json::{json, Value};

const TCKN: &str = "12345678950";
const AWS: &str = "AKIAIOSFODNN7EXAMPLE";

fn dry_run_policy() -> Policy {
    Policy::from_toml("schema_version = \"0.4\"\ndry_run = true\n[entities]\nEMAIL = \"log\"\n")
        .expect("policy")
}

/// A state whose audit sink collects the records.
fn audited(state: ApiState) -> (ApiState, Arc<Mutex<Vec<AuditRecord>>>) {
    let records = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&records);
    let state = state.with_audit_sink(Box::new(move |r: &AuditRecord| {
        sink.lock().unwrap().push(r.clone());
    }));
    (state, records)
}

fn post(state: &ApiState, path: &str, body: &Value) -> (u16, String) {
    let r = handle_request_with(state, "POST", path, &body.to_string());
    (r.status, r.body)
}

#[test]
fn dry_run_sanitize_returns_the_text_unchanged_and_audits_the_decision() {
    let (state, records) = audited(ApiState::default().with_policy(dry_run_policy()));
    let text = format!("TCKN {TCKN} key {AWS} mail a@b.com");
    let (s, body) = post(
        &state,
        "/v1/sanitize",
        &json!({ "text": text, "request_id": "r-1" }),
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["action"], "Allow");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["dry_run_action"], "Block");
    assert_eq!(v["text"], text.as_str(), "shadow mode changes nothing");
    assert!(v["rationale"]
        .as_str()
        .unwrap()
        .starts_with("dry run (not enforced): would Block"));
    let recs = records.lock().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].guard, "DRY_RUN");
    assert_eq!(recs[0].action, redactify::GuardAction::Block);
    assert_eq!(recs[0].request_id, "r-1");
    let line = recs[0].to_json();
    assert!(
        line.contains("TCKN=MASK x1") && line.contains("EMAIL=LOG x1"),
        "{line}"
    );
    assert!(!line.contains(TCKN) && !line.contains(AWS) && !line.contains("a@b.com"));
}

#[test]
fn dry_run_litellm_never_intervenes_but_audits() {
    let (state, records) = audited(ApiState::default().with_policy(dry_run_policy()));
    let (s, body) = post(
        &state,
        "/beta/litellm_basic_guardrail_api",
        &json!({ "texts": [format!("key {AWS}"), format!("TCKN {TCKN}")], "input_type": "request" }),
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["action"], "NONE", "{v}");
    let recs = records.lock().unwrap();
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|r| r.guard == "DRY_RUN"));
    assert_eq!(recs[0].action, redactify::GuardAction::Block);
    assert_eq!(recs[1].action, redactify::GuardAction::Mask);
}

#[test]
fn dry_run_stream_echoes_the_chunks_and_audits_the_would_be_block() {
    let (state, records) = audited(ApiState::default().with_policy(dry_run_policy()));
    let chunks = ["hello ", &format!("key {AWS}\n"), &format!("TCKN {TCKN}\n")];
    let (s, body) = post(&state, "/v1/stream/sanitize", &json!({ "chunks": chunks }));
    assert_eq!(s, 200);
    let frames: Vec<Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(frames.len(), 3, "{body}");
    for (f, c) in frames.iter().zip(chunks) {
        assert_eq!(f["type"], "segment");
        assert_eq!(f["text"], c);
        assert_eq!(f["dry_run"], true);
    }
    let recs = records.lock().unwrap();
    assert_eq!(recs.len(), 1, "one would-be Block");
    assert_eq!(recs[0].guard, "DRY_RUN");
    assert!(recs[0]
        .rationale
        .starts_with("dry run (not enforced): would Block; "));
    assert!(!recs[0].rationale.contains(AWS));
}

#[test]
fn dry_run_is_announced_on_health_and_absent_otherwise() {
    let on = ApiState::default().with_policy(dry_run_policy());
    let v: Value =
        serde_json::from_str(&handle_request_with(&on, "GET", "/health", "").body).unwrap();
    assert_eq!(v["dry_run"], true);
    let off = ApiState::default();
    let v: Value =
        serde_json::from_str(&handle_request_with(&off, "GET", "/health", "").body).unwrap();
    assert!(v.get("dry_run").is_none());
    // and a decision outside dry run carries no dry-run fields
    let (_, body) = post(
        &off,
        "/v1/sanitize",
        &json!({ "text": format!("TCKN {TCKN}") }),
    );
    assert!(!body.contains("dry_run"), "{body}");
}

#[test]
fn metrics_count_requests_decisions_and_entities_without_values() {
    let state = ApiState::default();
    post(
        &state,
        "/v1/sanitize",
        &json!({ "text": format!("TCKN {TCKN} and {TCKN}") }),
    );
    post(
        &state,
        "/v1/guard",
        &json!({ "text": format!("key {AWS}") }),
    );
    post(
        &state,
        "/v1/batch/sanitize",
        &json!({ "texts": ["mail a@b.com", "hello"] }),
    );
    post(&state, "/v1/sanitize", &json!({ "nope": 1 }));
    let _ = handle_request_with(&state, "GET", "/no/such/path", "");
    let r = handle_request_with(&state, "GET", "/metrics", "");
    assert_eq!(r.status, 200);
    let m = r.body;
    for line in [
        r#"redactify_requests_total{endpoint="/v1/sanitize",status="200"} 1"#,
        r#"redactify_requests_total{endpoint="/v1/sanitize",status="400"} 1"#,
        r#"redactify_requests_total{endpoint="other",status="404"} 1"#,
        r#"redactify_decisions_total{endpoint="/v1/sanitize",action="mask",mode="enforce"} 1"#,
        r#"redactify_decisions_total{endpoint="/v1/guard",action="block",mode="enforce"} 1"#,
        r#"redactify_decisions_total{endpoint="/v1/batch/sanitize",action="allow",mode="enforce"} 1"#,
        r#"redactify_entities_total{endpoint="/v1/sanitize",entity_type="TCKN",action="MASK"} 2"#,
        r#"redactify_entities_total{endpoint="/v1/batch/sanitize",entity_type="EMAIL",action="MASK"} 1"#,
        r#"redactify_request_duration_seconds_count{endpoint="/v1/sanitize"} 2"#,
        "# TYPE redactify_request_duration_seconds histogram",
    ] {
        assert!(m.contains(line), "missing {line}\n{m}");
    }
    assert!(!m.contains(TCKN) && !m.contains(AWS) && !m.contains("a@b.com"));
    assert!(!m.contains("/no/such/path"));
    // every sample line is `name{labels} value` with a numeric value
    for line in m.lines().filter(|l| !l.starts_with('#')) {
        let value = line.rsplit(' ').next().unwrap();
        assert!(value.parse::<f64>().is_ok(), "{line}");
    }
    assert_eq!(
        handle_request_with(&state, "POST", "/metrics", "").status,
        405
    );
}

#[test]
fn the_body_limit_is_configurable_and_answers_413() {
    let state = ApiState::default().with_max_body(2048);
    let small = json!({ "text": "a".repeat(1000) }).to_string();
    let big = json!({ "text": "a".repeat(3000) }).to_string();
    assert_eq!(
        handle_request_with(&state, "POST", "/v1/redact", &small).status,
        200
    );
    let r = handle_request_with(&state, "POST", "/v1/redact", &big);
    assert_eq!(r.status, 413);
    assert!(
        r.body.contains("payload_too_large") && r.body.contains("2048"),
        "{}",
        r.body
    );
    // the default stays 1 MiB
    let default = ApiState::default();
    assert_eq!(
        handle_request_with(&default, "POST", "/v1/redact", &big).status,
        200
    );
}

// ---------------------------------------------------------------- socket

#[test]
fn socket_server_enforces_the_configured_limit_with_and_without_content_length() {
    let port = start(ApiState::default().with_max_body(4096));
    let big = json!({ "text": "a".repeat(5000) }).to_string();
    let r = send(
        port,
        &format!(
            "POST /v1/redact HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{big}",
            big.len()
        ),
    );
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
    // chunked: no Content-Length, the bounded read rejects it
    let r = send(
        port,
        &format!(
            "POST /v1/redact HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{big}\r\n0\r\n\r\n",
            big.len()
        ),
    );
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
    let ok = json!({ "text": "a".repeat(3000) }).to_string();
    let r = send(
        port,
        &format!(
            "POST /v1/redact HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ok}",
            ok.len()
        ),
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
}

#[test]
fn socket_server_refuses_a_limit_outside_its_range() {
    for limit in [0, 1023, 16 * 1024 * 1024 + 1] {
        let e = serve_with("127.0.0.1:0", ApiState::default().with_max_body(limit)).unwrap_err();
        assert!(e.to_string().contains("body limit"), "{e}");
    }
}

#[test]
fn metrics_need_the_token_and_use_the_exposition_content_type() {
    let port = start(
        ApiState::default().with_bearer_token(BearerToken::new("m3tr1cs-T0ken").expect("token")),
    );
    let r = send(
        port,
        "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    let r = send(
        port,
        "GET /metrics HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer m3tr1cs-T0ken\r\nConnection: close\r\n\r\n",
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let content_type = r
        .lines()
        .find_map(|l| l.strip_prefix("Content-Type: "))
        .unwrap_or_default();
    assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");
    // the rejected request was counted (status 401), without its path text
    assert!(
        r.contains(r#"redactify_requests_total{endpoint="/metrics",status="401"} 1"#),
        "{r}"
    );
    assert!(r.ends_with('\n'));
}
