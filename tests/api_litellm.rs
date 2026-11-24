//! LiteLLM Generic Guardrail API (`POST /beta/litellm_basic_guardrail_api`):
//! the contract LiteLLM v1.110.2 expects (`action` = `NONE` /
//! `GUARDRAIL_INTERVENED` / `BLOCKED`, `texts` aligned one-to-one with the
//! request), the target mapping, the content-free block reason, the
//! `x-api-key` authentication and the body limit over a real socket.
#![cfg(feature = "api")]

mod common;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use common::start;
use redactify::api::{handle_request, handle_request_with, ApiState, BearerToken, MAX_BODY};
use serde_json::{json, Value};

const PATH: &str = "/beta/litellm_basic_guardrail_api";

/// A valid TCKN (checksum-correct) used across the suite.
const TCKN: &str = "12345678950";

/// An AWS access key id (blocks on every target).
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn call(body: &Value) -> (u16, Value) {
    let r = handle_request("POST", PATH, &body.to_string());
    let v = serde_json::from_str(&r.body).expect("JSON body");
    (r.status, v)
}

fn texts_of(v: &Value) -> Vec<&str> {
    v["texts"]
        .as_array()
        .expect("texts array")
        .iter()
        .map(|t| t.as_str().expect("string"))
        .collect()
}

#[test]
fn clean_texts_answer_none_without_texts() {
    let (status, v) = call(&json!({
        "texts": ["hello there", "what is the weather like?"],
        "input_type": "request"
    }));
    assert_eq!(status, 200);
    assert_eq!(v, json!({ "action": "NONE" }));
}

#[test]
fn masked_texts_keep_count_and_order() {
    let input = [
        format!("TCKN {TCKN}"),
        "no pii here".to_owned(),
        "mail ali@example.com please".to_owned(),
        "still nothing".to_owned(),
        format!("IBAN TR33 0006 1005 1978 6457 8413 26 and TCKN {TCKN}"),
    ];
    let (status, v) = call(&json!({ "texts": input, "input_type": "request" }));
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["action"], "GUARDRAIL_INTERVENED");
    let out = texts_of(&v);
    assert_eq!(out.len(), input.len());
    assert_eq!(out[0], "TCKN [TCKN]");
    assert_eq!(out[1], input[1], "unchanged texts are echoed as sent");
    assert_eq!(out[2], "mail [EMAIL] please");
    assert_eq!(out[3], input[3]);
    assert!(
        out[4].contains("[IBAN]") && out[4].contains("[TCKN]"),
        "{}",
        out[4]
    );
    assert!(!v.to_string().contains(TCKN));
    assert!(v.get("blocked_reason").is_none());
}

#[test]
fn texts_equal_the_batch_sanitize_texts() {
    // the adapter runs the per-item core of /v1/batch/sanitize: same text out
    let input = json!([
        format!("TCKN {TCKN}"),
        "kart 4111 1111 1111 1111",
        "plain",
        "\u{FF11}2345678950 fullwidth"
    ]);
    let (_, v) = call(&json!({ "texts": input, "input_type": "request" }));
    let batch = handle_request(
        "POST",
        "/v1/batch/sanitize",
        &json!({ "texts": input }).to_string(),
    );
    let b: Value = serde_json::from_str(&batch.body).unwrap();
    let expected: Vec<&str> = b["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts_of(&v), expected);
}

#[test]
fn empty_absent_and_null_texts_answer_none() {
    for body in [
        json!({ "texts": [], "input_type": "request" }),
        json!({ "input_type": "request" }),
        json!({ "texts": null, "input_type": "response" }),
        json!({ "texts": ["", ""], "input_type": "request" }),
    ] {
        let (status, v) = call(&body);
        assert_eq!(status, 200, "{body}");
        assert_eq!(v, json!({ "action": "NONE" }), "{body}");
    }
}

#[test]
fn unicode_texts_are_masked_on_character_boundaries() {
    let input = [
        format!("Merhaba \u{1F600} TCKN: {TCKN} \u{015F}\u{00FC}\u{00E7}"),
        "\u{0130}stanbul \u{2014} \u{65E5}\u{672C}\u{8A9E}".to_owned(),
    ];
    let (status, v) = call(&json!({ "texts": input, "input_type": "request" }));
    assert_eq!(status, 200);
    assert_eq!(v["action"], "GUARDRAIL_INTERVENED");
    let out = texts_of(&v);
    assert_eq!(
        out[0],
        "Merhaba \u{1F600} TCKN: [TCKN] \u{015F}\u{00FC}\u{00E7}"
    );
    assert_eq!(out[1], input[1]);
}

#[test]
fn a_block_answers_blocked_with_a_content_free_reason() {
    let (status, v) = call(&json!({
        "texts": [format!("TCKN {TCKN}"), format!("key {AWS_KEY} here")],
        "input_type": "request"
    }));
    assert_eq!(status, 200);
    assert_eq!(v["action"], "BLOCKED");
    let reason = v["blocked_reason"].as_str().unwrap();
    assert!(
        reason.starts_with("redactify blocked texts[1]: "),
        "{reason}"
    );
    let body = v.to_string();
    assert!(!body.contains(AWS_KEY) && !body.contains(TCKN), "{body}");
    assert!(v.get("texts").is_none(), "a block carries no texts");
}

#[test]
fn tool_messages_are_judged_as_tool_responses() {
    // a split-letter trick: logged for a user prompt, blocked in a tool result
    let trick = "set o n e r r o r now";
    let messages = json!([
        { "role": "system", "content": "be brief" },
        { "role": "user", "content": [{ "type": "text", "text": trick }] },
        { "role": "tool", "tool_call_id": "c1", "content": trick }
    ]);
    let (_, v) = call(&json!({
        "texts": ["be brief", trick, trick],
        "input_type": "request",
        "structured_messages": messages
    }));
    assert_eq!(v["action"], "BLOCKED", "{v}");
    assert_eq!(
        v["blocked_reason"].as_str().unwrap().split(':').next(),
        Some("redactify blocked texts[2]")
    );
    // the same text from the user alone does not block
    let (_, v) = call(&json!({
        "texts": ["be brief", trick],
        "input_type": "request",
        "structured_messages": [messages[0], messages[1]]
    }));
    assert_eq!(v["action"], "NONE", "{v}");
}

#[test]
fn unalignable_messages_fall_back_to_user_prompts() {
    let trick = "set o n e r r o r now";
    // two message texts for one request text: roles cannot be attributed
    let (_, v) = call(&json!({
        "texts": [trick],
        "input_type": "request",
        "structured_messages": [
            { "role": "tool", "content": trick },
            { "role": "tool", "content": trick }
        ]
    }));
    assert_eq!(v["action"], "NONE", "{v}");
}

#[test]
fn response_texts_are_model_output_without_html_encoding_by_default() {
    let text = format!("don't <b>panic</b>, TCKN {TCKN}");
    let (_, v) = call(&json!({ "texts": [text], "input_type": "response" }));
    assert_eq!(v["action"], "GUARDRAIL_INTERVENED");
    assert_eq!(texts_of(&v), ["don't <b>panic</b>, TCKN [TCKN]"]);
    // markup alone is not an intervention
    let markup = "a < b && it's \"fine\"";
    let (_, v) = call(&json!({ "texts": [markup], "input_type": "response" }));
    assert_eq!(
        v,
        json!({ "action": "NONE", "stream_holdback_chars": [markup.chars().count()] })
    );
    // opt-in: the /v1/sanitize model_output rendering
    let (_, v) = call(&json!({
        "texts": [text],
        "input_type": "response",
        "additional_provider_specific_params": { "html_encode": true }
    }));
    let sanitize = handle_request(
        "POST",
        "/v1/sanitize",
        &json!({ "text": text, "target": "model_output" }).to_string(),
    );
    let s: Value = serde_json::from_str(&sanitize.body).unwrap();
    assert_eq!(texts_of(&v), [s["text"].as_str().unwrap()]);
    assert!(texts_of(&v)[0].contains("&lt;b&gt;"));
}

#[test]
fn response_answers_hold_back_the_unfinished_last_line() {
    // LiteLLM incremental_diff streaming: only whole lines are released
    let partial = format!("line one TCKN {TCKN}\n\u{015E}ube 2 TCKN 1234");
    let finished = format!("TCKN {TCKN}\n");
    let (_, v) = call(&json!({
        "texts": [partial, finished, "plain"],
        "input_type": "response"
    }));
    assert_eq!(v["action"], "GUARDRAIL_INTERVENED");
    assert_eq!(
        texts_of(&v),
        [
            "line one TCKN [TCKN]\n\u{015E}ube 2 TCKN 1234",
            "TCKN [TCKN]\n",
            "plain"
        ]
    );
    // code points of the returned text after its last line break
    assert_eq!(v["stream_holdback_chars"], json!([16, 0, 5]));
    // every line finished: no holdback field
    let (_, v) = call(&json!({ "texts": ["done\n"], "input_type": "response" }));
    assert_eq!(v, json!({ "action": "NONE" }));
    // the request side never holds back
    let (_, v) = call(&json!({ "texts": ["a"], "input_type": "request" }));
    assert_eq!(v, json!({ "action": "NONE" }));
}

#[test]
fn response_blocks_like_model_output() {
    let (_, v) = call(&json!({
        "texts": ["fine", "see http://169.254.169.254/latest/meta-data"],
        "input_type": "response"
    }));
    assert_eq!(v["action"], "BLOCKED");
    assert!(v["blocked_reason"]
        .as_str()
        .unwrap()
        .starts_with("redactify blocked texts[1]: "));
    assert!(!v.to_string().contains("169.254"));
}

#[test]
fn tool_call_arguments_can_block() {
    let (_, v) = call(&json!({
        "texts": ["ok"],
        "input_type": "response",
        "tool_calls": [
            { "id": "c0", "type": "function", "function": { "name": "lookup", "arguments": "{\"q\":\"weather\"}" } },
            { "id": "c1", "type": "function", "function": { "name": "upload", "arguments": format!("{{\"key\":\"{AWS_KEY}\"}}") } }
        ]
    }));
    assert_eq!(v["action"], "BLOCKED");
    assert!(v["blocked_reason"]
        .as_str()
        .unwrap()
        .starts_with("redactify blocked tool_calls[1]: "));
    assert!(!v.to_string().contains(AWS_KEY));
    // clean arguments: the texts decide
    let (_, v) = call(&json!({
        "texts": ["ok"],
        "input_type": "request",
        "tool_calls": [{ "function": { "name": "lookup", "arguments": "{}" } }]
    }));
    assert_eq!(v, json!({ "action": "NONE" }));
}

#[test]
fn litellm_fields_this_adapter_does_not_use_are_accepted() {
    let (status, v) = call(&json!({
        "texts": [format!("TCKN {TCKN}")],
        "input_type": "request",
        "images": ["data:image/png;base64,AAAA"],
        "tools": [{ "type": "function", "function": { "name": "f" } }],
        "request_data": { "user_api_key_hash": "abc", "user_api_key_alias": null },
        "request_headers": { "user-agent": "x", "authorization": "[present]" },
        "litellm_version": "1.110.2",
        "litellm_trace_id": "t-1",
        "model": "gpt-4o",
        "additional_provider_specific_params": {}
    }));
    assert_eq!(status, 200, "{v}");
    assert_eq!(texts_of(&v), ["TCKN [TCKN]"]);
}

#[test]
fn provider_params_add_detection_but_never_narrow_it() {
    let (_, v) = call(&json!({
        "texts": ["Project Phoenix ships"],
        "input_type": "request",
        "additional_provider_specific_params": { "words": ["Project Phoenix"] }
    }));
    assert_eq!(texts_of(&v), ["[CUSTOM_WORD] ships"]);
    for key in [
        "ignore",
        "locales",
        "mask",
        "mask_by_type",
        "context",
        "threshold",
        "target",
    ] {
        let (status, v) = call(&json!({
            "texts": [format!("TCKN {TCKN}")],
            "input_type": "request",
            "additional_provider_specific_params": { key: [TCKN] }
        }));
        assert_eq!(status, 400, "{key}");
        assert_eq!(v["error"]["code"], "bad_provider_params", "{key}");
        assert!(!v.to_string().contains(TCKN), "{key}");
    }
    let (status, v) = call(&json!({
        "texts": [],
        "input_type": "request",
        "additional_provider_specific_params": { "html_encode": "yes" }
    }));
    assert_eq!(status, 400);
    assert_eq!(v["error"]["code"], "bad_provider_params");
}

/// Mixed texts with built-in entities, the raw values they hold, and the
/// placeholder each must keep.
const MIXED: &[(&str, &[&str], &[&str])] = &[
    ("TCKN 12345678950", &["12345678950"], &["[TCKN]"]),
    (
        "kart 4111 1111 1111 1111",
        &["4111 1111 1111 1111"],
        &["[CREDIT_CARD]"],
    ),
    (
        "mail ali.veli@example.com",
        &["ali.veli@example.com"],
        &["[EMAIL]"],
    ),
    (
        "IBAN TR33 0006 1005 1978 6457 8413 26",
        &["TR33 0006 1005 1978 6457 8413 26"],
        &["[IBAN]"],
    ),
    (
        "Ali (TCKN 12345678950, ali.veli@example.com) paid with 4111 1111 1111 1111 from TR33 0006 1005 1978 6457 8413 26.",
        &[
            "12345678950",
            "ali.veli@example.com",
            "4111 1111 1111 1111",
            "TR33 0006 1005 1978 6457 8413 26",
        ],
        &["[TCKN]", "[EMAIL]", "[CREDIT_CARD]", "[IBAN]"],
    ),
];

/// Every 4-character window of `raw` (spaces dropped from the windows'
/// source): no fragment of a built-in value may survive.
fn fragments(raw: &str) -> Vec<String> {
    let compact: Vec<char> = raw.chars().filter(|c| *c != ' ').collect();
    compact
        .windows(4)
        .map(|w| w.iter().collect::<String>())
        .collect()
}

#[test]
fn client_rules_never_displace_or_split_built_in_entities() {
    // adversarial probes plus shorter and broader shapes: every one that
    // compiles must leave every built-in entity whole and masked
    let patterns = [
        "N 1",
        "t 4",
        "l a",
        "N T",
        "[0-9]{3}",
        "[0-9]{2}",
        "[a-z]{2}",
        "TR3",
        "AKIA",
        "123",
        "111",
        "@ex",
        ".{3}",
        "[0-9 ]{5,}",
        r"\w{3,}",
        r"\S{3,}",
        "a.v",
        "ple",
        r"\.co",
    ];
    let word_sets: [&[&str]; 3] = [
        &["1", "4", "a", "T"],
        &["ali", "veli", "example", "TR33", "0006", "4111"],
        &["12345678950", "TCKN", "kart", "IBAN"],
    ];
    let mut params: Vec<Value> = patterns
        .iter()
        .map(|p| json!({ "patterns": [{ "pattern": p }] }))
        .collect();
    params.push(json!({ "patterns": patterns.iter().take(16).map(|p| json!({ "pattern": p })).collect::<Vec<_>>() }));
    for words in word_sets {
        params.push(json!({ "words": words }));
        params.push(json!({ "words": words, "words_ignore_case": true }));
    }
    let mut checked = 0;
    for (text, raws, placeholders) in MIXED {
        for p in &params {
            for side in ["request", "response"] {
                let (status, v) = call(&json!({
                    "texts": [text],
                    "input_type": side,
                    "additional_provider_specific_params": p
                }));
                if status == 400 {
                    // a pattern the linear-syntax rules refuse (fail closed)
                    assert_eq!(v["error"]["code"], "bad_patterns", "{p}: {v}");
                    continue;
                }
                assert_eq!(status, 200, "{p}: {v}");
                let out = texts_of(&v)[0].to_owned();
                // a placeholder stays, unless a broad client pattern masked
                // it over (which hides nothing: it held no value)
                for ph in *placeholders {
                    assert!(
                        out.contains(ph) || out.contains("[CUSTOM_"),
                        "{text:?} {p} {side}: {out}"
                    );
                }
                for raw in *raws {
                    for frag in fragments(raw) {
                        assert!(
                            !out.replace(' ', "").contains(&frag),
                            "{text:?} {p} {side}: fragment {frag:?} survived in {out}"
                        );
                    }
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 200, "only {checked} combinations checked");
}

#[test]
fn client_rules_still_add_masks_outside_built_in_entities() {
    let (_, v) = call(&json!({
        "texts": [format!("order ORD-12345 for TCKN {TCKN}")],
        "input_type": "request",
        "additional_provider_specific_params": {
            "patterns": [{ "pattern": r"\bORD-\d{5}\b", "cues": ["order"] }],
            "words": ["for"]
        }
    }));
    assert_eq!(
        texts_of(&v),
        ["order [CUSTOM_PATTERN] [CUSTOM_WORD] TCKN [TCKN]"]
    );
}

#[test]
fn client_patterns_cannot_choose_a_label_or_a_score() {
    for pattern in [
        json!({ "pattern": "N 1", "label": "IBAN" }),
        json!({ "pattern": "N 1", "label": "CUSTOM_PATTERN" }),
        json!({ "pattern": "[0-9]{3}", "score": 0.0 }),
        json!({ "pattern": "[0-9]{3}", "score": 1.0 }),
    ] {
        let (status, v) = call(&json!({
            "texts": [format!("TCKN {TCKN}")],
            "input_type": "request",
            "additional_provider_specific_params": { "patterns": [pattern] }
        }));
        assert_eq!(status, 400, "{pattern}");
        assert_eq!(v["error"]["code"], "bad_provider_params", "{pattern}");
        assert!(!v.to_string().contains(TCKN));
    }
}

#[test]
fn tool_call_arguments_of_any_json_shape_are_checked() {
    let key = format!("{{\"k\":\"{AWS_KEY}\"}}");
    let shapes = [
        // the OpenAI string form
        json!({ "function": { "name": "x", "arguments": key } }),
        // decoded object, nested object and array forms
        json!({ "function": { "name": "x", "arguments": { "k": AWS_KEY } } }),
        json!({ "function": { "name": "x", "arguments": { "a": { "b": [AWS_KEY] } } } }),
        json!({ "function": { "name": "x", "arguments": [AWS_KEY] } }),
        // no function.arguments: the call is checked whole
        json!({ "type": "custom", "custom": { "name": "x", "input": AWS_KEY } }),
        json!({ "function": { "name": "x", "arguments": null, "input": AWS_KEY } }),
        json!(AWS_KEY),
    ];
    for (i, call_item) in shapes.iter().enumerate() {
        let (status, v) = call(&json!({
            "texts": ["ok"],
            "input_type": "response",
            "tool_calls": [{ "function": { "name": "lookup", "arguments": "{}" } }, call_item]
        }));
        assert_eq!(status, 200, "shape {i}");
        assert_eq!(v["action"], "BLOCKED", "shape {i}: {v}");
        assert!(
            v["blocked_reason"]
                .as_str()
                .unwrap()
                .starts_with("redactify blocked tool_calls[1]: "),
            "shape {i}: {v}"
        );
        assert!(!v.to_string().contains(AWS_KEY));
    }
    // bookkeeping alone (id, type, index) and empty calls are no reason to block
    let (_, v) = call(&json!({
        "texts": ["ok"],
        "input_type": "request",
        "tool_calls": [
            { "id": "call_9f8e7d6c5b4a39281706", "type": "function", "index": 0,
              "function": { "name": "lookup" } },
            { "id": "call_1", "type": "function", "function": { "name": "lookup", "arguments": { "q": "weather" } } },
            { "function": { "name": "n", "arguments": 42 } },
            null,
            {}
        ]
    }));
    assert_eq!(v, json!({ "action": "NONE" }), "{v}");
}

#[test]
fn malformed_requests_are_400s_naming_the_field() {
    let cases = [
        (json!({ "texts": ["x"] }), "bad_input_type"),
        (
            json!({ "texts": ["x"], "input_type": "pre_call" }),
            "bad_input_type",
        ),
        (
            json!({ "texts": ["x", 3], "input_type": "request" }),
            "bad_texts",
        ),
        (
            json!({ "texts": "x", "input_type": "request" }),
            "bad_texts",
        ),
        (
            json!({ "input_type": "request", "tool_calls": {} }),
            "bad_tool_calls",
        ),
        (
            json!({ "input_type": "request", "additional_provider_specific_params": [] }),
            "bad_provider_params",
        ),
    ];
    for (body, code) in cases {
        let (status, v) = call(&body);
        assert_eq!(status, 400, "{body}");
        assert_eq!(v["error"]["code"], code, "{body}");
    }
    let r = handle_request("POST", PATH, "{not json");
    assert_eq!(r.status, 400);
    assert!(r.body.contains("bad_json"));
    let r = handle_request("GET", PATH, "");
    assert_eq!(r.status, 405);
}

#[test]
fn an_oversized_body_is_413() {
    let body = format!(
        r#"{{"input_type":"request","texts":["{}"]}}"#,
        "a".repeat(MAX_BODY)
    );
    let r = handle_request("POST", PATH, &body);
    assert_eq!(r.status, 413);
    assert!(r.body.contains("payload_too_large"));
}

#[test]
fn every_text_is_audited_under_the_litellm_call_id() {
    let records: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let sink = Arc::clone(&records);
    let state = ApiState::default().with_audit_sink(Box::new(move |r| {
        sink.lock()
            .unwrap()
            .push((r.request_id.clone(), format!("{r:?}")));
    }));
    let body = json!({
        "texts": [format!("TCKN {TCKN}"), "hello", "world"],
        "input_type": "request",
        "litellm_call_id": "call-7f3a"
    });
    let r = handle_request_with(&state, "POST", PATH, &body.to_string());
    assert_eq!(r.status, 200);
    let records = records.lock().unwrap();
    assert_eq!(records.len(), 3);
    for (id, debug) in records.iter() {
        assert_eq!(id, "call-7f3a");
        assert!(!debug.contains(TCKN), "{debug}");
    }
}

#[test]
fn the_endpoint_is_listed_on_the_index() {
    let r = handle_request("GET", "/", "");
    assert!(r.body.contains(&format!("POST {PATH}")), "{}", r.body);
}

// ---- real socket: authentication and the body limit ----

fn post(port: u16, path: &str, headers: &[&str], body: &str) -> String {
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    common::send(port, &request)
}

fn guarded_server() -> u16 {
    start(ApiState::default().with_bearer_token(BearerToken::new("s3cr3t-T0ken").unwrap()))
}

#[test]
fn x_api_key_or_bearer_authenticates_the_litellm_call() {
    let port = guarded_server();
    let body = json!({ "texts": [format!("TCKN {TCKN}")], "input_type": "request" }).to_string();

    let r = post(port, PATH, &[], &body);
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    assert!(r.contains(r#""code":"unauthorized""#), "{r}");
    assert!(!r.contains(TCKN), "{r}");

    let r = post(port, PATH, &["x-api-key: wrong"], &body);
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    assert!(r.contains(r#""code":"invalid_token""#), "{r}");

    let r = post(port, PATH, &["x-api-key: a", "x-api-key: b"], &body);
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");

    for header in [
        "x-api-key: s3cr3t-T0ken",
        "Authorization: Bearer s3cr3t-T0ken",
    ] {
        let r = post(port, PATH, &[header], &body);
        assert!(r.starts_with("HTTP/1.1 200"), "{header}: {r}");
        assert!(r.contains("GUARDRAIL_INTERVENED"), "{r}");
        assert!(!r.contains(TCKN), "{r}");
    }

    // an Authorization header takes precedence over x-api-key
    let r = post(
        port,
        PATH,
        &["Authorization: Bearer wrong", "x-api-key: s3cr3t-T0ken"],
        &body,
    );
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
}

#[test]
fn x_api_key_is_not_accepted_on_other_paths() {
    let port = guarded_server();
    let r = post(
        port,
        "/v1/redact",
        &["x-api-key: s3cr3t-T0ken"],
        r#"{"text":"x"}"#,
    );
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
}

#[test]
fn an_oversized_socket_body_is_413_before_it_is_read() {
    let port = start(ApiState::default());
    let request = format!(
        "POST {PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_BODY + 1
    );
    let mut s = common::connect(port);
    s.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    let _ = s.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(response.contains("payload_too_large"), "{response}");
}
