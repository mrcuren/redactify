//! Fuzz target: the pure REST handler never panics, answers with a status
//! from its documented set and always returns a JSON body (NDJSON for a
//! successful buffered stream). Two bodies per input: the raw input bytes
//! (malformed JSON, wrong shapes) and a well-formed request built from the
//! input text with option fields switched on by the first byte, so the
//! endpoint logic itself is reached on every run.
//!
//! Build/run: `cargo +nightly fuzz run api`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::api::{handle_request, ApiResponse};

const PATHS: [&str; 15] = [
    "/v1/detect",
    "/v1/redact",
    "/v1/json/redact",
    "/v1/guard",
    "/v1/sanitize",
    "/v1/batch/detect",
    "/v1/batch/redact",
    "/v1/batch/sanitize",
    "/v1/stream/sanitize",
    "/v1/stream/sse",
    "/v1/vault/pseudonymize",
    "/v1/vault/restore",
    "/v1/tool/check",
    "/health",
    "/",
];

fn check(path: &str, r: &ApiResponse) {
    assert!(
        matches!(r.status, 200 | 400 | 404 | 405 | 413),
        "{path}: status {}",
        r.status
    );
    if r.status == 200 && path == "/v1/stream/sanitize" {
        for line in r.body.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("NDJSON line is JSON");
        }
    } else {
        serde_json::from_str::<serde_json::Value>(&r.body).expect("body is JSON");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let path = PATHS[usize::from(flags) % PATHS.len()];
    let text = String::from_utf8_lossy(rest);

    // 1. the raw bytes as the body
    check(path, &handle_request("POST", path, &text));
    check(path, &handle_request("GET", path, &text));

    // 2. a well-formed request around the text
    let mut req = serde_json::json!({
        "text": text,
        "texts": [text, "TCKN 12345678950"],
        "json": {"note": text, "list": [text, 12345678950_u64]},
        "chunks": [text, "\n"],
        "entries": [{"placeholder": "TCKN_1", "original": text}],
    });
    if flags & 0x10 != 0 {
        req["locales"] = serde_json::json!(redactify::SUPPORTED_LOCALES);
    }
    if flags & 0x20 != 0 {
        req["context"] = serde_json::json!([text]);
        req["ignore"] = serde_json::json!([text]);
    }
    if flags & 0x40 != 0 {
        req["target"] = serde_json::json!("tool_response");
        req["explain"] = serde_json::json!(true);
        req["numeric_leaves"] = serde_json::json!(true);
    }
    if flags & 0x80 != 0 {
        req["threshold"] = serde_json::json!(0.9);
        req["request_id"] = serde_json::json!("fuzz-1");
    }
    let r = handle_request("POST", path, &req.to_string());
    check(path, &r);
});
