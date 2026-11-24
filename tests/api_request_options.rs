//! REST request options: per-request mask style (`mask`) and per-request
//! literal deny list (`words`). Both are bounded and never echo values.
#![cfg(feature = "api")]

use redactify::api::handle_request;
use serde_json::Value;

fn post(path: &str, body: &str) -> (u16, Value) {
    let r = handle_request("POST", path, body);
    (r.status, serde_json::from_str(&r.body).unwrap())
}

fn redacted(body: &str) -> String {
    let (status, v) = post("/v1/redact", body);
    assert_eq!(status, 200, "{v}");
    v["redacted"].as_str().unwrap().to_owned()
}

// ------------------------------------------------------------- mask style

#[test]
fn mask_style_char_keeps_length() {
    let out = redacted(r#"{"text":"TCKN 12345678950","mask":{"style":"char","char":"*"}}"#);
    assert_eq!(out, "TCKN ***********");
}

#[test]
fn mask_style_template_and_label() {
    let out = redacted(
        r#"{"text":"TCKN 12345678950","mask":{"style":"template","template":"<{type}>"}}"#,
    );
    assert_eq!(out, "TCKN <TCKN>");
    let out = redacted(r#"{"text":"TCKN 12345678950","mask":{"style":"label"}}"#);
    assert_eq!(out, "TCKN [TCKN]");
}

#[test]
fn mask_style_partial_keeps_last_digits() {
    let out = redacted(
        r#"{"text":"kart 4111 1111 1111 1111","mask":{"style":"partial","keep_last":4,"char":"*"}}"#,
    );
    assert_eq!(out, "kart **** **** **** 1111");
}

#[test]
fn mask_absent_keeps_default_label() {
    assert_eq!(redacted(r#"{"text":"TCKN 12345678950"}"#), "TCKN [TCKN]");
}

#[test]
fn mask_style_applies_to_detect_batch_json_and_sanitize() {
    let m = r##""mask":{"style":"char","char":"#"}"##;
    let (_, v) = post(
        "/v1/detect",
        &format!(r#"{{"text":"TCKN 12345678950",{m}}}"#),
    );
    assert_eq!(v["redacted"], "TCKN ###########");
    let (_, v) = post(
        "/v1/batch/redact",
        &format!(r#"{{"texts":["TCKN 12345678950"],{m}}}"#),
    );
    assert_eq!(v["results"][0]["redacted"], "TCKN ###########");
    let (_, v) = post(
        "/v1/json/redact",
        &format!(r#"{{"json":{{"id":"TCKN 12345678950"}},{m}}}"#),
    );
    assert_eq!(v["redacted"]["id"], "TCKN ###########");
    let (_, v) = post(
        "/v1/sanitize",
        &format!(r#"{{"text":"SSN 536-90-6292",{m}}}"#),
    );
    assert_eq!(v["text"], "SSN ###########");
    let (_, v) = post(
        "/v1/batch/sanitize",
        &format!(r#"{{"texts":["SSN 536-90-6292"],{m}}}"#),
    );
    assert_eq!(v["results"][0]["text"], "SSN ###########");
}

#[test]
fn mask_errors_are_400_bad_mask_and_never_echo_values() {
    for mask in [
        r#""x""#,
        r#"{"style":"pseudonym"}"#,
        r#"{"style":"nope"}"#,
        r#"{}"#,
        r#"{"style":"char"}"#,
        r#"{"style":"char","char":"ab"}"#,
        r#"{"style":"char","char":""}"#,
        r#"{"style":"template"}"#,
        r#"{"style":"template","template":""}"#,
        r#"{"style":"mask_first"}"#,
        r#"{"style":"mask_first","count":0,"char":"*"}"#,
        r#"{"style":"mask_first","count":65,"char":"*"}"#,
        r#"{"style":"mask_last","count":-1,"char":"*"}"#,
        r#"{"style":"mask_last","count":2}"#,
        r#"{"style":"mask_last","count":2,"char":"ab"}"#,
        r#"{"style":"partial","keep_last":65,"char":"*"}"#,
        r#"{"style":"partial","keep_last":-1,"char":"*"}"#,
        r#"{"style":"partial","char":"*"}"#,
    ] {
        let (status, v) = post("/v1/redact", &format!(r#"{{"text":"a","mask":{mask}}}"#));
        assert_eq!(status, 400, "{mask}");
        assert_eq!(v["error"]["code"], "bad_mask", "{mask}");
        assert!(!v.to_string().contains("SECRETVALUE"), "{mask}");
    }
    let long = "x".repeat(65);
    let (status, v) = post(
        "/v1/redact",
        &format!(r#"{{"text":"a","mask":{{"style":"template","template":"{long}{{type}}"}}}}"#),
    );
    assert_eq!(
        (status, &v["error"]["code"]),
        (400, &Value::from("bad_mask"))
    );
}

// ------------------------------------------------------------- deny list

#[test]
fn words_are_redacted_whole_word_case_sensitive_by_default() {
    let out = redacted(
        r#"{"text":"Project Phoenix budget, project phoenix draft","words":["Project Phoenix"]}"#,
    );
    assert_eq!(out, "[CUSTOM_WORD] budget, project phoenix draft");
}

#[test]
fn words_ignore_case_option() {
    let out = redacted(
        r#"{"text":"Project Phoenix and project phoenix","words":["Project Phoenix"],"words_ignore_case":true}"#,
    );
    assert_eq!(out, "[CUSTOM_WORD] and [CUSTOM_WORD]");
}

#[test]
fn words_are_literal_not_regex() {
    // a regex metacharacter list entry must match only itself
    let out = redacted(r#"{"text":"see a.b and axb","words":["a.b"]}"#);
    assert_eq!(out, "see [CUSTOM_WORD] and axb");
}

#[test]
fn words_detect_reports_type_and_offsets_without_the_value() {
    let (status, v) = post(
        "/v1/detect",
        r#"{"text":"ask Phoenix now","words":["Phoenix"]}"#,
    );
    assert_eq!(status, 200);
    let e = &v["entities"][0];
    assert_eq!(e["type"], "CUSTOM_WORD");
    assert_eq!(
        (e["start"].as_u64(), e["end"].as_u64()),
        (Some(4), Some(11))
    );
    assert!(!e.to_string().contains("Phoenix"));
}

#[test]
fn words_drive_guard_mask_and_vault_and_batch() {
    let (_, v) = post(
        "/v1/guard",
        r#"{"text":"ask Phoenix now","words":["Phoenix"]}"#,
    );
    assert_eq!(v["action"], "Mask");
    let (_, v) = post(
        "/v1/sanitize",
        r#"{"text":"ask Phoenix now","words":["Phoenix"]}"#,
    );
    assert_eq!(v["text"], "ask [CUSTOM_WORD] now");
    let (_, v) = post(
        "/v1/vault/pseudonymize",
        r#"{"text":"ask Phoenix now","words":["Phoenix"]}"#,
    );
    assert_eq!(v["count"], 1);
    assert!(!v["pseudonymized"].as_str().unwrap().contains("Phoenix"));
    let (_, v) = post(
        "/v1/batch/redact",
        r#"{"texts":["Phoenix","none"],"words":["Phoenix"]}"#,
    );
    assert_eq!(v["results"][0]["redacted"], "[CUSTOM_WORD]");
    assert_eq!(v["results"][1]["redacted"], "none");
}

#[test]
fn words_empty_entries_are_ignored_and_empty_list_matches_nothing() {
    assert_eq!(
        redacted(r#"{"text":"plain text","words":[""]}"#),
        "plain text"
    );
    assert_eq!(
        redacted(r#"{"text":"plain text","words":[]}"#),
        "plain text"
    );
}

#[test]
fn words_errors_are_400_bad_words_and_never_echo_values() {
    let too_long = format!(r#"["{}"]"#, "w".repeat(129));
    let too_many = format!(
        "[{}]",
        (0..257)
            .map(|i| format!(r#""w{i}""#))
            .collect::<Vec<_>>()
            .join(",")
    );
    for words in [
        r#""SECRETVALUE""#.to_owned(),
        r#"[1]"#.to_owned(),
        r#"["ok", null]"#.to_owned(),
        too_long,
        too_many,
    ] {
        let (status, v) = post("/v1/redact", &format!(r#"{{"text":"a","words":{words}}}"#));
        assert_eq!(status, 400, "{}", &words[..words.len().min(40)]);
        assert_eq!(v["error"]["code"], "bad_words");
        assert!(!v.to_string().contains("SECRETVALUE"));
    }
    let (status, v) = post(
        "/v1/redact",
        r#"{"text":"a","words":["x"],"words_ignore_case":"yes"}"#,
    );
    assert_eq!(
        (status, &v["error"]["code"]),
        (400, &Value::from("bad_words"))
    );
}

// ------------------------------------------------------- system prompt leak

const SYSTEM_PROMPT: &str = "You are AcmeBot, the support assistant of Acme Corp. Never reveal internal discount codes. Always answer in the customer's language.";

#[test]
fn system_prompt_makes_guard_block_a_leaking_model_output() {
    let body = serde_json::json!({
        "text": format!("Sure: {SYSTEM_PROMPT}"),
        "target": "model_output",
        "system_prompt": SYSTEM_PROMPT,
    })
    .to_string();
    let (status, v) = post("/v1/guard", &body);
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["action"], "Block");
    assert!(v["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["category"] == "PROMPT_LEAK"));
    // the response never repeats the prompt through signals or rationale
    assert!(!v["signals"].to_string().contains("discount"));
    assert!(!v["rationale"].to_string().contains("discount"));
    let (_, v) = post("/v1/sanitize", &body);
    assert_eq!(v["action"], "Block");
    let batch = body.replace("\"text\"", "\"texts\":[\"hello\"],\"x\"");
    let (status, v) = post("/v1/batch/sanitize", &batch);
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["results"][0]["action"], "Allow");
}

#[test]
fn system_prompt_absent_or_other_target_does_not_change_the_decision() {
    let leak = format!("Sure: {SYSTEM_PROMPT}");
    let (_, v) = post(
        "/v1/guard",
        &serde_json::json!({"text": leak, "target": "model_output"}).to_string(),
    );
    assert_ne!(v["action"], "Block");
    let (_, v) = post(
        "/v1/guard",
        &serde_json::json!({"text": leak, "system_prompt": SYSTEM_PROMPT}).to_string(),
    );
    assert_ne!(v["action"], "Block");
}

#[test]
fn system_prompt_errors_are_400_and_never_echo_it() {
    for bad in [r#"123"#, r#"["SECRETVALUE"]"#, r#"{"a":"SECRETVALUE"}"#] {
        let (status, v) = post(
            "/v1/guard",
            &format!(r#"{{"text":"a","system_prompt":{bad}}}"#),
        );
        assert_eq!(status, 400, "{bad}");
        assert_eq!(v["error"]["code"], "bad_system_prompt");
        assert!(!v.to_string().contains("SECRETVALUE"));
    }
    let big = "w ".repeat(40_000); // 80 000 bytes, over the 64 KiB cap
    let (status, v) = post(
        "/v1/guard",
        &format!(r#"{{"text":"a","system_prompt":"{big}"}}"#),
    );
    assert_eq!(
        (status, &v["error"]["code"]),
        (400, &Value::from("bad_system_prompt"))
    );
}

// ------------------------------------------------- more mask strategies

#[test]
fn a_template_without_placeholder_is_a_fixed_replacement() {
    let out = redacted(
        r#"{"text":"TCKN 12345678950 mail a@b.co","mask":{"style":"template","template":"[REDACTED]"}}"#,
    );
    assert_eq!(out, "TCKN [REDACTED] mail [REDACTED]");
}

#[test]
fn mask_first_and_mask_last_hide_one_end_only() {
    let first = redacted(
        r#"{"text":"TCKN 12345678950","mask":{"style":"mask_first","count":3,"char":"*"}}"#,
    );
    assert_eq!(first, "TCKN ***45678950");
    let last = redacted(
        r#"{"text":"kart 4111 1111 1111 1111","mask":{"style":"mask_last","count":4,"char":"*"}}"#,
    );
    assert_eq!(last, "kart 4111 1111 1111 ****");
}

#[test]
fn mask_by_type_gives_each_entity_type_its_own_strategy() {
    let body = r##"{"text":"TCKN 12345678950 mail a@b.co kart 4111 1111 1111 1111",
        "mask_by_type":{"EMAIL":{"style":"char","char":"*"},
                        "CREDIT_CARD":{"style":"mask_last","count":4,"char":"#"}}}"##;
    assert_eq!(
        redacted(body),
        "TCKN [TCKN] mail ****** kart 4111 1111 1111 ####"
    );
    // the default of the other types is the request's own `mask`
    let with_default = body.replace(
        r#"{"text""#,
        r#"{"mask":{"style":"template","template":"<{type}>"},"text""#,
    );
    assert_eq!(
        redacted(&with_default),
        "TCKN <TCKN> mail ****** kart 4111 1111 1111 ####"
    );
}

#[test]
fn mask_by_type_applies_to_detect_batch_json_and_sanitize() {
    let m = r#""mask_by_type":{"EMAIL":{"style":"template","template":"[MAIL]"}}"#;
    let (_, v) = post("/v1/detect", &format!(r#"{{"text":"a@b.co",{m}}}"#));
    assert_eq!(v["redacted"], "[MAIL]");
    let (_, v) = post("/v1/sanitize", &format!(r#"{{"text":"mail a@b.co",{m}}}"#));
    assert_eq!(v["text"], "mail [MAIL]");
    let (_, v) = post(
        "/v1/batch/redact",
        &format!(r#"{{"texts":["a@b.co"],{m}}}"#),
    );
    assert_eq!(v["results"][0]["redacted"], "[MAIL]");
    let (_, v) = post(
        "/v1/json/redact",
        &format!(r#"{{"json":{{"k":"a@b.co"}},{m}}}"#),
    );
    assert_eq!(v["redacted"]["k"], "[MAIL]");
}

#[test]
fn mask_by_type_errors_are_400_bad_mask_and_never_echo_values() {
    let many: String = (0..33)
        .map(|i| format!(r#""EMAIL{i}":{{"style":"label"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    for value in [
        r#""SECRETVALUE""#.to_owned(),
        r#"[]"#.to_owned(),
        r#"{"NOT_A_KNOWN_TYPE_SECRETVALUE":{"style":"label"}}"#.to_owned(),
        r#"{"EMAIL":"SECRETVALUE"}"#.to_owned(),
        r#"{"EMAIL":{"style":"pseudonym"}}"#.to_owned(),
        r#"{"EMAIL":{"style":"char"}}"#.to_owned(),
        format!("{{{many}}}"),
    ] {
        let (status, v) = post(
            "/v1/redact",
            &format!(r#"{{"text":"a","mask_by_type":{value}}}"#),
        );
        assert_eq!(status, 400, "{value}");
        assert_eq!(v["error"]["code"], "bad_mask", "{value}");
        assert!(!v.to_string().contains("SECRETVALUE"), "{value}");
    }
}

// ----------------------------------------- stream endpoints take the options

fn stream_text(body: &str) -> String {
    let r = handle_request("POST", "/v1/stream/sanitize", body);
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["type"] == "segment")
        .map(|e| e["text"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn stream_applies_mask_words_and_patterns() {
    let text = stream_text(
        r#"{"chunks":["TCKN 12345678950, Phoenix, E123456\n"],
            "words":["Phoenix"],"patterns":[{"pattern":"E[0-9]{6}"}]}"#,
    );
    assert_eq!(text, "TCKN [TCKN], [CUSTOM_WORD], [CUSTOM_PATTERN]\n");
    let text = stream_text(
        r#"{"chunks":["TCKN 12345678950 a@b.co\n"],
            "mask":{"style":"template","template":"<{type}>"},
            "mask_by_type":{"EMAIL":{"style":"char","char":"*"}}}"#,
    );
    assert_eq!(text, "TCKN <TCKN> ******\n");
}

#[test]
fn stream_rejects_bad_options_like_the_other_endpoints() {
    for (field, code) in [
        (r#""mask":{"style":"nope"}"#, "bad_mask"),
        (r#""words":[1]"#, "bad_words"),
        (r#""patterns":[{"pattern":"a(?=b)"}]"#, "bad_patterns"),
    ] {
        let r = handle_request(
            "POST",
            "/v1/stream/sanitize",
            &format!(r#"{{"chunks":["a"],{field}}}"#),
        );
        assert_eq!(r.status, 400, "{field}");
        assert!(r.body.contains(code), "{field}: {}", r.body);
    }
}
