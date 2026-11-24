//! Server-held tool-call sessions and the audit of tool decisions.
//!
//! The claims:
//! - every `tool_check` decision, on the REST endpoint and the MCP tool,
//!   writes exactly one record to the audit sink, the records chain and
//!   verify, and no record carries an argument value;
//! - in session mode the server holds the history: a caller cannot reset a
//!   budget or the loop check by omitting or shortening it, nor swap in a
//!   looser contract;
//! - a session decides every call exactly like the stateless check over
//!   the history of the calls it allowed;
//! - the table is bounded: session count, calls per session, idle expiry
//!   and remembered ended ids.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use proptest::prelude::*;
use redactify::guard::audit::{verify_chain, ChainedAuditSink};
use redactify::guard::tools::{
    check, check_json_with, SessionLimits, ToolCall, ToolCheckError, ToolContract, ToolSessions,
};
use serde_json::{json, Value};

/// An in-memory hash chain shared with a sink closure.
fn chain() -> Arc<Mutex<ChainedAuditSink<Vec<u8>>>> {
    Arc::new(Mutex::new(ChainedAuditSink::new(Vec::new())))
}

fn log_of(chain: &Arc<Mutex<ChainedAuditSink<Vec<u8>>>>) -> String {
    let sink = std::mem::replace(
        &mut *chain.lock().unwrap(),
        ChainedAuditSink::new(Vec::new()),
    );
    String::from_utf8(sink.into_log()).unwrap()
}

/// Requests covering every outcome: allow, each deny code, stateless and
/// session mode. Each argument value holds `ARGVAL` so the audit log can
/// be searched for it.
fn requests() -> Vec<Value> {
    let contract = json!({
        "allowed": ["search", "fetch"],
        "global_max": 4,
        "per_tool_max": {"fetch": 1},
        "repeat_tolerance": 2,
        "denied_arg_patterns": {"search": "DROP"},
        "egress_allowlist": ["api.example.com"]
    });
    let call = |tool: &str, args: Value| json!({"tool": tool, "args": args});
    vec![
        // stateless
        json!({"contract": contract, "call": call("search", json!({"q": "ARGVAL-1"}))}),
        json!({"contract": contract, "call": call("shell", json!("ARGVAL-2 rm -rf"))}),
        json!({"contract": contract, "call": call("search", json!("ARGVAL-3 DROP"))}),
        json!({"contract": contract, "call": call("fetch", json!({"url": "https://evil.example/?d=ARGVAL-4"}))}),
        // session mode
        json!({"contract": contract, "session_id": "s-1", "call": call("search", json!({"q": "ARGVAL-5"}))}),
        json!({"contract": contract, "session_id": "s-1", "call": call("search", json!({"q": "ARGVAL-5"}))}),
        json!({"contract": contract, "session_id": "s-1", "call": call("search", json!({"q": "ARGVAL-5"}))}),
        json!({"contract": contract, "session_id": "s-1", "call": call("fetch", json!({"url": "https://api.example.com/ARGVAL-6"}))}),
        json!({"contract": contract, "session_id": "s-1", "call": call("fetch", json!({"url": "https://api.example.com/ARGVAL-7"}))}),
        json!({"contract": contract, "session_id": "s-1", "call": call("search", json!({"q": "ARGVAL-8"}))}),
        json!({"contract": contract, "session_id": "s-1", "call": call("search", json!({"q": "ARGVAL-10"}))}),
        json!({"contract": {"allowed": ["search"]}, "session_id": "s-1", "call": call("search", json!({"q": "ARGVAL-9"}))}),
    ]
}

/// The verdict code each request of [`requests`] gets, in order.
const EXPECTED_CODES: &[&str] = &[
    "ALLOW",
    "NOT_ALLOWLISTED",
    "ARG_PATTERN",
    "EGRESS_HOST",
    "ALLOW",
    "ALLOW",
    "LOOP",
    "ALLOW",
    "TOOL_BUDGET",
    "ALLOW",
    "GLOBAL_BUDGET",
    "CONTRACT_MISMATCH",
];

/// Checks the audit log of [`requests`]: one verified record per
/// decision, codes in order, the session id where one was named, the same
/// policy hash for the same contract, and no argument value anywhere.
fn assert_audit_log(log: &str, codes: &[String]) {
    assert_eq!(
        verify_chain(log.lines(), None),
        Ok(EXPECTED_CODES.len() as u64),
        "{log}"
    );
    assert_eq!(codes, EXPECTED_CODES);
    assert!(
        !log.contains("ARGVAL"),
        "argument value in the audit log: {log}"
    );
    assert!(!log.contains("evil.example"), "{log}");
    let records: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    for (i, r) in records.iter().enumerate() {
        let t = &r["tool"];
        assert_eq!(r["layer"], "TOOL", "{r}");
        assert_eq!(r["guard"], "TOOL_CALL", "{r}");
        assert_eq!(t["code"], EXPECTED_CODES[i], "{r}");
        assert_eq!(t["engine_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(t["policy_hash"].as_str().unwrap().len(), 64);
        let action = if EXPECTED_CODES[i] == "ALLOW" {
            "Allow"
        } else {
            "Block"
        };
        assert_eq!(r["action"], action, "{r}");
        assert_eq!(t["session_id"].is_string(), i >= 4, "{r}");
    }
    // the name of a tool outside the allowlist is model text: left out
    assert!(records[1]["tool"]["tool"].is_null());
    assert_eq!(records[0]["tool"]["tool"], "search");
    // one contract, one hash; another contract, another hash
    assert_eq!(
        records[0]["tool"]["policy_hash"],
        records[10]["tool"]["policy_hash"]
    );
    assert_ne!(
        records[0]["tool"]["policy_hash"],
        records[11]["tool"]["policy_hash"]
    );
    // the session counts come from the server: the loop record saw 2 repeats
    assert_eq!(records[6]["tool"]["repeats"], 2);
    assert_eq!(records[10]["tool"]["calls"], 4);
}

#[cfg(feature = "api")]
#[test]
fn every_rest_tool_decision_is_in_the_verified_audit_chain() {
    use redactify::api::{handle_request_with, ApiState};
    let chain = chain();
    let sink = Arc::clone(&chain);
    let state = ApiState::default().with_audit_sink(Box::new(move |record| {
        sink.lock().unwrap().append(record).unwrap();
    }));
    let mut codes = Vec::new();
    for r in requests() {
        let resp = handle_request_with(&state, "POST", "/v1/tool/check", &r.to_string());
        assert_eq!(resp.status, 200, "{}", resp.body);
        assert!(!resp.body.contains("ARGVAL"), "{}", resp.body);
        let v: Value = serde_json::from_str(&resp.body).unwrap();
        codes.push(v["code"].as_str().unwrap().to_owned());
    }
    assert_audit_log(&log_of(&chain), &codes);
    // a request refused with a 4xx makes no decision and no record
    let bad = handle_request_with(
        &state,
        "POST",
        "/v1/tool/check",
        r#"{"contract":{"allowed":[]},"call":{"tool":"a"},"session_id":"s-2","history":[]}"#,
    );
    assert_eq!(bad.status, 400);
    assert!(bad.body.contains("history_not_allowed"), "{}", bad.body);
    let bad_id = handle_request_with(
        &state,
        "POST",
        "/v1/tool/check",
        r#"{"contract":{"allowed":[]},"call":{"tool":"a"},"session_id":""}"#,
    );
    assert_eq!(bad_id.status, 400);
    assert!(bad_id.body.contains("bad_session_id"), "{}", bad_id.body);
    assert_eq!(log_of(&chain), "");
}

#[test]
fn every_library_tool_decision_is_in_the_verified_audit_chain() {
    // the entry point the REST endpoint and the MCP tool share (the MCP
    // crate's own tests cover its JSON-RPC wiring and sink)
    let chain = chain();
    let sessions = ToolSessions::default();
    let mut codes = Vec::new();
    for (i, r) in requests().iter().enumerate() {
        let outcome = check_json_with(&sessions, r).unwrap();
        chain
            .lock()
            .unwrap()
            .append(&outcome.audit_record(format!("mcp-{i}")))
            .unwrap();
        codes.push(outcome.verdict.code().to_owned());
    }
    assert_audit_log(&log_of(&chain), &codes);
}

#[test]
fn audit_records_never_hold_argument_text() {
    proptest!(ProptestConfig::with_cases(256), |(arg in "Q[a-zA-Z0-9 ]{6,40}", tool in "zz[a-z]{3,6}")| {
        let sessions = ToolSessions::default();
        let request = json!({
            "contract": {"allowed": ["search"]},
            "session_id": "p",
            "call": {"tool": tool, "args": {"q": arg}}
        });
        let outcome = check_json_with(&sessions, &request).unwrap();
        let line = outcome.audit_record("r").to_json();
        prop_assert!(!line.contains(&arg), "{}", line);
        if tool != "search" {
            prop_assert!(!line.contains(&format!("\"{tool}\"")), "{}", line);
        }
    });
}

#[cfg(feature = "api")]
#[test]
fn a_caller_cannot_reset_its_budget_by_omitting_history() {
    use redactify::api::{handle_request_with, ApiState};
    let state = ApiState::default();
    let body = |session: Option<&str>, q: &str| {
        let mut v = json!({
            "contract": {"allowed": ["search"], "global_max": 2},
            "call": {"tool": "search", "args": {"q": q}}
        });
        if let Some(id) = session {
            v["session_id"] = json!(id);
        }
        v.to_string()
    };
    let code = |b: String| -> String {
        let r = handle_request_with(&state, "POST", "/v1/tool/check", &b);
        assert_eq!(r.status, 200, "{}", r.body);
        serde_json::from_str::<Value>(&r.body).unwrap()["code"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // the stateless mode trusts the caller: dropping the history resets
    // the budget (this is the gap the session mode closes)
    for q in ["a", "b", "c", "d"] {
        assert_eq!(code(body(None, q)), "ALLOW");
    }
    // session mode: the third call is over the budget although the caller
    // never sent a history, and it stays over the budget
    assert_eq!(code(body(Some("run-1"), "a")), "ALLOW");
    assert_eq!(code(body(Some("run-1"), "b")), "ALLOW");
    assert_eq!(code(body(Some("run-1"), "c")), "GLOBAL_BUDGET");
    assert_eq!(code(body(Some("run-1"), "d")), "GLOBAL_BUDGET");
    // sending an (empty, shortened) history is refused, not honored
    let mut v: Value = serde_json::from_str(&body(Some("run-1"), "e")).unwrap();
    v["history"] = json!([]);
    let r = handle_request_with(&state, "POST", "/v1/tool/check", &v.to_string());
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(r.body.contains("history_not_allowed"), "{}", r.body);
    // a looser contract cannot be swapped in
    let mut v: Value = serde_json::from_str(&body(Some("run-1"), "f")).unwrap();
    v["contract"]["global_max"] = json!(100);
    let r = handle_request_with(&state, "POST", "/v1/tool/check", &v.to_string());
    assert!(r.body.contains("CONTRACT_MISMATCH"), "{}", r.body);
    // the same contract with its allowlist in another order is the same policy
    let mut v: Value = serde_json::from_str(&body(Some("run-1"), "g")).unwrap();
    v["contract"]["allowed"] = json!(["search", "search"]);
    let r = handle_request_with(&state, "POST", "/v1/tool/check", &v.to_string());
    assert!(r.body.contains("GLOBAL_BUDGET"), "{}", r.body);
}

#[test]
fn library_session_mode_holds_the_history() {
    let state = ToolSessions::default();
    let call = |id: u32, q: &str, history: Option<Value>| {
        let mut args = json!({
            "contract": {"allowed": ["search"], "repeat_tolerance": 1},
            "session_id": "mcp-run",
            "call": {"tool": "search", "args": {"q": q}}
        });
        if let Some(h) = history {
            args["history"] = h;
        }
        check_json_with(&state, &args)
            .map(|o| o.verdict.code())
            .map_err(|e| (id, e))
    };
    assert_eq!(call(1, "x", None).ok(), Some("ALLOW"));
    assert_eq!(call(2, "x", None).ok(), Some("LOOP"));
    assert!(matches!(
        call(3, "x", Some(json!([]))),
        Err((3, ToolCheckError::HistoryInSession))
    ));
}

// ---------------------------------------------- session == stateless

fn call_strategy() -> impl Strategy<Value = ToolCall> {
    (0..4usize, 0..4usize).prop_map(|(t, a)| {
        let tool = ["search", "fetch", "calc", "shell"][t];
        ToolCall::new(tool, format!("args-{a}"))
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// A session decides every call like `check` over the calls it
    /// allowed so far (the stateless contract a caller with an honest,
    /// complete history gets).
    #[test]
    fn session_equals_check_over_its_allowed_history(
        calls in prop::collection::vec(call_strategy(), 1..40),
        global in prop::option::of(0..12usize),
        tokens in prop::option::of(0..60usize),
        per_tool in prop::option::of(0..4usize),
        tolerance in 0..4usize,
    ) {
        let mut contract = ToolContract::new(&["search", "fetch", "calc"])
            .with_repeat_tolerance(tolerance)
            .with_denied_arg_pattern("calc", "args-3")
            .unwrap();
        if let Some(g) = global { contract = contract.with_global_max(g); }
        if let Some(t) = tokens { contract = contract.with_token_budget(t); }
        if let Some(p) = per_tool { contract = contract.with_tool_max("fetch", p); }
        let sessions = ToolSessions::default();
        let mut allowed: Vec<ToolCall> = Vec::new();
        for call in &calls {
            let want = check(&contract, &allowed, call);
            let got = sessions.check("prop", &contract, call).unwrap();
            prop_assert_eq!(&got.verdict, &want, "{:?} after {:?}", call, allowed);
            if want.is_allow() {
                allowed.push(call.clone());
            }
        }
    }
}

// --------------------------------------------------------- limits

#[test]
fn session_limits_are_enforced() {
    let limits = SessionLimits {
        max_sessions: 2,
        max_calls_per_session: 3,
        idle_timeout: Duration::from_secs(60),
        max_ended_ids: 2,
    };
    let sessions = ToolSessions::new(limits);
    let contract = ToolContract::new(&["t"]).with_repeat_tolerance(100);
    let call = ToolCall::new("t", "x");
    let t0 = Instant::now();
    let at = |s: u64| t0 + Duration::from_secs(s);
    let code = |id: &str, now: Instant| {
        sessions
            .check_at(id, &contract, &call, now)
            .unwrap()
            .verdict
            .code()
    };

    // calls per session: the fourth call is refused, never recorded over
    for _ in 0..3 {
        assert_eq!(code("a", at(0)), "ALLOW");
    }
    assert_eq!(code("a", at(1)), "SESSION_LIMIT");
    // session count: a third live session is refused, live ones are kept
    assert_eq!(code("b", at(1)), "ALLOW");
    assert_eq!(code("c", at(2)), "SESSION_LIMIT");
    assert_eq!(sessions.len(), 2);
    // idle expiry: after the timeout `a` is expired on use, its id refused
    assert_eq!(code("a", at(100)), "SESSION_EXPIRED");
    assert_eq!(code("a", at(101)), "SESSION_EXPIRED");
    // `a` left room for `c`; with the table full again, room for `d` is
    // made only by sweeping idle sessions: `b` (idle since 1) goes
    assert_eq!(code("c", at(102)), "ALLOW");
    assert_eq!(code("d", at(102)), "ALLOW");
    assert_eq!(sessions.len(), 2);
    assert_eq!(code("b", at(103)), "SESSION_EXPIRED");
    // explicit end
    assert!(sessions.end("c"));
    assert_eq!(code("c", at(104)), "SESSION_EXPIRED");
    // the ended-id memory is a bounded FIFO (2): `a` and `b` were pushed
    // out by `c`, so `a` may start over
    assert_eq!(code("a", at(105)), "ALLOW");
    // bad ids are an error, not a verdict
    assert!(matches!(
        sessions.check_at("", &contract, &call, at(106)),
        Err(ToolCheckError::InvalidSessionId)
    ));
    assert!(matches!(
        sessions.check_at(&"x".repeat(129), &contract, &call, at(106)),
        Err(ToolCheckError::InvalidSessionId)
    ));
    assert!(matches!(
        sessions.check_at("tab\tid", &contract, &call, at(106)),
        Err(ToolCheckError::InvalidSessionId)
    ));
    // Debug never prints session ids
    let shown = format!("{sessions:?}");
    assert!(!shown.contains("\"a\""), "{shown}");
}

#[test]
fn the_session_table_is_shared_across_threads() {
    let sessions = Arc::new(ToolSessions::default());
    let contract = Arc::new(ToolContract::new(&["t"]).with_global_max(100));
    let handles: Vec<_> = (0..4)
        .map(|w| {
            let sessions = Arc::clone(&sessions);
            let contract = Arc::clone(&contract);
            std::thread::spawn(move || {
                let mut allowed = 0;
                for i in 0..50 {
                    let call = ToolCall::new("t", format!("{w}-{i}"));
                    if sessions
                        .check("shared", &contract, &call)
                        .unwrap()
                        .verdict
                        .is_allow()
                    {
                        allowed += 1;
                    }
                }
                allowed
            })
        })
        .collect();
    let allowed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    // 200 distinct calls against a budget of 100: exactly 100 pass
    assert_eq!(allowed, 100);
}

// ------------------------------------------------- measurements

/// Resident set size of this process in KiB (Linux `/proc/self/status`).
#[cfg(target_os = "linux")]
fn rss_kib() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// Memory per session, measured as resident-set growth (run alone, in
/// release: `cargo test --release --test tool_sessions -- --ignored
/// --nocapture measure_memory`).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "measurement: prints numbers, run alone in release"]
fn measure_memory_per_session() {
    let contract = ToolContract::new(&["search", "fetch", "calc"]);
    for calls in [0usize, 1, 16, 256, 1024, 4096] {
        let sessions = ToolSessions::new(SessionLimits {
            max_sessions: 1024,
            max_calls_per_session: 4096,
            ..SessionLimits::default()
        });
        let before = rss_kib();
        for s in 0..1024 {
            let id = format!("session-{s:04}");
            if calls == 0 {
                // a session with one denied call: started, nothing recorded
                let _ = sessions.check(&id, &contract, &ToolCall::new("shell", ""));
            }
            for c in 0..calls {
                let tool = ["search", "fetch", "calc"][c % 3];
                let call = ToolCall::new(tool, format!("{{\"q\":{c}}}"));
                let _ = sessions.check(&id, &contract, &call);
            }
        }
        let after = rss_kib();
        println!(
            "1024 sessions x {calls} distinct calls: {} KiB RSS growth, {:.0} bytes/session",
            after.saturating_sub(before),
            (after.saturating_sub(before) * 1024) as f64 / 1024.0
        );
        drop(sessions);
    }
}

/// Per-check latency: stateless (empty and 1000-call history), session
/// mode, and the egress scan (run alone, in release).
#[test]
#[ignore = "measurement: prints numbers, run alone in release"]
fn measure_check_latency() {
    use redactify::guard::egress::EgressAllowlist;
    const N: u32 = 20_000;
    let contract = ToolContract::new(&["search"]).with_global_max(1_000_000);
    let egress = contract
        .clone()
        .with_egress_allowlist(EgressAllowlist::new(["api.example.com"]).unwrap());
    let args = r#"{"q":"weather in Ankara","url":"https://api.example.com/v1/search?q=x"}"#;
    let call = ToolCall::new("search", args);
    let history: Vec<ToolCall> = (0..1000)
        .map(|i| ToolCall::new("search", format!("{{\"q\":{i}}}")))
        .collect();
    let time = |label: &str, f: &mut dyn FnMut(u32)| {
        let start = Instant::now();
        for i in 0..N {
            f(i);
        }
        println!(
            "{label}: {:.2} us/check",
            start.elapsed().as_secs_f64() * 1e6 / f64::from(N)
        );
    };
    time("stateless, empty history", &mut |_| {
        std::hint::black_box(check(&contract, &[], &call));
    });
    time("stateless, 1000-call history", &mut |_| {
        std::hint::black_box(check(&contract, &history, &call));
    });
    time("stateless + egress allowlist", &mut |_| {
        std::hint::black_box(check(&egress, &[], &call));
    });
    let sessions = ToolSessions::new(SessionLimits {
        max_calls_per_session: N as usize + 1,
        ..SessionLimits::default()
    });
    time("session mode (distinct calls)", &mut |i| {
        let c = ToolCall::new("search", format!("{{\"q\":{i}}}"));
        std::hint::black_box(sessions.check("bench", &contract, &c).unwrap());
    });
    time("session mode + egress allowlist", &mut |i| {
        let c = ToolCall::new(
            "search",
            format!("{{\"q\":{i},\"url\":\"https://api.example.com/x\"}}"),
        );
        std::hint::black_box(sessions.check("bench-egress", &egress, &c).unwrap());
    });
    time("policy hash alone", &mut |_| {
        std::hint::black_box(contract.policy_hash());
    });
}

#[cfg(feature = "api")]
#[test]
fn openapi_documents_the_session_id_bound() {
    let r = redactify::api::handle_request("GET", "/openapi.json", "");
    let spec: Value = serde_json::from_str(&r.body).unwrap();
    let schema = &spec["paths"]["/v1/tool/check"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"]["session_id"];
    assert_eq!(
        schema["maxLength"],
        redactify::guard::tools::MAX_SESSION_ID_LEN,
        "{spec}"
    );
}
