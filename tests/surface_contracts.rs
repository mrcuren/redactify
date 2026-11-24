//! Input validation and output contracts of the user-facing surfaces: the
//! CLI binary, the REST server (`api` feature), the TOML policy loader
//! (`config` feature) and the tool-call JSON contract. The wire tables pin
//! outputs byte for byte.

use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_redactify"))
}

/// Runs the CLI and returns (exit code, stdout, stderr).
fn run_cli(args: &[&str]) -> (Option<i32>, String, String) {
    let out = cli().args(args).output().expect("binary runs");
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
        String::from_utf8(out.stderr).expect("utf-8 stderr"),
    )
}

// ------------------------------------------------ CLI --sanitize on Block

#[test]
fn cli_sanitize_block_prints_the_loggable_remask_not_raw_pii() {
    let text = "AKIAIOSFODNN7EXAMPLE TCKN 12345678950";
    let (code, stdout, _) = run_cli(&["--sanitize", text]);
    assert_eq!(code, Some(1), "Block exits 1: {stdout}");
    assert!(stdout.contains("ACTION:      Block"), "{stdout}");
    assert!(
        stdout.contains("[SECRET:AWS_ACCESS_KEY] TCKN [TCKN]"),
        "{stdout}"
    );
    assert!(!stdout.contains("12345678950"), "raw PII printed: {stdout}");

    let (code, stdout, _) = run_cli(&["--sanitize", "--json", text]);
    assert_eq!(code, Some(1), "Block exits 1: {stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON value");
    assert_eq!(v["action"], "Block");
    assert_eq!(v["text"], "[SECRET:AWS_ACCESS_KEY] TCKN [TCKN]");
    assert!(!stdout.contains("12345678950"), "raw PII printed: {stdout}");
}

// ------------------------------------------------------ CLI locale codes

#[test]
fn cli_refuses_unknown_or_miscased_locale_codes() {
    for codes in ["TR", "tr,xx", "En", "tr,EN"] {
        let (code, stdout, stderr) = run_cli(&["--sanitize", "-l", codes, "TCKN 12345678950"]);
        assert_eq!(
            code,
            Some(2),
            "{codes}: stdout {stdout:?} stderr {stderr:?}"
        );
        assert!(stdout.is_empty(), "{codes}: {stdout}");
        assert!(stderr.contains("locale"), "{codes}: {stderr}");
    }
    // spaces around the commas of the list syntax stay accepted
    let (code, stdout, _) = run_cli(&["--sanitize", "-l", "tr, en", "TCKN 12345678950"]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("TCKN [TCKN]"), "{stdout}");
}

// --------------------------------------- non-Unicode REDACTIFY_POLICY (CLI)

/// A value that is not valid Unicode on this platform.
#[cfg(all(feature = "config", any(windows, unix)))]
fn non_unicode_value() -> std::ffi::OsString {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        // an unpaired surrogate cannot be converted to UTF-8
        std::ffi::OsString::from_wide(&[u16::from(b'p'), 0xD800])
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![b'p', 0xFF])
    }
}

#[cfg(all(feature = "config", any(windows, unix)))]
#[test]
fn cli_non_unicode_policy_variable_refuses_to_run() {
    let out = cli()
        .env("REDACTIFY_POLICY", non_unicode_value())
        .args(["--guard", "hello"])
        .output()
        .expect("binary runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("REDACTIFY_POLICY"), "{stderr}");
}

// --------------------------------------------- policy file locale codes

#[cfg(feature = "config")]
#[test]
fn policy_file_locale_codes_are_validated() {
    use redactify::policy::{ConfigError, Policy};
    for bad in ["TR", "tr ", " en", "xx", ""] {
        let toml = format!("schema_version = \"0.2\"\nlocales = [\"tr\", \"{bad}\"]\n");
        let err = Policy::from_toml(&toml).expect_err(&format!("locale {bad:?} must be refused"));
        assert!(err.to_string().contains("locale"), "{bad:?}: {err}");
        assert!(
            matches!(&err, ConfigError::UnknownLocale(code) if code == bad),
            "{bad:?}: {err:?}"
        );
    }
    let p = Policy::from_toml("schema_version = \"0.2\"\nlocales = [\"tr\", \"uk\"]\n").unwrap();
    assert_eq!(p.default_locales, ["tr", "uk"]);
}

// ------------------------------------- ToolCall: one JSON parser (serde)

#[cfg(feature = "serde")]
#[test]
fn tool_call_serde_and_from_json_accept_the_same_shapes() {
    use redactify::guard::tools::ToolCall;
    use serde_json::json;
    let cases = [
        json!({"tool": "x", "args": "y"}),
        json!({"tool": "x", "args": "y", "extra": 1}),
        json!({"tool": "x"}),
        json!({"tool": "x", "args": {"b": [1, {"d": 1, "c": 2}], "a": null}}),
        json!({"tool": "x", "args": null}),
        json!({"tool": "x", "args": 5}),
        json!({"tool": 1}),
        json!({"args": "y"}),
        json!("x"),
        json!([]),
    ];
    for v in cases {
        let from_json = ToolCall::from_json(&v).ok();
        let serde = serde_json::from_value::<ToolCall>(v.clone()).ok();
        assert_eq!(from_json, serde, "{v}");
    }
}

// ----------------------------------------------------------- REST server

#[cfg(feature = "api")]
mod rest {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    use redactify::api::handle_request;
    use serde_json::json;

    const TEXT: &str = "TCKN 12345678950 SSN 536-90-6292";

    /// A unique local port per spawned server: a pid-derived base plus a
    /// per-process counter (the `alloc_port` pattern of `tests/api_sse.rs`).
    /// Binding port 0, releasing it and serving on it later races the other
    /// tests of this binary running in parallel: `serve`'s bind error is
    /// swallowed and `connect` then reaches another listener.
    fn free_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        45_000 + (std::process::id() % 15_000) as u16 + n
    }

    fn spawn_server() -> u16 {
        let port = free_port();
        std::thread::spawn(move || {
            let _ = redactify::api::serve(&format!("127.0.0.1:{port}"));
        });
        port
    }

    fn connect(port: u16) -> TcpStream {
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("server did not come up");
    }

    /// The declared Content-Length of a response head, if any.
    fn content_length(head: &str) -> Option<usize> {
        head.lines().find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
    }

    #[test]
    fn sse_http10_keep_alive_client_gets_a_complete_delimited_response() {
        let port = spawn_server();
        let mut stream = connect(port);
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let body = r#"{"chunks":["TCKN 12345678950 satir\n","ikinci\n"]}"#;
        let req = format!(
            "POST /v1/stream/sse HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(req.as_bytes()).unwrap();
        // read until the head and the declared body are in; a body that only
        // the connection close delimits never completes here, because the
        // server keeps a keep-alive connection open
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let complete = loop {
            let text = String::from_utf8_lossy(&buf).into_owned();
            if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                if content_length(head).is_some_and(|n| rest.len() >= n) {
                    break true;
                }
            }
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break false,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let text = String::from_utf8_lossy(&buf);
        assert!(complete, "response never completed: {text:?}");
        assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        assert!(text.contains("Content-Type: text/event-stream"), "{text}");
        assert!(text.contains("Cache-Control: no-cache"), "{text}");
        assert_eq!(text.matches("data: {").count(), 2, "{text}");
        assert!(text.contains("TCKN [TCKN] satir"), "{text}");
        assert!(!text.contains("12345678950"), "{text}");
    }

    #[test]
    fn unknown_untrimmed_or_mistyped_locales_are_a_400() {
        let cases = [
            ("/v1/redact", json!({"text": TEXT, "locales": ["tr "]})),
            ("/v1/detect", json!({"text": TEXT, "locales": ["TR"]})),
            ("/v1/guard", json!({"text": TEXT, "locales": ["tr", "xx"]})),
            ("/v1/sanitize", json!({"text": TEXT, "locales": ["En"]})),
            (
                "/v1/vault/pseudonymize",
                json!({"text": TEXT, "locales": [""]}),
            ),
            (
                "/v1/stream/sanitize",
                json!({"chunks": [TEXT], "locales": ["TR"]}),
            ),
            ("/v1/redact", json!({"text": TEXT, "locales": "uk"})),
            ("/v1/redact", json!({"text": TEXT, "locales": ["uk", 5]})),
            (
                "/v1/sanitize",
                json!({"text": TEXT, "locales": ["tr", "zz-12345678950"]}),
            ),
        ];
        for (path, body) in cases {
            let r = handle_request("POST", path, &body.to_string());
            assert_eq!(r.status, 400, "{path} {body}: {}", r.body);
            assert!(r.body.contains("bad_locales"), "{path}: {}", r.body);
            assert!(!r.body.contains("12345678950"), "{path}: {}", r.body);
        }
        // supported codes and an absent, null or empty list keep working
        for locales in [json!(["tr", "en"]), json!(null), json!([])] {
            let body = json!({"text": TEXT, "locales": locales}).to_string();
            let r = handle_request("POST", "/v1/redact", &body);
            assert_eq!(r.status, 200, "{locales}: {}", r.body);
            assert!(r.body.contains("TCKN [TCKN] SSN [SSN]"), "{}", r.body);
        }
    }

    #[test]
    fn non_string_target_is_a_400_and_a_bad_target_is_not_echoed() {
        let cases = [
            ("/v1/guard", json!({"text": "x", "target": 5})),
            ("/v1/sanitize", json!({"text": "x", "target": true})),
            (
                "/v1/guard",
                json!({"text": "x", "target": {"kind": "tool"}}),
            ),
            (
                "/v1/stream/sanitize",
                json!({"chunks": ["x"], "target": ["tool"]}),
            ),
            (
                "/v1/sanitize",
                json!({"text": "x", "target": "tckn-12345678950"}),
            ),
        ];
        for (path, body) in cases {
            let r = handle_request("POST", path, &body.to_string());
            assert_eq!(r.status, 400, "{path} {body}: {}", r.body);
            assert!(r.body.contains("bad_target"), "{path}: {}", r.body);
            assert!(!r.body.contains("12345678950"), "{path}: {}", r.body);
            assert!(r.body.contains("user_prompt"), "{path}: {}", r.body);
        }
        // a null target keeps meaning "absent" (user_prompt)
        let r = handle_request("POST", "/v1/guard", r#"{"text":"x","target":null}"#);
        assert_eq!(r.status, 200, "{}", r.body);
    }
    /// Edge requests for `/v1/tool/check` (shared with the MCP table).
    fn tool_check_requests() -> Vec<serde_json::Value> {
        let max = redactify::api::MAX_TOOL_HISTORY;
        let a = json!({"allowed": ["a"]});
        let call = json!({"tool": "a"});
        let mut first_bad = vec![json!(3)];
        first_bad.extend((0..max).map(|_| json!({"tool": "a"})));
        let exactly_max: Vec<serde_json::Value> = (0..max).map(|_| json!({"tool": "a"})).collect();
        vec![
            json!({}),
            json!([]),
            json!({"contract": 5, "call": call}),
            json!({"contract": a}),
            json!({"contract": a, "call": "a"}),
            json!({"contract": {"allowed": ["a"], "global_maxx": 1}, "call": 5}),
            json!({"contract": a, "call": call, "history": null}),
            json!({"contract": a, "call": call, "history": {}}),
            json!({"contract": a, "call": call, "history": "x"}),
            json!({"contract": a, "call": call, "history": [{"tool": "a"}, 3]}),
            json!({"contract": a, "call": call, "history": [{"tool": "a", "extra": 1}]}),
            json!({"contract": a, "call": call, "history": first_bad}),
            json!({"contract": a, "call": call, "history": exactly_max}),
            json!({"contract": {"allowed": ["a"], "denied_arg_patterns": {"a": "("}}, "call": call}),
            json!({
                "contract": a,
                "call": {"tool": "a", "args": {"b": 1, "a": [2, {"d": 0, "c": 1}]}},
                "history": [
                    {"tool": "a", "args": {"a": [2, {"c": 1, "d": 0}], "b": 1}},
                    {"tool": "a", "args": "{\"a\":[2,{\"c\":1,\"d\":0}],\"b\":1}"}
                ]
            }),
            json!({"contract": a, "call": {"tool": "b"}}),
            json!({
                "contract": {"allowed": ["a"], "global_max": 1},
                "history": [{"tool": "a", "args": "1"}],
                "call": {"tool": "a", "args": "2"}
            }),
            json!({"contract": {"allowed": ["abcd"], "token_budget": 0}, "call": {"tool": "abcd"}}),
            json!({"contract": {"allowed": ["a"], "per_tool_max": {"a": 0}}, "call": call}),
            json!({
                "contract": {"allowed": ["a"], "denied_arg_patterns": {"a": "rm"}},
                "call": {"tool": "a", "args": "rm -rf"}
            }),
            json!({"contract": a, "call": call, "history": []}),
            json!({
                "contract": a,
                "call": {"tool": "a", "args": {"q": 1}},
                "history": [{"tool": "a", "args": {"q": 1}}]
            }),
        ]
    }

    /// The pinned status and body of every edge request.
    const TOOL_CHECK_WIRE: &[&str] = &[
        r#"400 {"error":{"code":"missing_field","message":"required object field `contract`"}}"#,
        r#"400 {"error":{"code":"missing_field","message":"required object field `contract`"}}"#,
        r#"400 {"error":{"code":"bad_contract","message":"contract: field `(root)` must be a JSON object"}}"#,
        r#"400 {"error":{"code":"missing_field","message":"required object field `call` {tool, args}"}}"#,
        r#"400 {"error":{"code":"bad_call","message":"call: field `(root)` must be a JSON object"}}"#,
        r#"400 {"error":{"code":"bad_contract","message":"contract: unknown field `global_maxx`"}}"#,
        r#"200 {"code":"ALLOW","verdict":"allow"}"#,
        r#"400 {"error":{"code":"bad_history","message":"`history` must be an array of calls {tool, args}"}}"#,
        r#"400 {"error":{"code":"bad_history","message":"`history` must be an array of calls {tool, args}"}}"#,
        r#"400 {"error":{"code":"bad_call","message":"history[1]: field `(root)` must be a JSON object"}}"#,
        r#"400 {"error":{"code":"bad_call","message":"history[0]: unknown field `extra`"}}"#,
        r#"413 {"error":{"code":"history_too_long","message":"history exceeds the 10000-call limit (10001 given)"}}"#,
        r#"200 {"code":"LOOP","verdict":"deny"}"#,
        r#"400 {"error":{"code":"bad_contract","message":"contract: invalid argument deny pattern for tool `a`"}}"#,
        r#"200 {"code":"LOOP","verdict":"deny"}"#,
        r#"200 {"code":"NOT_ALLOWLISTED","verdict":"deny"}"#,
        r#"200 {"code":"GLOBAL_BUDGET","verdict":"deny"}"#,
        r#"200 {"code":"TOKEN_BUDGET","verdict":"deny"}"#,
        r#"200 {"code":"TOOL_BUDGET","verdict":"deny"}"#,
        r#"200 {"code":"ARG_PATTERN","verdict":"deny"}"#,
        r#"200 {"code":"ALLOW","verdict":"allow"}"#,
        r#"200 {"code":"ALLOW","verdict":"allow"}"#,
    ];

    #[test]
    fn tool_check_wire_outputs_are_pinned() {
        let got: Vec<String> = tool_check_requests()
            .iter()
            .map(|req| {
                let r = handle_request("POST", "/v1/tool/check", &req.to_string());
                format!("{} {}", r.status, r.body)
            })
            .collect();
        assert_eq!(got, TOOL_CHECK_WIRE);
    }

    /// Edge requests for `/v1/vault/restore`.
    fn vault_requests() -> Vec<serde_json::Value> {
        let max = redactify::MAX_VAULT_ENTRIES;
        let valid = |n: usize| -> Vec<serde_json::Value> {
            (0..n)
                .map(|i| json!({"placeholder": format!("X_{i}"), "original": "v"}))
                .collect()
        };
        let mut bad_at_max = valid(max);
        bad_at_max.push(json!({"placeholder": "Y"}));
        let mut bad_after_max = valid(max + 1);
        bad_after_max.push(json!({"placeholder": "Y"}));
        vec![
            json!({"text": "x"}),
            json!({"text": "x", "entries": {}}),
            json!({"text": "x", "entries": null}),
            json!({"entries": []}),
            json!({"text": "[A_1] b", "entries": [{"placeholder": "A_1", "original": "v"}]}),
            json!({"text": "[A_1] b", "entries": [{"placeholder": "[A_1]", "original": "v", "extra": 1}]}),
            json!({"text": "x", "entries": [{"placeholder": "A_1"}]}),
            json!({"text": "x", "entries": [{"placeholder": 1, "original": "v"}]}),
            json!({"text": "x", "entries": [5]}),
            json!({"text": "[X_1]", "entries": valid(max + 1)}),
            json!({"text": "[X_1]", "entries": bad_at_max}),
            json!({"text": "[X_1]", "entries": bad_after_max}),
            json!({"text": "[X_1] [X_9999]", "entries": valid(max)}),
            json!({
                "text": "[A_1][B_1]",
                "entries": [
                    {"placeholder": "A_1", "original": "[B_1]"},
                    {"placeholder": "B_1", "original": "w"},
                    {"placeholder": "[A_1]", "original": "last"}
                ]
            }),
        ]
    }

    /// The pinned status and body of every edge request.
    const VAULT_WIRE: &[&str] = &[
        r#"400 {"error":{"code":"missing_field","message":"required array field `entries` [{placeholder, original}]"}}"#,
        r#"400 {"error":{"code":"missing_field","message":"required array field `entries` [{placeholder, original}]"}}"#,
        r#"400 {"error":{"code":"missing_field","message":"required array field `entries` [{placeholder, original}]"}}"#,
        r#"400 {"error":{"code":"missing_field","message":"required string field `text`"}}"#,
        r#"200 {"restored":"v b"}"#,
        r#"200 {"restored":"v b"}"#,
        r#"400 {"error":{"code":"bad_entries","message":"each entry needs string fields `placeholder` and `original`"}}"#,
        r#"400 {"error":{"code":"bad_entries","message":"each entry needs string fields `placeholder` and `original`"}}"#,
        r#"400 {"error":{"code":"bad_entries","message":"each entry needs string fields `placeholder` and `original`"}}"#,
        r#"413 {"error":{"code":"too_many_entries","message":"vault entries exceed the 10000-entry limit"}}"#,
        r#"400 {"error":{"code":"bad_entries","message":"each entry needs string fields `placeholder` and `original`"}}"#,
        r#"413 {"error":{"code":"too_many_entries","message":"vault entries exceed the 10000-entry limit"}}"#,
        r#"200 {"restored":"v v"}"#,
        r#"200 {"restored":"lastw"}"#,
    ];

    #[test]
    fn vault_restore_wire_outputs_are_pinned() {
        let got: Vec<String> = vault_requests()
            .iter()
            .map(|req| {
                let r = handle_request("POST", "/v1/vault/restore", &req.to_string());
                format!("{} {}", r.status, r.body)
            })
            .collect();
        assert_eq!(got, VAULT_WIRE);
    }
}
