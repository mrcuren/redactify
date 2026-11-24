//! End-to-end: spawn the real binary, speak the initialize-based MCP stdio
//! protocol over its pipes, and read the replies - the loop, framing and
//! flush behavior, not just the dispatcher.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: BufReader<ChildStdout>,
}

impl Server {
    fn spawn(extra_args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_redactify-mcp"))
            .args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn redactify-mcp");
        let stdin = child.stdin.take().expect("stdin pipe");
        let stdout = child.stdout.take().expect("stdout pipe");
        Self {
            child,
            stdin: Some(stdin),
            reader: BufReader::new(stdout),
        }
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        writeln!(stdin, "{line}").expect("write request");
        stdin.flush().expect("flush request");
    }

    /// Reads one reply line (blocks; the loop under test must flush).
    fn recv(&mut self) -> String {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read reply");
        assert!(!line.is_empty(), "server closed early");
        line.trim().to_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stdin.take(); // close the pipe: the server loop exits at EOF
        let _ = self.child.wait();
    }
}

#[test]
fn stdio_handshake_tools_and_tier_isolation() {
    let mut server = Server::spawn(&[]);

    // initialize handshake (legacy era, verified shapes)
    server.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0.0.1"}}}"#);
    let init = server.recv();
    assert!(
        init.contains("\"protocolVersion\":\"2025-06-18\""),
        "{init}"
    );
    assert!(init.contains("redactify-mcp"), "{init}");

    // initialized notification: no response allowed (the next reply must
    // belong to the request after it)
    server.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    server.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    let list = server.recv();
    assert!(list.contains("\"id\":2"), "{list}");
    assert!(list.contains("vault_pseudonymize"), "{list}");

    // a guard call through the pipes: masked text only
    server.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"guard","arguments":{"text":"AKIAIOSFODNN7EXAMPLE ve TCKN 12345678950"}}}"#);
    let guard = server.recv();
    assert!(guard.contains("\"action\":\"Block\""), "{guard}");
    assert!(guard.contains("[SECRET:AWS_ACCESS_KEY]"), "{guard}");
    assert!(!guard.contains("N7EXAMPLE"), "{guard}");
    assert!(!guard.contains("12345678950"), "{guard}");
    // MCP spec: content[].text must be a JSON
    // STRING - parse the frame and assert the type, not just containment
    let v: serde_json::Value = serde_json::from_str(&guard).expect("valid JSON-RPC frame");
    let content = v["result"]["content"].as_array().expect("content array");
    assert!(!content.is_empty());
    for item in content {
        assert!(item["text"].is_string(), "text must be a string: {item}");
    }
    assert!(v["result"]["structuredContent"].is_object());

    // agent tier: restore refused
    server.send(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"vault_restore","arguments":{"text":"[TCKN_1] x","entries":[]}}}"#);
    let denied = server.recv();
    assert!(denied.contains("\"isError\":true"), "{denied}");
}

#[test]
fn tool_check_locales_and_size_limit_over_the_pipes() {
    let mut server = Server::spawn(&[]);

    // tools/call BEFORE initialize: tolerated (stateless dispatcher)
    server.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool_check","arguments":{"contract":{"allowed":["search"]},"call":{"tool":"shell","args":{"cmd":"cat /etc/passwd"}}}}}"#);
    let verdict = server.recv();
    let v: serde_json::Value = serde_json::from_str(&verdict).expect("valid frame");
    assert_eq!(
        v["result"]["structuredContent"],
        serde_json::json!({"verdict": "deny", "code": "NOT_ALLOWLISTED"}),
        "{verdict}"
    );
    assert!(!verdict.contains("passwd"), "arguments echoed: {verdict}");

    // six tools listed
    server.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    let list: serde_json::Value = serde_json::from_str(&server.recv()).unwrap();
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 6);

    // locales reach the guard
    server.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"guard","arguments":{"text":"nhs 9434765870","locales":["uk"]}}}"#);
    let guard: serde_json::Value = serde_json::from_str(&server.recv()).unwrap();
    assert_eq!(
        guard["result"]["structuredContent"]["masked_text"],
        "nhs [UK_NHS]"
    );

    // an oversized text reports the size limit
    let big = "x".repeat(redactify_mcp::MAX_TEXT + 1);
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "redact", "arguments": {"text": big}}
    })
    .to_string();
    server.send(&line);
    let limited: serde_json::Value = serde_json::from_str(&server.recv()).unwrap();
    assert_eq!(limited["result"]["isError"], true);
    assert!(limited["result"]["structuredContent"]["error"]
        .as_str()
        .unwrap()
        .contains("byte limit"));
}

#[test]
fn operator_tier_restores() {
    let mut server = Server::spawn(&["--allow-restore"]);
    server.send(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    assert!(server.recv().contains("\"result\":{}"));
    server.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_restore","arguments":{"text":"[TCKN_1] burada","entries":[{"placeholder":"[TCKN_1]","original":"12345678950"}]}}}"#);
    let restored = server.recv();
    assert!(restored.contains("12345678950"), "{restored}");
    assert!(restored.contains("\"isError\":false"), "{restored}");
}

impl Server {
    /// Writes raw bytes plus a newline (for non-UTF-8 lines).
    fn send_bytes(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin.write_all(bytes).expect("write request");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush request");
    }
}

#[test]
fn non_utf8_line_is_a_parse_error_and_the_server_keeps_serving() {
    let mut server = Server::spawn(&[]);
    server.send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\x80\xff\"}");
    let reply: serde_json::Value = serde_json::from_str(&server.recv()).expect("valid frame");
    assert_eq!(reply["error"]["code"], -32700, "{reply}");
    assert!(reply["id"].is_null(), "{reply}");
    // the loop keeps serving the next line
    server.send(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
    let pong = server.recv();
    assert!(
        pong.contains("\"id\":2") && pong.contains("\"result\":{}"),
        "{pong}"
    );
}

/// A value that is not valid Unicode on this platform.
#[cfg(any(windows, unix))]
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

#[cfg(any(windows, unix))]
#[test]
fn non_unicode_policy_variable_refuses_startup() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_redactify-mcp"))
        .env("REDACTIFY_POLICY", non_unicode_value())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn redactify-mcp");
    // a server that treated the variable as unset would answer this ping
    let mut stdin = child.stdin.take().expect("stdin pipe");
    let _ = writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#);
    let _ = stdin.flush();
    drop(stdin);
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout {stdout:?} stderr {stderr:?}"
    );
    assert!(stdout.is_empty(), "served without its policy: {stdout}");
    assert!(stderr.contains("REDACTIFY_POLICY"), "{stderr}");
}
