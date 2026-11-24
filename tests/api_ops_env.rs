//! The REST server's environment knobs: `REDACTIFY_AUDIT_FILE` (+
//! `REDACTIFY_AUDIT_KEY`) and `REDACTIFY_MAX_BODY`. Its own test binary
//! with ONE test: it changes process environment that no other test may
//! see concurrently.
#![cfg(all(feature = "api", feature = "config"))]

use std::io::{Read, Write};
use std::net::TcpStream;

use redactify::api::{
    audit_sink_from_env, body_limit_from_env, serve_with, ApiState, AUDIT_FILE_ENV_VAR,
    AUDIT_KEY_ENV_VAR, BODY_LIMIT_ENV_VAR,
};
use redactify::guard::audit::verify_chain;

fn port() -> u16 {
    56_000 + (std::process::id() % 9_000) as u16 + 500
}

fn send(port: u16, path: &str, body: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    out
}

#[test]
fn environment_knobs_of_the_socket_server() {
    // ---- REDACTIFY_MAX_BODY
    std::env::remove_var(BODY_LIMIT_ENV_VAR);
    assert_eq!(body_limit_from_env().unwrap(), None);
    std::env::set_var(BODY_LIMIT_ENV_VAR, "4096");
    assert_eq!(body_limit_from_env().unwrap(), Some(4096));
    for bad in ["", "1k", "-1", "100", "16777217"] {
        std::env::set_var(BODY_LIMIT_ENV_VAR, bad);
        let e = body_limit_from_env().unwrap_err();
        assert!(e.to_string().contains(BODY_LIMIT_ENV_VAR), "{bad:?}: {e}");
        // the server refuses to start on it
        assert!(serve_with("127.0.0.1:0", ApiState::default()).is_err());
    }
    std::env::remove_var(BODY_LIMIT_ENV_VAR);

    // ---- REDACTIFY_AUDIT_FILE / REDACTIFY_AUDIT_KEY
    let path =
        std::env::temp_dir().join(format!("redactify-api-audit-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::env::remove_var(AUDIT_FILE_ENV_VAR);
    assert!(audit_sink_from_env().unwrap().is_none());
    std::env::set_var(AUDIT_FILE_ENV_VAR, &path);
    std::env::set_var(AUDIT_KEY_ENV_VAR, "");
    assert!(audit_sink_from_env().is_err(), "an empty key refuses");
    let key = "an audit key from the secret store";
    std::env::set_var(AUDIT_KEY_ENV_VAR, key);

    // the socket server records every decision in the file
    let port = port();
    std::thread::spawn(move || {
        let _ = serve_with(&format!("127.0.0.1:{port}"), ApiState::default());
    });
    let mut up = false;
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(up, "server did not come up");
    let r = send(
        port,
        "/v1/sanitize",
        r#"{"text":"TCKN 12345678950","request_id":"env-1"}"#,
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let r = send(port, "/v1/guard", r#"{"text":"key AKIAIOSFODNN7EXAMPLE"}"#);
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let r = send(
        port,
        "/v1/tool/check",
        r#"{"contract":{"allowed":["search"]},"call":{"tool":"shell","args":"x"}}"#,
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let log = std::fs::read_to_string(&path).expect("audit file");
    assert_eq!(
        verify_chain(log.lines(), Some(key.as_bytes())),
        Ok(3),
        "{log}"
    );
    assert!(log.contains("\"request_id\":\"env-1\""));
    assert!(!log.contains("12345678950") && !log.contains("AKIAIOSFODNN7EXAMPLE"));

    // a file that does not verify refuses startup (here: the wrong mode)
    std::env::remove_var(AUDIT_KEY_ENV_VAR);
    let e = serve_with("127.0.0.1:0", ApiState::default()).unwrap_err();
    assert!(e.to_string().contains(AUDIT_FILE_ENV_VAR), "{e}");
    // and so does an edited one
    std::env::set_var(AUDIT_KEY_ENV_VAR, key);
    std::fs::write(&path, log.replacen("env-1", "env-2", 1)).unwrap();
    assert!(audit_sink_from_env().is_err());
    std::env::remove_var(AUDIT_FILE_ENV_VAR);
    std::env::remove_var(AUDIT_KEY_ENV_VAR);
    let _ = std::fs::remove_file(&path);
}
