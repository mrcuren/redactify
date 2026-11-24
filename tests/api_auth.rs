//! REST bearer-token authentication (RFC 6750) over a real localhost
//! socket. Its own test binary: the environment-variable test changes
//! process state that the socket tests of `tests/api_http.rs` must not see.
#![cfg(feature = "api")]

mod common;

use common::send;
use redactify::api::{
    bearer_token_from_env, ApiState, BearerToken, BearerTokenError, API_TOKEN_ENV_VAR,
};

/// Starts a server that requires `token` and waits for its listener.
fn start(token: &str) -> u16 {
    common::start(ApiState::default().with_bearer_token(BearerToken::new(token).expect("token")))
}

/// A `/v1/redact` request with the given extra header lines.
fn redact_request(headers: &[&str]) -> String {
    let body = r#"{"text":"TCKN 12345678950"}"#;
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    format!(
        "POST /v1/redact HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The value of the `WWW-Authenticate` response header, if any.
fn challenge(response: &str) -> Option<&str> {
    response.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.eq_ignore_ascii_case("www-authenticate")
            .then(|| value.trim())
    })
}

#[test]
fn a_request_without_credentials_gets_a_bearer_challenge() {
    let port = start("s3cr3t-T0ken");
    let r = send(port, &redact_request(&[]));
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    // RFC 6750 section 3: no error code when the request lacks credentials
    assert_eq!(challenge(&r), Some(r#"Bearer realm="redactify""#), "{r}");
    assert!(r.contains(r#""code":"unauthorized""#), "{r}");
    assert!(!r.contains("12345678950"), "{r}");
}

#[test]
fn an_unsupported_scheme_is_treated_as_missing_credentials() {
    let port = start("s3cr3t-T0ken");
    let r = send(port, &redact_request(&["Authorization: Basic czNjcjN0"]));
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    assert_eq!(challenge(&r), Some(r#"Bearer realm="redactify""#), "{r}");
}

#[test]
fn a_wrong_token_gets_an_invalid_token_challenge() {
    let port = start("s3cr3t-T0ken");
    for header in [
        "Authorization: Bearer wrong-token",
        "Authorization: Bearer s3cr3t-T0ke",
        "Authorization: Bearer s3cr3t-T0ken2",
        "Authorization: Bearer not a token",
    ] {
        let r = send(port, &redact_request(&[header]));
        assert!(r.starts_with("HTTP/1.1 401"), "{header}: {r}");
        assert_eq!(
            challenge(&r),
            Some(r#"Bearer realm="redactify", error="invalid_token""#),
            "{header}: {r}"
        );
    }
}

#[test]
fn the_configured_token_is_accepted_with_a_case_insensitive_scheme() {
    let port = start("s3cr3t-T0ken");
    // RFC 9110 section 11.1: the scheme is a case-insensitive token;
    // RFC 6750 section 2.1: `credentials = "Bearer" 1*SP b64token`
    for header in [
        "Authorization: Bearer s3cr3t-T0ken",
        "Authorization: bearer s3cr3t-T0ken",
        "Authorization: BEARER  s3cr3t-T0ken",
    ] {
        let r = send(port, &redact_request(&[header]));
        assert!(r.starts_with("HTTP/1.1 200"), "{header}: {r}");
        assert!(r.contains(r#""redacted":"TCKN [TCKN]""#), "{header}: {r}");
    }
}

#[test]
fn two_authorization_headers_are_an_invalid_request() {
    let port = start("s3cr3t-T0ken");
    let r = send(
        port,
        &redact_request(&[
            "Authorization: Bearer s3cr3t-T0ken",
            "Authorization: Bearer s3cr3t-T0ken",
        ]),
    );
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    assert_eq!(
        challenge(&r),
        Some(r#"Bearer realm="redactify", error="invalid_request""#),
        "{r}"
    );
}

#[test]
fn health_stays_open_and_every_other_path_is_protected() {
    let port = start("s3cr3t-T0ken");
    let r = send(
        port,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    for path in ["/", "/v1/stream/sse", "/v1/batch/redact", "/nope"] {
        let r = send(
            port,
            &format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"),
        );
        assert!(r.starts_with("HTTP/1.1 401"), "{path}: {r}");
    }
}

#[test]
fn token_syntax_follows_the_rfc6750_b64token_rule() {
    // the RFC 6750 section 2.1 example token, and trailing `=` padding
    for ok in ["mF_9.B5f-4.1JqM", "abc==", "A-Z.a_z~0+9/"] {
        assert!(BearerToken::new(ok).is_ok(), "{ok}");
    }
    for bad in ["", "two words", "ab=c", "=abc", "t\u{f6}ken", "tab\there"] {
        assert_eq!(
            BearerToken::new(bad).err(),
            Some(BearerTokenError::InvalidSyntax),
            "{bad:?}"
        );
    }
}

#[test]
fn debug_output_never_shows_the_token() {
    let token = BearerToken::new("s3cr3t-T0ken").expect("token");
    assert!(!format!("{token:?}").contains("s3cr3t"));
    let state = ApiState::default().with_bearer_token(token);
    let shown = format!("{state:?}");
    assert!(!shown.contains("s3cr3t"), "{shown}");
    assert!(shown.contains("bearer_token: true"), "{shown}");
}

#[test]
fn the_environment_variable_supplies_the_token() {
    std::env::set_var(API_TOKEN_ENV_VAR, "env-T0ken");
    let from_env = bearer_token_from_env();
    std::env::set_var(API_TOKEN_ENV_VAR, "");
    let empty = bearer_token_from_env();
    std::env::remove_var(API_TOKEN_ENV_VAR);
    let unset = bearer_token_from_env();
    assert_eq!(
        from_env,
        Ok(Some(BearerToken::new("env-T0ken").expect("token")))
    );
    assert_eq!(empty, Err(BearerTokenError::InvalidSyntax));
    assert_eq!(unset, Ok(None));
}

#[test]
fn the_openapi_document_requires_the_token_like_every_other_endpoint() {
    let port = start("s3cr3t-T0ken");
    let r = send(
        port,
        "GET /openapi.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    let r = send(
        port,
        "GET /openapi.json HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer s3cr3t-T0ken\r\nConnection: close\r\n\r\n",
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.contains("\"openapi\""), "{r}");
    // the liveness probe stays open
    let r = send(
        port,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
}
