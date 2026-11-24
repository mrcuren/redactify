//! SSE streaming endpoint acceptance: `POST /v1/stream/sse` over a real
//! tiny_http socket. The response is `text/event-stream` with one
//! `data: {event json}\n\n` frame per guard event; the connection closes
//! after a Block event. Most tests use an HTTP/1.0 client, which gets the
//! frames buffered with a Content-Length (identity-encoded: no chunk-size
//! framing in the raw bytes); the incremental-delivery tests use HTTP/1.1,
//! where every frame is its own chunk written as it is produced.

#![cfg(feature = "api")]

mod common;

use std::io::{Read, Write};

fn sse_request(port: u16, body: &str) -> String {
    let mut stream = common::connect(port);
    let req = format!(
        "POST /v1/stream/sse HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn spawn_server() -> u16 {
    common::start(redactify::api::ApiState::default())
}

#[test]
fn sse_streams_segments_and_masks_pii_and_secrets() {
    let port = spawn_server();
    let body = r#"{"chunks": ["birinci satir TCKN 12345678950\n", "ikinci satir AKIAIOSFODNN7EXAMPLE\n", "ucuncu satir temiz\n"]}"#;
    let response = sse_request(port, body);
    assert!(response.starts_with("HTTP/1.0 200"), "response: {response}");
    assert!(
        response.contains("Content-Type: text/event-stream"),
        "response: {response}"
    );
    assert!(response.contains("Cache-Control: no-cache"));
    // PII masked in the segment frames
    assert!(response.contains("[TCKN]"), "response: {response}");
    // the vendor key BLOCKS the stream at its line and is never echoed
    assert!(
        !response.contains("N7EXAMPLE"),
        "raw key echoed: {response}"
    );
    assert!(
        response.contains("\"type\":\"block\""),
        "vendor key must block: {response}"
    );
    // frames use the SSE data: prefix (json keys are alphabetically ordered
    // by serde_json: entities, text, type)
    assert!(response.contains("data: {\"entities\""));
    // a block terminates the stream: the third (post-block) line never
    // arrives as a segment
    assert!(
        !response.contains("ucuncu"),
        "post-block segment leaked: {response}"
    );
}

#[test]
fn sse_completes_clean_streams_without_block() {
    let port = spawn_server();
    let body = r#"{"chunks": ["temiz satir bir\n", "temiz satir iki\n"]}"#;
    let response = sse_request(port, body);
    assert!(response.starts_with("HTTP/1.0 200"), "response: {response}");
    let segments = response.matches("\"type\":\"segment\"").count();
    assert_eq!(segments, 2, "response: {response}");
    assert!(!response.contains("\"type\":\"block\""));
    // connection closes after the producer finishes (EOF read_to_string)
}

#[test]
fn sse_validates_like_the_ndjson_endpoint() {
    let port = spawn_server();
    // missing chunks -> 400 JSON error (not an event stream)
    let response = sse_request(port, r#"{"text": "no chunks here"}"#);
    assert!(response.starts_with("HTTP/1.0 400"), "response: {response}");
    assert!(response.contains("application/json"));
    assert!(response.contains("missing_field"));
}

#[test]
fn pure_handler_reports_sse_as_socket_only() {
    let r = redactify::api::handle_request("POST", "/v1/stream/sse", r#"{"chunks": ["x\n"]}"#);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("socket_only"), "body: {}", r.body);
}

// -------------------------------------------------- incremental delivery

use common::connect;
use redactify::api::ApiState;
use redactify::{Entity, NerRecognizer};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A gate the test opens to release a parked recognizer.
type Gate = Arc<(Mutex<bool>, Condvar)>;

/// A recognizer that parks on any text containing `WAIT` until the gate
/// opens (at most 10 s), so a test can observe what the client received
/// while the producer is still working. It never reports spans.
struct GateRecognizer {
    gate: Gate,
}

impl NerRecognizer for GateRecognizer {
    fn recognize(&self, text: &str) -> Vec<Entity> {
        if text.contains("WAIT") {
            let (lock, cv) = &*self.gate;
            let open = lock.lock().unwrap();
            let _parked = cv
                .wait_timeout_while(open, Duration::from_secs(10), |open| !*open)
                .unwrap();
        }
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "gate"
    }
}

#[test]
fn sse_writes_each_frame_as_the_guard_produces_it() {
    let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
    let state = ApiState::default().with_ner(Arc::new(GateRecognizer {
        gate: Arc::clone(&gate),
    }));
    let port = common::start(state);
    let mut stream = connect(port);
    let body = r#"{"chunks": ["first line ok\n", "second WAIT line\n"]}"#;
    // HTTP/1.1: frames are streamed (an HTTP/1.0 client gets them buffered)
    let req = format!(
        "POST /v1/stream/sse HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // the producer is parked inside the second line's recognizer call: the
    // first segment must already be on the wire (frames are not computed
    // in full before the first byte is sent)
    let mut received = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&received).contains("first line ok") {
        let n = stream
            .read(&mut buf)
            .expect("the first frame must arrive while the stream is still being produced");
        assert!(n > 0, "connection closed before the first frame");
        received.extend_from_slice(&buf[..n]);
    }
    let early = String::from_utf8_lossy(&received).into_owned();
    assert!(early.starts_with("HTTP/1.1 200"), "{early}");
    assert!(!early.contains("second"), "{early}");

    // release the producer: the rest of the stream follows, then EOF
    {
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    stream.set_read_timeout(None).unwrap();
    stream.read_to_end(&mut received).unwrap();
    let all = String::from_utf8_lossy(&received);
    assert_eq!(all.matches("\"type\":\"segment\"").count(), 2, "{all}");
    assert!(all.contains("second WAIT line"), "{all}");
}

#[test]
fn sse_uses_one_chunk_per_frame_for_http11_clients() {
    let port = spawn_server();
    let mut stream = connect(port);
    let body = r#"{"chunks": ["TCKN 12345678950\n", "temiz satir\n"]}"#;
    let req = format!(
        "POST /v1/stream/sse HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains("Transfer-Encoding: chunked"),
        "{response}"
    );
    assert!(response.contains("Content-Type: text/event-stream"));

    // decode the chunked body: every chunk is exactly one SSE frame, and
    // the zero-length chunk ends the body
    let (_, mut rest) = response.split_once("\r\n\r\n").unwrap();
    let mut frames = Vec::new();
    loop {
        let (size, tail) = rest.split_once("\r\n").expect("chunk size line");
        let size = usize::from_str_radix(size, 16).expect("hex chunk size");
        if size == 0 {
            assert_eq!(tail, "\r\n", "terminating chunk");
            break;
        }
        let (data, tail) = tail.split_at(size);
        assert!(
            data.starts_with("data: {") && data.ends_with("}\n\n"),
            "{data:?}"
        );
        frames.push(data.to_owned());
        rest = tail.strip_prefix("\r\n").expect("chunk CRLF");
    }
    assert_eq!(frames.len(), 2, "{frames:?}");
    assert!(frames[0].contains("TCKN [TCKN]"), "{frames:?}");
    assert!(!response.contains("12345678950"));
}

#[test]
fn sse_block_is_audited_with_the_request_id() {
    let records: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&records);
    let state = ApiState::default().with_audit_sink(Box::new(move |rec| {
        sink.lock().unwrap().push(rec.to_json());
    }));
    let port = common::start(state);
    let response = sse_request(
        port,
        r#"{"chunks": ["guvenli\n", "bkz http://169.254.169.254/meta\n"], "request_id": "sse-1"}"#,
    );
    assert!(response.contains("\"type\":\"block\""), "{response}");
    let recs = records.lock().unwrap().clone();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let rec: serde_json::Value = serde_json::from_str(&recs[0]).unwrap();
    assert_eq!(rec["request_id"], "sse-1");
    assert_eq!(rec["action"], "Block");
    assert_eq!(rec["layer"], "L0+L1");
    assert!(!recs[0].contains("169.254"), "{}", recs[0]);
}

#[test]
fn sse_streams_with_the_attached_recognizer() {
    let state = ApiState::default().with_ner(Arc::new(redactify::MockNameRecognizer::new()));
    let port = common::start(state);
    let response = sse_request(port, r#"{"chunks": ["we met Ahmet Yilmaz today\n"]}"#);
    assert!(response.contains("we met [NAME] today"), "{response}");
    assert!(!response.contains("Ahmet"), "{response}");
}
