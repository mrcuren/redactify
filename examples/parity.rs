//! Differential parity runner.
//!
//! Input: a JSONL file where each line is `{"text": "..."}`. Output: one
//! `{"in": <text>, "out": <redact(text)>}` JSONL line per input (UTF-8, unescaped).
//! The reference side emits the same format; the two outputs are `diff`ed.
//!
//! ```text
//! cargo run --release --example parity inputs.jsonl > rust_out.jsonl
//! ```

use std::io::{BufRead, Write};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: parity <input.jsonl>");
    let file = std::fs::File::open(&path).expect("input file opens");
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in std::io::BufReader::new(file).lines() {
        let line = line.expect("line reads");
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON line");
        let text = v["text"].as_str().expect("text field");
        // Target JSON shape: {"in": "...", "out": "..."}
        let in_json = serde_json::to_string(text).expect("in serializes");
        let out_json = serde_json::to_string(&redactify::redact(text)).expect("out serializes");
        writeln!(out, "{{\"in\": {in_json}, \"out\": {out_json}}}").expect("writes");
    }
}
