//! redactify-mcp binary: stdio MCP server loop.
//!
//! Reads newline-delimited JSON-RPC 2.0 from stdin, writes one response
//! line per request to stdout (flushed immediately). stderr stays free for
//! diagnostics.
//!
//! Flags:
//! - `--allow-restore`  operator tier: `vault_restore` becomes callable
//!   (agent tier default: refused)
//!
//! Environment:
//! - `REDACTIFY_POLICY` optional TOML policy (fail-closed: a malformed
//!   file, or a value that is not valid Unicode, refuses startup, same
//!   posture as a model-load failure)
//! - `REDACTIFY_AUDIT_FILE` optional path of a hash-chained JSONL audit
//!   file that receives every `tool_check` decision; an existing file is
//!   verified first and resumed (a file that does not verify refuses
//!   startup). `REDACTIFY_AUDIT_KEY` optionally keys the chain
//!   (HMAC-SHA256). A failed write is reported on stderr and the sink
//!   refuses further records (see `redactify::guard::audit`).
//!
//! A panic inside a tool call is answered with a JSON-RPC internal error
//! and the loop keeps serving; stderr gets the panic LOCATION only (the
//! panic message may quote the tool input). A line that is not valid UTF-8
//! is answered with the parse error -32700, a line longer than
//! `redactify_mcp::MAX_LINE` with the server error -32000 (read past
//! without being buffered), and the loop keeps serving.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use redactify::guard::audit::FileAuditSink;
use redactify_mcp::LineRead;

/// The audit sink named by `REDACTIFY_AUDIT_FILE` (keyed by
/// `REDACTIFY_AUDIT_KEY` when set): `None` when the variable is unset.
fn audit_sink_from_env() -> Result<Option<redactify_mcp::AuditCallback>, String> {
    let Some(path) = std::env::var_os("REDACTIFY_AUDIT_FILE") else {
        return Ok(None);
    };
    let key = match std::env::var("REDACTIFY_AUDIT_KEY") {
        Ok(key) if key.is_empty() => return Err("REDACTIFY_AUDIT_KEY is empty".to_owned()),
        Ok(key) => Some(key),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("REDACTIFY_AUDIT_KEY is not valid Unicode".to_owned())
        }
    };
    let sink =
        FileAuditSink::open(&path, key.as_deref().map(str::as_bytes)).map_err(|e| e.to_string())?;
    let sink = Mutex::new(sink);
    Ok(Some(Arc::new(move |record| {
        let mut sink = sink.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(e) = sink.append(record) {
            eprintln!("redactify-mcp: audit write failed: {e}");
        }
    })))
}

fn main() {
    // the default hook prints the panic message, which may quote PII from
    // the tool input: log the source location only
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map_or_else(|| "unknown location".to_owned(), ToString::to_string);
        eprintln!("redactify-mcp: a tool call panicked at {location}");
    }));
    let allow_restore = std::env::args().any(|a| a == "--allow-restore");
    let mut state = redactify_mcp::ServerState {
        allow_restore,
        ..redactify_mcp::ServerState::default()
    };
    // absent = no policy; set but unreadable (not Unicode, IO, malformed)
    // = refuse startup, never "no policy"
    match redactify::policy::config::load_policy_env_if_set() {
        Ok(p) => state.policy = p,
        Err(e) => {
            eprintln!("redactify-mcp: cannot load policy: {e}");
            std::process::exit(1);
        }
    }
    match audit_sink_from_env() {
        Ok(sink) => state.audit_sink = sink,
        Err(e) => {
            eprintln!("redactify-mcp: cannot open the audit file: {e}");
            std::process::exit(1);
        }
    }

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // raw byte lines: one line that is not valid UTF-8 is answered with a
    // parse error instead of ending the loop (a `lines()` read error did);
    // the length bound keeps one newline-free line from growing the buffer
    let mut line = Vec::new();
    loop {
        let reply = match redactify_mcp::read_line_bounded(
            &mut input,
            &mut line,
            redactify_mcp::MAX_LINE,
        ) {
            Ok(LineRead::Eof) | Err(_) => break, // EOF or a broken stdin: shutdown
            Ok(LineRead::TooLong) => Some(redactify_mcp::too_long_reply()),
            Ok(LineRead::Line) => redactify_mcp::handle_line(&state, &line),
        };
        if let Some(reply) = reply {
            if writeln!(out, "{reply}").and_then(|_| out.flush()).is_err() {
                break; // client closed the pipe: shutdown
            }
        }
    }
}
