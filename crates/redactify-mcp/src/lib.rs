//! MCP (Model Context Protocol) server surface for
//! [redactify](https://github.com/mrcuren/redactify): PII detection,
//! redaction, guardrails, the reversible vault and the agent tool-call
//! guard as agent tools over newline-delimited JSON-RPC 2.0 on stdio.
//!
//! Protocol shapes follow the initialize-based ("legacy", `2025-11-25` and
//! earlier) MCP revisions verified against the specification
//! (2025-06-18 lifecycle/tools pages, fetched 2026-10-10): `initialize`
//! handshake with version echo-or-latest, `notifications/initialized` (no
//! response), `ping`, `tools/list`, `tools/call`. The message dispatcher is
//! a pure function ([`handle_message`]); the binary is a thin stdio loop -
//! everything is testable without sockets.
//!
//! The dispatcher is stateless: it does not track the lifecycle, so a
//! `tools/call` that arrives before `initialize` is answered like any other
//! (tolerated - the specification asks clients not to send it, and nothing
//! in a tool call depends on the negotiated version).
//!
//! # Tier isolation (agent tier vs operator tier)
//!
//! Tool outputs are what the MODEL sees, so they are shaped for it:
//! - `detect` reports span metadata ONLY (type/offsets/score) - raw values
//!   never enter the model context.
//! - `redact` and `guard` return MASKED text only (redact-before-return
//!   ordering is structural: there is no code path that returns the raw
//!   input; a `guard` Block returns the loggable re-mask).
//! - `vault_pseudonymize` returns ONLY the pseudonymized text - the
//!   placeholder->original mapping never transits the model context.
//! - `vault_restore` is OPERATOR-ONLY: without `--allow-restore` the
//!   call fails with `isError` (an agent must not be able to reverse its
//!   own pseudonymization by asking the server).
//! - `tool_check` returns the verdict and its stable code, never the
//!   checked call's arguments. With a `session_id` argument the server
//!   holds the call history ([`ServerState::tool_sessions`]): budgets and
//!   loop detection do not depend on the caller sending it, and a call
//!   that also sends `history` is refused. Every decision is written to
//!   the audit sink when one is attached ([`ServerState::audit_sink`]; the
//!   binary attaches a hash-chained file from `REDACTIFY_AUDIT_FILE`).
//!
//! The operations use the same library builders as the REST API: detection
//! and redaction run the `Detector` with the effective locales (the call's
//! `locales`, else the policy's default locales, else tr+en) and the
//! normalization pass on; `redact` masks leaked credentials first, then
//! PII; `guard` runs the `Guard` (policy + effective locales). The text
//! tools accept an optional `context` array (the text the call's text
//! answers): its cues unlock cue-gated identifiers, as on the REST API.
//!
//! Argument errors never echo the offending value. A `locales` entry that
//! is not one of `redactify::SUPPORTED_LOCALES` (compared exactly: no
//! trimming, no case folding) is the JSON-RPC error -32602 (an unknown code
//! would select no pack and switch detection off); a `guard` `target` that
//! is not a target name (or not a string) is a tool error (`isError`).
//!
//! A panic inside a tool is contained: the call is answered with the
//! JSON-RPC error -32603 (the panic message is never echoed) and the server
//! keeps serving.
//!
//! # Examples
//! ```
//! let state = redactify_mcp::ServerState::default();
//! let reply = redactify_mcp::handle_message(
//!     &state,
//!     r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"redact","arguments":{"text":"TCKN 12345678950"}}}"#,
//! )
//! .unwrap();
//! assert!(reply.contains("[TCKN]"), "{reply}");
//! assert!(!reply.contains("12345678950"), "raw PII echoed: {reply}");
//! ```

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use redactify::guard::audit::AuditRecord;
use redactify::guard::tools::{check_json_with, ToolCheckError, ToolSessions};
use redactify::policy::{GuardAction, GuardTarget, Policy};
use redactify::{Detector, Guard};

/// Legacy-era protocol versions this server speaks (initialize-based; the
/// current spec calls this "legacy" and requires dual-era servers to keep
/// serving it). If the client requests one of these, it is echoed back.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];

/// The version replied when the client asks for something we do not speak
/// (spec: respond with another supported version - ours is the 2025-06-18
/// revision whose lifecycle/tools shapes this server was built against).
pub const LATEST_SUPPORTED_VERSION: &str = "2025-06-18";

/// Audit callback: receives the metadata-only record of every `tool_check`
/// decision (wrap it around a `redactify::guard::audit::ChainedAuditSink`
/// or `FileAuditSink` for the tamper-evident chain).
pub type AuditCallback = Arc<dyn Fn(&AuditRecord) + Send + Sync>;

/// Server state: the policy applied to guard decisions, the operator-tier
/// switch for vault restore, the tool-call session table and the audit
/// sink.
#[derive(Clone, Default)]
pub struct ServerState {
    /// Optional policy override (e.g. a TOML pack loaded from
    /// `REDACTIFY_POLICY`); `None` = the built-in per-target defaults. Its
    /// default locales apply to every call that names no locales.
    pub policy: Option<Policy>,
    /// Operator tier: `vault_restore` refuses with `isError` unless
    /// this is set (the binary sets it from `--allow-restore`).
    pub allow_restore: bool,
    /// Server-held sessions of `tool_check` calls that name a
    /// `session_id` (default: an empty table with the default limits).
    pub tool_sessions: Arc<ToolSessions>,
    /// Receives the audit record of every `tool_check` decision (`None` =
    /// no audit).
    pub audit_sink: Option<AuditCallback>,
}

/// Presence only for the sink (a closure is not `Debug`).
impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("policy", &self.policy)
            .field("allow_restore", &self.allow_restore)
            .field("tool_sessions", &self.tool_sessions)
            .field("audit_sink", &self.audit_sink.is_some())
            .finish()
    }
}

impl ServerState {
    /// Attaches the audit sink (builder style).
    #[must_use]
    pub fn with_audit_sink(mut self, sink: AuditCallback) -> Self {
        self.audit_sink = Some(sink);
        self
    }
}

/// Per-process counter behind the request ids of `tool_check` audit
/// records (`mcp-1`, `mcp-2`, ...).
static NEXT_AUDIT_ID: AtomicU64 = AtomicU64::new(1);

/// Handles one stdio line (a JSON-RPC 2.0 message) and returns the line to
/// send back, or `None` for notifications (and unknown notifications, per
/// the spec) where no response is allowed.
#[must_use]
pub fn handle_message(state: &ServerState, line: &str) -> Option<String> {
    let msg: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            return Some(error_response(
                serde_json::Value::Null,
                -32700,
                "parse error",
            ))
        }
    };
    let id = msg.get("id").cloned();
    let Some(method) = msg.get("method").and_then(serde_json::Value::as_str) else {
        return id.map(|id| error_response(id, -32600, "invalid request: missing method"));
    };
    // notifications (no id): nothing to send, including unknown ones
    let id = id?;
    let result = match method {
        "initialize" => initialize_result(&msg),
        "ping" => serde_json::json!({}),
        "tools/list" => tools_list_result(),
        "tools/call" => return Some(tool_call(state, id, &msg)),
        other => {
            return Some(error_response(
                id,
                -32601,
                &format!("method not found: {other}"),
            ))
        }
    };
    Some(format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}"
    ))
}

/// Handles one raw stdio line (the bytes between two newlines) the way the
/// binary's loop does: surrounding whitespace is ignored and a blank line
/// answers nothing. A line that is not valid UTF-8 is not JSON text ("JSON
/// text exchanged between systems that are not part of a closed ecosystem
/// MUST be encoded using UTF-8", RFC 8259 section 8.1,
/// <https://www.rfc-editor.org/rfc/rfc8259#section-8.1>), so it gets the
/// answer of any other unparsable line: the parse error -32700 (JSON-RPC
/// 2.0 specification section 5.1) with a `null` id (section 5: the id
/// "MUST be Null" when it could not be detected;
/// <https://www.jsonrpc.org/specification>; both retrieved 2026-10-30), and
/// the loop keeps serving.
///
/// # Examples
/// ```
/// let state = redactify_mcp::ServerState::default();
/// let reply = redactify_mcp::handle_line(&state, b"\xff\xfe not utf-8").unwrap();
/// assert!(reply.contains("-32700") && reply.contains("\"id\":null"), "{reply}");
/// assert!(redactify_mcp::handle_line(&state, b"  \r").is_none());
/// ```
#[must_use]
pub fn handle_line(state: &ServerState, line: &[u8]) -> Option<String> {
    let Ok(line) = std::str::from_utf8(line) else {
        return Some(error_response(
            serde_json::Value::Null,
            -32700,
            "parse error",
        ));
    };
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    handle_message(state, trimmed)
}

/// Maximum accepted stdio line, in bytes (newline excluded). A
/// [`MAX_TEXT`] text must always fit: JSON writes a control character as
/// `\u00XX` (RFC 8259 section 7,
/// <https://www.rfc-editor.org/rfc/rfc8259#section-7>), six bytes for one,
/// so the text alone may take `6 * MAX_TEXT`; 2 MiB more holds the
/// envelope and the other arguments. Without this bound one line without a
/// newline grew the read buffer without limit before any check ran.
pub const MAX_LINE: usize = 6 * MAX_TEXT + 2 * 1_048_576;

/// The outcome of one [`read_line_bounded`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineRead {
    /// The input is exhausted; the buffer is empty.
    Eof,
    /// The buffer holds one line, with its newline unless it ended the
    /// input.
    Line,
    /// The line was longer than the limit: it was consumed up to and
    /// including its newline (or the end of the input) without being
    /// stored, and the buffer is empty.
    TooLong,
}

/// Reads one newline-terminated line into `buf` (cleared first), keeping at
/// most `max` bytes before the newline. A longer line is skipped chunk by
/// chunk, so memory stays within `max` plus the reader's own buffer, and
/// the next call reads the line after it.
///
/// # Errors
/// Any read error other than [`std::io::ErrorKind::Interrupted`] (retried).
///
/// # Examples
/// ```
/// use redactify_mcp::{read_line_bounded, LineRead};
/// let mut input = std::io::Cursor::new(b"0123456789\n{}\n".to_vec());
/// let mut buf = Vec::new();
/// assert_eq!(read_line_bounded(&mut input, &mut buf, 4).unwrap(), LineRead::TooLong);
/// assert_eq!(read_line_bounded(&mut input, &mut buf, 4).unwrap(), LineRead::Line);
/// assert_eq!(buf, b"{}\n");
/// assert_eq!(read_line_bounded(&mut input, &mut buf, 4).unwrap(), LineRead::Eof);
/// ```
pub fn read_line_bounded<R: std::io::BufRead + ?Sized>(
    input: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    buf.clear();
    let mut too_long = false;
    loop {
        let available = match input.fill_buf() {
            Ok(available) => available,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(match (too_long, buf.is_empty()) {
                (true, _) => LineRead::TooLong,
                (false, true) => LineRead::Eof,
                (false, false) => LineRead::Line,
            });
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let chunk = newline.map_or(available, |i| &available[..=i]);
        let used = chunk.len();
        if !too_long {
            let content = buf.len() + used - usize::from(newline.is_some());
            if content > max {
                too_long = true;
                *buf = Vec::new(); // release what the line already took
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        input.consume(used);
        if newline.is_some() {
            return Ok(if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
    }
}

/// The answer to a line longer than [`MAX_LINE`]: its id was never read,
/// so it is `null` (JSON-RPC 2.0 section 5), and the code is from the range
/// section 5.1 reserves for implementation-defined server errors
/// (-32000 to -32099; <https://www.jsonrpc.org/specification>, retrieved
/// 2026-10-30): the line was refused unread, not found invalid.
#[must_use]
pub fn too_long_reply() -> String {
    error_response(
        serde_json::Value::Null,
        -32000,
        &format!("request refused: the line exceeds the {MAX_LINE}-byte limit"),
    )
}

fn initialize_result(msg: &serde_json::Value) -> serde_json::Value {
    let requested = msg
        .pointer("/params/protocolVersion")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
        requested
    } else {
        LATEST_SUPPORTED_VERSION
    };
    serde_json::json!({
        "protocolVersion": version,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": "redactify-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "PII guardrail tools. redact/guard return masked text; detect returns span metadata only; vault_pseudonymize returns pseudonymized text only; vault_restore is operator-only; tool_check returns an allow/deny verdict for an agent tool call (arguments are never echoed)."
    })
}

fn tools_list_result() -> serde_json::Value {
    serde_json::json!({ "tools": tool_specs() })
}

fn tool_specs() -> serde_json::Value {
    let locales = serde_json::json!({
        "type": "array",
        "items": { "type": "string", "enum": redactify::SUPPORTED_LOCALES },
        "description": "locale packs (e.g. [\"uk\",\"de\"]); default: the policy's default locales, else tr+en; an unknown code is an invalid-params error"
    });
    let threshold = serde_json::json!({
        "type": "number",
        "description": "minimum score (0.0-1.0), applied inside overlap resolution"
    });
    let ignore = serde_json::json!({
        "type": "array",
        "items": { "type": "string" },
        "description": "allowlisted values: an exact match (also in fullwidth or zero-width-scattered form) is not reported"
    });
    let context = serde_json::json!({
        "type": "array",
        "items": { "type": "string" },
        "description": "the text this text answers (e.g. the previous conversation turn): a cue in it unlocks cue-gated identifiers that stand alone in the text; never echoed"
    });
    let call = serde_json::json!({
        "type": "object",
        "properties": {
            "tool": { "type": "string" },
            "args": { "description": "the call's arguments: a string (taken verbatim) or any JSON value (canonicalized)" }
        },
        "required": ["tool"]
    });
    serde_json::json!([
        {
            "name": "detect",
            "description": "Detect PII spans (checksum-validated where math exists). Returns span metadata only (type, byte offsets, score); raw values are never returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "text to scan" },
                    "locales": locales,
                    "threshold": threshold,
                    "ignore": ignore,
                    "context": context
                },
                "required": ["text"]
            }
        },
        {
            "name": "redact",
            "description": "Mask leaked credentials ([SECRET:VENDOR]) and redact PII (typed [TYPE] placeholders). Returns the masked text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "locales": locales,
                    "threshold": threshold,
                    "ignore": ignore,
                    "context": context
                },
                "required": ["text"]
            }
        },
        {
            "name": "guard",
            "description": "Full guardrail decision (injection/secrets/PII policy) plus the MASKED text. Check decision.action before forwarding anything: Block means do not use the input.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "target": { "type": "string", "description": "guard target: user_prompt (default), tool_response or model_output (aliases: user, prompt, tool, tool-response, model, model-output)" },
                    "locales": locales,
                    "ignore": ignore,
                    "context": context
                },
                "required": ["text"]
            }
        },
        {
            "name": "vault_pseudonymize",
            "description": "Reversibly pseudonymize PII into typed placeholders ([TCKN_1], ...). Agent tier: returns ONLY the pseudonymized text. Operator tier (--allow-restore): also returns the placeholder->original entries so the document can be restored later.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "locales": locales,
                    "ignore": ignore,
                    "context": context
                },
                "required": ["text"]
            }
        },
        {
            "name": "vault_restore",
            "description": "OPERATOR ONLY: restore placeholders using a caller-supplied mapping. Refused unless the server runs with --allow-restore. The placeholder may be written with or without its brackets ([TCKN_1] or TCKN_1).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "entries": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "placeholder": { "type": "string" },
                                "original": { "type": "string" }
                            },
                            "required": ["placeholder", "original"]
                        }
                    }
                },
                "required": ["text", "entries"]
            }
        },
        {
            "name": "tool_check",
            "description": "Check one agent tool call against a contract (deny-by-default allowlist, call budgets, loop detection, argument deny patterns, egress URL allowlist) and the call history. With session_id the server holds the history (do not send history). Returns {verdict: allow|deny, code}; the arguments are never echoed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract": {
                        "type": "object",
                        "description": "{allowed: [tool, ...], global_max?, token_budget?, per_tool_max?: {tool: n}, repeat_tolerance?, denied_arg_patterns?: {tool: regex}, egress_allowlist?: [host or *.domain, ...]}"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "server-held session (1 to 128 printable ASCII characters): the server keeps the history and binds the session to the contract of its first call"
                    },
                    "history": {
                        "type": "array",
                        "items": call,
                        "description": "earlier calls, oldest first (at most 10000)"
                    },
                    "call": call
                },
                "required": ["contract", "call"]
            }
        }
    ])
}

fn tool_call(state: &ServerState, id: serde_json::Value, msg: &serde_json::Value) -> String {
    let name = msg
        .pointer("/params/name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    // borrowed, not cloned: the arguments hold the whole text
    let no_args = serde_json::Value::Object(serde_json::Map::new());
    let args = msg.pointer("/params/arguments").unwrap_or(&no_args);
    // a panic inside a tool must not take the server down: answer this call
    // with an internal error (the panic payload may quote input text, so it
    // is never echoed) and keep serving
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(state, name, args)));
    let (structured, is_error) = match outcome {
        Ok(Some(Ok(v))) => (v, false),
        Ok(Some(Err(ToolError::Execution(message)))) => {
            (serde_json::json!({ "error": message }), true)
        }
        // invalid arguments are a protocol error: the 2025-06-18 tools page,
        // "Error Handling", lists "Invalid arguments" under "Protocol
        // Errors: Standard JSON-RPC errors"; -32602 is JSON-RPC "Invalid
        // params" (https://modelcontextprotocol.io/specification/2025-06-18/server/tools,
        // retrieved 2026-10-30)
        Ok(Some(Err(ToolError::InvalidParams(message)))) => {
            return error_response(id, -32602, &message)
        }
        // protocol error per the spec's tools example
        Ok(None) => return error_response(id, -32602, &format!("Unknown tool: {name}")),
        Err(_) => return error_response(id, -32603, "internal error: the tool call failed"),
    };
    // structured content is mirrored as text (spec SHOULD). The text
    // field MUST be a JSON string: every MCP client expects a string, so
    // the Value is serialized and then quoted, never interpolated raw
    let text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".into());
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}],\"structuredContent\":{},\"isError\":{}}}}}",
        serde_json::to_string(&text).unwrap_or_else(|_| String::new()),
        structured,
        is_error
    )
}

/// Runs the named tool; `None` for an unknown tool name.
fn dispatch(state: &ServerState, name: &str, args: &serde_json::Value) -> Option<ToolResult> {
    Some(match name {
        "detect" => tool_detect(state, args),
        "redact" => tool_redact(state, args),
        "guard" => tool_guard(state, args),
        "vault_pseudonymize" => tool_vault_pseudonymize(state, args),
        "vault_restore" => tool_vault_restore(state, args),
        "tool_check" => tool_check(state, args),
        // test-only hook: proves the panic isolation of `tool_call`
        #[cfg(test)]
        "__panic_for_test" => panic!("test panic carrying input text: {args}"),
        _ => return None,
    })
}

/// Why a tool call failed.
enum ToolError {
    /// A tool execution error: answered as a result with `isError: true`.
    Execution(String),
    /// Invalid arguments: answered with the JSON-RPC error -32602.
    InvalidParams(String),
}

impl From<String> for ToolError {
    fn from(message: String) -> Self {
        Self::Execution(message)
    }
}

/// A tool's result: the structured output, or why the call failed.
type ToolResult = Result<serde_json::Value, ToolError>;

/// Maximum accepted `text` size per tool call: the same 1 MiB contract as
/// the REST API's `MAX_BODY`, so a single call cannot feed unbounded
/// memory/CPU into the scanners.
pub const MAX_TEXT: usize = 1_048_576;
/// Maximum accepted `entries` array length for `vault_restore` (the
/// library's [`redactify::MAX_VAULT_ENTRIES`]).
pub const MAX_ENTRIES: usize = redactify::MAX_VAULT_ENTRIES;
/// Maximum accepted `history` length for `tool_check` (the tool guard's
/// own bound, the same one the REST `/v1/tool/check` endpoint applies).
pub use redactify::guard::tools::MAX_TOOL_HISTORY;

/// The `text` argument (required string, at most [`MAX_TEXT`] bytes).
fn arg_text(args: &serde_json::Value) -> Result<&str, String> {
    let text = args
        .get("text")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing required string argument `text`".to_owned())?;
    if text.len() > MAX_TEXT {
        return Err(format!(
            "text exceeds the {MAX_TEXT}-byte limit ({} bytes given)",
            text.len()
        ));
    }
    Ok(text)
}

/// The optional `locales` argument (empty when absent, `null` or empty:
/// the policy default, else tr+en). Every entry must be a string from
/// [`redactify::SUPPORTED_LOCALES`], compared exactly (an unknown code
/// would select no pack and switch detection off); anything else is an
/// invalid-params error that names the position, never the value.
fn arg_locales(args: &serde_json::Value) -> Result<Vec<&str>, ToolError> {
    let supported = || redactify::SUPPORTED_LOCALES.join(", ");
    let codes = match args.get("locales") {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(serde_json::Value::Array(codes)) => codes,
        Some(_) => {
            return Err(ToolError::InvalidParams(format!(
                "invalid params: `locales` must be an array of locale codes ({})",
                supported()
            )))
        }
    };
    codes
        .iter()
        .enumerate()
        .map(|(i, code)| match code.as_str() {
            Some(code) if redactify::SUPPORTED_LOCALES.contains(&code) => Ok(code),
            _ => Err(ToolError::InvalidParams(format!(
                "invalid params: `locales[{i}]` is not a supported locale code ({}; lowercase, no surrounding spaces)",
                supported()
            ))),
        })
        .collect()
}

/// The optional `context` argument: the text the call's text answers (the
/// previous conversation turn), as an array of strings; empty when absent
/// or `null`. Anything else is an invalid-params error that names the
/// position, never the value.
fn arg_context(args: &serde_json::Value) -> Result<Vec<&str>, ToolError> {
    match args.get("context") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(texts)) => texts
            .iter()
            .enumerate()
            .map(|(i, t)| {
                t.as_str().ok_or_else(|| {
                    ToolError::InvalidParams(format!(
                        "invalid params: `context[{i}]` is not a string"
                    ))
                })
            })
            .collect(),
        Some(_) => Err(ToolError::InvalidParams(
            "invalid params: `context` must be an array of strings".to_owned(),
        )),
    }
}

/// The optional `target` argument: absent or `null` is `user_prompt`;
/// anything else that is not a target name (a non-string included) is a
/// tool error whose message does not echo the value.
fn arg_target(args: &serde_json::Value) -> Result<GuardTarget, ToolError> {
    let bad_target = || {
        ToolError::Execution(
            "`target` must be one of user_prompt | tool_response | model_output \
             (aliases: user, prompt, tool, tool-response, model, model-output)"
                .to_owned(),
        )
    };
    match args.get("target") {
        None | Some(serde_json::Value::Null) => Ok(GuardTarget::UserPrompt),
        Some(serde_json::Value::String(name)) => {
            GuardTarget::from_str(name).map_err(|_| bad_target())
        }
        Some(_) => Err(bad_target()),
    }
}

/// The detection arguments of `detect` / `redact`.
struct PiiArgs<'v> {
    locales: Vec<&'v str>,
    ignored: Vec<&'v str>,
    threshold: f32,
    context: Vec<&'v str>,
}

/// The optional `ignore` allowlist (string entries; anything else in the
/// array is skipped).
fn arg_ignored(args: &serde_json::Value) -> Vec<&str> {
    args.get("ignore")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default()
}

impl<'v> PiiArgs<'v> {
    fn from_args(args: &'v serde_json::Value) -> Result<Self, ToolError> {
        Ok(Self {
            locales: arg_locales(args)?,
            ignored: arg_ignored(args),
            threshold: args
                .get("threshold")
                .and_then(serde_json::Value::as_f64)
                .map_or(0.0, |f| f as f32),
            context: arg_context(args)?,
        })
    }

    /// The call's detector: the guard's (effective locales, context,
    /// allowlist, normalization on) plus the threshold.
    fn detector<'a>(&'a self, guard: &'a Guard<'_>) -> Detector<'a> {
        guard.detector().with_threshold(self.threshold)
    }
}

/// The guard of one call: the server policy, the call's locales (the
/// guard resolves the effective list: the call's, else the policy's default
/// locales, else tr+en), the call's context texts and its `ignore`
/// allowlist. Its detector serves detect, redact and the vault.
fn guard_for<'a>(
    state: &'a ServerState,
    target: GuardTarget,
    locales: &'a [&'a str],
    context: &'a [&'a str],
    ignored: &'a [&'a str],
) -> Guard<'a> {
    Guard::new(target)
        .with_policy(state.policy.as_ref())
        .with_locales(locales)
        .with_context(context)
        .with_ignored(ignored)
}

fn tool_detect(state: &ServerState, args: &serde_json::Value) -> ToolResult {
    let text = arg_text(args)?;
    let opts = PiiArgs::from_args(args)?;
    let guard = guard_for(
        state,
        GuardTarget::UserPrompt,
        &opts.locales,
        &opts.context,
        &opts.ignored,
    );
    let ents = opts.detector(&guard).detect(text);
    // span metadata only: the raw value never enters the model context
    let spans: Vec<serde_json::Value> = ents
        .iter()
        .map(|e| {
            serde_json::json!({
                "type": e.kind.as_str(),
                "start": e.start,
                "end": e.end,
                "score": e.score,
            })
        })
        .collect();
    Ok(serde_json::json!({ "entities": spans }))
}

fn tool_redact(state: &ServerState, args: &serde_json::Value) -> ToolResult {
    let text = arg_text(args)?;
    let opts = PiiArgs::from_args(args)?;
    let guard = guard_for(
        state,
        GuardTarget::UserPrompt,
        &opts.locales,
        &opts.context,
        &opts.ignored,
    );
    // credentials FIRST (a key is never split by a PII span), then PII
    let redacted = opts
        .detector(&guard)
        .redact(&redactify::guard::mask_secrets(text));
    Ok(serde_json::json!({ "redacted": redacted }))
}

fn tool_guard(state: &ServerState, args: &serde_json::Value) -> ToolResult {
    let text = arg_text(args)?;
    let target = arg_target(args)?;
    let locales = arg_locales(args)?;
    let context = arg_context(args)?;
    let ignored = arg_ignored(args);
    // `None` policy selects the built-in per-target policy
    let guard = guard_for(state, target, &locales, &context, &ignored);
    let r = guard.sanitize(text);
    let d = &r.decision;
    // tool outputs are MODEL-FACING: unlike the library contract (where
    // Block returns raw PII because the caller owns the pipeline), the
    // Block branch returns the loggable re-mask - exactly like the HTTP
    // API (an agent must never receive raw identifiers in any decision
    // branch). Every other branch is already masked (and HTML-encoded for
    // model_output) by the sanitize transform: returned unchanged.
    // A dry-run policy (shadow mode) returns the text unchanged from the
    // library; a tool output is model-facing, so it gets the re-mask too.
    let model_safe_text = if d.action == GuardAction::Block || d.dry_run_action.is_some() {
        guard.mask_all(text)
    } else {
        r.text.clone()
    };
    let mut out = serde_json::json!({
        "action": d.action.to_string(),
        "score": d.top_signal.as_ref().map_or(0.0, |s| s.score),
        "category": d.top_signal.as_ref().map_or("", |s| s.kind.as_str()),
        "rationale": d.rationale,
        // redact-before-return: the model-safe text is the ONLY text returned
        "masked_text": model_safe_text,
    });
    if let Some(decided) = d.dry_run_action {
        out["dry_run"] = serde_json::Value::Bool(true);
        out["dry_run_action"] = serde_json::Value::String(decided.to_string());
    }
    Ok(out)
}

fn tool_vault_pseudonymize(state: &ServerState, args: &serde_json::Value) -> ToolResult {
    let text = arg_text(args)?;
    let locales = arg_locales(args)?;
    let context = arg_context(args)?;
    let ignored = arg_ignored(args);
    let guard = guard_for(state, GuardTarget::UserPrompt, &locales, &context, &ignored);
    // normalization-aware: fullwidth / zero-width-scattered values are
    // pseudonymized too
    let (pseudonymized, vault) = guard.detector().pseudonymize(text);
    // tier split: the placeholder->original mapping NEVER enters the model
    // context (agent tier). Operator tier (--allow-restore) additionally
    // receives it - without the entries the operator could never restore
    // the document later, breaking the round trip.
    let mut out = serde_json::json!({ "pseudonymized": pseudonymized });
    if state.allow_restore {
        out["entries"] = serde_json::json!(vault
            .entries_iter()
            .map(|(p, o)| serde_json::json!({ "placeholder": p, "original": o }))
            .collect::<Vec<_>>());
    }
    Ok(out)
}

fn tool_vault_restore(state: &ServerState, args: &serde_json::Value) -> ToolResult {
    if !state.allow_restore {
        return Err(ToolError::Execution(
            "vault restore is operator-only: restart the server with --allow-restore".to_owned(),
        ));
    }
    let text = arg_text(args)?;
    let entries = args
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "missing required array argument `entries`".to_owned())?;
    // bounded restore table (unbounded entries would make restore an
    // O(entries x text) amplification vector), parsed
    // by the library's shared table reader; brackets optional: `[TCKN_1]`
    // and `TCKN_1` name the same placeholder
    let vault = redactify::Vault::try_from_json_entries(entries).map_err(|e| match e {
        redactify::VaultError::InvalidEntry { .. } => {
            "every entry needs `placeholder` and `original` strings".to_owned()
        }
        other => other.to_string(),
    })?;
    Ok(serde_json::json!({ "restored": vault.restore(text) }))
}

/// `tool_check`: one tool call against a contract and the history (the
/// semantics of the REST `/v1/tool/check` endpoint, server-held sessions
/// included); every decision goes to the audit sink. Error messages name
/// fields, never argument values.
fn tool_check(state: &ServerState, args: &serde_json::Value) -> ToolResult {
    let outcome = check_json_with(&state.tool_sessions, args).map_err(|e| match e {
        ToolCheckError::MissingField { field } => {
            format!("missing required object argument `{field}`")
        }
        other => other.to_string(),
    })?;
    if let Some(sink) = &state.audit_sink {
        let id = NEXT_AUDIT_ID.fetch_add(1, Ordering::Relaxed);
        sink(&outcome.audit_record(format!("mcp-{id}")));
    }
    Ok(outcome.verdict.to_json())
}

fn error_response(id: serde_json::Value, code: i64, message: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":{}}}}}",
        serde_json::Value::String(message.to_owned())
    )
}

#[cfg(test)]
mod tests {
    use super::{handle_message, ServerState};

    fn call(state: &ServerState, line: &str) -> String {
        handle_message(state, line).expect("a response was expected")
    }

    /// One `tools/call` request line for `tool` with `args`.
    fn tool_line(tool: &str, args: &serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        })
        .to_string()
    }

    /// The structured content of a tool reply.
    fn structured(reply: &str) -> serde_json::Value {
        let v: serde_json::Value = serde_json::from_str(reply).expect("valid JSON-RPC frame");
        v["result"]["structuredContent"].clone()
    }

    #[test]
    fn initialize_echoes_supported_versions() {
        let state = ServerState::default();
        let r = call(
            &state,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        );
        assert!(r.contains("\"protocolVersion\":\"2025-06-18\""), "{r}");
        assert!(r.contains("\"tools\""), "{r}");
        assert!(r.contains("redactify-mcp"), "{r}");
        assert!(
            r.contains("tool_check"),
            "instructions name tool_check: {r}"
        );
        // unknown requested version -> server's latest supported
        let r2 = call(
            &state,
            r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1.0.0"}}"#,
        );
        assert!(r2.contains("2025-06-18"), "{r2}");
    }

    #[test]
    fn notifications_answer_nothing() {
        let state = ServerState::default();
        assert!(handle_message(
            &state,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .is_none());
    }

    #[test]
    fn ping_returns_empty_result() {
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
        );
        assert!(r.ends_with("\"result\":{}}"), "{r}");
    }

    #[test]
    fn tools_list_has_six_tools_with_schemas() {
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        let tools = v["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(
            names,
            [
                "detect",
                "redact",
                "guard",
                "vault_pseudonymize",
                "vault_restore",
                "tool_check"
            ]
        );
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object", "{t}");
        }
        // every text tool takes locales
        for t in &tools[..4] {
            assert!(t["inputSchema"]["properties"]["locales"].is_object(), "{t}");
        }
    }

    #[test]
    fn unknown_method_and_tool_use_jsonrpc_errors() {
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":9,"method":"nope"}"#,
        );
        assert!(r.contains("-32601"), "{r}");
        let r2 = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
        );
        assert!(r2.contains("-32602"), "{r2}");
    }

    #[test]
    fn parse_error_answers_with_null_id() {
        let r = call(&ServerState::default(), "this is not json");
        assert!(r.contains("\"id\":null"), "{r}");
        assert!(r.contains("-32700"), "{r}");
    }

    #[test]
    fn tool_panic_is_contained_as_internal_error() {
        let state = ServerState::default();
        let r = call(
            &state,
            &tool_line(
                "__panic_for_test",
                &serde_json::json!({"text": "TCKN 12345678950"}),
            ),
        );
        assert!(r.contains("-32603"), "{r}");
        // the panic message quotes the input: it must not be echoed
        assert!(!r.contains("12345678950"), "{r}");
        assert!(!r.contains("panic carrying"), "{r}");
        // and the dispatcher keeps serving
        let ok = call(&state, r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
        assert!(ok.ends_with("\"result\":{}}"), "{ok}");
    }

    #[test]
    fn tools_call_before_initialize_is_tolerated() {
        // a fresh state that never saw `initialize`
        let r = call(
            &ServerState::default(),
            &tool_line("redact", &serde_json::json!({"text": "mail a@b.com"})),
        );
        assert_eq!(structured(&r)["redacted"], "mail [EMAIL]");
    }

    #[test]
    fn oversized_text_reports_the_size_limit_not_a_missing_field() {
        let big = "x".repeat(super::MAX_TEXT + 1);
        for tool in ["detect", "redact", "guard", "vault_pseudonymize"] {
            let r = call(
                &ServerState::default(),
                &tool_line(tool, &serde_json::json!({ "text": big })),
            );
            assert!(r.contains("\"isError\":true"), "{tool}: {}", &r[..200]);
            let msg = structured(&r)["error"].as_str().unwrap().to_owned();
            assert!(msg.contains("byte limit"), "{tool}: {msg}");
            assert!(!msg.contains("missing"), "{tool}: {msg}");
        }
        // a genuinely missing text still says so
        let r = call(
            &ServerState::default(),
            &tool_line("redact", &serde_json::json!({})),
        );
        assert!(structured(&r)["error"]
            .as_str()
            .unwrap()
            .contains("missing required string argument `text`"));
    }

    #[test]
    fn detect_returns_spans_without_raw_values() {
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"detect","arguments":{"text":"TCKN 12345678950 ve a@b.com"}}}"#,
        );
        assert!(r.contains("\"type\":\"TCKN\""), "{r}");
        assert!(!r.contains("12345678950"), "raw PII value echoed: {r}");
        assert!(r.contains("\"isError\":false"), "{r}");
    }

    #[test]
    fn detect_and_redact_honor_locales_threshold_and_ignore() {
        let state = ServerState::default();
        // the uk pack is opt-in
        let r = call(
            &state,
            &tool_line("detect", &serde_json::json!({"text": "nhs 9434765870"})),
        );
        assert_eq!(structured(&r)["entities"], serde_json::json!([]));
        let r = call(
            &state,
            &tool_line(
                "detect",
                &serde_json::json!({"text": "nhs 9434765870", "locales": ["uk"]}),
            ),
        );
        assert_eq!(structured(&r)["entities"][0]["type"], "UK_NHS");
        // threshold: the bare e-mail (0.85) drops, the TCKN (1.0) stays
        let r = call(
            &state,
            &tool_line(
                "redact",
                &serde_json::json!({"text": "TCKN 12345678950 a@b.com", "threshold": 0.9}),
            ),
        );
        assert_eq!(structured(&r)["redacted"], "TCKN [TCKN] a@b.com");
        // ignore is normalization-aware: the zero-width-scattered spelling
        // of the allowlisted TCKN stays, the other TCKN is masked
        let r = call(
            &state,
            &tool_line(
                "redact",
                &serde_json::json!({
                    "text": "TCKN 1\u{200B}2345678950 ve 10000000146",
                    "ignore": ["12345678950"]
                }),
            ),
        );
        assert_eq!(
            structured(&r)["redacted"],
            "TCKN 1\u{200B}2345678950 ve [TCKN]"
        );
    }

    #[test]
    fn policy_default_locales_apply_when_the_call_names_none() {
        let state = ServerState {
            policy: Some(redactify::policy::Policy {
                default_locales: vec!["uk".to_owned()],
                ..redactify::policy::Policy::default()
            }),
            ..ServerState::default()
        };
        let r = call(
            &state,
            &tool_line("redact", &serde_json::json!({"text": "nhs 9434765870"})),
        );
        assert_eq!(structured(&r)["redacted"], "nhs [UK_NHS]");
    }

    #[test]
    fn redact_masks_pii_and_secrets() {
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"redact","arguments":{"text":"TCKN 12345678950 key AKIAIOSFODNN7EXAMPLE"}}}"#,
        );
        assert!(r.contains("[TCKN]"), "{r}");
        assert!(r.contains("[SECRET:AWS_ACCESS_KEY]"), "{r}");
        assert!(!r.contains("N7EXAMPLE"), "{r}");
    }

    #[test]
    fn guard_blocks_secret_and_returns_only_masked_text() {
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"guard","arguments":{"text":"AKIAIOSFODNN7EXAMPLE ve TCKN 12345678950 gidiyor"}}}"#,
        );
        assert!(r.contains("\"action\":\"Block\""), "{r}");
        assert!(r.contains("[SECRET:AWS_ACCESS_KEY]"), "{r}");
        assert!(!r.contains("N7EXAMPLE"), "{r}");
        // model-facing output: raw PII must be masked on the Block branch too
        assert!(r.contains("[TCKN]"), "{r}");
        assert!(!r.contains("12345678950"), "{r}");
    }

    #[test]
    fn guard_honours_entity_actions_and_keeps_dry_run_output_masked() {
        use redactify::policy::{EntityAction, Policy};
        let block = ServerState {
            policy: Some(
                Policy::default()
                    .with_entity_action(redactify::EntityType::Tckn, EntityAction::Block),
            ),
            ..ServerState::default()
        };
        let r = call(
            &block,
            &tool_line("guard", &serde_json::json!({ "text": "TCKN 12345678950" })),
        );
        let out = structured(&r);
        assert_eq!(out["action"], "Block", "{r}");
        assert!(!r.contains("12345678950"), "{r}");

        // shadow mode: nothing enforced, but the model-facing text stays masked
        let dry = ServerState {
            policy: Some(Policy {
                dry_run: true,
                ..Policy::default()
            }),
            ..ServerState::default()
        };
        let r = call(
            &dry,
            &tool_line("guard", &serde_json::json!({ "text": "TCKN 12345678950" })),
        );
        let out = structured(&r);
        assert_eq!(out["action"], "Allow", "{r}");
        assert_eq!(out["dry_run"], true);
        assert_eq!(out["dry_run_action"], "Mask");
        assert_eq!(out["masked_text"], "TCKN [TCKN]");
    }

    #[test]
    fn guard_block_remask_is_normalization_aware() {
        // fullwidth TCKN digits + a secret: Block, and the re-mask covers
        // the value only the normalizer can see
        let text = "AKIAIOSFODNN7EXAMPLE TCKN \u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}";
        let r = call(
            &ServerState::default(),
            &tool_line("guard", &serde_json::json!({ "text": text })),
        );
        let out = structured(&r);
        assert_eq!(out["action"], "Block", "{r}");
        assert_eq!(out["masked_text"], "[SECRET:AWS_ACCESS_KEY] TCKN [TCKN]");
    }

    #[test]
    fn guard_accepts_target_aliases_and_locales() {
        let state = ServerState::default();
        // alias: `model` = model_output (HTML-encoded, returned unchanged)
        let r = call(
            &state,
            &tool_line(
                "guard",
                &serde_json::json!({"text": "a < b", "target": "model"}),
            ),
        );
        assert_eq!(structured(&r)["masked_text"], "a &lt; b");
        // a bad target is a tool error naming the accepted names
        let r = call(
            &state,
            &tool_line("guard", &serde_json::json!({"text": "x", "target": "nope"})),
        );
        assert!(r.contains("\"isError\":true"), "{r}");
        assert!(r.contains("user_prompt"), "{r}");
        // locales reach the guard
        let r = call(
            &state,
            &tool_line(
                "guard",
                &serde_json::json!({"text": "nhs 9434765870", "locales": ["uk"]}),
            ),
        );
        let out = structured(&r);
        assert_eq!(out["action"], "Mask");
        assert_eq!(out["masked_text"], "nhs [UK_NHS]");
    }

    #[test]
    fn tool_check_allows_denies_and_caps_history() {
        let state = ServerState::default();
        let contract = serde_json::json!({"allowed": ["search"], "global_max": 2});
        let allow = call(
            &state,
            &tool_line(
                "tool_check",
                &serde_json::json!({
                    "contract": contract,
                    "call": {"tool": "search", "args": {"q": "secret-arg-value"}}
                }),
            ),
        );
        assert_eq!(
            structured(&allow),
            serde_json::json!({"verdict": "allow", "code": "ALLOW"})
        );
        assert!(!allow.contains("secret-arg-value"), "{allow}");
        let deny = call(
            &state,
            &tool_line(
                "tool_check",
                &serde_json::json!({
                    "contract": contract,
                    "history": [{"tool": "search", "args": "a"}, {"tool": "search", "args": "b"}],
                    "call": {"tool": "search", "args": "c"}
                }),
            ),
        );
        assert_eq!(
            structured(&deny),
            serde_json::json!({"verdict": "deny", "code": "GLOBAL_BUDGET"})
        );
        let history: Vec<serde_json::Value> = (0..=super::MAX_TOOL_HISTORY)
            .map(|_| serde_json::json!({"tool": "search"}))
            .collect();
        let capped = call(
            &state,
            &tool_line(
                "tool_check",
                &serde_json::json!({
                    "contract": contract,
                    "history": history,
                    "call": {"tool": "search"}
                }),
            ),
        );
        assert!(capped.contains("\"isError\":true"), "{}", &capped[..200]);
        assert!(capped.contains("10000-call limit"), "{}", &capped[..300]);
        // a malformed contract names the field
        let bad = call(
            &state,
            &tool_line(
                "tool_check",
                &serde_json::json!({"contract": {"allowed": [], "global_maxx": 1}, "call": {"tool": "x"}}),
            ),
        );
        assert!(bad.contains("global_maxx"), "{bad}");
    }

    #[test]
    fn tool_check_sessions_hold_the_history_and_every_decision_is_audited() {
        use redactify::guard::audit::{verify_chain, ChainedAuditSink};
        use std::sync::{Arc, Mutex};
        let chain = Arc::new(Mutex::new(ChainedAuditSink::new(Vec::new())));
        let sink = Arc::clone(&chain);
        let state = ServerState::default().with_audit_sink(Arc::new(move |record| {
            sink.lock().unwrap().append(record).unwrap();
        }));
        let args = |q: &str| {
            serde_json::json!({
                "contract": {"allowed": ["search"], "global_max": 1},
                "session_id": "mcp-session",
                "call": {"tool": "search", "args": {"q": q}}
            })
        };
        let first = call(&state, &tool_line("tool_check", &args("secret-one")));
        assert_eq!(
            structured(&first),
            serde_json::json!({"verdict": "allow", "code": "ALLOW"})
        );
        // no history was sent: the server remembers the first call
        let second = call(&state, &tool_line("tool_check", &args("secret-two")));
        assert_eq!(structured(&second)["code"], "GLOBAL_BUDGET", "{second}");
        // a history next to a session id is refused (no decision, no record)
        let mut with_history = args("secret-three");
        with_history["history"] = serde_json::json!([]);
        let refused = call(&state, &tool_line("tool_check", &with_history));
        assert!(refused.contains("\"isError\":true"), "{refused}");
        assert!(
            refused.contains("the server holds the session history"),
            "{refused}"
        );
        let log = {
            let mut guard = chain.lock().unwrap();
            let sink = std::mem::replace(&mut *guard, ChainedAuditSink::new(Vec::new()));
            String::from_utf8(sink.into_log()).unwrap()
        };
        assert_eq!(verify_chain(log.lines(), None), Ok(2), "{log}");
        assert!(!log.contains("secret-"), "{log}");
        assert!(log.contains("\"request_id\":\"mcp-"), "{log}");
        assert!(log.contains("\"session_id\":\"mcp-session\""), "{log}");
        assert!(log.contains("\"code\":\"GLOBAL_BUDGET\""), "{log}");
    }

    #[test]
    fn vault_pseudonymize_never_leaks_the_mapping_to_agents() {
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"vault_pseudonymize","arguments":{"text":"TCKN 12345678950 burada"}}}"#,
        );
        assert!(r.contains("[TCKN_1]"), "{r}");
        // agent tier: the placeholder->original mapping must NOT appear
        assert!(!r.contains("12345678950"), "vault mapping leaked: {r}");
    }

    #[test]
    fn vault_pseudonymize_is_normalization_aware_and_takes_locales() {
        let state = ServerState::default();
        let r = call(
            &state,
            &tool_line(
                "vault_pseudonymize",
                &serde_json::json!({"text": "TCKN 1\u{200B}2345678950"}),
            ),
        );
        assert_eq!(structured(&r)["pseudonymized"], "TCKN [TCKN_1]");
        let r = call(
            &state,
            &tool_line(
                "vault_pseudonymize",
                &serde_json::json!({"text": "nhs 9434765870", "locales": ["uk"]}),
            ),
        );
        assert_eq!(structured(&r)["pseudonymized"], "nhs [UK_NHS_1]");
    }

    #[test]
    fn vault_round_trip_completes_on_the_operator_tier() {
        // operator tier receives the entries; without them a document
        // pseudonymized through MCP could never be restored
        let op = ServerState {
            allow_restore: true,
            ..ServerState::default()
        };
        let anon = call(
            &op,
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"vault_pseudonymize","arguments":{"text":"TCKN 12345678950 burada"}}}"#,
        );
        assert!(anon.contains("[TCKN_1]"), "{anon}");
        assert!(
            anon.contains("\"entries\""),
            "operator tier missing entries: {anon}"
        );
        assert!(anon.contains("12345678950"), "{anon}");
        // and those entries drive a successful restore
        let restored = call(
            &op,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"vault_restore","arguments":{"text":"[TCKN_1] burada","entries":[{"placeholder":"[TCKN_1]","original":"12345678950"}]}}}"#,
        );
        assert!(restored.contains("12345678950"), "{restored}");
    }

    #[test]
    fn vault_restore_caps_the_entry_table() {
        let op = ServerState {
            allow_restore: true,
            ..ServerState::default()
        };
        let entries: Vec<serde_json::Value> = (0..=super::MAX_ENTRIES)
            .map(|i| serde_json::json!({"placeholder": format!("X_{i}"), "original": "v"}))
            .collect();
        let r = call(
            &op,
            &tool_line(
                "vault_restore",
                &serde_json::json!({"text": "[X_1]", "entries": entries}),
            ),
        );
        assert!(r.contains("\"isError\":true"), "{}", &r[..200]);
        assert!(r.contains("10000-entry limit"), "{}", &r[..300]);
    }

    #[test]
    fn vault_restore_is_operator_only() {
        // agent tier: refused with isError
        let r = call(
            &ServerState::default(),
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"vault_restore","arguments":{"text":"[TCKN_1] burada","entries":[]}}}"#,
        );
        assert!(r.contains("\"isError\":true"), "{r}");
        assert!(r.contains("operator-only"), "{r}");

        // operator tier (--allow-restore): round trip works
        let op = ServerState {
            allow_restore: true,
            ..ServerState::default()
        };
        let anon = call(
            &op,
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"vault_pseudonymize","arguments":{"text":"TCKN 12345678950 burada"}}}"#,
        );
        let restored = call(
            &op,
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"vault_restore","arguments":{"text":"[TCKN_1] burada","entries":[{"placeholder":"[TCKN_1]","original":"12345678950"}]}}}"#,
        );
        assert!(restored.contains("12345678950"), "{restored}");
        assert!(anon.contains("[TCKN_1]"), "{anon}");
    }

    #[test]
    fn unknown_or_mistyped_locales_are_invalid_params() {
        let state = ServerState::default();
        let text = "TCKN 12345678950";
        let cases = [
            (
                "redact",
                serde_json::json!({"text": text, "locales": ["TR"]}),
            ),
            (
                "detect",
                serde_json::json!({"text": text, "locales": ["tr "]}),
            ),
            (
                "guard",
                serde_json::json!({"text": text, "locales": ["xx"]}),
            ),
            (
                "vault_pseudonymize",
                serde_json::json!({"text": text, "locales": [""]}),
            ),
            ("redact", serde_json::json!({"text": text, "locales": "tr"})),
            (
                "redact",
                serde_json::json!({"text": text, "locales": ["tr", 1]}),
            ),
            (
                "redact",
                serde_json::json!({"text": "x", "locales": ["zz-12345678950"]}),
            ),
        ];
        for (tool, args) in cases {
            let r = call(&state, &tool_line(tool, &args));
            let v: serde_json::Value = serde_json::from_str(&r).expect("valid frame");
            assert_eq!(v["error"]["code"], -32602, "{tool} {args}: {r}");
            assert!(!r.contains("12345678950"), "{tool}: {r}");
        }
        // supported codes, null and an empty list keep working
        for locales in [
            serde_json::json!(["tr"]),
            serde_json::json!(null),
            serde_json::json!([]),
        ] {
            let r = call(
                &state,
                &tool_line(
                    "redact",
                    &serde_json::json!({"text": text, "locales": locales}),
                ),
            );
            assert_eq!(structured(&r)["redacted"], "TCKN [TCKN]", "{r}");
        }
    }

    #[test]
    fn context_unlocks_cue_gated_values_in_every_text_tool() {
        let state = ServerState::default();
        let turn = serde_json::json!(["Vergi numaranızı yazar mısınız?"]);
        let with = |tool: &str| {
            call(
                &state,
                &tool_line(
                    tool,
                    &serde_json::json!({"text": "1234567890", "context": turn}),
                ),
            )
        };
        assert_eq!(structured(&with("redact"))["redacted"], "[VKN]");
        assert_eq!(structured(&with("detect"))["entities"][0]["type"], "VKN");
        assert_eq!(structured(&with("guard"))["masked_text"], "[VKN]");
        assert_eq!(
            structured(&with("vault_pseudonymize"))["pseudonymized"],
            "[VKN_1]"
        );
        // without the context the bare number stays
        let plain = call(
            &state,
            &tool_line("redact", &serde_json::json!({"text": "1234567890"})),
        );
        assert_eq!(structured(&plain)["redacted"], "1234567890");
        // a non-array or a non-string item is invalid params, never echoed
        for context in [serde_json::json!("vergi"), serde_json::json!(["ok", 3])] {
            let r = call(
                &state,
                &tool_line(
                    "redact",
                    &serde_json::json!({"text": "x", "context": context}),
                ),
            );
            let v: serde_json::Value = serde_json::from_str(&r).expect("valid frame");
            assert_eq!(v["error"]["code"], -32602, "{r}");
            assert!(!r.contains("vergi"), "{r}");
        }
    }

    #[test]
    fn bounded_line_reads_keep_lines_up_to_the_limit() {
        use super::{read_line_bounded, LineRead};
        let mut input = std::io::Cursor::new(b"abc\nabcd\nxyz".to_vec());
        let mut buf = Vec::new();
        // a line of exactly `max` bytes (plus its newline) is kept
        assert_eq!(
            read_line_bounded(&mut input, &mut buf, 3).unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"abc\n");
        // one byte more is refused, consumed to its newline, not stored
        assert_eq!(
            read_line_bounded(&mut input, &mut buf, 3).unwrap(),
            LineRead::TooLong
        );
        assert!(buf.is_empty());
        // the next line reads normally; a last line without newline counts
        assert_eq!(
            read_line_bounded(&mut input, &mut buf, 3).unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"xyz");
        assert_eq!(
            read_line_bounded(&mut input, &mut buf, 3).unwrap(),
            LineRead::Eof
        );
    }

    #[test]
    fn an_overlong_line_is_skipped_without_buffering_it() {
        use super::{read_line_bounded, LineRead};
        let mut data = vec![b'a'; 5_000_000];
        data.extend_from_slice(b"\n{\"ok\":1}\n");
        let mut input = std::io::BufReader::with_capacity(4096, std::io::Cursor::new(data));
        let mut buf = Vec::new();
        assert_eq!(
            read_line_bounded(&mut input, &mut buf, 1024).unwrap(),
            LineRead::TooLong
        );
        assert!(buf.capacity() <= 4096, "buffered {} bytes", buf.capacity());
        assert_eq!(
            read_line_bounded(&mut input, &mut buf, 1024).unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"{\"ok\":1}\n");
    }

    #[test]
    fn the_line_limit_fits_a_max_text_call_with_worst_case_escaping() {
        // RFC 8259 section 7: a control character is written \u00XX (6 bytes)
        let text: String = "\u{1}".repeat(super::MAX_TEXT);
        let line = tool_line("redact", &serde_json::json!({ "text": text }));
        assert!(
            line.len() <= super::MAX_LINE,
            "{} > {}",
            line.len(),
            super::MAX_LINE
        );
        let reply = super::too_long_reply();
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["error"]["code"], -32000);
        assert!(v["id"].is_null());
    }

    #[test]
    fn guard_and_vault_honor_the_ignore_allowlist() {
        let state = ServerState::default();
        let args = serde_json::json!({
            "text": "Destek: 0532 123 45 67, TCKN 12345678950",
            "ignore": ["0532 123 45 67"]
        });
        let guard = structured(&call(&state, &tool_line("guard", &args)));
        assert_eq!(guard["masked_text"], "Destek: 0532 123 45 67, TCKN [TCKN]");
        let vault = structured(&call(&state, &tool_line("vault_pseudonymize", &args)));
        assert_eq!(
            vault["pseudonymized"],
            "Destek: 0532 123 45 67, TCKN [TCKN_1]"
        );
    }

    #[test]
    fn a_non_string_or_unknown_target_is_refused_without_echo() {
        let state = ServerState::default();
        for target in [
            serde_json::json!(5),
            serde_json::json!(true),
            serde_json::json!(["tool"]),
            serde_json::json!("tckn-12345678950"),
        ] {
            let r = call(
                &state,
                &tool_line(
                    "guard",
                    &serde_json::json!({"text": "TCKN 12345678950", "target": target}),
                ),
            );
            assert!(r.contains("\"isError\":true"), "{target}: {r}");
            assert!(r.contains("user_prompt"), "{target}: {r}");
            assert!(!r.contains("12345678950"), "{target}: {r}");
        }
        // a null target keeps meaning "absent" (user_prompt)
        let r = call(
            &state,
            &tool_line(
                "guard",
                &serde_json::json!({"text": "TCKN 12345678950", "target": null}),
            ),
        );
        assert_eq!(structured(&r)["masked_text"], "TCKN [TCKN]", "{r}");
    }

    /// Edge arguments for `tool_check` (the REST table's requests).
    fn tool_check_args() -> Vec<serde_json::Value> {
        use serde_json::json;
        let max = super::MAX_TOOL_HISTORY;
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

    /// Every edge call's reply line, as recorded on the code before the
    /// tool-check core moved into `redactify::guard::tools`.
    const TOOL_CHECK_WIRE: &[&str] = &[
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"missing required object argument `contract`\"}"}],"structuredContent":{"error":"missing required object argument `contract`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"missing required object argument `contract`\"}"}],"structuredContent":{"error":"missing required object argument `contract`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"contract: field `(root)` must be a JSON object\"}"}],"structuredContent":{"error":"contract: field `(root)` must be a JSON object"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"missing required object argument `call`\"}"}],"structuredContent":{"error":"missing required object argument `call`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"call: field `(root)` must be a JSON object\"}"}],"structuredContent":{"error":"call: field `(root)` must be a JSON object"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"contract: unknown field `global_maxx`\"}"}],"structuredContent":{"error":"contract: unknown field `global_maxx`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"ALLOW\",\"verdict\":\"allow\"}"}],"structuredContent":{"code":"ALLOW","verdict":"allow"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"`history` must be an array of calls {tool, args}\"}"}],"structuredContent":{"error":"`history` must be an array of calls {tool, args}"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"`history` must be an array of calls {tool, args}\"}"}],"structuredContent":{"error":"`history` must be an array of calls {tool, args}"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"history[1]: field `(root)` must be a JSON object\"}"}],"structuredContent":{"error":"history[1]: field `(root)` must be a JSON object"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"history[0]: unknown field `extra`\"}"}],"structuredContent":{"error":"history[0]: unknown field `extra`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"history exceeds the 10000-call limit (10001 given)\"}"}],"structuredContent":{"error":"history exceeds the 10000-call limit (10001 given)"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"LOOP\",\"verdict\":\"deny\"}"}],"structuredContent":{"code":"LOOP","verdict":"deny"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"contract: invalid argument deny pattern for tool `a`\"}"}],"structuredContent":{"error":"contract: invalid argument deny pattern for tool `a`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"LOOP\",\"verdict\":\"deny\"}"}],"structuredContent":{"code":"LOOP","verdict":"deny"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"NOT_ALLOWLISTED\",\"verdict\":\"deny\"}"}],"structuredContent":{"code":"NOT_ALLOWLISTED","verdict":"deny"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"GLOBAL_BUDGET\",\"verdict\":\"deny\"}"}],"structuredContent":{"code":"GLOBAL_BUDGET","verdict":"deny"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"TOKEN_BUDGET\",\"verdict\":\"deny\"}"}],"structuredContent":{"code":"TOKEN_BUDGET","verdict":"deny"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"TOOL_BUDGET\",\"verdict\":\"deny\"}"}],"structuredContent":{"code":"TOOL_BUDGET","verdict":"deny"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"ARG_PATTERN\",\"verdict\":\"deny\"}"}],"structuredContent":{"code":"ARG_PATTERN","verdict":"deny"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"ALLOW\",\"verdict\":\"allow\"}"}],"structuredContent":{"code":"ALLOW","verdict":"allow"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"ALLOW\",\"verdict\":\"allow\"}"}],"structuredContent":{"code":"ALLOW","verdict":"allow"},"isError":false}}"#,
    ];

    #[test]
    fn tool_check_wire_outputs_are_unchanged() {
        let state = ServerState::default();
        let got: Vec<String> = tool_check_args()
            .iter()
            .map(|args| call(&state, &tool_line("tool_check", args)))
            .collect();
        assert_eq!(got, TOOL_CHECK_WIRE);
    }

    /// Edge arguments for `vault_restore` (the REST table's requests).
    fn vault_args() -> Vec<serde_json::Value> {
        use serde_json::json;
        let max = super::MAX_ENTRIES;
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

    /// Every edge call's reply line on the operator tier, as recorded on the
    /// code before the entry parsing moved into
    /// `redactify::Vault::try_from_json_entries`.
    const VAULT_WIRE: &[&str] = &[
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"missing required array argument `entries`\"}"}],"structuredContent":{"error":"missing required array argument `entries`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"missing required array argument `entries`\"}"}],"structuredContent":{"error":"missing required array argument `entries`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"missing required array argument `entries`\"}"}],"structuredContent":{"error":"missing required array argument `entries`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"missing required string argument `text`\"}"}],"structuredContent":{"error":"missing required string argument `text`"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"restored\":\"v b\"}"}],"structuredContent":{"restored":"v b"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"restored\":\"v b\"}"}],"structuredContent":{"restored":"v b"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"every entry needs `placeholder` and `original` strings\"}"}],"structuredContent":{"error":"every entry needs `placeholder` and `original` strings"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"every entry needs `placeholder` and `original` strings\"}"}],"structuredContent":{"error":"every entry needs `placeholder` and `original` strings"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"every entry needs `placeholder` and `original` strings\"}"}],"structuredContent":{"error":"every entry needs `placeholder` and `original` strings"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"vault entries exceed the 10000-entry limit\"}"}],"structuredContent":{"error":"vault entries exceed the 10000-entry limit"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"every entry needs `placeholder` and `original` strings\"}"}],"structuredContent":{"error":"every entry needs `placeholder` and `original` strings"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"error\":\"vault entries exceed the 10000-entry limit\"}"}],"structuredContent":{"error":"vault entries exceed the 10000-entry limit"},"isError":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"restored\":\"v v\"}"}],"structuredContent":{"restored":"v v"},"isError":false}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"restored\":\"lastw\"}"}],"structuredContent":{"restored":"lastw"},"isError":false}}"#,
    ];

    #[test]
    fn vault_restore_wire_outputs_are_unchanged() {
        let op = ServerState {
            allow_restore: true,
            ..ServerState::default()
        };
        let got: Vec<String> = vault_args()
            .iter()
            .map(|args| call(&op, &tool_line("vault_restore", args)))
            .collect();
        assert_eq!(got, VAULT_WIRE);
    }
}
