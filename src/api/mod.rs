//! REST API server (optional, behind the `api` feature).
//!
//! A **simple RESTful interface with a detailed response format** over the
//! deterministic core (L0 rules + L1 PII + policy). Local-first like the rest
//! of the crate: the server binds where you run it and nothing leaves the
//! process. Attach ML classifiers and an NER recognizer via
//! [`ApiState`](crate::api::ApiState) (built with the `ml-onnx` feature,
//! e.g. `--ml-security`/`--ml-safety`/`--ml-ner` on `--serve`): `/v1/guard`
//! and `/v1/sanitize` then run the full L0+L1+ML pipeline, and the stream
//! endpoints scan with the recognizer and the security classifier.
//!
//! # Endpoints
//!
//! | method | path | request | response |
//! |---|---|---|---|
//! | GET  | `/health` | - | `{"status": "ok"\|"degraded", "version", "ml_active", "ml_health": {"security", "safety", "ner"}}` |
//! | GET  | `/openapi.json` | - | the OpenAPI 3.1 description of this API (needs the token when one is set) |
//! | GET  | `/metrics` | - | Prometheus text exposition format 0.0.4 (`text/plain; version=0.0.4`): requests, latency histogram, decisions and entities by endpoint (needs the token when one is set) |
//! | POST | `/v1/detect` | `{"text", "locales"?: ["tr","en"], "threshold"?: 0.0, "ignore"?: [...], "explain"?: false}` | entities (+ `explain` per entity) + masked text |
//! | POST | `/v1/redact` | `{"text", "locales"?, "threshold"?, "ignore"?}` | `{"redacted"}` |
//! | POST | `/v1/json/redact` | `{"json": <any JSON value>, "locales"?, "threshold"?, "ignore"?, "numeric_leaves"?: false}` | `{"redacted": <the document, PII and secrets masked>, "findings": [{"pointer", "kind", "type", "in_key"}], "complete"}` |
//! | POST | `/v1/guard` | `{"text", "target"?, "locales"?, "request_id"?}` | full decision (signals + verdicts + PII spans) |
//! | POST | `/v1/sanitize` | `{"text", "target"?, "locales"?, "request_id"?}` | decision + sanitized text |
//! | POST | `/v1/batch/detect`, `/v1/batch/redact`, `/v1/batch/sanitize` | the single endpoint's request with `"texts": ["..."]` in place of `"text"` | `{"count", "results": [...]}`, `results[i]` = the single endpoint's body for `texts[i]` |
//! | POST | `/v1/stream/sanitize` | `{"chunks": ["..."], "target"?, "locales"?, "request_id"?}` **or** raw NDJSON (one JSON string per line = one chunk) | `application/x-ndjson` event stream (segment/block per line) |
//! | POST | `/v1/stream/sse` | same request as `/v1/stream/sanitize` | `text/event-stream`: one `data: {event}` frame per guard event, written as it is produced (HTTP/1.1; an HTTP/1.0 client gets the same frames buffered with a `Content-Length`); socket server only, terminates after a Block |
//! | POST | `/v1/vault/pseudonymize` | `{"text", "locales"?}` | pseudonymized text + mapping (the mapping contains the originals by design) |
//! | POST | `/v1/vault/restore` | `{"text", "entries": [{placeholder, original}]}` | restored text |
//! | POST | `/v1/tool/check` | `{"contract", "call", "session_id"?, "history"?: [call, ...], "request_id"?}` | `{"verdict": "allow"\|"deny", "code"}` |
//! | POST | `/beta/litellm_basic_guardrail_api` | LiteLLM Generic Guardrail API: `{"texts", "input_type": "request"\|"response", "structured_messages"?, "tool_calls"?, "litellm_call_id"?, "additional_provider_specific_params"?}` | `{"action": "NONE"}`, `{"action": "GUARDRAIL_INTERVENED", "texts"}` or `{"action": "BLOCKED", "blocked_reason"}` |
//!
//! One semantics per operation (the MCP server uses the same builders):
//! - detection, redaction and pseudonymization run the
//!   [`Detector`] with the EFFECTIVE locales (the
//!   request's `locales`, else the server policy's `default_locales`, else
//!   tr+en), the normalization pass on (fullwidth
//!   and zero-width-scattered values are found too), `threshold` and the
//!   `ignore` allowlist applied inside overlap resolution. Redacted text
//!   masks leaked credentials FIRST (`[SECRET:VENDOR]`), then PII; a line
//!   the engine could not fully scan becomes `[SCAN_INCOMPLETE]`;
//! - guard and sanitize run the [`Guard`] (policy,
//!   effective locales, NER, ML classifiers). On `Block`, `/v1/sanitize`
//!   returns the loggable re-mask
//!   ([`Guard::mask_all`]) instead of the raw text;
//! - `/v1/detect` with `"explain": true` adds an `explain` object to every
//!   entity: `source` (`{"kind": "RULE", "id"}`, `{"kind": "CUSTOM",
//!   "index"}` or `{"kind": "NER", "name"}`), `validator_passed`, `cue`
//!   (the configured cue literal, never request text), `base_score`,
//!   `score` and `view` (`"RAW"` / `"NORMALIZED"`);
//! - `/v1/json/redact` runs [`JsonRedactor`](crate::JsonRedactor) with the
//!   same detector: string leaves (number leaves too with
//!   `"numeric_leaves": true`) are masked, each member name is a context
//!   cue for its values, and every finding is reported by RFC 6901
//!   pointer, `kind` (`PII` / `SECRET` / `SCAN_INCOMPLETE`) and `type`
//!   (entity type or secret label; `null` for an incomplete scan). A
//!   pointer never carries a detected value;
//! - every detect, redact, JSON, guard, sanitize, batch and vault-pseudonymize
//!   request accepts an optional `"context": ["..."]`: the text the
//!   request text answers (the previous conversation turn). A cue in it
//!   unlocks cue-gated identifiers that stand alone in the text (see
//!   [`Detector::with_context`]); it is
//!   never echoed. A non-array or a non-string item is `bad_context`. The
//!   stream endpoints take no context;
//! - every text endpoint (detect, redact, JSON, guard, sanitize, batch,
//!   vault pseudonymize and both stream endpoints) accepts the `ignore`
//!   allowlist: an allowlisted value is neither reported nor masked and
//!   does not drive the decision;
//! - a request may carry its own rules, bounded so that the caller never
//!   chooses the scan cost. `"words": ["..."]` is a literal deny list (at
//!   most 256 words of at most 128 bytes, matched as whole words, masked as
//!   `CUSTOM_WORD`; `"words_ignore_case": true` ignores case); bad input is
//!   `bad_words`. `"patterns": [{"pattern", "label"?, "cues"?, "score"?}]`
//!   holds regular expressions (at most 16): only the linear-time syntax is
//!   accepted (look-around, back-references and atomic groups are refused,
//!   so the engine never backtracks), at most 256 bytes, a shortest match
//!   of 3 characters and a bounded compiled size (see
//!   [`CustomRule::new_linear`]). The
//!   `label` must already exist (a built-in type or a label the server
//!   policy registered; a request never registers one) and defaults to
//!   `CUSTOM_PATTERN`; `cues` (at most 16 words of at most 64 bytes) gate a
//!   match; `score` is 0.0 to 1.0. Bad input is `bad_patterns`, naming the
//!   field and position, never the pattern. Rules with look-around or other
//!   backtracking constructs stay in the server policy (TOML
//!   `[[custom_rules]]` via `REDACTIFY_POLICY`);
//! - detect, redact, JSON, guard, sanitize, batch and both stream requests
//!   (the vault endpoint takes only `words` and `patterns`) accept a mask
//!   strategy. `"mask"` is `{"style": "label"}` (default),
//!   `{"style": "template", "template": "[REDACTED]"}` (1 to 64 bytes;
//!   every `{type}` becomes the type label, a text without it is a fixed
//!   replacement), `{"style": "char", "char": "*"}`, `{"style": "partial",
//!   "keep_last": 4, "char": "*"}` (all but the last characters masked),
//!   `{"style": "mask_first", "count": 3, "char": "*"}` or
//!   `{"style": "mask_last", "count": 4, "char": "*"}` (only that many
//!   characters from the start or the end masked; `count` 1 to 64).
//!   `"mask_by_type"` maps entity type labels (at most 32, each an existing
//!   type) to their own mask object, so an e-mail can be starred while a
//!   card keeps its last four digits; a type without an entry uses `mask`.
//!   A pseudonym style needs a server-held key and is not offered. Bad
//!   input is `bad_mask`;
//! - `/v1/guard`, `/v1/sanitize` and `/v1/batch/sanitize` accept
//!   `"system_prompt"` (a string of at most 64 KiB): with
//!   `"target": "model_output"`, a text that reproduces a run of 8 or more
//!   of its words gets a `PROMPT_LEAK` verdict (see
//!   [`prompt_leak_risk`](crate::guard::prompt_leak_risk)); other targets
//!   ignore it, and it is never echoed. Bad input is `bad_system_prompt`;
//! - the batch endpoints apply one request's options to every item of
//!   `texts`; a batch sanitize emits one audit record per item, all with
//!   the request's `request_id`;
//! - `/v1/tool/check` evaluates one agent tool call against a
//!   [`ToolContract`](crate::guard::tools::ToolContract) and the call
//!   history (at most [`MAX_TOOL_HISTORY`](crate::api::MAX_TOOL_HISTORY)
//!   calls); the response carries the verdict and its stable code, never
//!   the call arguments. With `"session_id"` (1 to 128 printable ASCII
//!   characters) the server holds the history instead
//!   ([`ApiState::tool_sessions`](crate::api::ApiState::tool_sessions),
//!   see [`ToolSessions`](crate::guard::tools::ToolSessions)): the session
//!   is bound to the contract of its first call, a request that also
//!   sends `history` is refused (`history_not_allowed`), and a bad id is
//!   `bad_session_id`. Sessions live as long as the state: the socket
//!   server keeps one table, the pure [`handle_request`](crate::api::handle_request) starts a fresh
//!   one on every call. A contract's `egress_allowlist` denies a call
//!   whose arguments hold a URL to another host (`EGRESS_HOST`);
//! - `/beta/litellm_basic_guardrail_api` is the LiteLLM Generic Guardrail
//!   API (LiteLLM proxy `guardrail: generic_guardrail_api`, contract of
//!   LiteLLM v1.110.2): every text of `texts` runs through the guard (the
//!   per-item core of `/v1/batch/sanitize`, audited with
//!   `litellm_call_id`). Any Block (a text, or the `function.arguments` of
//!   a tool call) answers `BLOCKED` with a reason that names the position
//!   and a static category label; else, when any text changed,
//!   `GUARDRAIL_INTERVENED` with every text in request order; else `NONE`.
//!   `input_type: "response"` texts are `model_output` (decided as such,
//!   not HTML-encoded unless `"html_encode": true`); `"request"` texts are
//!   `user_prompt`, or `tool_response` for the texts of `tool` /
//!   `function` messages in `structured_messages`. A response-side answer
//!   carries `stream_holdback_chars` (the characters of each text's
//!   unfinished last line), so LiteLLM's `incremental_diff` streaming
//!   releases whole, masked lines.
//!   `additional_provider_specific_params` accepts only `words`,
//!   `words_ignore_case`, `patterns`, `html_encode` and `restore` (LiteLLM
//!   lets a client override these params, so options that narrow detection
//!   stay in the server policy).
//!   Response-side restoration (off by default; enabled with
//!   [`ApiState::with_litellm_restore`](crate::api::ApiState::with_litellm_restore)
//!   or [`LITELLM_RESTORE_ENV_VAR`](crate::api::LITELLM_RESTORE_ENV_VAR),
//!   which the socket server accepts only together with a bearer token):
//!   the request side of a LiteLLM call numbers its placeholders
//!   (`[TCKN_1]`) and keeps the originals in a bounded server-side session
//!   ([`RestoreSessions`](crate::api::RestoreSessions)); the response side
//!   of the same call (one call, or every streaming round) gets them back.
//!   The endpoint then returns original PII values BY DESIGN, to
//!   response-side calls only. See the `litellm` module docs for the
//!   session binding and the failure behavior.
//!
//! Design notes (privacy/detail):
//! - PII spans are reported as `type`/`start`/`end`/`score` with **byte
//!   offsets into the request text** - the raw matched value is NOT echoed
//!   back (the caller already has it; responses stay loggable).
//! - Errors are JSON: `{"error": {"code", "message"}}` with 400/404/405/413.
//!   Messages name fields and positions, never request values: a
//!   `target` that is not one of the target names (or not a string) is
//!   `bad_target`; `locales` must be an array of codes from
//!   [`SUPPORTED_LOCALES`](crate::SUPPORTED_LOCALES), compared exactly
//!   (no trimming, no case folding), else `bad_locales` (an unknown code
//!   would select no pack and switch detection off).
//! - Request bodies are capped at 1 MiB by default (413 beyond that;
//!   [`ApiState::with_max_body`](crate::api::ApiState::with_max_body) or
//!   [`BODY_LIMIT_ENV_VAR`](crate::api::BODY_LIMIT_ENV_VAR) set another limit
//!   from 1 KiB to 16 MiB; the socket server refuses to start outside that); vault restore
//!   tables at [`MAX_VAULT_ENTRIES`](crate::MAX_VAULT_ENTRIES) entries and
//!   tool-call histories at
//!   [`MAX_TOOL_HISTORY`](crate::api::MAX_TOOL_HISTORY) calls (413 beyond
//!   that).
//! - Audit (when a sink is attached, see
//!   [`ApiState::with_audit_sink`](crate::api::ApiState::with_audit_sink)):
//!   one metadata-only record per `/v1/guard` and `/v1/sanitize` decision,
//!   per Block event of the stream endpoints, and per `/v1/tool/check`
//!   decision (layer `"TOOL"`, guard `"TOOL_CALL"`, the verdict code,
//!   policy hash, engine version, session id and counts under `tool`;
//!   never the arguments; a request refused with a 4xx makes no
//!   decision and no record). The record's request id
//!   is the request's optional `request_id` field (1 to
//!   [`MAX_REQUEST_ID_LEN`](crate::api::MAX_REQUEST_ID_LEN) printable
//!   ASCII characters; anything else is a 400) or, when absent, a
//!   per-process counter (`api-1`, `api-2`, ...).
//!   The layer is `"L0+L1"`, or `"L0+L1+L2/L3"` when ML classifiers take
//!   part. A stream Block event carries only a rationale, so its record has
//!   score 0.0 (the rationale names the score).
//!   The socket server attaches a hash-chained JSONL file sink when
//!   [`AUDIT_FILE_ENV_VAR`](crate::api::AUDIT_FILE_ENV_VAR) is set (keyed by
//!   [`AUDIT_KEY_ENV_VAR`](crate::api::AUDIT_KEY_ENV_VAR); the MCP server's
//!   variables and semantics): an existing file that does not verify
//!   refuses startup. The LiteLLM endpoint audits every text decision.
//! - Entity actions and dry run (server policy, TOML schema 0.4): a type
//!   configured `block` blocks the decision, `log` leaves it unmasked,
//!   `ignore` removes it from every endpoint's detection (see
//!   [`crate::policy::actions`]). When the policy configures entity actions
//!   or dry run, decision bodies add `"entities": [{"type", "action",
//!   "count"}]`. In dry run (`dry_run = true`) every decision is computed,
//!   audited (guard `DRY_RUN`, the decided action) and counted, but not
//!   enforced: the body carries `"action": "Allow"`, `"dry_run": true` and
//!   `"dry_run_action"`, sanitize returns the text unchanged, the stream
//!   endpoints echo every chunk as a `"dry_run": true` segment, and
//!   `/health` reports `"dry_run": true`. Detect, redact, JSON redact and
//!   the vault are detection utilities without a decision: dry run does
//!   not change them.
//! - Metrics (`GET /metrics`): label values are fixed server vocabulary
//!   only (an endpoint path or `other`, a status code, an action, an
//!   entity type label), never request text. The endpoint sits behind the
//!   bearer token like every endpoint but `/health` (configure the token as
//!   the scrape job's `authorization` credentials): request counts per
//!   endpoint describe the traffic a deployment guards.
//! - Server-wide policy (`config` feature): the `REDACTIFY_POLICY`
//!   environment variable points at a TOML policy applied to every guard
//!   decision; a malformed file REFUSES startup (fail-closed).
//! - Authentication (optional, socket server): with a token configured
//!   ([`ApiState::with_bearer_token`](crate::api::ApiState::with_bearer_token)
//!   or the [`API_TOKEN_ENV_VAR`](crate::api::API_TOKEN_ENV_VAR) variable)
//!   every request except `GET /health` must carry
//!   `Authorization: Bearer <token>` (RFC 6750 section 2.1; the scheme is
//!   case-insensitive, RFC 9110 section 11.1), checked before the body is
//!   read and compared in constant time. No credentials, or another
//!   scheme: 401 with `WWW-Authenticate: Bearer realm="redactify"`; a
//!   wrong token: 401 with `error="invalid_token"`; two `Authorization`
//!   headers: 400 with `error="invalid_request"` (RFC 6750 sections 3 and
//!   3.1). `/health` stays open for container liveness probes; it carries
//!   no request data. An empty or malformed token refuses startup. The
//!   LiteLLM endpoint also accepts the token as `x-api-key: <token>` (the
//!   header LiteLLM sends its configured `api_key` in) when no
//!   `Authorization` header is present.
//!
//! # Examples
//! ```
//! # #[cfg(feature = "api")]
//! # {
//! use redactify::api::handle_request;
//!
//! let r = handle_request("POST", "/v1/guard", r#"{"text":"TCKN 12345678950"}"#);
//! assert_eq!(r.status, 200);
//! assert!(r.body.contains("\"action\":\"Mask\""));
//! assert!(r.body.contains("\"mask_summary\":[\"TCKN\"]"));
//!
//! // model_output also HTML-encodes dangerous characters (OWASP LLM05)
//! let r = handle_request("POST", "/v1/sanitize",
//!     r#"{"text":"a < b","target":"model_output"}"#);
//! assert!(r.body.contains("a &lt; b"));
//!
//! // agent tool guard: the verdict and its code, never the arguments
//! let r = handle_request("POST", "/v1/tool/check",
//!     r#"{"contract":{"allowed":["search"]},"call":{"tool":"shell","args":"rm -rf /"}}"#);
//! assert!(r.body.contains("\"verdict\":\"deny\""));
//! assert!(r.body.contains("\"code\":\"NOT_ALLOWLISTED\""));
//! assert!(!r.body.contains("rm -rf"));
//! # }
//! ```
#![cfg(feature = "api")]
// The module docs above link with explicit `crate::` paths: stable rustdoc
// (1.100) resolves this file's inner docs in the crate root's scope and
// nightly (1.102, what docs.rs builds with) in this module's scope, so a
// bare label resolves on one toolchain only. The explicit paths are
// correct on both; only the redundancy lint differs between them.
#![allow(rustdoc::redundant_explicit_links)]

mod litellm;
mod metrics;
mod openapi;

pub use litellm::{RestoreLimits, RestoreSessions};
pub use metrics::Metrics;

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::guard::ml::{MlClassifier, MlHealth, MlRouter};
use crate::guard::tools::{check_json_with, ToolCheckError, ToolSessions};
use crate::pii::{
    CustomRule, DetectionSource, Entity, EntityType, Explanation, NerHealth, NerRecognizer,
};
use crate::policy::stream::{GuardEvent, MlStreamBudget, StreamingGuard};
use crate::policy::{Decision, Detector, Guard, GuardAction, GuardTarget, MaskStyle};

/// Audit callback: receives metadata-only records for every guard decision.
pub type AuditCallback = Arc<dyn Fn(&crate::guard::audit::AuditRecord) + Send + Sync>;

/// Environment variable that makes the socket server require a bearer
/// token (see [`bearer_token_from_env`]).
pub const API_TOKEN_ENV_VAR: &str = "REDACTIFY_API_TOKEN";

/// Environment variable that enables response-side restoration on the
/// LiteLLM endpoint with [`RestoreLimits::default`] when the state carries
/// no session table: `1`, `true` or `on` enable it; `0`, `false`, `off`
/// or an empty value leave it off; any other value refuses startup. It
/// needs a bearer token (restoration returns original values).
pub const LITELLM_RESTORE_ENV_VAR: &str = "REDACTIFY_LITELLM_RESTORE";

/// Environment variable naming the hash-chained JSONL audit file of the
/// socket server (the same variable and semantics as the MCP server):
/// when set and the state carries no audit sink, [`serve_with`] opens it
/// with [`FileAuditSink::open`](crate::guard::audit::FileAuditSink::open)
/// (an existing file is verified first and resumed; a file that does not
/// verify refuses startup) and records every decision in it.
pub const AUDIT_FILE_ENV_VAR: &str = "REDACTIFY_AUDIT_FILE";

/// Environment variable holding the optional key of the audit chain
/// (HMAC-SHA256 links; see [`AUDIT_FILE_ENV_VAR`]). An empty value, or one
/// that is not valid Unicode, refuses startup.
pub const AUDIT_KEY_ENV_VAR: &str = "REDACTIFY_AUDIT_KEY";

/// Environment variable setting the socket server's request body limit
/// in bytes (a whole number from [`MIN_BODY_LIMIT`] to
/// [`MAX_BODY_LIMIT`]; default [`MAX_BODY`]) when the state sets none
/// (see [`ApiState::with_max_body`]). Any other value refuses startup.
pub const BODY_LIMIT_ENV_VAR: &str = "REDACTIFY_MAX_BODY";

/// An access token the socket server requires as
/// `Authorization: Bearer <token>` (RFC 6750 section 2.1,
/// <https://www.rfc-editor.org/rfc/rfc6750>, retrieved 2026-10-31).
///
/// `Debug` never prints the token, and equality is checked in constant
/// time over the bytes of equal-length tokens.
///
/// # Examples
/// ```
/// # #[cfg(feature = "api")]
/// # {
/// use redactify::api::{ApiState, BearerToken};
///
/// let token = BearerToken::new("mF_9.B5f-4.1JqM").unwrap(); // the RFC example
/// let state = ApiState::default().with_bearer_token(token);
/// assert!(state.bearer_token.is_some());
/// assert!(BearerToken::new("two words").is_err());
/// # }
/// ```
#[derive(Clone)]
pub struct BearerToken(String);

impl BearerToken {
    /// Validates `token` against the RFC 6750 section 2.1 syntax
    /// `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`,
    /// the only form a client can send in the header.
    ///
    /// # Errors
    /// [`BearerTokenError::InvalidSyntax`] when `token` is empty or not a
    /// `b64token`.
    pub fn new(token: &str) -> Result<Self, BearerTokenError> {
        let body = token.trim_end_matches('=');
        let b64token = !body.is_empty()
            && body.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
            });
        if b64token {
            Ok(Self(token.to_owned()))
        } else {
            Err(BearerTokenError::InvalidSyntax)
        }
    }

    /// Whether `presented` is this token: a length check, then a
    /// comparison that reads every byte (no early exit on the first
    /// difference).
    fn matches(&self, presented: &str) -> bool {
        let (a, b) = (self.0.as_bytes(), presented.as_bytes());
        a.len() == b.len()
            && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(..)")
    }
}

impl PartialEq for BearerToken {
    fn eq(&self, other: &Self) -> bool {
        self.matches(&other.0)
    }
}

impl Eq for BearerToken {}

/// Why a bearer token was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BearerTokenError {
    /// The token is empty or not an RFC 6750 `b64token`.
    #[error(
        "a bearer token must be an RFC 6750 b64token: letters, digits and - . _ ~ + /, \
         optionally followed by = padding"
    )]
    InvalidSyntax,
    /// The environment variable is set but its value is not valid Unicode.
    #[error("{var} is set but its value is not valid Unicode")]
    NonUnicodeEnv {
        /// The variable name.
        var: &'static str,
    },
}

/// The bearer token named by [`API_TOKEN_ENV_VAR`]: `None` when the
/// variable is unset. The socket server ([`serve`], [`serve_with`]) reads
/// it at startup when the state carries no token.
///
/// # Errors
/// [`BearerTokenError::InvalidSyntax`] for an empty or malformed value and
/// [`BearerTokenError::NonUnicodeEnv`] for a value that is not valid
/// Unicode: the server then refuses to start (fail-closed) instead of
/// serving without the protection the operator asked for.
pub fn bearer_token_from_env() -> Result<Option<BearerToken>, BearerTokenError> {
    match std::env::var(API_TOKEN_ENV_VAR) {
        Ok(value) => BearerToken::new(&value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(BearerTokenError::NonUnicodeEnv {
            var: API_TOKEN_ENV_VAR,
        }),
    }
}

/// Server state with optional ML classifiers, NER, and audit sink.
#[derive(Clone, Default)]
pub struct ApiState {
    /// L2 security classifier (a prompt-injection / jailbreak model export).
    pub security: Option<Arc<dyn MlClassifier>>,
    /// L3 safety classifier (a multi-head content-safety model export).
    pub safety: Option<Arc<dyn MlClassifier>>,
    /// L1 NER recognizer (a token-classification model export or the NER
    /// router): free-prose person names join the PII findings of every
    /// endpoint, the stream endpoints included.
    pub ner: Option<Arc<dyn NerRecognizer>>,
    /// Audit sink: invoked with a metadata-only AuditRecord for every guard
    /// decision when attached. None (default)
    /// = no audit overhead, responses byte-identical.
    pub audit_sink: Option<AuditCallback>,
    /// Server-wide policy override (e.g. a TOML pack loaded from the
    /// `REDACTIFY_POLICY` env by the `config` feature; see
    /// [`crate::policy::Policy`]). None (default) = the built-in
    /// per-target policies. ToolResponse keeps at least its built-in
    /// strictness regardless (see [`crate::policy::Policy::for_target`]).
    pub policy: Option<crate::policy::Policy>,
    /// Bearer token the socket server requires on every request except
    /// `GET /health` (see the module docs). None (default) = no
    /// authentication; [`serve_with`] then reads [`API_TOKEN_ENV_VAR`].
    pub bearer_token: Option<BearerToken>,
    /// Server-held tool-call sessions of `/v1/tool/check` requests that
    /// name a `session_id` (default: an empty table with
    /// [`SessionLimits::default`](crate::guard::tools::SessionLimits);
    /// clones of the state share it).
    pub tool_sessions: Arc<ToolSessions>,
    /// Server-held vaults of LiteLLM calls: when set, the LiteLLM endpoint
    /// numbers the placeholders of a request-side call (`[TCKN_1]`) and
    /// restores the originals in the response-side calls of the same call
    /// (see the module docs). None (default) = no restoration: the
    /// endpoint never returns an original; [`serve_with`] then reads
    /// [`LITELLM_RESTORE_ENV_VAR`].
    pub litellm_restore: Option<Arc<RestoreSessions>>,
    /// Request body limit in bytes (`None` = [`MAX_BODY`]): larger bodies
    /// are answered 413. [`serve_with`] refuses a value outside
    /// [`MIN_BODY_LIMIT`]..=[`MAX_BODY_LIMIT`] and, when `None`, reads
    /// [`BODY_LIMIT_ENV_VAR`].
    pub max_body: Option<usize>,
    /// The Prometheus metrics of this server (`GET /metrics`; clones of
    /// the state share them).
    pub metrics: Arc<Metrics>,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // presence-only: the trait objects themselves are not Debug
        f.debug_struct("ApiState")
            .field("security", &self.security.is_some())
            .field("safety", &self.safety.is_some())
            .field("ner", &self.ner.is_some())
            .field("audit_sink", &self.audit_sink.is_some())
            .field("policy", &self.policy)
            .field("bearer_token", &self.bearer_token.is_some())
            .field("tool_sessions", &self.tool_sessions)
            .field("litellm_restore", &self.litellm_restore)
            .field("max_body", &self.max_body)
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl ApiState {
    /// Attaches the L2 security classifier (builder style).
    #[must_use]
    pub fn with_security(mut self, classifier: Arc<dyn MlClassifier>) -> Self {
        self.security = Some(classifier);
        self
    }

    /// Attaches the L3 safety classifier (builder style).
    #[must_use]
    pub fn with_safety(mut self, classifier: Arc<dyn MlClassifier>) -> Self {
        self.safety = Some(classifier);
        self
    }

    /// Attaches the L1 NER recognizer (builder style).
    #[must_use]
    pub fn with_ner(mut self, recognizer: Arc<dyn NerRecognizer>) -> Self {
        self.ner = Some(recognizer);
        self
    }

    /// Attaches an audit sink (builder style): every guard and sanitize
    /// decision and every stream Block event emits a metadata-only
    /// [`AuditRecord`](crate::guard::audit::AuditRecord) to it (see the
    /// module docs for the request id and layer fields). The sink is a
    /// plain callback - wrap it around
    /// [`ChainedAuditSink`](crate::guard::audit::ChainedAuditSink) for the
    /// tamper-evident JSONL chain.
    #[must_use]
    pub fn with_audit_sink(
        mut self,
        sink: Box<dyn Fn(&crate::guard::audit::AuditRecord) + Send + Sync>,
    ) -> Self {
        self.audit_sink = Some(Arc::from(sink));
        self
    }

    /// Attaches a server-wide policy override (builder style): every guard
    /// decision the server makes uses these lines instead of the built-in
    /// per-target defaults (ToolResponse still never gets looser than its
    /// built-in strictness), and its `default_locales` apply to every
    /// request that names no locales.
    #[must_use]
    pub fn with_policy(mut self, policy: crate::policy::Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Requires `token` on every socket request except `GET /health`
    /// (builder style; see the module docs for the responses). The pure
    /// handler ([`handle_request_with`]) sees no headers: an embedder that
    /// calls it directly owns authentication.
    #[must_use]
    pub fn with_bearer_token(mut self, token: BearerToken) -> Self {
        self.bearer_token = Some(token);
        self
    }

    /// Replaces the tool-call session table (builder style), e.g. to set
    /// other [`SessionLimits`](crate::guard::tools::SessionLimits).
    #[must_use]
    pub fn with_tool_sessions(mut self, sessions: ToolSessions) -> Self {
        self.tool_sessions = Arc::new(sessions);
        self
    }

    /// Enables response-side restoration on the LiteLLM endpoint with this
    /// session table (builder style). The endpoint then returns original
    /// PII values on response-side calls BY DESIGN: the socket server
    /// refuses to start it without a bearer token (see the module docs).
    #[must_use]
    pub fn with_litellm_restore(mut self, sessions: RestoreSessions) -> Self {
        self.litellm_restore = Some(Arc::new(sessions));
        self
    }

    /// Sets the request body limit in bytes (builder style; default
    /// [`MAX_BODY`]). The socket server refuses to start with a limit
    /// outside [`MIN_BODY_LIMIT`]..=[`MAX_BODY_LIMIT`]; the pure handler
    /// applies the value as given.
    ///
    /// # Examples
    /// ```
    /// # #[cfg(feature = "api")]
    /// # {
    /// use redactify::api::{handle_request_with, ApiState};
    ///
    /// let state = ApiState::default().with_max_body(4096);
    /// let big = format!(r#"{{"text":"{}"}}"#, "a".repeat(5000));
    /// assert_eq!(handle_request_with(&state, "POST", "/v1/redact", &big).status, 413);
    /// # }
    /// ```
    #[must_use]
    pub fn with_max_body(mut self, bytes: usize) -> Self {
        self.max_body = Some(bytes);
        self
    }

    /// The effective request body limit in bytes.
    fn body_limit(&self) -> usize {
        self.max_body.unwrap_or(MAX_BODY)
    }

    /// Whether the server policy runs in shadow mode (see
    /// [`Policy::dry_run`](crate::policy::Policy::dry_run)).
    fn dry_run(&self) -> bool {
        self.policy.as_ref().is_some_and(|p| p.dry_run)
    }

    /// Whether decision bodies report the per-type entity counts: only when
    /// the server policy configures entity actions or dry run (responses
    /// stay byte-identical otherwise).
    fn reports_entities(&self) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|p| p.dry_run || !p.entity_actions.is_empty())
    }

    /// Whether any model (classifier or recognizer) is attached (reported by
    /// `/health`).
    #[must_use]
    pub fn ml_active(&self) -> bool {
        self.security.is_some() || self.safety.is_some() || self.ner.is_some()
    }

    /// The audit layer of a guard or sanitize decision: the ML classifiers
    /// (L2/L3) take part whenever one is attached.
    fn decision_layer(&self) -> &'static str {
        if self.security.is_some() || self.safety.is_some() {
            LAYER_ML
        } else {
            LAYER_DETERMINISTIC
        }
    }

    /// The audit layer of a stream Block event: the stream runs only the
    /// security classifier (L2).
    fn stream_layer(&self) -> &'static str {
        if self.security.is_some() {
            LAYER_ML
        } else {
            LAYER_DETERMINISTIC
        }
    }

    /// Emits the decision summary of a LiteLLM endpoint decision (see
    /// [`Self::emit_decision`]).
    fn emit_audit(&self, request_id: Option<&str>, decision: &Decision) {
        self.emit_decision(litellm::PATH, request_id, decision);
    }

    /// Records one decision of `endpoint`: its metrics, and its summary
    /// record to the audit sink when attached (a dry-run decision is
    /// recorded with the decided action, see
    /// [`audit_from_decision`](crate::policy::audit_from_decision)).
    fn emit_decision(&self, endpoint: &str, request_id: Option<&str>, decision: &Decision) {
        self.metrics.observe_decision(endpoint, decision);
        if let Some(sink) = &self.audit_sink {
            sink(&crate::policy::audit_from_decision(
                audit_request_id(request_id),
                self.decision_layer(),
                decision,
            ));
        }
    }

    /// Emits the record of a stream Block event to the audit sink when
    /// attached. The event carries no score: the record's score is 0.0 and
    /// the rationale names the signal and its score.
    ///
    /// In dry-run mode the record carries guard `DRY_RUN` and a rationale
    /// prefixed `dry run (not enforced): would Block; `.
    fn emit_stream_block_audit(&self, endpoint: &str, request_id: Option<&str>, rationale: &str) {
        let dry_run = self.dry_run();
        self.metrics.observe_stream_block(endpoint, dry_run);
        if let Some(sink) = &self.audit_sink {
            let mut record = crate::guard::audit::AuditRecord::decision(
                audit_request_id(request_id),
                self.stream_layer(),
                0.0,
                GuardAction::Block,
                if dry_run {
                    format!("dry run (not enforced): would Block; {rationale}")
                } else {
                    rationale.to_owned()
                },
            );
            if dry_run {
                "DRY_RUN".clone_into(&mut record.guard);
            }
            sink(&record);
        }
    }

    /// The NER recognizer as a slice for the detector / guard builders
    /// (empty when absent: zero overhead, identical to before).
    fn ner_slice(&self) -> Vec<&dyn NerRecognizer> {
        self.ner.as_deref().into_iter().collect()
    }

    /// The guard pipeline of one request: the server-wide policy override
    /// (see [`Self::with_policy`]), the request's locales (the guard
    /// resolves the EFFECTIVE list: the request's when non-empty, else the
    /// policy's `default_locales`, else tr+en), the attached NER recognizer,
    /// the request's `context` texts and `ignore` allowlist, and the
    /// attached ML classifiers (with none attached the guard stays
    /// deterministic). Its [`Guard::detector`] is the detector of the
    /// detect, redact and vault endpoints too: one effective-locale rule
    /// for every endpoint.
    fn guard<'a>(
        &'a self,
        target: GuardTarget,
        locales: &'a [&'a str],
        ner: &'a [&'a dyn NerRecognizer],
        context: &'a [&'a str],
        ignored: &'a [&'a str],
    ) -> Guard<'a> {
        Guard::new(target)
            .with_policy(self.policy.as_ref())
            .with_locales(locales)
            .with_ner(ner)
            .with_context(context)
            .with_ignored(ignored)
            .with_ml(
                MlRouter::default(),
                self.security.as_deref(),
                self.safety.as_deref(),
            )
    }

    /// The `/health` body: overall status (`degraded` when any attached
    /// model reports degraded health), version, whether models are
    /// attached, and the health of each model slot (`null` when absent).
    fn health(&self) -> serde_json::Value {
        let security = self
            .security
            .as_deref()
            .map(|c| health_json(ml_degraded_reason(&c.health())));
        let safety = self
            .safety
            .as_deref()
            .map(|c| health_json(ml_degraded_reason(&c.health())));
        let ner = self
            .ner
            .as_deref()
            .map(|r| health_json(ner_degraded_reason(&r.health())));
        let degraded = [&security, &safety, &ner]
            .iter()
            .any(|h| h.as_ref().is_some_and(|v| v["status"] != "ok"));
        let mut body = serde_json::json!({
            "status": if degraded { "degraded" } else { "ok" },
            "version": env!("CARGO_PKG_VERSION"),
            // true only when models are actually ATTACHED (not just compiled in)
            "ml_active": self.ml_active(),
            "ml_health": {
                "security": security,
                "safety": safety,
                "ner": ner,
            },
        });
        // shadow mode is announced (the field is absent otherwise)
        if self.dry_run() {
            body["dry_run"] = serde_json::Value::Bool(true);
        }
        body
    }
}

/// Audit layer label of the deterministic pipeline.
const LAYER_DETERMINISTIC: &str = "L0+L1";

/// Audit layer label when ML classifiers take part.
const LAYER_ML: &str = "L0+L1+L2/L3";

/// Default request body limit (1 MiB); see [`ApiState::with_max_body`].
pub const MAX_BODY: usize = 1024 * 1024;

/// Smallest body limit the socket server accepts (1 KiB).
pub const MIN_BODY_LIMIT: usize = 1024;

/// Largest body limit the socket server accepts (16 MiB): each of the 4
/// workers holds a whole body plus its parsed JSON in memory.
pub const MAX_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Maximum number of calls in the `history` of a `/v1/tool/check`
/// request (the tool guard's own bound, re-exported here).
pub use crate::guard::tools::MAX_TOOL_HISTORY;

/// Maximum length of the optional `request_id` field (printable ASCII,
/// carried into audit records).
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Per-process counter behind the generated audit request ids.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// The audit request id: the caller's, else the next counter value.
fn audit_request_id(explicit: Option<&str>) -> String {
    explicit.map_or_else(
        || format!("api-{}", NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)),
        str::to_owned,
    )
}

/// Every POST endpoint, in documentation order: routing, the 405 answer and
/// the `/` index share this one list.
const POST_ENDPOINTS: &[&str] = &[
    "/v1/detect",
    "/v1/redact",
    "/v1/json/redact",
    "/v1/guard",
    "/v1/sanitize",
    "/v1/batch/detect",
    "/v1/batch/redact",
    "/v1/batch/sanitize",
    "/v1/stream/sanitize",
    "/v1/stream/sse",
    "/v1/vault/pseudonymize",
    "/v1/vault/restore",
    "/v1/tool/check",
    litellm::PATH,
];

/// The SSE endpoint (served by the socket layer only).
const SSE_PATH: &str = "/v1/stream/sse";

/// The buffered NDJSON stream endpoint.
const NDJSON_PATH: &str = "/v1/stream/sanitize";

/// The Prometheus metrics endpoint.
const METRICS_PATH: &str = "/metrics";

/// The liveness endpoint (the one path that needs no bearer token).
const HEALTH_PATH: &str = "/health";

/// The OpenAPI document.
const OPENAPI_PATH: &str = "/openapi.json";

/// The endpoint index.
const INDEX_PATH: &str = "/";

/// Every GET endpoint: routing, the 405 answer, the `/` index and the
/// metrics labels share this one list (with [`POST_ENDPOINTS`]).
const GET_ENDPOINTS: &[&str] = &[HEALTH_PATH, OPENAPI_PATH, METRICS_PATH, INDEX_PATH];

/// The Content-Type of the metrics body: the text exposition format 0.0.4.
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// A rendered API response: HTTP status + JSON body.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ApiResponse {
    /// HTTP status code (200, 400, 404, 405, 413).
    pub status: u16,
    /// JSON body (always valid JSON; errors use `{"error":{...}}`). The
    /// one exception is a successful `/v1/stream/sanitize` response: NDJSON,
    /// one JSON event per line.
    pub body: String,
}

/// Handler result: an early error response is the `Err` side.
type Handled = Result<ApiResponse, ApiResponse>;

fn ok(value: serde_json::Value) -> ApiResponse {
    ApiResponse {
        status: 200,
        body: value.to_string(),
    }
}

fn err(status: u16, code: &str, message: impl Into<String>) -> ApiResponse {
    ApiResponse {
        status,
        body: serde_json::json!({ "error": { "code": code, "message": message.into() } })
            .to_string(),
    }
}

/// The Content-Type of a response: NDJSON for a successful buffered stream
/// response, JSON for everything else (errors included).
fn content_type_for(path: &str, status: u16) -> &'static str {
    if status == 200 && path == NDJSON_PATH {
        "application/x-ndjson"
    } else if status == 200 && path == METRICS_PATH {
        METRICS_CONTENT_TYPE
    } else {
        "application/json"
    }
}

/// Parses the optional `target` field via the single source of truth:
/// [`GuardTarget::from_str`](std::str::FromStr) (aliases included). Absent
/// or `null` is `user_prompt`; anything else that is not a target name (a
/// non-string included) is a 400 whose message does not echo the value.
fn parse_target(v: &serde_json::Value) -> Result<GuardTarget, ApiResponse> {
    let bad_target = || {
        err(
            400,
            "bad_target",
            "`target` must be one of user_prompt | tool_response | model_output \
             (aliases: user, prompt, tool, tool-response, model, model-output)",
        )
    };
    match v.get("target") {
        None | Some(serde_json::Value::Null) => Ok(GuardTarget::UserPrompt),
        Some(serde_json::Value::String(s)) => s.parse().map_err(|_| bad_target()),
        Some(_) => Err(bad_target()),
    }
}

/// The optional `request_id` field: 1 to [`MAX_REQUEST_ID_LEN`] printable
/// ASCII characters (it is copied into audit records, so it must not carry
/// control characters or arbitrary payloads).
fn request_id_from(v: &serde_json::Value) -> Result<Option<String>, ApiResponse> {
    match v.get("request_id") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s))
            if !s.is_empty()
                && s.len() <= MAX_REQUEST_ID_LEN
                && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ') =>
        {
            Ok(Some(s.clone()))
        }
        Some(_) => Err(err(
            400,
            "bad_request_id",
            format!(
                "`request_id` must be a string of 1 to {MAX_REQUEST_ID_LEN} printable ASCII characters"
            ),
        )),
    }
}

/// The `locales` request field as `&str` refs (empty when absent, `null`
/// or empty: the effective list then comes from the policy or the default
/// set). Every entry must be a string from
/// [`SUPPORTED_LOCALES`](crate::SUPPORTED_LOCALES), compared exactly;
/// anything else is a 400 that names the position, never the value.
fn locale_refs_from(v: &serde_json::Value) -> Result<Vec<&str>, ApiResponse> {
    let codes = match v.get("locales") {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(serde_json::Value::Array(codes)) => codes,
        Some(_) => {
            return Err(err(
                400,
                "bad_locales",
                format!(
                    "`locales` must be an array of locale codes ({})",
                    crate::SUPPORTED_LOCALES.join(", ")
                ),
            ))
        }
    };
    codes
        .iter()
        .enumerate()
        .map(|(i, code)| match code.as_str() {
            Some(code) if crate::SUPPORTED_LOCALES.contains(&code) => Ok(code),
            _ => Err(err(
                400,
                "bad_locales",
                format!(
                    "`locales[{i}]` is not a supported locale code ({}; lowercase, no surrounding spaces)",
                    crate::SUPPORTED_LOCALES.join(", ")
                ),
            )),
        })
        .collect()
}

/// The optional `context` field: an array of strings (the text the request
/// text answers, e.g. the previous conversation turn); empty when absent
/// or `null`. Anything else is a 400 that names the position, never the
/// value.
fn context_from(v: &serde_json::Value) -> Result<Vec<&str>, ApiResponse> {
    let bad = |what: String| err(400, "bad_context", what);
    match v.get("context") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(texts)) => texts
            .iter()
            .enumerate()
            .map(|(i, t)| {
                t.as_str()
                    .ok_or_else(|| bad(format!("`context[{i}]` is not a string")))
            })
            .collect(),
        Some(_) => Err(bad("`context` must be an array of strings".to_owned())),
    }
}

/// Most words one request's `words` deny list may hold.
const MAX_DENY_WORDS: usize = 256;
/// Longest single deny-list word, in bytes.
const MAX_DENY_WORD_LEN: usize = 128;
/// Longest `mask` template, in bytes.
const MAX_MASK_TEMPLATE_LEN: usize = 64;
/// Most trailing characters a partial mask may keep visible.
const MAX_KEEP_LAST: u64 = 64;
/// Longest `system_prompt`, in bytes.
const MAX_SYSTEM_PROMPT_LEN: usize = 64 * 1024;
/// Most patterns one request's `patterns` list may hold.
const MAX_PATTERNS: usize = 16;
/// Most cue words of one request pattern.
const MAX_PATTERN_CUES: usize = 16;
/// Longest single cue word of a request pattern, in bytes.
const MAX_PATTERN_CUE_LEN: usize = 64;
/// The entity label of a request pattern that names none.
const PATTERN_LABEL: &str = "CUSTOM_PATTERN";
/// The entity label of every request deny-list match (`[CUSTOM_WORD]`).
/// One fixed label: a request must not register labels (they live for the
/// whole process).
const DENY_WORD_LABEL: &str = "CUSTOM_WORD";

/// Per-request detection extras: the mask style (`mask`) and the literal
/// deny list (`words`, `words_ignore_case`). Every error names the field,
/// never a value.
struct RequestExtras {
    mask: MaskStyle,
    /// The deny-list rule (when `words` is given), then the `patterns`.
    rules: Vec<CustomRule>,
}

impl RequestExtras {
    fn from_request(v: &serde_json::Value) -> Result<Self, ApiResponse> {
        let mut rules: Vec<CustomRule> = deny_rule_from(v)?.into_iter().collect();
        rules.extend(pattern_rules_from(v)?);
        Ok(Self {
            mask: mask_from(v)?,
            rules,
        })
    }

    /// The rule list a guard takes (`with_custom_rules`).
    fn rule_refs(&self) -> Vec<&CustomRule> {
        self.rules.iter().collect()
    }
}

/// Most entries of a request's `mask_by_type`.
const MAX_MASK_BY_TYPE: usize = 32;

/// One mask style object: `{"style": "label"}`, `{"style": "template",
/// "template": "[REDACTED]"}` (1 to 64 bytes; every `{type}` is replaced by
/// the type label, a text without it is a fixed replacement), `{"style":
/// "char", "char": "*"}` (exactly one character), `{"style": "partial",
/// "keep_last": 4, "char": "*"}` (`keep_last` 0 to 64: all but the last
/// characters masked), `{"style": "mask_first", "count": 3, "char": "*"}`
/// or `{"style": "mask_last", "count": 4, "char": "*"}` (`count` 1 to 64:
/// only that many characters from the start / end masked). A pseudonym style
/// is not available over HTTP: it needs a server-held key. `what` names the
/// field in errors.
fn mask_object(
    obj: &serde_json::Map<String, serde_json::Value>,
    what: &str,
) -> Result<MaskStyle, ApiResponse> {
    let bad = |m: &str| err(400, "bad_mask", format!("`{what}`: {m}"));
    let one_char = |field: &str| -> Result<char, ApiResponse> {
        let s = obj
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| bad(&format!("`{field}` must be a one-character string")))?;
        let mut it = s.chars();
        match (it.next(), it.next()) {
            (Some(c), None) if !c.is_control() => Ok(c),
            _ => Err(bad(&format!(
                "`{field}` must be exactly one printable character"
            ))),
        }
    };
    let count = |field: &str, min: u64| -> Result<usize, ApiResponse> {
        obj.get(field)
            .and_then(serde_json::Value::as_u64)
            .filter(|k| (min..=MAX_KEEP_LAST).contains(k))
            .map(|k| k as usize)
            .ok_or_else(|| {
                bad(&format!(
                    "`{field}` must be an integer from {min} to {MAX_KEEP_LAST}"
                ))
            })
    };
    match obj.get("style").and_then(serde_json::Value::as_str) {
        Some("label") => Ok(MaskStyle::Label),
        Some("template") => {
            let t = obj
                .get("template")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| bad("`template` must be a string"))?;
            if t.is_empty() || t.len() > MAX_MASK_TEMPLATE_LEN {
                return Err(bad("`template` must be 1 to 64 bytes"));
            }
            Ok(MaskStyle::Template(t.to_owned()))
        }
        Some("char") => Ok(MaskStyle::Char(one_char("char")?)),
        Some("partial") => Ok(MaskStyle::Partial {
            keep_last: count("keep_last", 0)?,
            ch: one_char("char")?,
        }),
        Some("mask_first") => Ok(MaskStyle::MaskFirst {
            count: count("count", 1)?,
            ch: one_char("char")?,
        }),
        Some("mask_last") => Ok(MaskStyle::MaskLast {
            count: count("count", 1)?,
            ch: one_char("char")?,
        }),
        _ => Err(bad(
            "`style` must be one of \"label\", \"template\", \"char\", \"partial\", \"mask_first\", \"mask_last\"",
        )),
    }
}

/// The request's mask strategy: the optional `mask` object (default: label)
/// and the optional `mask_by_type` object, which maps entity type labels
/// (a built-in type or a label the server policy registered; at most 32) to
/// their own mask object. A type without an entry uses `mask`. Errors name
/// the field, never a value.
fn mask_from(v: &serde_json::Value) -> Result<MaskStyle, ApiResponse> {
    let bad = |m: &str| err(400, "bad_mask", m.to_owned());
    let default = match v.get("mask") {
        None | Some(serde_json::Value::Null) => MaskStyle::default(),
        Some(serde_json::Value::Object(o)) => mask_object(o, "mask")?,
        Some(_) => return Err(bad("`mask` must be an object")),
    };
    let by_type = match v.get("mask_by_type") {
        None | Some(serde_json::Value::Null) => return Ok(default),
        Some(serde_json::Value::Object(o)) => o,
        Some(_) => return Err(bad("`mask_by_type` must be an object")),
    };
    if by_type.len() > MAX_MASK_BY_TYPE {
        return Err(bad("`mask_by_type` holds more than 32 entries"));
    }
    let mut overrides = Vec::with_capacity(by_type.len());
    for (i, (label, style)) in by_type.iter().enumerate() {
        let kind = label.parse::<EntityType>().map_err(|_| {
            bad(&format!(
                "`mask_by_type` entry {i} is not a known entity label"
            ))
        })?;
        let obj = style
            .as_object()
            .ok_or_else(|| bad(&format!("`mask_by_type` entry {i} must be a mask object")))?;
        overrides.push((kind, mask_object(obj, &format!("mask_by_type entry {i}"))?));
    }
    Ok(MaskStyle::by_type(default, overrides))
}

/// The optional `system_prompt` of a guard / sanitize request: the prompt a
/// `model_output` text is checked against for leakage (`PROMPT_LEAK`). A
/// string of at most 64 KiB; never echoed. Ignored for other targets.
fn system_prompt_from(v: &serde_json::Value) -> Result<Option<&str>, ApiResponse> {
    match v.get("system_prompt") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(p)) if p.len() <= MAX_SYSTEM_PROMPT_LEN => Ok(Some(p)),
        Some(serde_json::Value::String(_)) => Err(err(
            400,
            "bad_system_prompt",
            "`system_prompt` is longer than 64 KiB",
        )),
        Some(_) => Err(err(
            400,
            "bad_system_prompt",
            "`system_prompt` must be a string",
        )),
    }
}

/// Adds the request's system prompt (when given) to a guard.
fn with_prompt<'a>(guard: Guard<'a>, prompt: Option<&str>) -> Guard<'a> {
    match prompt {
        Some(p) => guard.with_system_prompt(p),
        None => guard,
    }
}

/// The optional `patterns` list: custom regular expressions, each
/// `{"pattern": "...", "label"?: "...", "cues"?: ["..."], "score"?: 0.9}`.
/// A pattern is compiled by [`CustomRule::new_linear`]: the linear-time
/// syntax only (no look-around, back-references or atomic groups), at most
/// 256 bytes, a shortest match of 3 characters, a bounded compiled size, so
/// a caller never chooses the scan cost. At most 16 patterns. The `label`
/// must already exist (a built-in type, or a label the server policy
/// registered): a request can never register a label, which would live for
/// the whole process; without a label the match is `CUSTOM_PATTERN`.
/// `cues` (at most 16 words of at most 64 bytes) make a match count only
/// next to one of them; `score` is 0.0 to 1.0. Errors name the field and
/// position, never the pattern.
fn pattern_rules_from(v: &serde_json::Value) -> Result<Vec<CustomRule>, ApiResponse> {
    let bad = |m: String| err(400, "bad_patterns", m);
    let list = match v.get("patterns") {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(serde_json::Value::Array(a)) => a,
        Some(_) => return Err(bad("`patterns` must be an array of objects".to_owned())),
    };
    if list.len() > MAX_PATTERNS {
        return Err(bad(format!(
            "`patterns` holds more than {MAX_PATTERNS} entries"
        )));
    }
    let mut rules = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| bad(format!("`patterns[{i}]` must be an object")))?;
        if obj
            .keys()
            .any(|k| !matches!(k.as_str(), "pattern" | "label" | "cues" | "score"))
        {
            return Err(bad(format!(
                "`patterns[{i}]` has a field other than pattern, label, cues, score"
            )));
        }
        let pattern = obj
            .get("pattern")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| bad(format!("`patterns[{i}].pattern` must be a string")))?;
        let kind = match obj.get("label") {
            None | Some(serde_json::Value::Null) => EntityType::custom(PATTERN_LABEL)
                .map_err(|_| bad("custom patterns unavailable".to_owned()))?,
            Some(serde_json::Value::String(label)) => label
                .parse::<EntityType>()
                .map_err(|_| bad(format!("`patterns[{i}].label` is not a known entity label")))?,
            Some(_) => return Err(bad(format!("`patterns[{i}].label` must be a string"))),
        };
        let mut rule = CustomRule::new_linear(kind, pattern)
            .map_err(|e| bad(format!("`patterns[{i}].pattern`: {e}")))?;
        match obj.get("cues") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(cues)) => {
                let mut words: Vec<&str> = Vec::with_capacity(cues.len());
                for cue in cues {
                    match cue.as_str() {
                        Some(c) if c.len() <= MAX_PATTERN_CUE_LEN => words.push(c),
                        _ => {
                            return Err(bad(format!(
                                "`patterns[{i}].cues` must hold strings of at most {MAX_PATTERN_CUE_LEN} bytes"
                            )))
                        }
                    }
                }
                if words.len() > MAX_PATTERN_CUES {
                    return Err(bad(format!(
                        "`patterns[{i}].cues` holds more than {MAX_PATTERN_CUES} entries"
                    )));
                }
                if !words.is_empty() {
                    rule = rule.with_cue(&words);
                }
            }
            Some(_) => {
                return Err(bad(format!(
                    "`patterns[{i}].cues` must be an array of strings"
                )))
            }
        }
        match obj.get("score") {
            None | Some(serde_json::Value::Null) => {}
            Some(n) => match n.as_f64().filter(|f| (0.0..=1.0).contains(f)) {
                Some(f) => rule = rule.with_score(f as f32),
                None => {
                    return Err(bad(format!(
                        "`patterns[{i}].score` must be a number from 0.0 to 1.0"
                    )))
                }
            },
        }
        rules.push(rule);
    }
    Ok(rules)
}

/// The optional `words` deny list: literal strings (not patterns, so a
/// caller never chooses the scan cost), at most 256 of at most 128 bytes
/// each, matched as whole words, case-sensitive unless
/// `"words_ignore_case": true`. Empty strings are dropped. Matches carry
/// the fixed `CUSTOM_WORD` label.
fn deny_rule_from(v: &serde_json::Value) -> Result<Option<CustomRule>, ApiResponse> {
    let bad = |m: &str| err(400, "bad_words", m.to_owned());
    let ignore_case = match v.get("words_ignore_case") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => return Err(bad("`words_ignore_case` must be a boolean")),
    };
    let list = match v.get("words") {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::Array(a)) => a,
        Some(_) => return Err(bad("`words` must be an array of strings")),
    };
    if list.len() > MAX_DENY_WORDS {
        return Err(bad("`words` holds more than 256 entries"));
    }
    let mut words: Vec<&str> = Vec::with_capacity(list.len());
    for (i, w) in list.iter().enumerate() {
        let w = w
            .as_str()
            .ok_or_else(|| bad(&format!("`words[{i}]` is not a string")))?;
        if w.len() > MAX_DENY_WORD_LEN {
            return Err(bad(&format!("`words[{i}]` is longer than 128 bytes")));
        }
        words.push(w);
    }
    let kind = EntityType::custom(DENY_WORD_LABEL).map_err(|_| bad("deny list unavailable"))?;
    Ok(Some(if ignore_case {
        CustomRule::deny_list_ignore_case(kind, &words)
    } else {
        CustomRule::deny_list(kind, &words)
    }))
}

/// The detection options of a detect / redact request.
struct PiiOptions<'v> {
    /// Requested locale codes (empty = policy default, else tr+en).
    locales: Vec<&'v str>,
    /// Allowlisted values (`ignore`).
    ignored: Vec<&'v str>,
    /// Minimum score (`threshold`; 0.0 when absent).
    threshold: f32,
    /// Context texts whose cues unlock cue-gated rules (`context`).
    context: Vec<&'v str>,
    /// The request's mask style and deny list.
    extras: RequestExtras,
}

/// The optional `ignore` allowlist (string entries; anything else in the
/// array is skipped): an allowlisted value is neither reported nor masked.
fn ignored_from(v: &serde_json::Value) -> Vec<&str> {
    v.get("ignore")
        .and_then(serde_json::Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default()
}

impl<'v> PiiOptions<'v> {
    fn from_request(v: &'v serde_json::Value) -> Result<Self, ApiResponse> {
        Ok(Self {
            locales: locale_refs_from(v)?,
            ignored: ignored_from(v),
            threshold: v
                .get("threshold")
                .and_then(serde_json::Value::as_f64)
                .map_or(0.0, |f| f as f32),
            context: context_from(v)?,
            extras: RequestExtras::from_request(v)?,
        })
    }

    /// The user-prompt guard of the request: the server state plus the
    /// request's locales, context, allowlist, custom rules and mask style.
    /// `ner` and `rules` come from [`ApiState::ner_slice`] and
    /// [`RequestExtras::rule_refs`]; the caller keeps them alive.
    fn guard<'a>(
        &'a self,
        state: &'a ApiState,
        ner: &'a [&'a dyn NerRecognizer],
        rules: &'a [&'a CustomRule],
    ) -> Guard<'a> {
        state
            .guard(
                GuardTarget::UserPrompt,
                &self.locales,
                ner,
                &self.context,
                &self.ignored,
            )
            .with_custom_rules(rules)
            .with_mask_style(self.extras.mask.clone())
    }

    /// The request's detector: the guard's (effective locales, NER,
    /// context, allowlist, normalization on) plus the threshold, applied
    /// inside overlap resolution.
    fn detector<'a>(&'a self, guard: &'a Guard<'_>) -> Detector<'a> {
        guard.detector().with_threshold(self.threshold)
    }
}

/// The redacted rendering of `text`: leaked credentials masked FIRST
/// (`[SECRET:VENDOR]`; a key is never split by a PII span), then PII with
/// the detector (incompletely scanned lines become `[SCAN_INCOMPLETE]`).
fn redact_output(detector: &Detector<'_>, text: &str) -> String {
    detector.redact(&crate::guard::mask_secrets(text))
}

/// Parses a raw NDJSON body for the stream endpoints: every non-empty line
/// must be a JSON string (one chunk per line - the natural dump shape for a
/// streaming client). Empty bodies and any non-string line yield `None`.
fn parse_ndjson_chunks(body: &str) -> Option<Vec<String>> {
    let mut chunks = Vec::new();
    let mut any = false;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        any = true;
        chunks.push(serde_json::from_str::<String>(line).ok()?);
    }
    any.then_some(chunks)
}

/// One entity as span metadata (the raw value is never echoed).
fn entity_json(e: &Entity) -> serde_json::Value {
    serde_json::json!({
        "type": e.kind.as_str(),
        // byte offsets into the request text (raw value deliberately
        // not echoed - responses stay safe to log)
        "start": e.start,
        "end": e.end,
        "score": e.score,
    })
}

fn entities_json(pii: &[Entity]) -> serde_json::Value {
    serde_json::Value::Array(pii.iter().map(entity_json).collect())
}

/// One explanation (`"explain": true` on `/v1/detect`): where the entity
/// came from and how it scored - configured strings and numbers only,
/// never request text.
fn explanation_json(why: &Explanation) -> serde_json::Value {
    let source = if let DetectionSource::Rule { id } = why.source {
        serde_json::json!({ "kind": "RULE", "id": id })
    } else if let DetectionSource::Custom { index } = why.source {
        serde_json::json!({ "kind": "CUSTOM", "index": index })
    } else if let DetectionSource::Ner { name } = why.source {
        serde_json::json!({ "kind": "NER", "name": name })
    } else {
        serde_json::json!({ "kind": "OTHER" })
    };
    serde_json::json!({
        "source": source,
        "validator_passed": why.validator_passed,
        "cue": why.cue,
        "base_score": why.base_score,
        "score": why.score,
        "view": why.view.as_str(),
    })
}

/// The one health shape of every model slot: `{"status": "ok"}` without a
/// degraded reason, else `{"status": "degraded", "reason"}` (reasons
/// never carry input text).
fn health_json(degraded_reason: Option<&str>) -> serde_json::Value {
    match degraded_reason {
        None => serde_json::json!({ "status": "ok" }),
        Some(reason) => serde_json::json!({ "status": "degraded", "reason": reason }),
    }
}

/// The reason reported for a health state this server does not know (both
/// health enums are non-exhaustive).
const UNKNOWN_HEALTH: &str = "unknown health state";

/// A classifier's degraded reason (`None` when healthy).
fn ml_degraded_reason(h: &MlHealth) -> Option<&str> {
    if *h == MlHealth::Ok {
        None
    } else if let MlHealth::Degraded(reason) = h {
        Some(reason)
    } else {
        Some(UNKNOWN_HEALTH)
    }
}

/// A recognizer's degraded reason (`None` when healthy).
fn ner_degraded_reason(h: &NerHealth) -> Option<&'static str> {
    if *h == NerHealth::Ok {
        None
    } else if let NerHealth::Degraded(reason) = h {
        Some(reason)
    } else {
        Some(UNKNOWN_HEALTH)
    }
}

fn decision_json(state: &ApiState, d: &Decision) -> serde_json::Value {
    let signals: Vec<serde_json::Value> = d
        .signals
        .iter()
        .map(|s| {
            serde_json::json!({
                "kind": s.kind.as_str().to_owned(),
                "score": s.score,
                "evidence": s.evidence,
                "rationale": s.rationale,
            })
        })
        .collect();
    let verdicts: Vec<serde_json::Value> = d
        .verdicts
        .iter()
        .map(|v| {
            serde_json::json!({
                "category": v.category.as_str(),
                "score": v.score,
                "severity": v.severity.as_str(),
                "action": v.action.to_string(),
                "rationale": v.rationale,
            })
        })
        .collect();
    let relevance_downgraded: Vec<serde_json::Value> = d
        .relevance_downgraded
        .iter()
        .map(|s| {
            serde_json::json!({
                "type": s.kind.as_str(),
                "start": s.start,
                "end": s.end,
            })
        })
        .collect();
    let mut out = serde_json::json!({
        "action": d.action.to_string(),
        "rationale": d.rationale,
        "mask_summary": d.mask_summary,
        "signals": signals,
        "verdicts": verdicts,
        "relevance_downgraded": relevance_downgraded,
    });
    // opt-in fields: present only when the server policy configures
    // entity actions or dry run (bodies stay byte-identical otherwise)
    if state.reports_entities() {
        out["entities"] = d
            .entity_counts
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": c.kind.as_str(),
                    "action": c.action.as_str(),
                    "count": c.count,
                })
            })
            .collect();
    }
    if let Some(decided) = d.dry_run_action {
        out["dry_run"] = serde_json::Value::Bool(true);
        out["dry_run_action"] = serde_json::Value::String(decided.to_string());
    }
    out
}

/// Handles one request with the DEFAULT (deterministic-only) state. Pure:
/// no sockets, no global state.
#[must_use]
pub fn handle_request(method: &str, path: &str, body: &str) -> ApiResponse {
    handle_request_with(&ApiState::default(), method, path, body)
}

/// Handles one logical request against the given server state. Pure: no
/// sockets - the HTTP loop and the tests both call this. The only side
/// effect is the audit sink of `state`, when attached.
#[must_use]
pub fn handle_request_with(state: &ApiState, method: &str, path: &str, body: &str) -> ApiResponse {
    let started = std::time::Instant::now();
    let r = route(state, method, path, body);
    state
        .metrics
        .observe_request(path, r.status, started.elapsed());
    r
}

/// The 413 answer of a body above `limit` bytes.
fn too_large(limit: usize) -> ApiResponse {
    err(
        413,
        "payload_too_large",
        format!("body exceeds {limit} bytes"),
    )
}

/// Routes one request (see [`handle_request_with`]).
fn route(state: &ApiState, method: &str, path: &str, body: &str) -> ApiResponse {
    if body.len() > state.body_limit() {
        return too_large(state.body_limit());
    }

    match (method, path) {
        ("GET", HEALTH_PATH) => ok(state.health()),
        // the text exposition format (see the `metrics` module), served
        // `text/plain; version=0.0.4` by the socket layer
        ("GET", METRICS_PATH) => ApiResponse {
            status: 200,
            body: state.metrics.render(),
        },
        ("GET", OPENAPI_PATH) => ok(openapi::document()),
        ("GET", INDEX_PATH) => {
            let mut endpoints: Vec<String> = GET_ENDPOINTS
                .iter()
                .filter(|p| **p != INDEX_PATH)
                .map(|p| format!("GET {p}"))
                .collect();
            endpoints.extend(POST_ENDPOINTS.iter().map(|p| {
                if *p == SSE_PATH {
                    format!("POST {p} (socket server only)")
                } else {
                    format!("POST {p}")
                }
            }));
            ok(serde_json::json!({
                "name": "redactify",
                "version": env!("CARGO_PKG_VERSION"),
                "endpoints": endpoints,
            }))
        }
        // SSE streaming exists only at the socket layer (a pure handler
        // returns one buffered value by contract); point embedders at the
        // buffered NDJSON form
        ("POST", SSE_PATH) => err(
            400,
            "socket_only",
            "SSE streaming is served by the socket server (POST /v1/stream/sse); \
             the pure handler offers the buffered form at POST /v1/stream/sanitize",
        ),
        ("POST", p) if POST_ENDPOINTS.contains(&p) => {
            handle_endpoint(state, path, body).unwrap_or_else(|e| e)
        }
        // wrong method on a known path -> 405; unknown path -> 404
        (_, p) if GET_ENDPOINTS.contains(&p) => err(405, "method_not_allowed", "GET only"),
        (_, p) if POST_ENDPOINTS.contains(&p) => err(405, "method_not_allowed", "POST only"),
        _ => err(404, "unknown_path", format!("no such endpoint: {path}")),
    }
}

fn handle_endpoint(state: &ApiState, path: &str, body: &str) -> Handled {
    // the stream endpoint also accepts raw NDJSON: its own parser (shared
    // with the SSE socket endpoint)
    if path == NDJSON_PATH {
        return handle_stream(state, body);
    }
    let mut v: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        err(
            400,
            "bad_json",
            format!("request body is not valid JSON: {e}"),
        )
    })?;
    match path {
        "/v1/tool/check" => return tool_check(state, &v),
        "/v1/json/redact" => return json_redact(state, &mut v),
        "/v1/batch/detect" | "/v1/batch/redact" | "/v1/batch/sanitize" => {
            return batch(state, path, &v)
        }
        litellm::PATH => return litellm::handle(state, &v),
        _ => {}
    }
    let text = v
        .get("text")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| err(400, "missing_field", "required string field `text`"))?;
    match path {
        "/v1/detect" => detect(state, &v, text),
        "/v1/redact" => {
            let opts = PiiOptions::from_request(&v)?;
            let ner = state.ner_slice();
            let rules = opts.extras.rule_refs();
            let guard = opts.guard(state, &ner, &rules);
            Ok(ok(redact_json(&opts.detector(&guard), text)))
        }
        "/v1/guard" | "/v1/sanitize" => guard_endpoint(state, path, &v, text),
        "/v1/vault/pseudonymize" => {
            // NOTE (by design): the response carries the placeholder ->
            // ORIGINAL mapping - that is the vault's function. The caller
            // must persist it; this response is NOT log-safe by intention.
            let locales = locale_refs_from(&v)?;
            let context = context_from(&v)?;
            let ignored = ignored_from(&v);
            let extras = RequestExtras::from_request(&v)?;
            let rules = extras.rule_refs();
            let ner = state.ner_slice();
            let guard = state
                .guard(GuardTarget::UserPrompt, &locales, &ner, &context, &ignored)
                .with_custom_rules(&rules);
            let (anon, vault) = guard.detector().pseudonymize(text);
            let entries: Vec<serde_json::Value> = vault
                .entries_iter()
                .map(|(placeholder, original)| {
                    serde_json::json!({"placeholder": placeholder, "original": original})
                })
                .collect();
            Ok(ok(serde_json::json!({
                "pseudonymized": anon,
                "count": vault.len(),
                "entries": entries,
            })))
        }
        "/v1/vault/restore" => vault_restore(&v, text),
        _ => Err(err(404, "unknown_path", "unreachable")),
    }
}

/// `/v1/detect`: entities (optionally explained) + the redacted rendering.
fn detect(state: &ApiState, v: &serde_json::Value, text: &str) -> Handled {
    let opts = PiiOptions::from_request(v)?;
    let ner = state.ner_slice();
    let rules = opts.extras.rule_refs();
    let guard = opts.guard(state, &ner, &rules);
    Ok(ok(detect_json(
        &opts.detector(&guard),
        explain_from(v),
        text,
    )))
}

/// The optional `explain` flag of a detect request (`false` when absent).
fn explain_from(v: &serde_json::Value) -> bool {
    v.get("explain")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// The `/v1/redact` body of one text.
fn redact_json(detector: &Detector<'_>, text: &str) -> serde_json::Value {
    serde_json::json!({ "redacted": redact_output(detector, text) })
}

/// The `/v1/detect` body of one text.
fn detect_json(detector: &Detector<'_>, explain: bool, text: &str) -> serde_json::Value {
    // normalization-aware: encoding-evasion entities (fullwidth/
    // zero-width values) surface with raw-text spans
    let entities: Vec<serde_json::Value> = if explain {
        detector
            .explain(text)
            .iter()
            .map(|(e, why)| {
                let mut j = entity_json(e);
                j["explain"] = explanation_json(why);
                j
            })
            .collect()
    } else {
        detector.detect(text).iter().map(entity_json).collect()
    };
    serde_json::json!({
        "count": entities.len(),
        "entities": entities,
        "redacted": redact_output(detector, text),
    })
}

/// `/v1/guard` (decision + PII spans) and `/v1/sanitize` (decision +
/// sanitized text); both audited.
fn guard_endpoint(state: &ApiState, path: &str, v: &serde_json::Value, text: &str) -> Handled {
    let target = parse_target(v)?;
    let request_id = request_id_from(v)?;
    let locales = locale_refs_from(v)?;
    let context = context_from(v)?;
    let ignored = ignored_from(v);
    let extras = RequestExtras::from_request(v)?;
    let rules = extras.rule_refs();
    let ner = state.ner_slice();
    // one guard for the decision, the PII spans, the masking and the Block
    // re-mask: the same effective locales and recognizers everywhere
    let guard = with_prompt(
        state
            .guard(target, &locales, &ner, &context, &ignored)
            .with_custom_rules(&rules)
            .with_mask_style(extras.mask.clone()),
        system_prompt_from(v)?,
    );
    if path == "/v1/sanitize" {
        return Ok(ok(sanitize_json(
            state,
            path,
            &guard,
            request_id.as_deref(),
            text,
        )));
    }
    let d = guard.decide(text);
    state.emit_decision(path, request_id.as_deref(), &d); // metadata-only
    let mut out = decision_json(state, &d);
    // normalization-aware: evasion entities surface with raw spans
    out["pii"] = entities_json(&guard.detector().detect(text));
    out["ml"] = serde_json::Value::Bool(state.ml_active());
    Ok(ok(out))
}

/// The `/v1/sanitize` body of one text (audited).
fn sanitize_json(
    state: &ApiState,
    endpoint: &str,
    guard: &Guard<'_>,
    request_id: Option<&str>,
    text: &str,
) -> serde_json::Value {
    let r = guard.sanitize(text);
    state.emit_decision(endpoint, request_id, &r.decision);
    let mut out = decision_json(state, &r.decision);
    // policy keeps the RAW text on Block ("caller decides"), but an
    // HTTP response is loggable surface: return the loggable re-mask
    // (secrets, then normalization-aware PII, then HTML encoding for
    // ModelOutput) so raw PII/secrets never appear in the body (the
    // caller already holds the original from its own request)
    let text_out = if r.decision.action == GuardAction::Block {
        guard.mask_all(text)
    } else {
        r.text
    };
    out["text"] = serde_json::Value::String(text_out);
    out["ml"] = serde_json::Value::Bool(state.ml_active());
    out
}

/// `/v1/json/redact`: masks PII and secrets inside the string leaves (and,
/// with `numeric_leaves`, the number leaves) of the `json` field and
/// reports every finding by RFC 6901 pointer (see
/// [`JsonRedactor`](crate::JsonRedactor)); no detected value is echoed.
fn json_redact(state: &ApiState, v: &mut serde_json::Value) -> Handled {
    // moved out, not cloned: the document is the whole request body
    let mut doc = v
        .get_mut("json")
        .map(serde_json::Value::take)
        .ok_or_else(|| {
            err(
                400,
                "missing_field",
                "required field `json` (any JSON value)",
            )
        })?;
    let numeric_leaves = match v.get("numeric_leaves") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(on)) => *on,
        Some(_) => {
            return Err(err(
                400,
                "bad_numeric_leaves",
                "`numeric_leaves` must be a boolean",
            ))
        }
    };
    let opts = PiiOptions::from_request(v)?;
    let ner = state.ner_slice();
    let rules = opts.extras.rule_refs();
    let guard = opts.guard(state, &ner, &rules);
    let report = crate::JsonRedactor::new()
        .with_detector(opts.detector(&guard))
        .with_numeric_leaves(numeric_leaves)
        .redact(&mut doc);
    let findings: Vec<serde_json::Value> = report.findings.iter().map(json_finding).collect();
    Ok(ok(serde_json::json!({
        "redacted": doc,
        "findings": findings,
        "complete": report.is_complete(),
    })))
}

/// One JSON finding: pointer, kind (`PII` / `SECRET` / `SCAN_INCOMPLETE`),
/// the entity type or secret label (`null` for an incomplete scan) and
/// whether it sits in a member name.
fn json_finding(f: &crate::JsonFinding) -> serde_json::Value {
    let (kind, label) = match f.kind {
        crate::JsonFindingKind::Pii(t) => ("PII", Some(t.as_str())),
        crate::JsonFindingKind::Secret(vendor) => ("SECRET", Some(vendor)),
        crate::JsonFindingKind::ScanIncomplete => ("SCAN_INCOMPLETE", None),
    };
    serde_json::json!({
        "pointer": f.pointer,
        "kind": kind,
        "type": label,
        "in_key": f.in_key,
    })
}

/// The `texts` field of a batch request: an array of strings. A missing
/// field is `missing_field`; a non-string item is `bad_texts`, naming its
/// position (never its value).
fn texts_from(v: &serde_json::Value) -> Result<Vec<&str>, ApiResponse> {
    let texts = v
        .get("texts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            err(
                400,
                "missing_field",
                "required array field `texts` [string, ...]",
            )
        })?;
    texts
        .iter()
        .enumerate()
        .map(|(i, t)| {
            t.as_str()
                .ok_or_else(|| err(400, "bad_texts", format!("`texts[{i}]` is not a string")))
        })
        .collect()
}

/// `/v1/batch/{detect,redact,sanitize}`: the single-text endpoint applied
/// to every item of `texts` with the request's other fields; `results[i]`
/// is exactly the single endpoint's body for `texts[i]`. A batch sanitize
/// emits one audit record per item, all with the request's `request_id`.
fn batch(state: &ApiState, path: &str, v: &serde_json::Value) -> Handled {
    let texts = texts_from(v)?;
    let ner = state.ner_slice();
    let results: Vec<serde_json::Value> = if path == "/v1/batch/sanitize" {
        let target = parse_target(v)?;
        let request_id = request_id_from(v)?;
        let locales = locale_refs_from(v)?;
        let context = context_from(v)?;
        let ignored = ignored_from(v);
        let extras = RequestExtras::from_request(v)?;
        let rules = extras.rule_refs();
        let guard = with_prompt(
            state
                .guard(target, &locales, &ner, &context, &ignored)
                .with_custom_rules(&rules)
                .with_mask_style(extras.mask.clone()),
            system_prompt_from(v)?,
        );
        texts
            .iter()
            .map(|t| sanitize_json(state, path, &guard, request_id.as_deref(), t))
            .collect()
    } else {
        let opts = PiiOptions::from_request(v)?;
        let rules = opts.extras.rule_refs();
        let guard = opts.guard(state, &ner, &rules);
        let detector = opts.detector(&guard);
        if path == "/v1/batch/detect" {
            let explain = explain_from(v);
            texts
                .iter()
                .map(|t| detect_json(&detector, explain, t))
                .collect()
        } else {
            texts.iter().map(|t| redact_json(&detector, t)).collect()
        }
    };
    Ok(ok(serde_json::json!({
        "count": results.len(),
        "results": results,
    })))
}

/// `/v1/vault/restore`: restores placeholders from a caller-supplied
/// table (brackets optional, at most `MAX_VAULT_ENTRIES` entries).
fn vault_restore(v: &serde_json::Value, text: &str) -> Handled {
    let entries = v
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            err(
                400,
                "missing_field",
                "required array field `entries` [{placeholder, original}]",
            )
        })?;
    // the shared table parser ([`crate::Vault::try_from_json_entries`]);
    // the HTTP status and code per error are this endpoint's contract
    let vault = crate::Vault::try_from_json_entries(entries).map_err(|e| match e {
        crate::VaultError::TooManyEntries { .. } => err(413, "too_many_entries", e.to_string()),
        crate::VaultError::InvalidEntry { .. } => err(
            400,
            "bad_entries",
            "each entry needs string fields `placeholder` and `original`",
        ),
    })?;
    Ok(ok(serde_json::json!({ "restored": vault.restore(text) })))
}

/// `/v1/tool/check`: one tool call against a contract and the history (the
/// caller's, or the server-held session's), evaluated by the shared
/// [`check_json_with`]; every decision goes to the audit sink. Error
/// messages name fields, never argument values.
fn tool_check(state: &ApiState, v: &serde_json::Value) -> Handled {
    let request_id = request_id_from(v)?;
    let outcome = check_json_with(&state.tool_sessions, v).map_err(|e| match e {
        ToolCheckError::MissingField { field: "contract" } => {
            err(400, "missing_field", "required object field `contract`")
        }
        ToolCheckError::MissingField { .. } => err(
            400,
            "missing_field",
            "required object field `call` {tool, args}",
        ),
        ToolCheckError::Contract(_) => err(400, "bad_contract", e.to_string()),
        ToolCheckError::Call(_) | ToolCheckError::HistoryCall { .. } => {
            err(400, "bad_call", e.to_string())
        }
        ToolCheckError::HistoryNotArray => err(400, "bad_history", e.to_string()),
        ToolCheckError::HistoryTooLong { .. } => err(413, "history_too_long", e.to_string()),
        ToolCheckError::InvalidSessionId => err(400, "bad_session_id", e.to_string()),
        ToolCheckError::HistoryInSession => err(400, "history_not_allowed", e.to_string()),
    })?;
    if let Some(sink) = &state.audit_sink {
        sink(&outcome.audit_record(audit_request_id(request_id.as_deref())));
    }
    Ok(ok(outcome.verdict.to_json()))
}

/// A parsed stream request (shared by the NDJSON and SSE endpoints).
struct StreamRequest {
    target: GuardTarget,
    chunks: Vec<String>,
    /// Requested locale codes (empty = policy default, else tr+en).
    locales: Vec<String>,
    request_id: Option<String>,
    /// Allowlisted values (`ignore`).
    ignored: Vec<String>,
    /// The mask strategy (`mask`, `mask_by_type`).
    mask: MaskStyle,
    /// The request's deny list and patterns (`words`, `patterns`).
    rules: Vec<CustomRule>,
}

/// The ONE request parser of the stream endpoints: a JSON object
/// `{"chunks", "target"?, "locales"?, "request_id"?, "ignore"?}`, raw NDJSON (one
/// JSON string per line = one chunk) or a single JSON string (one chunk).
fn parse_stream_request(body: &str) -> Result<StreamRequest, ApiResponse> {
    let mut v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => match parse_ndjson_chunks(body) {
            Some(chunks) => serde_json::json!({ "chunks": chunks }),
            None => {
                return Err(err(
                    400,
                    "bad_json",
                    format!("request body is neither a JSON object nor NDJSON string lines: {e}"),
                ))
            }
        },
    };
    // Single-chunk NDJSON edge: a body that is
    // exactly one JSON string is valid buffered JSON (a scalar), so the
    // NDJSON fallback above never runs for it - map it to one chunk.
    if let Some(s) = v.as_str() {
        v = serde_json::json!({ "chunks": [s] });
    }
    let target = parse_target(&v)?;
    let request_id = request_id_from(&v)?;
    let chunks = v
        .get("chunks")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            err(
                400,
                "missing_field",
                "required array field `chunks` [string, ...]",
            )
        })?
        .iter()
        .map(|c| c.as_str().map(String::from))
        .collect::<Option<Vec<String>>>()
        .ok_or_else(|| err(400, "bad_chunks", "every chunk must be a string"))?;
    let locales = locale_refs_from(&v)?
        .into_iter()
        .map(String::from)
        .collect();
    let ignored = ignored_from(&v).into_iter().map(String::from).collect();
    let extras = RequestExtras::from_request(&v)?;
    Ok(StreamRequest {
        target,
        chunks,
        locales,
        request_id,
        ignored,
        mask: extras.mask,
        rules: extras.rules,
    })
}

/// `/v1/stream/sanitize`: single round-trip chunk streaming. The
/// client sends the chunks it received (order preserved,
/// arbitrary split points) and gets the guard event stream as NDJSON - one
/// event per line. JSON escaping inside each line keeps embedded newlines
/// unambiguous.
fn handle_stream(state: &ApiState, body: &str) -> Handled {
    let req = parse_stream_request(body)?;
    let mut frames: Vec<String> = Vec::new();
    stream_event_frames(state, NDJSON_PATH, &req, |frame| {
        frames.push(frame);
        true
    });
    let mut body = frames.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    Ok(ApiResponse { status: 200, body })
}

/// Runs the streaming guard over the request's chunks and hands every
/// guard event, rendered as one JSON frame (`{"type":"segment",...}` /
/// `{"type":"block",...}`), to `emit` AS SOON AS the guard produces it;
/// `emit` returns `false` to stop (the client went away). Processing stops
/// at the first Block event, which is audited. The guard runs under the
/// server policy, the request's locales (the policy's default locales when
/// none) and the attached NER recognizer and security classifier (budgeted,
/// [`MlStreamBudget::default`]). Shared by the buffered NDJSON response
/// (which collects the frames) and the SSE endpoint (which writes each);
/// `endpoint` labels the metrics.
///
/// Dry run ([`Policy::dry_run`](crate::policy::Policy::dry_run)): every
/// chunk is echoed unchanged as its own segment frame (`"dry_run": true`,
/// no entities) while the guard runs in the shadow; a would-be Block is
/// audited and counted, never emitted, and the echo continues.
fn stream_event_frames(
    state: &ApiState,
    endpoint: &str,
    req: &StreamRequest,
    mut emit: impl FnMut(String) -> bool,
) {
    let locales: Vec<&str> = req.locales.iter().map(String::as_str).collect();
    let mut sg = StreamingGuard::new(req.target)
        .with_locales(&locales)
        .with_ignored(req.ignored.clone())
        .with_mask_style(req.mask.clone())
        .with_custom_rules(req.rules.clone());
    if let Some(p) = &state.policy {
        sg = sg.with_policy(p.clone());
    }
    if let Some(ner) = &state.ner {
        sg = sg.with_ner(vec![Arc::clone(ner)]);
    }
    if let Some(security) = &state.security {
        sg = sg.with_ml(Arc::clone(security), MlStreamBudget::default());
    }
    let request_id = req.request_id.as_deref();
    if state.dry_run() {
        let mut shadow = true;
        for chunk in &req.chunks {
            if shadow {
                shadow = shadow_events(state, endpoint, request_id, sg.push(chunk));
            }
            let frame = serde_json::json!({
                "type": "segment",
                "text": chunk,
                "entities": [],
                "dry_run": true,
            });
            if !emit(frame.to_string()) {
                return;
            }
        }
        if shadow {
            shadow_events(state, endpoint, request_id, sg.finish());
        }
        return;
    }
    for chunk in &req.chunks {
        if !forward_events(state, endpoint, request_id, sg.push(chunk), &mut emit) {
            return;
        }
    }
    forward_events(state, endpoint, request_id, sg.finish(), &mut emit);
}

/// The dry-run side of [`stream_event_frames`]: audits and counts a
/// would-be Block event; `false` once one was seen (the shadow guard
/// stops there, like an enforcing stream).
fn shadow_events(
    state: &ApiState,
    endpoint: &str,
    request_id: Option<&str>,
    events: Vec<GuardEvent>,
) -> bool {
    for ev in events {
        if let GuardEvent::Block { rationale } = &ev {
            state.emit_stream_block_audit(endpoint, request_id, rationale);
            return false;
        }
    }
    true
}

/// Renders and emits `events` in order; `false` once the stream must stop
/// (a Block event, or `emit` reported the client gone).
fn forward_events(
    state: &ApiState,
    endpoint: &str,
    request_id: Option<&str>,
    events: Vec<GuardEvent>,
    emit: &mut impl FnMut(String) -> bool,
) -> bool {
    for ev in events {
        if let Some((text, entities)) = ev.as_segment() {
            let frame = serde_json::json!({
                "type": "segment",
                "text": text,
                "entities": entities_json(entities),
            });
            if !emit(frame.to_string()) {
                return false;
            }
        } else if let GuardEvent::Block { rationale } = &ev {
            state.emit_stream_block_audit(endpoint, request_id, rationale);
            let frame = serde_json::json!({ "type": "block", "rationale": rationale });
            emit(frame.to_string());
            return false;
        }
    }
    true
}

/// Starts the HTTP server on `addr` (e.g. `127.0.0.1:8080`) with a small
/// fixed worker pool (4 threads). Runs until the process is killed.
///
/// # Errors
/// Returns an error when the address cannot be bound.
pub fn serve(addr: &str) -> std::io::Result<()> {
    serve_with(addr, ApiState::default())
}

/// Applies the environment to the state: [`API_TOKEN_ENV_VAR`] when the
/// state carries no token, then (with the `config` feature) the
/// `REDACTIFY_POLICY` policy. An invalid value refuses startup.
fn configured_state(mut state: ApiState) -> std::io::Result<ApiState> {
    if state.bearer_token.is_none() {
        state.bearer_token = bearer_token_from_env()
            .map_err(|e| std::io::Error::other(format!("{API_TOKEN_ENV_VAR}: {e}")))?;
    }
    if state.litellm_restore.is_none() && litellm_restore_from_env()? {
        state = state.with_litellm_restore(RestoreSessions::default());
    }
    // restoration hands original values to whoever can call the endpoint
    // with a live call id: never without authentication
    if state.litellm_restore.is_some() && state.bearer_token.is_none() {
        return Err(std::io::Error::other(format!(
            "LiteLLM restoration ({LITELLM_RESTORE_ENV_VAR}) needs a bearer token ({API_TOKEN_ENV_VAR})"
        )));
    }
    if state.max_body.is_none() {
        state.max_body = body_limit_from_env()?;
    }
    let limit = state.body_limit();
    if !(MIN_BODY_LIMIT..=MAX_BODY_LIMIT).contains(&limit) {
        return Err(std::io::Error::other(format!(
            "body limit {limit} bytes is outside {MIN_BODY_LIMIT}..={MAX_BODY_LIMIT}"
        )));
    }
    if state.audit_sink.is_none() {
        if let Some(sink) = audit_sink_from_env()? {
            state.audit_sink = Some(sink);
        }
    }
    configured_policy(state)
}

/// The body limit named by [`BODY_LIMIT_ENV_VAR`] (`None` when unset): a
/// whole number of bytes from [`MIN_BODY_LIMIT`] to [`MAX_BODY_LIMIT`].
///
/// # Errors
/// Any other value (not valid Unicode, not a whole number, out of range).
pub fn body_limit_from_env() -> std::io::Result<Option<usize>> {
    let bad = |detail: &str| {
        std::io::Error::other(format!(
            "{BODY_LIMIT_ENV_VAR}: {detail} (expected a whole number of bytes from \
             {MIN_BODY_LIMIT} to {MAX_BODY_LIMIT})"
        ))
    };
    match std::env::var(BODY_LIMIT_ENV_VAR) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(bad("not valid Unicode")),
        Ok(value) => match value.trim().parse::<usize>() {
            Ok(n) if (MIN_BODY_LIMIT..=MAX_BODY_LIMIT).contains(&n) => Ok(Some(n)),
            Ok(_) => Err(bad("out of range")),
            Err(_) => Err(bad("not a whole number")),
        },
    }
}

/// The audit sink named by [`AUDIT_FILE_ENV_VAR`] (keyed by
/// [`AUDIT_KEY_ENV_VAR`] when set): `None` when the file variable is
/// unset. The file is opened with
/// [`FileAuditSink::open`](crate::guard::audit::FileAuditSink::open): an
/// existing file is verified first and resumed. A failed write is reported
/// on stderr (content-free: the I/O error only) and the sink refuses every
/// later record, as the MCP server's does.
///
/// # Errors
/// An empty key, a key that is not valid Unicode, an unreadable file, or
/// an existing file that does not verify in the requested mode: the server
/// then refuses to start.
pub fn audit_sink_from_env() -> std::io::Result<Option<AuditCallback>> {
    let Some(path) = std::env::var_os(AUDIT_FILE_ENV_VAR) else {
        return Ok(None);
    };
    let key = match std::env::var(AUDIT_KEY_ENV_VAR) {
        Ok(key) if key.is_empty() => {
            return Err(std::io::Error::other(format!(
                "{AUDIT_KEY_ENV_VAR} is empty"
            )))
        }
        Ok(key) => Some(key),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(std::io::Error::other(format!(
                "{AUDIT_KEY_ENV_VAR} is not valid Unicode"
            )))
        }
    };
    let sink = crate::guard::audit::FileAuditSink::open(&path, key.as_deref().map(str::as_bytes))
        .map_err(|e| std::io::Error::other(format!("{AUDIT_FILE_ENV_VAR}: {e}")))?;
    let sink = std::sync::Mutex::new(sink);
    Ok(Some(Arc::new(move |record| {
        let mut sink = sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = sink.append(record) {
            eprintln!("redactify api: audit write failed: {e}");
        }
    })))
}

/// Whether [`LITELLM_RESTORE_ENV_VAR`] enables restoration (unset: no).
fn litellm_restore_from_env() -> std::io::Result<bool> {
    let bad = |detail: &str| {
        std::io::Error::other(format!(
            "{LITELLM_RESTORE_ENV_VAR}: {detail} (use 1, true, on, 0, false or off)"
        ))
    };
    match std::env::var(LITELLM_RESTORE_ENV_VAR) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => Err(bad("not valid Unicode")),
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" => Ok(true),
            "" | "0" | "false" | "off" => Ok(false),
            _ => Err(bad("unknown value")),
        },
    }
}

/// Applies the `REDACTIFY_POLICY` environment variable to the state when the
/// `config` feature is on; identity otherwise. Kept behind a helper so the
/// `mut` lives where the mutation lives (an api-only build has no mutation
/// and must stay warning-clean).
#[cfg(feature = "config")]
fn configured_policy(mut state: ApiState) -> std::io::Result<ApiState> {
    // Single-knob Docker story: REDACTIFY_POLICY points at a TOML policy;
    // a malformed file (or a value that is not valid Unicode) REFUSES
    // STARTUP (fail-closed, same posture as a model-load failure) instead
    // of silently serving with the built-in lines.
    if state.policy.is_none() {
        let loaded = crate::policy::config::load_policy_env_if_set().map_err(|e| {
            std::io::Error::other(format!("{}: {e}", crate::policy::POLICY_ENV_VAR))
        })?;
        if let Some(policy) = loaded {
            state = state.with_policy(policy);
        }
    }
    Ok(state)
}

#[cfg(not(feature = "config"))]
fn configured_policy(state: ApiState) -> std::io::Result<ApiState> {
    Ok(state)
}

/// The `WWW-Authenticate` challenge of a request without credentials (RFC
/// 6750 section 3: the `Bearer` scheme followed by at least one auth-param,
/// no error code when the request lacks credentials).
const CHALLENGE_MISSING: &str = r#"Bearer realm="redactify""#;

/// The challenge of a request whose bearer token is not the configured one
/// (RFC 6750 section 3.1 `invalid_token`, status 401).
const CHALLENGE_INVALID_TOKEN: &str = r#"Bearer realm="redactify", error="invalid_token""#;

/// The challenge of a request with more than one `Authorization` header
/// (RFC 6750 section 3.1 `invalid_request`, status 400).
const CHALLENGE_INVALID_REQUEST: &str = r#"Bearer realm="redactify", error="invalid_request""#;

/// The token of a `Bearer` credential (`credentials = "Bearer" 1*SP
/// b64token`, RFC 6750 section 2.1; the scheme is a case-insensitive token,
/// RFC 9110 section 11.1); `None` for any other scheme.
fn bearer_credentials(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once(' ').unwrap_or((value, ""));
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| rest.trim_start_matches(' '))
}

/// Checks the `Authorization` header values of one request against
/// `token`; the `Err` side is the response and its challenge. A scheme
/// other than `Bearer` counts as no credentials (RFC 6750 section 3).
fn authorize<'h>(
    token: &BearerToken,
    mut values: impl Iterator<Item = &'h str>,
) -> Result<(), (ApiResponse, &'static str)> {
    let first = values.next();
    if values.next().is_some() {
        return Err((
            err(
                400,
                "invalid_request",
                "send exactly one Authorization header",
            ),
            CHALLENGE_INVALID_REQUEST,
        ));
    }
    match first.and_then(bearer_credentials) {
        None => Err((
            err(
                401,
                "unauthorized",
                "this server requires `Authorization: Bearer <token>`",
            ),
            CHALLENGE_MISSING,
        )),
        Some(presented) if token.matches(presented) => Ok(()),
        Some(_) => Err((
            err(401, "invalid_token", "the bearer token is not accepted"),
            CHALLENGE_INVALID_TOKEN,
        )),
    }
}

/// Starts the HTTP server with the given state (ML classifiers attached or
/// not). See [`serve`] for behavior details.
///
/// # Errors
/// Returns an error when the address cannot be bound.
pub fn serve_with(addr: &str, state: ApiState) -> std::io::Result<()> {
    let state = configured_state(state)?;
    let server =
        Arc::new(tiny_http::Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?);
    let state = Arc::new(state);
    let mut workers = Vec::new();
    for _ in 0..4 {
        let s = Arc::clone(&server);
        let state = Arc::clone(&state);
        workers.push(std::thread::spawn(move || loop {
            let mut request = match s.recv() {
                Ok(r) => r,
                Err(_) => break,
            };
            let started = std::time::Instant::now();
            let method = request.method().as_str().to_owned();
            let path = request.url().split('?').next().unwrap_or("").to_owned();
            // the answers given before the pure handler runs count too
            let early = |r: &ApiResponse| {
                state
                    .metrics
                    .observe_request(&path, r.status, started.elapsed());
            };
            // authentication first: an unauthenticated body is never read
            if let Some(token) = state.bearer_token.as_ref().filter(|_| path != HEALTH_PATH) {
                let verdict = if path == litellm::PATH {
                    // LiteLLM sends its `api_key` as `x-api-key`
                    litellm::authorize(token, request.headers())
                } else {
                    let values = request
                        .headers()
                        .iter()
                        .filter(|h| h.field.equiv("Authorization"))
                        .map(|h| h.value.as_str());
                    authorize(token, values)
                };
                if let Err((r, challenge)) = verdict {
                    early(&r);
                    respond_with_challenge(request, &r, challenge);
                    continue;
                }
            }
            // reject oversized bodies before reading them (fast path for
            // requests that declare a Content-Length)
            let limit = state.body_limit();
            if request.body_length().is_some_and(|n| n > limit) {
                let r = too_large(limit);
                early(&r);
                respond(request, &r, "application/json");
                continue;
            }
            // Chunked/unknown-length bodies carry no Content-Length, so the
            // fast path above cannot judge them; bound the read itself
            // (take) and reject after reading (all endpoints, SSE included)
            let mut body = String::new();
            let mut capped = std::io::Read::take(request.as_reader(), limit as u64 + 1);
            if std::io::Read::read_to_string(&mut capped, &mut body).is_err() {
                let r = err(400, "bad_body", "request body is not valid UTF-8");
                early(&r);
                respond(request, &r, "application/json");
                continue;
            }
            if body.len() > limit {
                let r = too_large(limit);
                early(&r);
                respond(request, &r, "application/json");
                continue;
            }
            // SSE streaming is a socket-layer response shape (frames written
            // as they are produced); everything else stays on the pure
            // handler
            if method == "POST" && path == SSE_PATH {
                let status = respond_sse(request, &state, &body);
                state
                    .metrics
                    .observe_request(&path, status, started.elapsed());
                continue;
            }
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_request_with(&state, &method, &path, &body)
            }))
            .unwrap_or_else(|p| {
                eprintln!("api worker caught a handler panic: {p:?}");
                let r = err(500, "internal", "request handler panicked");
                early(&r);
                r
            });
            respond(request, &r, content_type_for(&path, r.status));
        }));
    }
    // NOTE (library hygiene): no startup banner here - the BINARY that owns
    // this server prints operational messages; the library stays silent.
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

/// A JSON error response with its `WWW-Authenticate` challenge.
fn respond_with_challenge(request: tiny_http::Request, r: &ApiResponse, challenge: &str) {
    let content_type =
        tiny_http::Header::from_bytes("Content-Type", "application/json").expect("static header");
    let www_authenticate =
        tiny_http::Header::from_bytes("WWW-Authenticate", challenge).expect("static header");
    let response = tiny_http::Response::from_string(&r.body)
        .with_status_code(r.status)
        .with_header(content_type)
        .with_header(www_authenticate);
    let _ = request.respond(response);
}

fn respond(request: tiny_http::Request, r: &ApiResponse, content_type: &str) {
    let header =
        tiny_http::Header::from_bytes("Content-Type", content_type).expect("static header");
    let response = tiny_http::Response::from_string(&r.body)
        .with_status_code(r.status)
        .with_header(header);
    let _ = request.respond(response);
}

/// One SSE frame: `data: {json}` and the blank line that ends the event.
fn sse_frame(json: &str) -> String {
    format!("data: {json}\n\n")
}

/// The frame that ends a stream whose producer panicked.
const PRODUCER_PANIC_FRAME: &str = r#"{"type":"error","code":"producer_panic"}"#;

/// The streamed body writer of an SSE response to an HTTP/1.1 client: the
/// response head and every frame go to the raw connection and are flushed
/// immediately (the buffered response path would hold frames back until a
/// whole transfer chunk or the end of the stream), one chunk of the
/// chunked transfer coding per frame (so the connection can stay alive).
struct SseBody {
    out: Box<dyn Write + Send>,
}

impl SseBody {
    /// Writes the `200` response head (`text/event-stream`) for `request`.
    fn start(request: tiny_http::Request) -> std::io::Result<Self> {
        let version = request.http_version();
        let (major, minor) = (version.0, version.1);
        let mut out = request.into_writer();
        write!(
            out,
            "HTTP/{major}.{minor} 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n"
        )?;
        out.flush()?;
        Ok(Self { out })
    }

    /// Writes one frame as one chunk and flushes it to the client.
    fn frame(&mut self, json: &str) -> std::io::Result<()> {
        let data = sse_frame(json);
        write!(self.out, "{:x}\r\n{data}\r\n", data.len())?;
        self.out.flush()
    }

    /// Ends the body with the terminating zero-length chunk.
    fn finish(mut self) -> std::io::Result<()> {
        self.out.write_all(b"0\r\n\r\n")?;
        self.out.flush()
    }
}

/// SSE (Server-Sent Events) variant of the chunk-stream endpoint, served at
/// the socket layer only: the request is fully read (tiny_http semantics),
/// then every guard event is written to the client as a
/// `data: {event json}\n\n` frame the moment the streaming guard produces
/// it (`text/event-stream`), terminating after a Block event. Consumers:
/// `EventSource`-compatible clients and streaming proxies that cannot
/// buffer the whole NDJSON body. A panic while producing frames ends the
/// stream with a machine-readable `{"type":"error","code":"producer_panic"}`
/// frame. HTTP/1.0 clients get the same frames buffered
/// ([`respond_sse_buffered`]).
fn respond_sse(request: tiny_http::Request, state: &ApiState, body: &str) -> u16 {
    let req = match parse_stream_request(body) {
        Ok(req) => req,
        Err(e) => {
            respond(request, &e, "application/json");
            return e.status;
        }
    };
    let version = request.http_version();
    if (version.0, version.1) < (1, 1) {
        respond_sse_buffered(request, state, &req);
        return 200;
    }
    let Ok(mut sse) = SseBody::start(request) else {
        return 200; // client went away after the 200 head was sent
    };
    let produced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stream_event_frames(state, SSE_PATH, &req, |frame| sse.frame(&frame).is_ok());
    }));
    if produced.is_err() {
        eprintln!("api sse producer panicked");
        let _ = sse.frame(PRODUCER_PANIC_FRAME);
    }
    let _ = sse.finish();
    200
}

/// The SSE response to an HTTP/1.0 client: the same frames (and the same
/// audit records), collected first and sent with a `Content-Length`. "A
/// server MUST NOT send a response containing Transfer-Encoding unless the
/// corresponding request indicates HTTP/1.1" (RFC 9112 section 6.1), and a
/// body without a declared length ends only when the server closes the
/// connection (RFC 9112 section 6.3, rule 8;
/// https://www.rfc-editor.org/rfc/rfc9112, retrieved 2026-10-30), which
/// the socket layer does not do for an HTTP/1.0 client that sent
/// `Connection: keep-alive`: such a client never saw the end of the body.
fn respond_sse_buffered(request: tiny_http::Request, state: &ApiState, req: &StreamRequest) {
    let mut body = String::new();
    let produced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stream_event_frames(state, SSE_PATH, req, |frame| {
            body.push_str(&sse_frame(&frame));
            true
        });
    }));
    if produced.is_err() {
        eprintln!("api sse producer panicked");
        body.push_str(&sse_frame(PRODUCER_PANIC_FRAME));
    }
    let header = |name: &str, value: &str| {
        tiny_http::Header::from_bytes(name, value).expect("static header")
    };
    let response = tiny_http::Response::from_string(body)
        .with_header(header("Content-Type", "text/event-stream"))
        .with_header(header("Cache-Control", "no-cache"));
    let _ = request.respond(response);
}
