//! The OpenAPI 3.1 description of the REST API, served at
//! `GET /openapi.json`.
//!
//! The document is static (it never depends on a request or on the server
//! configuration) and is built from the same constants the handlers
//! enforce, so a documented limit cannot drift from the real one. The
//! integration test `tests/api_openapi.rs` posts every example request in
//! this document to the live handler.

use serde_json::{json, Value};

use super::{
    MAX_BODY, MAX_BODY_LIMIT, MAX_DENY_WORDS, MAX_DENY_WORD_LEN, MAX_KEEP_LAST, MAX_MASK_BY_TYPE,
    MAX_MASK_TEMPLATE_LEN, MAX_PATTERNS, MAX_PATTERN_CUES, MAX_PATTERN_CUE_LEN, MAX_REQUEST_ID_LEN,
    MAX_SYSTEM_PROMPT_LEN, MIN_BODY_LIMIT,
};
use crate::{LINEAR_MAX_PATTERN_BYTES, LINEAR_MIN_MATCH_LEN};

/// The `GET /openapi.json` body.
pub(super) fn document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "redactify",
            "version": env!("CARGO_PKG_VERSION"),
            "summary": "Checksum-validated PII detection, redaction and guard runtime",
            "description": format!(
                "Local-first REST interface over the deterministic core (L0 rules, L1 PII, policy), \
                 with optional ML classifiers and NER attached at startup. PII spans are reported as \
                 byte offsets and types; the matched value is never echoed. Request bodies are \
                 capped at {MAX_BODY} bytes by default (REDACTIFY_MAX_BODY sets another limit from \
                 {MIN_BODY_LIMIT} to {MAX_BODY_LIMIT} bytes)."
            ),
            "license": { "name": "MIT OR Apache-2.0" },
        },
        "servers": [{ "url": "http://127.0.0.1:8080", "description": "default `--serve` address" }],
        "security": [{ "bearerAuth": [] }],
        "paths": paths(),
        "components": components(),
    })
}

fn body(example: &Value, schema: &Value) -> Value {
    json!({
        "required": true,
        "content": { "application/json": { "schema": schema, "example": example } }
    })
}

fn json_response(description: &str, schema: &Value) -> Value {
    json!({ "description": description, "content": { "application/json": { "schema": schema } } })
}

fn error_ref(description: &str) -> Value {
    json_response(
        description,
        &json!({ "$ref": "#/components/schemas/Error" }),
    )
}

fn post(summary: &str, description: &str, request: &Value, example: &Value, ok: &Value) -> Value {
    json!({
        "post": {
            "summary": summary,
            "description": description,
            "requestBody": body(example, request),
            "responses": {
                "200": ok,
                "400": error_ref("A request field is missing or invalid; the message names the field, never its value."),
                "401": {
                    "description": "Bearer token missing or wrong (only when the server runs with a token).",
                    "headers": { "WWW-Authenticate": { "schema": { "type": "string" } } },
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } }
                },
                "413": error_ref("Body, vault table or tool history over its limit."),
            }
        }
    })
}

fn schema_ref(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

/// A request schema: the shared option properties plus `extra` ones.
fn request(required: &[&str], extra: &Value, options: &[&str]) -> Value {
    let mut props = serde_json::Map::new();
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            props.insert(k.clone(), v.clone());
        }
    }
    for name in options {
        let schema = match *name {
            "locales" => schema_ref("Locales"),
            "target" => schema_ref("Target"),
            "request_id" => schema_ref("RequestId"),
            "ignore" => schema_ref("Ignore"),
            "context" => schema_ref("Context"),
            "mask" => schema_ref("Mask"),
            "mask_by_type" => schema_ref("MaskByType"),
            "words" => schema_ref("Words"),
            "patterns" => schema_ref("Patterns"),
            "system_prompt" => schema_ref("SystemPrompt"),
            "threshold" => json!({
                "type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.0,
                "description": "Minimum entity score; lower-scored entities are dropped inside overlap resolution."
            }),
            "explain" => json!({
                "type": "boolean", "default": false,
                "description": "Add an `explain` object (rule, validator, cue, score, view) to every entity."
            }),
            "words_ignore_case" => json!({
                "type": "boolean", "default": false,
                "description": "Match `words` regardless of letter case."
            }),
            other => panic!("unknown option {other}"),
        };
        props.insert((*name).to_owned(), schema);
    }
    json!({ "type": "object", "required": required, "properties": props })
}

fn text_field() -> Value {
    json!({ "text": { "type": "string", "description": "The text to scan." } })
}

fn texts_field() -> Value {
    json!({ "texts": { "type": "array", "items": { "type": "string" }, "description": "The texts; the single endpoint's options apply to every item." } })
}

const PII_OPTIONS: &[&str] = &[
    "locales",
    "threshold",
    "ignore",
    "context",
    "mask",
    "mask_by_type",
    "words",
    "words_ignore_case",
    "patterns",
];
const GUARD_OPTIONS: &[&str] = &[
    "target",
    "system_prompt",
    "locales",
    "request_id",
    "ignore",
    "context",
    "mask",
    "mask_by_type",
    "words",
    "words_ignore_case",
    "patterns",
];

fn batch_of(single: &Value) -> Value {
    json!({
        "type": "object",
        "required": ["count", "results"],
        "properties": {
            "count": { "type": "integer" },
            "results": { "type": "array", "items": single, "description": "`results[i]` is the single endpoint's body for `texts[i]`." }
        }
    })
}

fn paths() -> Value {
    let detect_ok = schema_ref("DetectResponse");
    let redact_ok = json!({
        "type": "object", "required": ["redacted"],
        "properties": { "redacted": { "type": "string", "description": "Credentials masked first as `[SECRET:VENDOR]`, then PII per the mask style; an unscannable line becomes `[SCAN_INCOMPLETE]`." } }
    });
    let sanitize_ok = json!({
        "allOf": [ schema_ref("Decision"), {
            "type": "object", "required": ["text", "ml"],
            "properties": {
                "text": { "type": "string", "description": "The sanitized text. On Block this is the loggable re-mask, never the raw text." },
                "ml": { "type": "boolean" }
            }
        }]
    });
    let guard_ok = json!({
        "allOf": [ schema_ref("Decision"), {
            "type": "object", "required": ["pii", "ml"],
            "properties": { "pii": { "type": "array", "items": schema_ref("Entity") }, "ml": { "type": "boolean" } }
        }]
    });
    let stream_chunks = json!({ "chunks": { "type": "array", "items": { "type": "string" }, "description": "The chunks as received, in order, at arbitrary split points." } });
    let stream_opts: &[&str] = &[
        "target",
        "locales",
        "request_id",
        "ignore",
        "mask",
        "mask_by_type",
        "words",
        "words_ignore_case",
        "patterns",
    ];
    let stream_example = json!({ "chunks": ["TCKN 1234", "5678950 geldi\n"], "target": "model_output",
                "mask": { "style": "template", "template": "<{type}>" }, "words": ["Phoenix"] });

    let mut p = serde_json::Map::new();
    p.insert("/health".into(), json!({
        "get": {
            "summary": "Liveness and model health",
            "description": "Open even when a bearer token is configured; it carries no request data.",
            "security": [],
            "responses": { "200": json_response("Server status.", &schema_ref("Health")) }
        }
    }));
    p.insert("/openapi.json".into(), json!({
        "get": {
            "summary": "This OpenAPI document",
            "description": "Requires the bearer token like every endpoint except `/health`.",
            "responses": { "200": json_response("The OpenAPI 3.1 description.", &json!({ "type": "object" })) }
        }
    }));
    p.insert("/metrics".into(), json!({
        "get": {
            "summary": "Prometheus metrics",
            "description": "Text exposition format 0.0.4: redactify_requests_total, \n                redactify_request_duration_seconds (histogram), redactify_decisions_total and \n                redactify_entities_total, labelled by endpoint, status, action and entity type only \n                (never request text). Requires the bearer token like every endpoint except `/health`.",
            "responses": { "200": {
                "description": "The metrics.",
                "content": { "text/plain; version=0.0.4; charset=utf-8": { "schema": { "type": "string" } } }
            } }
        }
    }));
    p.insert("/v1/detect".into(), post(
        "Detect PII",
        "Entities with byte offsets (no matched values) plus the redacted text.",
        &request(&["text"], &text_field(), PII_OPTIONS),
        &json!({ "text": "TCKN 12345678950 ve ali@example.com", "locales": ["tr", "en"], "explain": true,
                 "mask": { "style": "template", "template": "<{type}>" }, "words": ["Project Phoenix"],
                 "patterns": [{ "pattern": r"\bORD-\d{5}\b", "label": "ITIN", "cues": ["order"], "score": 0.9 }] }),
        &json_response("Entities and redacted text.", &detect_ok),
    ));
    p.insert("/v1/redact".into(), post(
        "Redact PII",
        "The redacted text only.",
        &request(&["text"], &text_field(), PII_OPTIONS),
        &json!({ "text": "kart 4111 1111 1111 1111", "mask": { "style": "partial", "keep_last": 4, "char": "*" } }),
        &json_response("Redacted text.", &redact_ok),
    ));
    p.insert("/v1/json/redact".into(), post(
        "Redact PII inside a JSON document",
        "String leaves (number leaves with `numeric_leaves`) are masked, each member name is a context cue for its value, findings are reported by RFC 6901 pointer.",
        &request(&["json"], &json!({
            "json": { "description": "Any JSON value." },
            "numeric_leaves": { "type": "boolean", "default": false }
        }), PII_OPTIONS),
        &json!({ "json": { "user": { "tckn": "12345678950" } } }),
        &json_response("The redacted document and its findings.", &json!({
            "type": "object", "required": ["redacted", "findings", "complete"],
            "properties": {
                "redacted": { "description": "The document with PII and secrets masked." },
                "findings": { "type": "array", "items": { "type": "object", "properties": {
                    "pointer": { "type": "string" },
                    "kind": { "enum": ["PII", "SECRET", "SCAN_INCOMPLETE"] },
                    "type": { "type": ["string", "null"] },
                    "in_key": { "type": "boolean" }
                } } },
                "complete": { "type": "boolean" }
            }
        })),
    ));
    p.insert("/v1/guard".into(), post(
        "Guard decision",
        "Full decision: signals, verdicts and PII spans. Audited (metadata only) when a sink is attached.",
        &request(&["text"], &text_field(), GUARD_OPTIONS),
        &json!({ "text": "TCKN 12345678950", "target": "user_prompt", "request_id": "req-1" }),
        &json_response("The decision.", &guard_ok),
    ));
    p.insert(
        "/v1/sanitize".into(),
        post(
            "Guard decision plus sanitized text",
            "`model_output` also HTML-encodes dangerous characters (OWASP LLM05).",
            &request(&["text"], &text_field(), GUARD_OPTIONS),
            &json!({ "text": "a < b", "target": "model_output" }),
            &json_response("The decision and the sanitized text.", &sanitize_ok),
        ),
    );
    p.insert(
        "/v1/batch/detect".into(),
        post(
            "Detect PII in several texts",
            "The `/v1/detect` request with `texts` in place of `text`.",
            &request(&["texts"], &texts_field(), PII_OPTIONS),
            &json!({ "texts": ["TCKN 12345678950", "merhaba"] }),
            &json_response("One detect body per text.", &batch_of(&detect_ok)),
        ),
    );
    p.insert(
        "/v1/batch/redact".into(),
        post(
            "Redact PII in several texts",
            "The `/v1/redact` request with `texts` in place of `text`.",
            &request(&["texts"], &texts_field(), PII_OPTIONS),
            &json!({ "texts": ["TCKN 12345678950", "merhaba"] }),
            &json_response("One redact body per text.", &batch_of(&redact_ok)),
        ),
    );
    p.insert("/v1/batch/sanitize".into(), post(
        "Sanitize several texts",
        "The `/v1/sanitize` request with `texts` in place of `text`; one audit record per item.",
        &request(&["texts"], &texts_field(), GUARD_OPTIONS),
        &json!({ "texts": ["TCKN 12345678950", "merhaba"] }),
        &json_response("One sanitize body per text.", &batch_of(&sanitize_ok)),
    ));
    p.insert("/v1/stream/sanitize".into(), post(
        "Guard a chunked stream (buffered NDJSON)",
        "The body is a JSON object, or raw NDJSON with one JSON string per line as one chunk. The response is `application/x-ndjson`, one guard event per line; it stops after a Block. `mask`, `mask_by_type`, `words` and `patterns` apply as on the other text endpoints; `context` and `system_prompt` do not.",
        &request(&["chunks"], &stream_chunks, stream_opts),
        &stream_example,
        &json!({ "description": "One guard event per line.", "content": { "application/x-ndjson": { "schema": { "type": "object", "description": "A segment or block event." } } } }),
    ));
    p.insert("/v1/stream/sse".into(), post(
        "Guard a chunked stream (server-sent events)",
        "Same request as `/v1/stream/sanitize`. Socket server only: the pure in-process handler answers 400 `socket_only`.",
        &request(&["chunks"], &stream_chunks, stream_opts),
        &stream_example,
        &json!({ "description": "`text/event-stream`: one `data:` frame per guard event.", "content": { "text/event-stream": { "schema": { "type": "string" } } } }),
    ));
    p.insert("/v1/vault/pseudonymize".into(), post(
        "Reversible pseudonymization",
        "The response carries the placeholder to ORIGINAL mapping by design: it is not log-safe, persist it on the caller side. `words` applies; `mask` does not (placeholders are numbered).",
        &request(&["text"], &text_field(), &["locales", "ignore", "context", "words", "words_ignore_case", "patterns"]),
        &json!({ "text": "TCKN 12345678950 burada" }),
        &json_response("Pseudonymized text and the restore table.", &json!({
            "type": "object", "required": ["pseudonymized", "count", "entries"],
            "properties": {
                "pseudonymized": { "type": "string" },
                "count": { "type": "integer" },
                "entries": { "type": "array", "items": { "type": "object", "properties": {
                    "placeholder": { "type": "string" }, "original": { "type": "string" } } } }
            }
        })),
    ));
    p.insert("/v1/vault/restore".into(), post(
        "Restore placeholders",
        "Brackets around a placeholder are optional. The table is capped.",
        &request(&["text", "entries"], &json!({
            "text": { "type": "string" },
            "entries": { "type": "array", "items": { "type": "object", "required": ["placeholder", "original"],
                "properties": { "placeholder": { "type": "string" }, "original": { "type": "string" } } } }
        }), &[]),
        &json!({ "text": "[TCKN_1] burada", "entries": [{ "placeholder": "[TCKN_1]", "original": "12345678950" }] }),
        &json_response("Restored text.", &json!({ "type": "object", "properties": { "restored": { "type": "string" } } })),
    ));
    p.insert("/v1/tool/check".into(), post(
        "Check one agent tool call",
        "Evaluates a call against a contract and the call history; the response carries the verdict and a stable code, never the arguments. With `session_id` the server holds the history (a request that also sends `history` is refused with `history_not_allowed`) and binds the session to the contract of its first call. Deny codes: NOT_ALLOWLISTED, GLOBAL_BUDGET, TOKEN_BUDGET, TOOL_BUDGET, LOOP, ARG_PATTERN, ARG_PATTERN_ERROR, EGRESS_HOST, and in session mode CONTRACT_MISMATCH, SESSION_LIMIT, SESSION_EXPIRED. Every decision is written to the audit sink when one is attached.",
        &request(&["contract", "call"], &json!({
            "contract": { "type": "object", "description": "Tool contract (allowed tools, argument rules, sequence rules, optional `egress_allowlist` of hosts or `*.domain` wildcards for URLs in arguments)." },
            "history": { "type": "array", "items": { "type": "object" }, "description": "Earlier calls, oldest first (capped). Not accepted with `session_id`." },
            "session_id": { "type": "string", "minLength": 1, "maxLength": 128, "description": "Server-held session: the server keeps the history behind the budgets and the loop check." },
            "call": { "type": "object", "required": ["tool", "args"], "properties": { "tool": { "type": "string" }, "args": {} } }
        }), &["request_id"]),
        &json!({ "contract": { "allowed": ["search"] }, "call": { "tool": "shell", "args": "rm -rf /" } }),
        &json_response("The verdict.", &json!({
            "type": "object", "required": ["verdict", "code"],
            "properties": { "verdict": { "enum": ["allow", "deny"] }, "code": { "type": "string" } }
        })),
    ));
    p.insert(super::litellm::PATH.into(), litellm_operation());
    Value::Object(p)
}

/// The LiteLLM Generic Guardrail API operation (contract of LiteLLM
/// v1.110.2). The bearer token or, on this path, `x-api-key` authenticates.
fn litellm_operation() -> Value {
    let mut op = post(
        "LiteLLM Generic Guardrail API",
        "Called by a LiteLLM proxy configured with `guardrail: generic_guardrail_api` and `api_base` set to this server. \
         Every text runs through the guard. Any Block (a text, or the `function.arguments` of a tool call) answers `BLOCKED` \
         with a reason naming the position and a static category label, never content; else, when any text changed, \
         `GUARDRAIL_INTERVENED` with every text in request order; else `NONE`. `input_type: response` texts are decided as \
         `model_output` (HTML-encoded only with `html_encode`); `request` texts are `user_prompt`, or `tool_response` for the \
         texts of `tool` / `function` messages in `structured_messages`. A 4xx answer is a failed check, which LiteLLM treats \
         as a block unless `fail_on_error: false`. With restoration enabled on the server (`REDACTIFY_LITELLM_RESTORE`, off \
         by default), a request-side call of a call id LiteLLM generated numbers its placeholders (`[TCKN_1]`) and keeps the \
         originals in a bounded server-side session bound to that id and to `request_data.user_api_key_hash`; the \
         response-side calls of the same call get the originals back (by design, that answer then contains PII). A call \
         whose client set `x-litellm-call-id`, or without `request_headers`, gets labels and no session; a missing or \
         expired session leaves the placeholders in place.",
        &json!({
            "type": "object", "required": ["input_type"],
            "properties": {
                "texts": { "type": ["array", "null"], "items": { "type": "string" }, "description": "The texts LiteLLM extracted, in its order." },
                "input_type": { "enum": ["request", "response"], "description": "`request`: the call's input (pre_call, during_call); `response`: the model's output (post_call)." },
                "structured_messages": { "type": ["array", "null"], "items": { "type": "object" }, "description": "OpenAI chat messages of the request; their roles pick each text's target. Never echoed." },
                "tool_calls": { "type": ["array", "null"], "items": { "type": "object" }, "description": "OpenAI tool calls; their `function.arguments` can block, they are not rewritten." },
                "litellm_call_id": { "type": ["string", "null"], "description": "Audit request id when it is 1 to 128 printable ASCII characters; with restoration, also the session id." },
                "additional_provider_specific_params": {
                    "type": ["object", "null"], "additionalProperties": false,
                    "description": "Only options that add detection, plus `html_encode` and `restore`. LiteLLM merges a client's `extra_body` over the configured params, so options that narrow detection belong in the server policy.",
                    "properties": {
                        "words": schema_ref("Words"),
                        "words_ignore_case": { "type": "boolean", "default": false },
                        "patterns": schema_ref("Patterns"),
                        "html_encode": { "type": "boolean", "default": false, "description": "HTML-encode model output like `/v1/sanitize` with `model_output`." },
                        "restore": { "type": "boolean", "description": "`false` opts this guardrail out of restoration; `true` requires it (400 when the server does not enable it). Absent: the server setting." }
                    }
                },
                "images": { "description": "Accepted and ignored." },
                "tools": { "description": "Accepted and ignored." },
                "request_data": { "type": ["object", "null"], "description": "With restoration, `user_api_key_hash` binds the session; otherwise ignored." },
                "request_headers": { "type": ["object", "null"], "description": "With restoration, required for a session, which a client-set `x-litellm-call-id` header prevents; otherwise ignored." },
                "litellm_trace_id": { "description": "Accepted and ignored." },
                "litellm_version": { "description": "Accepted and ignored." },
                "model": { "description": "Accepted and ignored." }
            }
        }),
        &json!({
            "texts": ["You are a helpful assistant.", "My TCKN is 12345678950", "ok"],
            "input_type": "request",
            "structured_messages": [
                { "role": "system", "content": "You are a helpful assistant." },
                { "role": "user", "content": "My TCKN is 12345678950" },
                { "role": "tool", "tool_call_id": "call_1", "content": "ok" }
            ],
            "litellm_call_id": "4b5f0c1e-0d7a-4c39-9a51-1c2f0e6b7d10",
            "additional_provider_specific_params": { "words": ["Project Phoenix"] }
        }),
        &json_response("The guardrail verdict.", &json!({
            "type": "object", "required": ["action"],
            "properties": {
                "action": { "enum": ["NONE", "GUARDRAIL_INTERVENED", "BLOCKED"] },
                "texts": { "type": "array", "items": { "type": "string" }, "description": "GUARDRAIL_INTERVENED only: one text per request text, same order." },
                "blocked_reason": { "type": "string", "description": "BLOCKED only: position and static label, e.g. `redactify blocked texts[1]: SECRETS`." },
                "stream_holdback_chars": { "type": "array", "items": { "type": "integer", "minimum": 0 }, "description": "`input_type: response` only, present when a text has an unfinished last line: per returned text, the characters after its last line break. LiteLLM's `streaming_transform_mode: incremental_diff` withholds them until a later round, so a stream is released line by line, masked." }
            }
        })),
    );
    op["post"]["security"] = json!([{ "bearerAuth": [] }, { "apiKeyAuth": [] }]);
    op
}

fn components() -> Value {
    let styles = [
        "label",
        "template",
        "char",
        "partial",
        "mask_first",
        "mask_last",
    ];
    json!({
        "securitySchemes": {
            "bearerAuth": {
                "type": "http", "scheme": "bearer",
                "description": "Required only when the server starts with REDACTIFY_API_TOKEN (RFC 6750). `/health` stays open."
            },
            "apiKeyAuth": {
                "type": "apiKey", "in": "header", "name": "x-api-key",
                "description": "The same token, accepted on the LiteLLM endpoint only (LiteLLM sends its `api_key` in this header) when no Authorization header is present."
            }
        },
        "schemas": {
            "Locales": {
                "type": "array",
                "items": { "enum": crate::SUPPORTED_LOCALES },
                "description": "Locale packs to scan with, compared exactly (no trimming, no case folding). Default: the server policy's default locales, else tr + en."
            },
            "Target": {
                "enum": ["user_prompt", "tool_response", "model_output"],
                "default": "user_prompt",
                "description": "What the text is: a user prompt, a tool result (stricter lines) or model output (also HTML-encoded by sanitize). Aliases such as `tool` and `model` are accepted."
            },
            "RequestId": {
                "type": "string", "minLength": 1, "maxLength": MAX_REQUEST_ID_LEN,
                "pattern": "^[\\x20-\\x7e]+$",
                "description": "Audit correlation id: printable ASCII."
            },
            "Ignore": {
                "type": "array", "items": { "type": "string" },
                "description": "Allowlisted values: neither reported nor masked, and they do not drive the decision."
            },
            "Context": {
                "type": "array", "items": { "type": "string" },
                "description": "The text the request text answers (the previous turn). A cue in it unlocks cue-gated identifiers; never echoed."
            },
            "Mask": {
                "type": "object", "required": ["style"],
                "description": "How a detected span is rendered. Secrets always render as `[SECRET:VENDOR]`. A pseudonym style is not offered over HTTP (it needs a server-held key).",
                "properties": {
                    "style": { "enum": styles },
                    "template": { "type": "string", "minLength": 1, "maxLength": MAX_MASK_TEMPLATE_LEN, "description": "style=template: every `{type}` becomes the type label; a text without it is a fixed replacement such as `[REDACTED]`." },
                    "char": { "type": "string", "minLength": 1, "maxLength": 1, "description": "style=char, partial, mask_first or mask_last: exactly one printable character." },
                    "count": { "type": "integer", "minimum": 1, "maximum": MAX_KEEP_LAST, "description": "style=mask_first or mask_last: how many alphanumeric characters are masked from the start or the end; the rest stays visible." },
                    "keep_last": { "type": "integer", "minimum": 0, "maximum": MAX_KEEP_LAST, "description": "style=partial: trailing alphanumerics left visible." }
                }
            },
            "MaskByType": {
                "type": "object", "maxProperties": MAX_MASK_BY_TYPE,
                "additionalProperties": { "$ref": "#/components/schemas/Mask" },
                "description": "A mask strategy per entity type: keys are entity labels that already exist (e.g. EMAIL, CREDIT_CARD, CUSTOM_WORD), values are Mask objects. A type without an entry uses `mask` (default: label). Overlapping spans form one region that takes the type of its longest span."
            },
            "SystemPrompt": {
                "type": "string", "maxLength": MAX_SYSTEM_PROMPT_LEN,
                "description": "The system prompt a `model_output` text is checked against: a reproduced run of 8 or more words raises a `PROMPT_LEAK` verdict (OWASP LLM07). Needs at least 8 words; ignored for other targets; never echoed."
            },
            "Patterns": {
                "type": "array", "maxItems": MAX_PATTERNS,
                "description": format!(
                    "Custom regular expressions. Only the linear-time syntax is accepted (no look-around, back-references or atomic groups), so the engine never backtracks and a caller cannot choose the scan cost; inline flags such as `(?i)` are fine. A pattern is at most {LINEAR_MAX_PATTERN_BYTES} bytes, must match at least {LINEAR_MIN_MATCH_LEN} characters at the shortest and compiles within a size limit. Matches are reported as `CUSTOM_PATTERN` unless `label` names an entity type that already exists (a built-in type or a label the server policy registered): a request never registers a label. Errors are `bad_patterns`, naming the field and position, never the pattern."
                ),
                "items": {
                    "type": "object", "required": ["pattern"], "additionalProperties": false,
                    "properties": {
                        "pattern": { "type": "string", "maxLength": LINEAR_MAX_PATTERN_BYTES },
                        "label": { "type": "string", "description": "An existing entity label, e.g. ITIN. Default: CUSTOM_PATTERN." },
                        "cues": {
                            "type": "array", "maxItems": MAX_PATTERN_CUES,
                            "items": { "type": "string", "maxLength": MAX_PATTERN_CUE_LEN },
                            "description": "A match counts only next to one of these words."
                        },
                        "score": { "type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.8 }
                    }
                }
            },
            "Words": {
                "type": "array", "maxItems": MAX_DENY_WORDS,
                "items": { "type": "string", "maxLength": MAX_DENY_WORD_LEN },
                "description": "Literal deny list (not patterns): whole-word matches are reported and masked as `CUSTOM_WORD`. Case-sensitive unless `words_ignore_case`. Empty entries are dropped."
            },
            "Entity": {
                "type": "object", "required": ["type", "start", "end", "score"],
                "properties": {
                    "type": { "type": "string", "description": "Entity type label, e.g. TCKN, IBAN, EMAIL, CUSTOM_WORD." },
                    "start": { "type": "integer", "description": "Byte offset into the request text." },
                    "end": { "type": "integer", "description": "Byte offset, exclusive." },
                    "score": { "type": "number" },
                    "explain": { "type": "object", "description": "Present with `explain: true`." }
                }
            },
            "DetectResponse": {
                "type": "object", "required": ["count", "entities", "redacted"],
                "properties": {
                    "count": { "type": "integer" },
                    "entities": { "type": "array", "items": { "$ref": "#/components/schemas/Entity" } },
                    "redacted": { "type": "string" }
                }
            },
            "Decision": {
                "type": "object", "required": ["action", "rationale", "mask_summary", "signals", "verdicts", "relevance_downgraded"],
                "properties": {
                    "action": { "enum": ["Allow", "Log", "Mask", "Block"], "description": "`Allow` in dry run: see `dry_run_action`." },
                    "rationale": { "type": "string" },
                    "entities": { "type": "array", "description": "Present when the server policy configures entity actions or dry run: per entity type, the action applied and the count (no values).",
                        "items": { "type": "object", "properties": {
                            "type": { "type": "string" }, "action": { "enum": ["MASK", "BLOCK", "LOG"] }, "count": { "type": "integer" } } } },
                    "dry_run": { "type": "boolean", "description": "Present (true) in dry-run mode: nothing was enforced." },
                    "dry_run_action": { "enum": ["Allow", "Log", "Mask", "Block"], "description": "Present in dry-run mode: the action the policy decided." },
                    "mask_summary": { "type": "array", "items": { "type": "string" } },
                    "signals": { "type": "array", "items": { "type": "object", "properties": {
                        "kind": { "type": "string" }, "score": { "type": "number" },
                        "evidence": { "type": "string", "description": "Leak-safe preview, never the full value." },
                        "rationale": { "type": "string" } } } },
                    "verdicts": { "type": "array", "items": { "type": "object", "properties": {
                        "category": { "type": "string" }, "score": { "type": "number" },
                        "severity": { "type": "string" }, "action": { "type": "string" }, "rationale": { "type": "string" } } } },
                    "relevance_downgraded": { "type": "array", "items": { "type": "object", "properties": {
                        "type": { "type": "string" }, "start": { "type": "integer" }, "end": { "type": "integer" } } } }
                }
            },
            "Health": {
                "type": "object",
                "properties": {
                    "status": { "enum": ["ok", "degraded"] },
                    "version": { "type": "string" },
                    "ml_active": { "type": "boolean" },
                    "ml_health": { "type": "object", "description": "Per model slot (`security`, `safety`, `ner`): null when absent, else `{status, reason?}`." },
                    "dry_run": { "type": "boolean", "description": "Present (true) when the server policy runs in dry-run mode." }
                }
            },
            "Error": {
                "type": "object", "required": ["error"],
                "properties": { "error": { "type": "object", "required": ["code", "message"], "properties": {
                    "code": { "type": "string", "description": "Stable machine code, e.g. bad_json, missing_field, bad_mask, bad_words, bad_locales, payload_too_large, unauthorized." },
                    "message": { "type": "string", "description": "Names the field and position, never a request value." } } } }
            }
        }
    })
}
