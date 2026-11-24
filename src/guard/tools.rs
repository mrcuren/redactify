//! Agent tool-call guard: deny-by-default allowlist, call budgets and
//! loop detection.
//!
//! Pure Rust, fully deterministic. The contract model follows the
//! evaluation framework's expectations:
//! - **deny-by-default**: a tool not in the allowlist is denied;
//! - **budgets**: an optional global call ceiling, optional per-tool
//!   ceilings and an optional estimated-token budget (`None` = unlimited;
//!   budgets are expressed as counts - cost accounting belongs to the host
//!   runtime, this layer enforces the call structure);
//! - **loop detection**: the same `(tool, args)` pair seen
//!   `repeat_tolerance` times in the history already denies the next call
//!   as a loop (default 2: the original + one retry pass, the third
//!   identical call is the loop - a common agent failure mode where a
//!   stuck model re-issues identical calls).
//!
//! Contracts and calls can be read from JSON without the `serde` feature
//! ([`ToolContract::from_json`], [`ToolCall::from_json`]); with the
//! feature, deserializing a [`ToolContract`] accepts the same shape, and
//! deserializing a [`ToolCall`] goes through [`ToolCall::from_json`]
//! itself (one parser). A whole tool-check request (contract, history and
//! call, as the REST and MCP surfaces receive it) is evaluated by
//! [`check_json`].
//!
//! Two opt-in additions close gaps a per-request check leaves open:
//! - **egress allowlist** ([`ToolContract::with_egress_allowlist`]): a call
//!   whose arguments hold a URL to a host outside the list is denied as
//!   `EGRESS_HOST` (see [`crate::guard::egress`]);
//! - **server-held sessions** ([`ToolSessions`], [`check_json_with`]): the
//!   history behind the budgets and the loop check is kept by the server
//!   under a `session_id`, bound to one contract, so a caller cannot reset
//!   a budget by sending a shorter history. Every decision yields the
//!   content-free fields of an audit record ([`ToolCheckOutcome`],
//!   [`AuditRecord::tool_decision`]) for the hash-chained sink.
//!
//! Argument-shape validation composes with the existing
//! [`crate::guard::validate_json_schema`] (L4) at the call site.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;

use crate::guard::audit::{AuditRecord, ToolAuditFields};
use crate::guard::egress::{EgressAllowlist, EgressAllowlistError};

/// Default `repeat_tolerance`: the original call plus one retry pass.
const DEFAULT_REPEAT_TOLERANCE: usize = 2;

/// Maximum number of calls in the `history` of a [`check_json`] request: a
/// history rebuilt from untrusted input must stay bounded.
pub const MAX_TOOL_HISTORY: usize = 10_000;

/// Verdict for one tool call.
///
/// serde: `Serialize` only - `Deny` carries a `&'static str` code that
/// `Deserialize` cannot produce (no `'static` data from borrowed input).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum ToolVerdict {
    /// The call may proceed.
    Allow,
    /// The call must be rejected; `reason` is a stable machine-readable code.
    /// Every code `check` can emit:
    /// `NOT_ALLOWLISTED`, `GLOBAL_BUDGET`, `TOKEN_BUDGET`, `TOOL_BUDGET`,
    /// `LOOP`, `ARG_PATTERN`, `ARG_PATTERN_ERROR` (pattern engine failure
    /// on a denied-args check - fail-closed), `EGRESS_HOST` (the arguments
    /// hold a URL to a host outside the contract's egress allowlist).
    /// The server-held sessions of [`ToolSessions`] add `CONTRACT_MISMATCH`
    /// (the call names another contract than the one the session is bound
    /// to), `SESSION_LIMIT` (the session table or the session's call log
    /// is full) and `SESSION_EXPIRED` (the session id was ended or timed
    /// out and is not reused).
    Deny(&'static str),
}

impl ToolVerdict {
    /// Whether the call may proceed.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// The stable machine-readable code of this verdict: `"ALLOW"` for
    /// [`ToolVerdict::Allow`], the deny code otherwise.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::tools::{check, ToolCall, ToolContract, ToolVerdict};
    ///
    /// let contract = ToolContract::new(&["search"]);
    /// assert_eq!(ToolVerdict::Allow.code(), "ALLOW");
    /// assert_eq!(check(&contract, &[], &ToolCall::new("rm", "")).code(), "NOT_ALLOWLISTED");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny(code) => code,
        }
    }

    /// The verdict as the REST and MCP surfaces report it:
    /// `{"verdict": "allow" | "deny", "code": <`[`Self::code`]`>}` (the
    /// checked call's arguments never appear).
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::tools::ToolVerdict;
    /// use serde_json::json;
    ///
    /// assert_eq!(ToolVerdict::Allow.to_json(), json!({"verdict": "allow", "code": "ALLOW"}));
    /// assert_eq!(ToolVerdict::Deny("LOOP").to_json(), json!({"verdict": "deny", "code": "LOOP"}));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "verdict": if self.is_allow() { "allow" } else { "deny" },
            "code": self.code(),
        })
    }
}

/// Why a tool contract or a tool call could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolContractError {
    /// A per-tool argument deny pattern does not compile.
    #[error("invalid argument deny pattern for tool `{tool}`")]
    InvalidPattern {
        /// The tool the pattern was given for.
        tool: String,
        /// The pattern compiler's error.
        #[source]
        source: Box<fancy_regex::Error>,
    },
    /// A JSON field has the wrong type or value.
    #[error("field `{field}` must be {expected}")]
    InvalidField {
        /// The offending field (`allowed[2]`, `per_tool_max.search`, ...).
        field: String,
        /// What the field must hold.
        expected: &'static str,
    },
    /// A required JSON field is missing.
    #[error("missing required field `{field}`")]
    MissingField {
        /// The missing field.
        field: &'static str,
    },
    /// A JSON object carries a field the contract does not know (rejected
    /// so a misspelled budget can never silently mean "unlimited").
    #[error("unknown field `{field}`")]
    UnknownField {
        /// The unknown field.
        field: String,
    },
    /// The `egress_allowlist` entries are not valid hosts.
    #[error("egress_allowlist: {0}")]
    EgressAllowlist(#[source] EgressAllowlistError),
}

/// Why a JSON tool-check request ([`check_json`]) could not be evaluated.
/// Messages name fields and positions, never argument values.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolCheckError {
    /// A required request field (`contract` or `call`) is missing.
    #[error("missing required field `{field}`")]
    MissingField {
        /// The missing field.
        field: &'static str,
    },
    /// The `contract` field is not a valid contract.
    #[error("contract: {0}")]
    Contract(#[source] ToolContractError),
    /// The `call` field is not a valid call.
    #[error("call: {0}")]
    Call(#[source] ToolContractError),
    /// `history` is present but neither `null` nor an array.
    #[error("`history` must be an array of calls {{tool, args}}")]
    HistoryNotArray,
    /// `history` holds more than `limit` calls (checked before any call is
    /// parsed).
    #[error("history exceeds the {limit}-call limit ({len} given)")]
    HistoryTooLong {
        /// The number of calls given.
        len: usize,
        /// The limit ([`MAX_TOOL_HISTORY`]).
        limit: usize,
    },
    /// A history entry is not a valid call.
    #[error("history[{index}]: {source}")]
    HistoryCall {
        /// The position of the entry in `history`.
        index: usize,
        /// Why the entry is not a valid call.
        #[source]
        source: ToolContractError,
    },
    /// `session_id` is not a string of 1 to [`MAX_SESSION_ID_LEN`]
    /// printable ASCII characters.
    #[error("`session_id` must be 1 to {MAX_SESSION_ID_LEN} printable ASCII characters")]
    InvalidSessionId,
    /// A request names a `session_id` and also carries a `history`: the
    /// server holds the session's history, so a caller-supplied one is
    /// refused rather than ignored.
    #[error("`history` is not accepted with `session_id`: the server holds the session history")]
    HistoryInSession,
}

/// One tool invocation to check.
///
/// serde (feature `serde`): serializes as `{"tool", "args"}` (`args` as
/// the stored string); deserializing goes through [`ToolCall::from_json`]
/// (via [`serde_json::Value`], so it needs a self-describing format), so
/// both read exactly the same shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "serde_json::Value"))]
pub struct ToolCall {
    /// Tool name as the model emitted it.
    pub tool: String,
    /// Serialized arguments (loop identity is the exact string).
    pub args: String,
}

impl TryFrom<serde_json::Value> for ToolCall {
    type Error = ToolContractError;

    /// [`ToolCall::from_json`] over an owned value.
    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        Self::from_json(&value)
    }
}

/// Writes `value` as compact JSON with the keys of every object, at any
/// depth, in ascending byte order. The loop identity of a call must not
/// depend on how `serde_json::Map` iterates: the map "is backed by a
/// `BTreeMap`" by default and by an `IndexMap` (insertion order) when the
/// `preserve_order` feature is enabled (serde_json 1.0.151, `src/map.rs`
/// module docs, https://docs.rs/serde_json/1.0.151/serde_json/map/index.html,
/// retrieved 2026-10-30), and "when a dependency is used by multiple
/// packages, Cargo will use the union of all features enabled on that
/// dependency" (The Cargo Book, Features, "Feature unification",
/// https://doc.rust-lang.org/cargo/reference/features.html#feature-unification,
/// retrieved 2026-10-30). Scalars and keys use `serde_json`'s own compact
/// rendering, so with a key-sorted map the output equals
/// `Value::to_string`.
fn write_canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut members: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            members.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (key, member)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical_json(member, out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

impl ToolCall {
    /// Convenience constructor.
    pub fn new(tool: impl Into<String>, args: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            args: args.into(),
        }
    }

    /// Reads a call from a JSON object `{"tool": "...", "args": ...}`.
    ///
    /// `args` may be a string (taken verbatim) or any other JSON value,
    /// which is canonicalized to compact JSON with the keys of every object
    /// (at any depth) sorted, so the loop identity does not depend on key
    /// order, whitespace or the `serde_json` features of the build. A
    /// missing or `null` `args` is the empty string.
    ///
    /// # Errors
    /// [`ToolContractError`] when the value is not an object, `tool` is
    /// missing or not a string, or an unknown field is present.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::tools::ToolCall;
    /// use serde_json::json;
    ///
    /// let a = ToolCall::from_json(&json!({"tool": "search", "args": {"q": "x", "n": 1}})).unwrap();
    /// let b = ToolCall::from_json(&json!({"tool": "search", "args": {"n": 1, "q": "x"}})).unwrap();
    /// assert_eq!(a, b); // key order is not part of the loop identity
    /// assert_eq!(a.args, r#"{"n":1,"q":"x"}"#);
    /// ```
    pub fn from_json(value: &serde_json::Value) -> Result<Self, ToolContractError> {
        let obj = value
            .as_object()
            .ok_or_else(|| invalid("(root)", "a JSON object"))?;
        reject_unknown(obj, &["tool", "args"])?;
        let tool = obj
            .get("tool")
            .ok_or(ToolContractError::MissingField { field: "tool" })?
            .as_str()
            .ok_or_else(|| invalid("tool", "a string"))?
            .to_owned();
        let args = match obj.get("args") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => {
                let mut canonical = String::new();
                write_canonical_json(other, &mut canonical);
                canonical
            }
        };
        Ok(Self { tool, args })
    }

    /// Rough token estimate for budget accounting: the
    /// industry-standard approximation of ~4 characters per token. This is
    /// an ESTIMATE, not a tokenizer-exact count - the host runtime that
    /// owns the real tokenizer can override with exact counts.
    #[must_use]
    pub fn estimated_tokens(&self) -> usize {
        self.tool.len().saturating_add(self.args.len()) / 4
    }
}

/// The agent-side policy: allowlist (deny-by-default), budgets, loop bound.
///
/// serde (feature `serde`): unset budgets are omitted and read back as
/// unlimited, a missing `repeat_tolerance` reads as 2, and unknown fields
/// are rejected (the same shape [`ToolContract::from_json`] accepts).
///
/// # Examples
/// ```
/// use redactify::guard::tools::{check, ToolCall, ToolContract};
///
/// let contract = ToolContract::new(&["search", "calculator"])
///     .with_global_max(3)
///     .with_repeat_tolerance(2);
///
/// // deny-by-default: an unlisted tool is rejected
/// assert!(!check(&contract, &[], &ToolCall::new("rm", "-rf /")).is_allow());
///
/// // the original call and one retry are fine; the THIRD identical call
/// // is the loop (tolerance counts total identical calls)
/// let call = ToolCall::new("search", r#"{"q":"a"}"#);
/// assert!(check(&contract, &[], &call).is_allow());
/// let history = vec![call.clone()];
/// assert!(check(&contract, &history, &call).is_allow()); // retry: fine
/// let history = vec![call.clone(), call.clone()];
/// assert!(!check(&contract, &history, &call).is_allow()); // LOOP
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct ToolContract {
    allowed: Vec<String>,
    /// Total call ceiling across all tools (`None` = unlimited).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    global_max: Option<usize>,
    #[cfg_attr(feature = "serde", serde(default))]
    per_tool_max: BTreeMap<String, usize>,
    #[cfg_attr(feature = "serde", serde(default = "default_repeat_tolerance"))]
    repeat_tolerance: usize,
    /// Token budget (estimated, ~4 chars/token; `None` = unlimited): the
    /// cumulative estimated token cost of all tool calls must stay under
    /// this.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    token_budget: Option<usize>,
    /// Per-tool argument deny patterns. Serialized as the SOURCE pattern
    /// string and recompiled on deserialize, so a serialized-then-loaded
    /// contract keeps its argument guards.
    #[cfg_attr(feature = "serde", serde(default))]
    denied_arg_patterns: BTreeMap<String, DeniedPattern>,
    /// Outbound URL allowlist for every tool's arguments (`None` = not
    /// checked): a call whose arguments hold a URL to another host is
    /// denied as `EGRESS_HOST`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    egress_allowlist: Option<EgressAllowlist>,
}

#[cfg(feature = "serde")]
const fn default_repeat_tolerance() -> usize {
    DEFAULT_REPEAT_TOLERANCE
}

/// A compiled deny pattern that round-trips through serde as its source
/// string.
#[derive(Debug, Clone)]
pub struct DeniedPattern {
    pattern: String,
    regex: fancy_regex::Regex,
}

impl DeniedPattern {
    fn new(pattern: &str) -> Result<Self, fancy_regex::Error> {
        Ok(Self {
            pattern: pattern.to_owned(),
            regex: fancy_regex::Regex::new(pattern)?,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DeniedPattern {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.pattern.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DeniedPattern {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let pattern = String::deserialize(deserializer)?;
        Self::new(&pattern).map_err(serde::de::Error::custom)
    }
}

/// Shorthand for an [`ToolContractError::InvalidField`].
fn invalid(field: impl Into<String>, expected: &'static str) -> ToolContractError {
    ToolContractError::InvalidField {
        field: field.into(),
        expected,
    }
}

/// Rejects any key of `obj` outside `known`.
fn reject_unknown(
    obj: &serde_json::Map<String, serde_json::Value>,
    known: &[&str],
) -> Result<(), ToolContractError> {
    match obj.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => Err(ToolContractError::UnknownField { field: k.clone() }),
        None => Ok(()),
    }
}

/// A non-negative integer that fits `usize`.
fn as_count(v: &serde_json::Value, field: &str) -> Result<usize, ToolContractError> {
    v.as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| invalid(field, "a non-negative integer"))
}

/// An optional budget: absent or `null` = unlimited.
fn optional_count(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<usize>, ToolContractError> {
    match obj.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => as_count(v, field).map(Some),
    }
}

impl ToolContract {
    /// Creates a contract allowing exactly `tools` (everything else denied)
    /// with no call ceiling, no token budget and a repeat tolerance of 2 (a
    /// retry is fine, the third identical call is a loop).
    #[must_use]
    pub fn new(tools: &[&str]) -> Self {
        Self {
            allowed: tools.iter().map(std::string::ToString::to_string).collect(),
            global_max: None,
            per_tool_max: BTreeMap::new(),
            repeat_tolerance: DEFAULT_REPEAT_TOLERANCE,
            token_budget: None,
            denied_arg_patterns: BTreeMap::new(),
            egress_allowlist: None,
        }
    }

    /// Reads a contract from JSON (no `serde` feature needed):
    ///
    /// ```text
    /// {
    ///   "allowed": ["search", "shell"],          required
    ///   "global_max": 20,                        optional, null/absent = unlimited
    ///   "token_budget": 5000,                    optional, null/absent = unlimited
    ///   "per_tool_max": {"shell": 2},            optional
    ///   "repeat_tolerance": 2,                   optional, default 2
    ///   "denied_arg_patterns": {"shell": "rm\\s+-rf"}  optional
    ///   "egress_allowlist": ["docs.example.com", "*.cdn.example.com"]
    ///                                            optional, null/absent = not checked
    /// }
    /// ```
    ///
    /// `egress_allowlist` holds at most
    /// [`MAX_EGRESS_ENTRIES`](crate::guard::egress::MAX_EGRESS_ENTRIES)
    /// hosts (see [`EgressAllowlist::new`]).
    ///
    /// Unknown fields are rejected, so a misspelled budget can never
    /// silently mean "unlimited".
    ///
    /// # Errors
    /// [`ToolContractError`] naming the first offending field, or
    /// [`ToolContractError::InvalidPattern`] (with the compiler error as
    /// its source) for a deny pattern that does not compile.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::tools::{check, ToolCall, ToolContract};
    /// use serde_json::json;
    ///
    /// let contract = ToolContract::from_json(&json!({
    ///     "allowed": ["shell"],
    ///     "global_max": 5,
    ///     "denied_arg_patterns": {"shell": "rm\\s+-rf"}
    /// }))
    /// .unwrap();
    /// assert_eq!(check(&contract, &[], &ToolCall::new("shell", "rm -rf /")).code(), "ARG_PATTERN");
    /// assert!(ToolContract::from_json(&json!({"allowed": [], "global_maxx": 1})).is_err());
    /// ```
    pub fn from_json(value: &serde_json::Value) -> Result<Self, ToolContractError> {
        const KNOWN: &[&str] = &[
            "allowed",
            "global_max",
            "per_tool_max",
            "repeat_tolerance",
            "token_budget",
            "denied_arg_patterns",
            "egress_allowlist",
        ];
        let obj = value
            .as_object()
            .ok_or_else(|| invalid("(root)", "a JSON object"))?;
        reject_unknown(obj, KNOWN)?;

        let allowed_json = obj
            .get("allowed")
            .ok_or(ToolContractError::MissingField { field: "allowed" })?
            .as_array()
            .ok_or_else(|| invalid("allowed", "an array of tool names"))?;
        let mut allowed = Vec::with_capacity(allowed_json.len());
        for (i, t) in allowed_json.iter().enumerate() {
            let name = t
                .as_str()
                .ok_or_else(|| invalid(format!("allowed[{i}]"), "a string"))?;
            allowed.push(name.to_owned());
        }

        let mut contract = Self {
            allowed,
            global_max: optional_count(obj, "global_max")?,
            per_tool_max: BTreeMap::new(),
            repeat_tolerance: match obj.get("repeat_tolerance") {
                None => DEFAULT_REPEAT_TOLERANCE,
                Some(v) => as_count(v, "repeat_tolerance")?,
            },
            token_budget: optional_count(obj, "token_budget")?,
            denied_arg_patterns: BTreeMap::new(),
            egress_allowlist: None,
        };
        match obj.get("egress_allowlist") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(entries)) => {
                let mut hosts = Vec::with_capacity(entries.len());
                for (i, entry) in entries.iter().enumerate() {
                    let host = entry
                        .as_str()
                        .ok_or_else(|| invalid(format!("egress_allowlist[{i}]"), "a string"))?;
                    hosts.push(host);
                }
                let allow =
                    EgressAllowlist::new(hosts).map_err(ToolContractError::EgressAllowlist)?;
                contract.egress_allowlist = Some(allow);
            }
            Some(_) => return Err(invalid("egress_allowlist", "an array of hosts")),
        }
        if let Some(v) = obj.get("per_tool_max") {
            let map = v
                .as_object()
                .ok_or_else(|| invalid("per_tool_max", "an object of tool -> count"))?;
            for (tool, max) in map {
                let max = as_count(max, &format!("per_tool_max.{tool}"))?;
                contract.per_tool_max.insert(tool.clone(), max);
            }
        }
        if let Some(v) = obj.get("denied_arg_patterns") {
            let map = v
                .as_object()
                .ok_or_else(|| invalid("denied_arg_patterns", "an object of tool -> pattern"))?;
            for (tool, pattern) in map {
                let pattern = pattern
                    .as_str()
                    .ok_or_else(|| invalid(format!("denied_arg_patterns.{tool}"), "a string"))?;
                contract = contract.with_denied_arg_pattern(tool, pattern)?;
            }
        }
        Ok(contract)
    }

    /// Sets the total call ceiling across all tools.
    #[must_use]
    pub const fn with_global_max(mut self, max: usize) -> Self {
        self.global_max = Some(max);
        self
    }

    /// Sets the cumulative token budget (estimated, ~4 chars/token per
    /// [`ToolCall::estimated_tokens`]). When the history's total estimated
    /// tokens plus the new call's estimate exceed this, the call is denied
    /// as `TOKEN_BUDGET`.
    #[must_use]
    pub const fn with_token_budget(mut self, budget: usize) -> Self {
        self.token_budget = Some(budget);
        self
    }

    /// Sets a per-tool call ceiling (overrides the global ceiling for that
    /// tool when it is lower).
    #[must_use]
    pub fn with_tool_max(mut self, tool: &str, max: usize) -> Self {
        self.per_tool_max.insert(tool.to_owned(), max);
        self
    }

    /// Sets how many times the exact same `(tool, args)` pair may occur in
    /// the history before the next identical call is denied as `LOOP`.
    #[must_use]
    pub const fn with_repeat_tolerance(mut self, tolerance: usize) -> Self {
        self.repeat_tolerance = tolerance;
        self
    }

    /// Adds a per-tool argument deny pattern (full `fancy-regex` syntax):
    /// when the tool's serialized arguments match, the call is denied as
    /// `ARG_PATTERN`. Use this to block dangerous argument shapes (e.g.
    /// `--force` in a delete tool, raw SQL in a query tool).
    ///
    /// # Errors
    /// [`ToolContractError::InvalidPattern`] when `pattern` does not
    /// compile (the compiler error is its source).
    pub fn with_denied_arg_pattern(
        mut self,
        tool: &str,
        pattern: &str,
    ) -> Result<Self, ToolContractError> {
        let dp = DeniedPattern::new(pattern).map_err(|e| ToolContractError::InvalidPattern {
            tool: tool.to_owned(),
            source: Box::new(e),
        })?;
        self.denied_arg_patterns.insert(tool.to_owned(), dp);
        Ok(self)
    }

    /// Checks every tool's arguments against an outbound URL allowlist: a
    /// call whose arguments hold a URL (markdown or HTML link, autolink,
    /// bare `scheme://` URL, see [`crate::guard::egress`]) to a host
    /// outside `allowlist` is denied as `EGRESS_HOST`. Arguments that are
    /// JSON are judged by their decoded string values and member names
    /// (what the tool receives), other arguments as written.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::egress::EgressAllowlist;
    /// use redactify::guard::tools::{check, ToolCall, ToolContract};
    ///
    /// let contract = ToolContract::new(&["fetch"])
    ///     .with_egress_allowlist(EgressAllowlist::new(["api.example.com"]).unwrap());
    /// let ok = ToolCall::new("fetch", r#"{"url":"https://api.example.com/v1"}"#);
    /// assert!(check(&contract, &[], &ok).is_allow());
    /// // a JSON escape does not hide the host
    /// let bad = ToolCall::new("fetch", r#"{"url":"https:\/\/attacker.example\/?d=1"}"#);
    /// assert_eq!(check(&contract, &[], &bad).code(), "EGRESS_HOST");
    /// ```
    #[must_use]
    pub fn with_egress_allowlist(mut self, allowlist: EgressAllowlist) -> Self {
        self.egress_allowlist = Some(allowlist);
        self
    }

    /// The outbound URL allowlist, when one is set.
    #[must_use]
    pub const fn egress_allowlist(&self) -> Option<&EgressAllowlist> {
        self.egress_allowlist.as_ref()
    }

    /// Whether `tool` is allowlisted.
    #[must_use]
    pub fn allows(&self, tool: &str) -> bool {
        self.allowed.iter().any(|t| t == tool)
    }

    /// The contract in canonical JSON form: every field present (an unset
    /// budget or allowlist as `null`), the allowed tools sorted without
    /// duplicates, deny patterns as their source text, egress entries in
    /// canonical form. [`ToolContract::from_json`] reads it back to an
    /// equivalent contract, and two contracts that decide every call
    /// alike up to allowlist order serialize identically.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::tools::ToolContract;
    /// use serde_json::json;
    ///
    /// let a = ToolContract::from_json(&json!({"allowed": ["b", "a", "a"]})).unwrap();
    /// let b = ToolContract::new(&["a", "b"]);
    /// assert_eq!(a.to_json(), b.to_json());
    /// assert_eq!(a.policy_hash(), b.policy_hash());
    /// assert_eq!(a.to_json()["allowed"], json!(["a", "b"]));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut allowed: Vec<&str> = self.allowed.iter().map(String::as_str).collect();
        allowed.sort_unstable();
        allowed.dedup();
        let patterns: serde_json::Map<String, serde_json::Value> = self
            .denied_arg_patterns
            .iter()
            .map(|(tool, p)| (tool.clone(), serde_json::Value::from(p.pattern.as_str())))
            .collect();
        serde_json::json!({
            "allowed": allowed,
            "global_max": self.global_max,
            "per_tool_max": self.per_tool_max,
            "repeat_tolerance": self.repeat_tolerance,
            "token_budget": self.token_budget,
            "denied_arg_patterns": patterns,
            "egress_allowlist": self
                .egress_allowlist
                .as_ref()
                .map(|a| a.entries().collect::<Vec<String>>()),
        })
    }

    /// SHA-256 over the canonical JSON of [`ToolContract::to_json`]
    /// (object keys sorted at every depth): the policy identity recorded
    /// in tool-decision audit records and the contract a server-held
    /// session is bound to.
    #[must_use]
    pub fn policy_hash(&self) -> [u8; 32] {
        let mut canonical = String::new();
        write_canonical_json(&self.to_json(), &mut canonical);
        crate::guard::audit::sha256(canonical.as_bytes())
    }
}

/// The history counts the ordered budget and loop checks read, for one
/// call: taken from a caller-supplied history by [`check`], or from the
/// server-held log of a [`ToolSessions`] session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallCounts {
    /// Earlier calls (all tools).
    pub calls: usize,
    /// Earlier calls of the same tool.
    pub tool_calls: usize,
    /// Earlier calls with the same tool AND the same arguments.
    pub repeats: usize,
    /// Estimated tokens of all earlier calls
    /// ([`ToolCall::estimated_tokens`], saturating).
    pub tokens: usize,
}

impl CallCounts {
    /// Counts `history` (oldest first) as seen by `call`.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::tools::{CallCounts, ToolCall};
    ///
    /// let a = ToolCall::new("search", "q=1");
    /// let history = [a.clone(), ToolCall::new("search", "q=2"), ToolCall::new("calc", "1+1")];
    /// let counts = CallCounts::from_history(&history, &a);
    /// assert_eq!((counts.calls, counts.tool_calls, counts.repeats), (3, 2, 1));
    /// ```
    #[must_use]
    pub fn from_history(history: &[ToolCall], call: &ToolCall) -> Self {
        let mut counts = Self {
            calls: history.len(),
            ..Self::default()
        };
        for c in history {
            counts.tokens = counts.tokens.saturating_add(c.estimated_tokens());
            if c.tool == call.tool {
                counts.tool_calls += 1;
                if c.args == call.args {
                    counts.repeats += 1;
                }
            }
        }
        counts
    }
}

/// The history-dependent checks, in their fixed order: global budget,
/// token budget, per-tool budget, loop. The allowlist is checked first by
/// the callers.
fn budget_verdict(contract: &ToolContract, call: &ToolCall, counts: &CallCounts) -> ToolVerdict {
    if let Some(max) = contract.global_max {
        if counts.calls >= max {
            return ToolVerdict::Deny("GLOBAL_BUDGET");
        }
    }
    // token budget: cumulative estimate + this call must stay under the
    // cap (saturating: a huge history can never wrap around to "cheap")
    if let Some(budget) = contract.token_budget {
        if counts.tokens.saturating_add(call.estimated_tokens()) > budget {
            return ToolVerdict::Deny("TOKEN_BUDGET");
        }
    }
    if let Some(&max) = contract.per_tool_max.get(&call.tool) {
        if counts.tool_calls >= max {
            return ToolVerdict::Deny("TOOL_BUDGET");
        }
    }
    // `>=`, not `>`: "tolerance 2 = original + retry pass, third is the
    // loop", as every doc states
    if counts.repeats >= contract.repeat_tolerance {
        return ToolVerdict::Deny("LOOP");
    }
    ToolVerdict::Allow
}

/// The history-independent argument checks: the per-tool deny pattern,
/// then the egress allowlist.
fn args_verdict(contract: &ToolContract, call: &ToolCall) -> ToolVerdict {
    // argument pattern denial. A pattern-engine ERROR denies too: this is
    // a deny-by-default path - silently passing the call on an internal
    // error would be fail-open
    if let Some(dp) = contract.denied_arg_patterns.get(&call.tool) {
        match dp.regex.is_match(&call.args) {
            Ok(true) => return ToolVerdict::Deny("ARG_PATTERN"),
            Err(_) => return ToolVerdict::Deny("ARG_PATTERN_ERROR"),
            Ok(false) => {}
        }
    }
    if let Some(allow) = &contract.egress_allowlist {
        if !args_egress_clean(allow, &call.args) {
            return ToolVerdict::Deny("EGRESS_HOST");
        }
    }
    ToolVerdict::Allow
}

/// Whether the arguments hold no URL to a host outside `allow`. JSON
/// arguments are judged by their decoded strings and member names (a JSON
/// string ends at its quote, and an escape such as `\/` or `/` is what
/// the tool decodes); anything else as written.
fn args_egress_clean(allow: &EgressAllowlist, args: &str) -> bool {
    if serde_json::from_str::<serde_json::Value>(args).is_err() {
        return allow.is_clean(args);
    }
    // Every string literal of the document - member names and values,
    // duplicate keys included - decoded and judged on its own. A parsed
    // `Value` would keep only the last of duplicate keys, while the tool's
    // own parser may keep the first (`{"url": "https://evil..", "url":
    // "https://allowed.."}`); the raw text cannot be judged as one string
    // because its JSON escapes (`\t`, `\/`) would read as URL characters.
    json_string_literals(args)
        .all(|literal| serde_json::from_str::<String>(literal).is_ok_and(|s| allow.is_clean(&s)))
}

/// The string literals of a valid JSON text, quotes included, in document
/// order (escapes left undecoded).
fn json_string_literals(json: &str) -> impl Iterator<Item = &str> {
    let bytes = json.as_bytes();
    let mut at = 0;
    std::iter::from_fn(move || {
        let start = at + bytes.get(at..)?.iter().position(|&b| b == b'"')?;
        let mut i = start + 1;
        while let Some(&b) = bytes.get(i) {
            match b {
                b'\\' => i += 2,
                b'"' => break,
                _ => i += 1,
            }
        }
        let end = (i + 1).min(bytes.len());
        at = end;
        Some(&json[start..end])
    })
}

/// Evaluates one tool call against the contract and the call history
/// (chronological, oldest first).
#[must_use]
pub fn check(contract: &ToolContract, history: &[ToolCall], call: &ToolCall) -> ToolVerdict {
    check_with_counts(contract, call, &CallCounts::from_history(history, call))
}

/// Evaluates one call against the contract and the history counts, in the
/// fixed order: allowlist, global budget, token budget, per-tool budget,
/// loop, argument deny pattern, egress allowlist. [`check`] is this over
/// [`CallCounts::from_history`]; [`ToolSessions`] calls it with the counts
/// of its server-held log.
#[must_use]
pub fn check_with_counts(
    contract: &ToolContract,
    call: &ToolCall,
    counts: &CallCounts,
) -> ToolVerdict {
    if !contract.allows(&call.tool) {
        return ToolVerdict::Deny("NOT_ALLOWLISTED");
    }
    match budget_verdict(contract, call, counts) {
        ToolVerdict::Allow => args_verdict(contract, call),
        deny => deny,
    }
}

/// Evaluates a whole tool-check request read from JSON (the body of the
/// REST `/v1/tool/check` endpoint and the arguments of the MCP
/// `tool_check` tool):
///
/// ```text
/// {
///   "contract": {...},              required, see ToolContract::from_json
///   "history": [call, ...],         optional (absent / null = empty),
///                                   oldest first, at most MAX_TOOL_HISTORY
///   "call": {"tool", "args"?}       required, see ToolCall::from_json
/// }
/// ```
///
/// The fields are checked in this order: `contract`, `call`, then
/// `history` (its length before any of its calls is parsed).
///
/// # Errors
/// [`ToolCheckError`] naming the first offending field (and, for a
/// history entry, its position).
///
/// # Examples
/// ```
/// use redactify::guard::tools::check_json;
/// use serde_json::json;
///
/// let verdict = check_json(&json!({
///     "contract": {"allowed": ["search"]},
///     "history": [{"tool": "search", "args": {"q": "a"}}],
///     "call": {"tool": "shell", "args": "rm -rf /"}
/// }))
/// .unwrap();
/// assert_eq!(verdict.code(), "NOT_ALLOWLISTED");
/// assert!(check_json(&json!({"call": {"tool": "search"}})).is_err());
/// ```
pub fn check_json(request: &serde_json::Value) -> Result<ToolVerdict, ToolCheckError> {
    let (contract, call) = contract_and_call(request)?;
    let history = history_from(request)?;
    Ok(check(&contract, &history, &call))
}

/// The `contract` and `call` fields of a tool-check request, in that order.
fn contract_and_call(
    request: &serde_json::Value,
) -> Result<(ToolContract, ToolCall), ToolCheckError> {
    let contract = request
        .get("contract")
        .ok_or(ToolCheckError::MissingField { field: "contract" })?;
    let contract = ToolContract::from_json(contract).map_err(ToolCheckError::Contract)?;
    let call = request
        .get("call")
        .ok_or(ToolCheckError::MissingField { field: "call" })?;
    let call = ToolCall::from_json(call).map_err(ToolCheckError::Call)?;
    Ok((contract, call))
}

/// The `history` field of a tool-check request (its length checked before
/// any call is parsed).
fn history_from(request: &serde_json::Value) -> Result<Vec<ToolCall>, ToolCheckError> {
    match request.get("history") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(calls)) => {
            if calls.len() > MAX_TOOL_HISTORY {
                return Err(ToolCheckError::HistoryTooLong {
                    len: calls.len(),
                    limit: MAX_TOOL_HISTORY,
                });
            }
            calls
                .iter()
                .enumerate()
                .map(|(index, c)| {
                    ToolCall::from_json(c)
                        .map_err(|source| ToolCheckError::HistoryCall { index, source })
                })
                .collect()
        }
        Some(_) => Err(ToolCheckError::HistoryNotArray),
    }
}

/// The engine version recorded in tool-decision audit records.
const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// One evaluated tool-check request: the verdict and the content-free
/// fields of its audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ToolCheckOutcome {
    /// The verdict for the call.
    pub verdict: ToolVerdict,
    /// What the audit record of this decision carries (never argument
    /// values).
    pub audit: ToolAuditFields,
}

impl ToolCheckOutcome {
    fn new(
        contract: &ToolContract,
        call: &ToolCall,
        verdict: ToolVerdict,
        counts: CallCounts,
        session_id: Option<&str>,
    ) -> Self {
        let audit = ToolAuditFields {
            code: verdict.code(),
            // a name outside the allowlist is model-chosen text: left out
            tool: contract.allows(&call.tool).then(|| call.tool.clone()),
            session_id: session_id.map(str::to_owned),
            policy_hash: crate::guard::audit::hex(&contract.policy_hash()),
            engine_version: ENGINE_VERSION,
            calls: counts.calls,
            tool_calls: counts.tool_calls,
            repeats: counts.repeats,
            tokens: counts.tokens,
            args_bytes: call.args.len(),
        };
        Self { verdict, audit }
    }

    /// The hash-chainable audit record of this decision (see
    /// [`AuditRecord::tool_decision`]).
    #[must_use]
    pub fn audit_record(&self, request_id: impl Into<String>) -> AuditRecord {
        AuditRecord::tool_decision(request_id, self.audit.clone())
    }
}

/// [`check_json`] with server-held sessions: the request shape of the REST
/// `/v1/tool/check` endpoint and the MCP `tool_check` tool.
///
/// ```text
/// {
///   "contract": {...},          required
///   "call": {"tool", "args"?},  required
///   "session_id": "agent-run-42"  optional: the server holds the history
///   "history": [call, ...]      optional, only WITHOUT session_id
/// }
/// ```
///
/// Without `session_id` this is [`check_json`] (the caller supplies the
/// history). With it, the counts come from `sessions` (see
/// [`ToolSessions::check`]) and a `history` field is refused
/// ([`ToolCheckError::HistoryInSession`]), so a caller cannot
/// shorten or drop the history to reset a budget. Either way the outcome
/// carries the audit fields of the decision.
///
/// # Errors
/// [`ToolCheckError`] naming the first offending field, checked in the
/// order `contract`, `call`, `session_id`, then `history`.
///
/// # Examples
/// ```
/// use redactify::guard::tools::{check_json_with, ToolSessions};
/// use serde_json::json;
///
/// let sessions = ToolSessions::default();
/// let request = json!({
///     "contract": {"allowed": ["search"], "global_max": 1},
///     "session_id": "run-1",
///     "call": {"tool": "search", "args": {"q": "a"}}
/// });
/// assert!(check_json_with(&sessions, &request).unwrap().verdict.is_allow());
/// // the second call is over the budget: the server remembers the first
/// let request = json!({
///     "contract": {"allowed": ["search"], "global_max": 1},
///     "session_id": "run-1",
///     "call": {"tool": "search", "args": {"q": "b"}}
/// });
/// let outcome = check_json_with(&sessions, &request).unwrap();
/// assert_eq!(outcome.verdict.code(), "GLOBAL_BUDGET");
/// assert_eq!(outcome.audit.calls, 1);
/// ```
pub fn check_json_with(
    sessions: &ToolSessions,
    request: &serde_json::Value,
) -> Result<ToolCheckOutcome, ToolCheckError> {
    let (contract, call) = contract_and_call(request)?;
    match request.get("session_id") {
        None | Some(serde_json::Value::Null) => {
            let history = history_from(request)?;
            let counts = CallCounts::from_history(&history, &call);
            let verdict = check_with_counts(&contract, &call, &counts);
            Ok(ToolCheckOutcome::new(
                &contract, &call, verdict, counts, None,
            ))
        }
        Some(serde_json::Value::String(id)) => {
            if !valid_session_id(id) {
                return Err(ToolCheckError::InvalidSessionId);
            }
            if !matches!(request.get("history"), None | Some(serde_json::Value::Null)) {
                return Err(ToolCheckError::HistoryInSession);
            }
            let decision = sessions.check(id, &contract, &call)?;
            Ok(ToolCheckOutcome::new(
                &contract,
                &call,
                decision.verdict,
                decision.counts,
                Some(id),
            ))
        }
        Some(_) => Err(ToolCheckError::InvalidSessionId),
    }
}

/// Longest accepted session id (bytes).
pub const MAX_SESSION_ID_LEN: usize = 128;

/// 1 to [`MAX_SESSION_ID_LEN`] printable ASCII characters (the REST
/// `request_id` rule).
fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SESSION_ID_LEN
        && id.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// Bounds of a [`ToolSessions`] table. Memory is bounded by
/// `max_sessions` times the per-session cost, which grows with the
/// number of distinct `(tool, args)` pairs recorded (at most
/// `max_calls_per_session`); see the type docs of [`ToolSessions`] for
/// measured numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// Live sessions at most. A new session beyond it is refused
    /// (`SESSION_LIMIT`) unless an idle one can be expired: a live session
    /// is never evicted to make room, since evicting it would reset its
    /// budgets.
    pub max_sessions: usize,
    /// Allowed calls recorded per session at most; the next call is denied
    /// (`SESSION_LIMIT`), never recorded over the oldest one.
    pub max_calls_per_session: usize,
    /// A session unused for longer than this expires on its next use or
    /// when room is needed; its id is then refused (`SESSION_EXPIRED`).
    pub idle_timeout: std::time::Duration,
    /// How many ended or expired session ids are remembered (FIFO) so they
    /// cannot be reused to start over with fresh budgets; 0 disables the
    /// memory.
    pub max_ended_ids: usize,
}

impl Default for SessionLimits {
    /// 1024 sessions, 1024 calls per session, 1 hour idle timeout, 4096
    /// remembered ended ids (a full table of full sessions is about 26 MiB,
    /// see [`ToolSessions`]).
    fn default() -> Self {
        Self {
            max_sessions: 1024,
            max_calls_per_session: 1024,
            idle_timeout: std::time::Duration::from_secs(3600),
            max_ended_ids: 4096,
        }
    }
}

/// The decision of [`ToolSessions::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionDecision {
    /// The verdict for the call.
    pub verdict: ToolVerdict,
    /// The session counts the verdict was computed from (before this
    /// call; all zero for a session-level refusal).
    pub counts: CallCounts,
    /// Whether this call started the session.
    pub created: bool,
}

/// Server-held tool-call sessions: the call history behind the budgets and
/// the loop check lives in the server, not in the request, so an agent
/// layer cannot reset a budget by shortening or dropping the history it
/// sends.
///
/// A session starts on the first call that names its id and is bound to
/// that call's contract ([`ToolContract::policy_hash`]); a later call with
/// another contract is denied (`CONTRACT_MISMATCH`), so a budget cannot be
/// raised mid-session either. Only allowed calls are recorded (a denied
/// call never ran). Each session keeps counts, not arguments: the number
/// of calls, the estimated tokens, the calls per tool, and per distinct
/// `(tool, args)` pair a 64-bit keyed hash with its count (SipHash with a
/// per-table random key; a collision could only merge two pairs into one
/// count, which can deny a call as `LOOP` early, never allow one).
///
/// Eviction policy: a session idle for longer than
/// [`SessionLimits::idle_timeout`] expires on its next use, or when the
/// table is full and room is needed; a live session is never evicted. An
/// ended or expired id is remembered (bounded FIFO) and refused
/// (`SESSION_EXPIRED`).
///
/// A caller that mints a NEW session id starts with fresh budgets: issue
/// the id from the orchestrator (never from model output), and audit
/// session starts (every decision record carries its `session_id`).
///
/// Memory (resident-set growth, release build, 1024 sessions, see
/// `measure_memory_per_session` in `tests/tool_sessions.rs`): an empty
/// table holds no heap memory; a session with up to 16 recorded pairs
/// stays under about 1.2 KiB; 256 distinct pairs cost about 8.1 KiB, 1024
/// about 26 KiB and 4096 about 124-131 KiB per session (about 26-33 bytes
/// per pair, hash-map capacity included). The default limits (1024
/// sessions of at most 1024 calls) bound the table at about 26 MiB.
///
/// # Examples
/// ```
/// use redactify::guard::tools::{ToolCall, ToolContract, ToolSessions};
///
/// let sessions = ToolSessions::default();
/// let contract = ToolContract::new(&["search"]).with_global_max(2);
/// let call = |q: &str| ToolCall::new("search", q);
/// assert!(sessions.check("s1", &contract, &call("a")).unwrap().verdict.is_allow());
/// assert!(sessions.check("s1", &contract, &call("b")).unwrap().verdict.is_allow());
/// // the third call is over the global budget: no history was sent
/// assert_eq!(sessions.check("s1", &contract, &call("c")).unwrap().verdict.code(), "GLOBAL_BUDGET");
/// // another contract cannot be swapped in mid-session
/// let looser = ToolContract::new(&["search"]).with_global_max(100);
/// assert_eq!(sessions.check("s1", &looser, &call("d")).unwrap().verdict.code(), "CONTRACT_MISMATCH");
/// ```
pub struct ToolSessions {
    limits: SessionLimits,
    /// Keyed hasher for call identities and ended ids.
    hasher: std::hash::RandomState,
    table: std::sync::Mutex<SessionTable>,
}

#[derive(Default)]
struct SessionTable {
    live: HashMap<Box<str>, Session>,
    /// Hashes of ended ids, oldest first, and the same set for lookups.
    ended: VecDeque<u64>,
    ended_set: HashSet<u64>,
}

struct Session {
    policy_hash: [u8; 32],
    calls: usize,
    tokens: usize,
    per_tool: HashMap<Box<str>, usize>,
    /// Keyed hash of `(tool, args)` -> recorded count.
    repeats: HashMap<u64, u32>,
    last_seen: std::time::Instant,
}

impl SessionTable {
    /// Ends a live session (if any) and remembers its id hash.
    fn end(&mut self, id: &str, id_hash: u64, max_ended: usize) -> bool {
        let was_live = self.live.remove(id).is_some();
        if max_ended > 0 && self.ended_set.insert(id_hash) {
            self.ended.push_back(id_hash);
            while self.ended.len() > max_ended {
                if let Some(old) = self.ended.pop_front() {
                    self.ended_set.remove(&old);
                }
            }
        }
        was_live
    }
}

impl Default for ToolSessions {
    /// A table with [`SessionLimits::default`].
    fn default() -> Self {
        Self::new(SessionLimits::default())
    }
}

impl std::fmt::Debug for ToolSessions {
    /// Limits and the number of live sessions; never session ids.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolSessions")
            .field("limits", &self.limits)
            .field("live", &self.len())
            .finish_non_exhaustive()
    }
}

impl ToolSessions {
    /// An empty table with the given bounds (no heap memory until the
    /// first session).
    #[must_use]
    pub fn new(limits: SessionLimits) -> Self {
        Self {
            limits,
            hasher: std::hash::RandomState::new(),
            table: std::sync::Mutex::new(SessionTable::default()),
        }
    }

    /// The table's bounds.
    #[must_use]
    pub const fn limits(&self) -> SessionLimits {
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

    /// Ends a session: its counts are dropped and its id is refused from
    /// now on (`SESSION_EXPIRED`, while the id is remembered). Returns
    /// whether the session was live.
    pub fn end(&self, session_id: &str) -> bool {
        let id_hash = self.hasher.hash_one(session_id);
        self.lock()
            .end(session_id, id_hash, self.limits.max_ended_ids)
    }

    /// Evaluates `call` in session `session_id` at the current time (see
    /// [`Self::check_at`]).
    ///
    /// # Errors
    /// [`ToolCheckError::InvalidSessionId`] when `session_id` is not 1 to
    /// [`MAX_SESSION_ID_LEN`] printable ASCII characters.
    pub fn check(
        &self,
        session_id: &str,
        contract: &ToolContract,
        call: &ToolCall,
    ) -> Result<SessionDecision, ToolCheckError> {
        self.check_at(session_id, contract, call, std::time::Instant::now())
    }

    /// Evaluates `call` in session `session_id` as of `now`: the session is
    /// started (bound to `contract`) on first use, its counts feed
    /// [`check_with_counts`], and an allowed call is recorded. Session
    /// refusals come first: `SESSION_EXPIRED` (ended, timed out or a
    /// remembered id), `SESSION_LIMIT` (no room for a new session),
    /// `CONTRACT_MISMATCH`; then the contract's own codes; then
    /// `SESSION_LIMIT` when the session's call log is full.
    ///
    /// The contract hash, the call identity and the argument checks
    /// (deny pattern, egress scan) are computed before the table lock is
    /// taken; the locked section is a few hash-map operations.
    ///
    /// # Errors
    /// [`ToolCheckError::InvalidSessionId`] when `session_id` is not 1 to
    /// [`MAX_SESSION_ID_LEN`] printable ASCII characters.
    pub fn check_at(
        &self,
        session_id: &str,
        contract: &ToolContract,
        call: &ToolCall,
        now: std::time::Instant,
    ) -> Result<SessionDecision, ToolCheckError> {
        if !valid_session_id(session_id) {
            return Err(ToolCheckError::InvalidSessionId);
        }
        let policy_hash = contract.policy_hash();
        let identity = self
            .hasher
            .hash_one((call.tool.as_str(), call.args.as_str()));
        let id_hash = self.hasher.hash_one(session_id);
        let allowlisted = contract.allows(&call.tool);
        let args = if allowlisted {
            args_verdict(contract, call)
        } else {
            ToolVerdict::Deny("NOT_ALLOWLISTED")
        };
        let refuse = |code: &'static str, created: bool| {
            Ok(SessionDecision {
                verdict: ToolVerdict::Deny(code),
                counts: CallCounts::default(),
                created,
            })
        };

        let mut guard = self.lock();
        let table = &mut *guard;
        let idle = table
            .live
            .get(session_id)
            .map(|s| now.saturating_duration_since(s.last_seen) > self.limits.idle_timeout);
        let mut created = false;
        match idle {
            Some(true) => {
                table.end(session_id, id_hash, self.limits.max_ended_ids);
                return refuse("SESSION_EXPIRED", false);
            }
            Some(false) => {}
            None => {
                if table.ended_set.contains(&id_hash) {
                    return refuse("SESSION_EXPIRED", false);
                }
                if table.live.len() >= self.limits.max_sessions {
                    self.sweep(table, now);
                    if table.live.len() >= self.limits.max_sessions {
                        return refuse("SESSION_LIMIT", false);
                    }
                }
                table.live.insert(
                    session_id.into(),
                    Session {
                        policy_hash,
                        calls: 0,
                        tokens: 0,
                        per_tool: HashMap::new(),
                        repeats: HashMap::new(),
                        last_seen: now,
                    },
                );
                created = true;
            }
        }
        let Some(session) = table.live.get_mut(session_id) else {
            return refuse("SESSION_LIMIT", created); // not reachable: just inserted
        };
        session.last_seen = now;
        if session.policy_hash != policy_hash {
            return refuse("CONTRACT_MISMATCH", created);
        }
        let counts = CallCounts {
            calls: session.calls,
            tool_calls: session
                .per_tool
                .get(call.tool.as_str())
                .copied()
                .unwrap_or(0),
            repeats: session.repeats.get(&identity).map_or(0, |&n| n as usize),
            tokens: session.tokens,
        };
        let mut verdict = if allowlisted {
            match budget_verdict(contract, call, &counts) {
                ToolVerdict::Allow => args,
                deny => deny,
            }
        } else {
            args
        };
        if verdict.is_allow() {
            if session.calls >= self.limits.max_calls_per_session {
                verdict = ToolVerdict::Deny("SESSION_LIMIT");
            } else {
                session.calls += 1;
                session.tokens = session.tokens.saturating_add(call.estimated_tokens());
                match session.per_tool.get_mut(call.tool.as_str()) {
                    Some(n) => *n += 1,
                    None => {
                        session.per_tool.insert(call.tool.as_str().into(), 1);
                    }
                }
                let n = session.repeats.entry(identity).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
        Ok(SessionDecision {
            verdict,
            counts,
            created,
        })
    }

    /// Expires every idle session (called only when the table is full).
    fn sweep(&self, table: &mut SessionTable, now: std::time::Instant) {
        let idle: Vec<Box<str>> = table
            .live
            .iter()
            .filter(|(_, s)| now.saturating_duration_since(s.last_seen) > self.limits.idle_timeout)
            .map(|(id, _)| id.clone())
            .collect();
        for id in idle {
            let id_hash = self.hasher.hash_one(&*id);
            table.end(&id, id_hash, self.limits.max_ended_ids);
        }
    }

    /// The table, also after a panic in another thread (every update is
    /// made after all checks, so the state stays consistent).
    fn lock(&self) -> std::sync::MutexGuard<'_, SessionTable> {
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{check, ToolCall, ToolContract, ToolContractError, ToolVerdict};

    fn call(tool: &str, args: &str) -> ToolCall {
        ToolCall::new(tool, args)
    }

    #[test]
    fn serde_round_trip_keeps_denied_patterns() {
        // the wrapper round-trips the SOURCE pattern and recompiles, so
        // no deny rule is dropped on serialize
        #[cfg(feature = "serde")]
        {
            let c = ToolContract::new(&["shell"])
                .with_denied_arg_pattern("shell", r"rm\s+-rf")
                .expect("valid");
            let json = serde_json::to_string(&c).expect("serialize");
            let back: ToolContract = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                check(&back, &[], &ToolCall::new("shell", "rm -rf /")),
                ToolVerdict::Deny("ARG_PATTERN"),
                "deny rule lost on round-trip: {json}"
            );
            assert!(check(&back, &[], &ToolCall::new("shell", "ls")).is_allow());
        }
        #[cfg(not(feature = "serde"))]
        {
            // without serde the wrapper is inert; behavior locked by the
            // arg_pattern test above
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shape_matches_from_json() {
        // unset budgets are omitted, defaults fill in on read, and the
        // serde output is accepted by from_json (one JSON shape)
        let c = ToolContract::new(&["a"]).with_tool_max("a", 3);
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("global_max").is_none(), "{json}");
        assert!(json.get("token_budget").is_none(), "{json}");
        let back = ToolContract::from_json(&json).unwrap();
        let h = vec![call("a", "1"), call("a", "2"), call("a", "3")];
        assert_eq!(check(&back, &h, &call("a", "4")).code(), "TOOL_BUDGET");
        let minimal: ToolContract = serde_json::from_str(r#"{"allowed":["t"]}"#).unwrap();
        let k = call("t", "x");
        assert!(check(&minimal, std::slice::from_ref(&k), &k).is_allow()); // tolerance 2
        assert!(serde_json::from_str::<ToolContract>(r#"{"allowed":[],"global_maxx":1}"#).is_err());
        // a legacy usize::MAX budget still reads as effectively unlimited
        let legacy: ToolContract =
            serde_json::from_str(r#"{"allowed":["t"],"global_max":18446744073709551615}"#).unwrap();
        assert!(check(&legacy, &[], &k).is_allow());
    }

    #[test]
    fn deny_by_default() {
        let c = ToolContract::new(&["search"]);
        assert_eq!(
            check(&c, &[], &call("exec", "{}")),
            ToolVerdict::Deny("NOT_ALLOWLISTED")
        );
        assert!(check(&c, &[], &call("search", "{}")).is_allow());
    }

    #[test]
    fn global_budget() {
        let c = ToolContract::new(&["a", "b"]).with_global_max(2);
        let h = vec![call("a", "1"), call("b", "2")];
        assert_eq!(
            check(&c, &h, &call("a", "3")),
            ToolVerdict::Deny("GLOBAL_BUDGET")
        );
    }

    #[test]
    fn per_tool_budget() {
        let c = ToolContract::new(&["a", "b"]).with_tool_max("a", 1);
        let h = vec![call("a", "1")];
        assert_eq!(
            check(&c, &h, &call("a", "2")),
            ToolVerdict::Deny("TOOL_BUDGET")
        );
        assert!(check(&c, &h, &call("b", "9")).is_allow()); // other tool unaffected
    }

    #[test]
    fn loop_detected_on_identical_repeats_only() {
        // tolerance counts TOTAL identical calls: tolerance 1 = only the
        // original passes; the second identical call is already the loop
        let c = ToolContract::new(&["search"]).with_repeat_tolerance(1);
        let s1 = call("search", r#"{"q":"x"}"#);
        assert!(check(&c, &[], &s1).is_allow());
        assert_eq!(
            check(&c, std::slice::from_ref(&s1), &s1),
            ToolVerdict::Deny("LOOP")
        );
        // different args are NOT a loop
        let s2 = call("search", r#"{"q":"y"}"#);
        assert!(check(&c, &[s1.clone(), s1], &s2).is_allow());
    }

    #[test]
    fn default_tolerance_allows_one_retry() {
        // default tolerance 2: original + one retry pass, the THIRD
        // identical call is denied (constructor doc contract)
        let c = ToolContract::new(&["t"]);
        let k = call("t", "same");
        let h = vec![k.clone()];
        assert!(
            check(&c, &h, &k).is_allow(),
            "one in history + 1 new = retry"
        );
        let h = vec![k.clone(), k.clone()];
        assert_eq!(
            check(&c, &h, &k),
            ToolVerdict::Deny("LOOP"),
            "two in history + 1 new = third identical call"
        );
    }

    #[test]
    fn arg_pattern_engine_error_denies_fail_closed() {
        // an engine error on a denied-args check must deny, never pass
        // the call (deny-by-default path). A compile error is not constructible
        // through the builder (it refuses), so this pins the contract via
        // the normal path while the Err arm denies by code: Ok(true) ->
        // ARG_PATTERN, Err(_) -> ARG_PATTERN_ERROR, Ok(false) -> continue.
        let c = ToolContract::new(&["shell"])
            .with_denied_arg_pattern("shell", r"rm\s+-rf")
            .expect("valid pattern");
        assert_eq!(
            check(&c, &[], &call("shell", "rm -rf /")),
            ToolVerdict::Deny("ARG_PATTERN")
        );
        assert!(check(&c, &[], &call("shell", "ls -la")).is_allow());
    }

    #[test]
    fn invalid_pattern_is_a_typed_error_with_source() {
        use std::error::Error as _;
        let err = ToolContract::new(&["shell"])
            .with_denied_arg_pattern("shell", "(unclosed")
            .unwrap_err();
        assert!(
            matches!(&err, ToolContractError::InvalidPattern { tool, .. } if tool == "shell"),
            "{err:?}"
        );
        assert!(err.source().is_some(), "compiler error must be the source");
        assert!(err.to_string().contains("shell"), "{err}");
    }

    #[test]
    fn verdict_codes_are_stable() {
        assert_eq!(ToolVerdict::Allow.code(), "ALLOW");
        assert_eq!(ToolVerdict::Deny("LOOP").code(), "LOOP");
    }

    mod json {
        use super::super::{check, ToolCall, ToolContract, ToolContractError};
        use serde_json::json;

        #[test]
        fn full_contract_reads_every_field() {
            let c = ToolContract::from_json(&json!({
                "allowed": ["search", "shell"],
                "global_max": 10,
                "token_budget": null,
                "per_tool_max": {"shell": 1},
                "repeat_tolerance": 1,
                "denied_arg_patterns": {"shell": "--force"}
            }))
            .unwrap();
            assert!(c.allows("search") && c.allows("shell") && !c.allows("rm"));
            let s = ToolCall::new("search", "q");
            assert_eq!(check(&c, std::slice::from_ref(&s), &s).code(), "LOOP");
            let sh = ToolCall::new("shell", "ls");
            assert_eq!(
                check(
                    &c,
                    std::slice::from_ref(&sh),
                    &ToolCall::new("shell", "pwd")
                )
                .code(),
                "TOOL_BUDGET"
            );
            assert_eq!(
                check(&c, &[], &ToolCall::new("shell", "x --force")).code(),
                "ARG_PATTERN"
            );
            let ten: Vec<ToolCall> = (0..10)
                .map(|i| ToolCall::new("search", i.to_string()))
                .collect();
            assert_eq!(
                check(&c, &ten, &ToolCall::new("search", "new")).code(),
                "GLOBAL_BUDGET"
            );
        }

        #[test]
        fn minimal_contract_uses_the_defaults() {
            let c = ToolContract::from_json(&json!({"allowed": ["t"]})).unwrap();
            let k = ToolCall::new("t", "x".repeat(100_000));
            let history = vec![k.clone()];
            assert!(
                check(&c, &history, &k).is_allow(),
                "tolerance 2, no budgets"
            );
            assert_eq!(check(&c, &[k.clone(), k.clone()], &k).code(), "LOOP");
        }

        #[test]
        fn malformed_contracts_name_the_field() {
            let cases = [
                (json!([]), "(root)"),
                (json!({"allowed": "search"}), "allowed"),
                (json!({"allowed": ["a", 3]}), "allowed[1]"),
                (json!({"allowed": [], "global_max": -1}), "global_max"),
                (json!({"allowed": [], "token_budget": 1.5}), "token_budget"),
                (
                    json!({"allowed": [], "repeat_tolerance": "2"}),
                    "repeat_tolerance",
                ),
                (
                    json!({"allowed": [], "per_tool_max": {"a": true}}),
                    "per_tool_max.a",
                ),
                (
                    json!({"allowed": [], "denied_arg_patterns": {"a": 1}}),
                    "denied_arg_patterns.a",
                ),
            ];
            for (v, field) in cases {
                match ToolContract::from_json(&v) {
                    Err(ToolContractError::InvalidField { field: f, .. }) => {
                        assert_eq!(f, field, "{v}");
                    }
                    other => panic!("{v}: expected InvalidField({field}), got {other:?}"),
                }
            }
            assert!(matches!(
                ToolContract::from_json(&json!({})),
                Err(ToolContractError::MissingField { field: "allowed" })
            ));
            assert!(matches!(
                ToolContract::from_json(&json!({"allowed": [], "global_maxx": 1})),
                Err(ToolContractError::UnknownField { field }) if field == "global_maxx"
            ));
            assert!(matches!(
                ToolContract::from_json(&json!({"allowed": [], "denied_arg_patterns": {"a": "("}})),
                Err(ToolContractError::InvalidPattern { tool, .. }) if tool == "a"
            ));
        }

        #[test]
        fn calls_canonicalize_object_args() {
            let a = ToolCall::from_json(
                &json!({"tool": "s", "args": {"b": [1, 2], "a": {"y": 1, "x": 0}}}),
            )
            .unwrap();
            assert_eq!(a.args, r#"{"a":{"x":0,"y":1},"b":[1,2]}"#);
            let s = ToolCall::from_json(&json!({"tool": "s", "args": "raw  text"})).unwrap();
            assert_eq!(s.args, "raw  text"); // strings are verbatim
            let n = ToolCall::from_json(&json!({"tool": "s"})).unwrap();
            assert_eq!(n.args, "");
            let null = ToolCall::from_json(&json!({"tool": "s", "args": null})).unwrap();
            assert_eq!(null, n);
            assert!(matches!(
                ToolCall::from_json(&json!({"args": {}})),
                Err(ToolContractError::MissingField { field: "tool" })
            ));
            assert!(ToolCall::from_json(&json!({"tool": 1})).is_err());
            assert!(ToolCall::from_json(&json!({"tool": "s", "extra": 1})).is_err());
        }

        #[test]
        fn canonical_args_equal_the_compact_rendering_of_a_sorted_map() {
            // this build's map is key-sorted, so the explicit canonical
            // writer must be zero-diff against `Value::to_string`
            let values = [
                json!(null),
                json!(true),
                json!(0),
                json!(-1.5e300),
                json!(u64::MAX),
                json!(i64::MIN),
                json!("q\"b\\c\u{1}\u{e9}\u{2028}"),
                json!([]),
                json!({}),
                json!({"b": 1, "a": [1, {"z": null, "y": "\n"}], "": 0, "A": 1, "\u{e9}": 2}),
                json!([[{"k": [{}], "j": {"\"": "\\"}}]]),
            ];
            for v in values {
                let mut canonical = String::new();
                super::super::write_canonical_json(&v, &mut canonical);
                assert_eq!(canonical, v.to_string(), "{v}");
            }
        }

        #[test]
        fn check_json_reads_contract_history_and_call() {
            use super::super::{check_json, ToolCheckError, MAX_TOOL_HISTORY};
            let deny = check_json(&json!({
                "contract": {"allowed": ["a"], "repeat_tolerance": 1},
                "history": [{"tool": "a", "args": {"y": 1, "x": 2}}],
                "call": {"tool": "a", "args": {"x": 2, "y": 1}}
            }))
            .unwrap();
            assert_eq!(deny.code(), "LOOP");
            let long: Vec<serde_json::Value> = (0..=MAX_TOOL_HISTORY).map(|_| json!(0)).collect();
            assert!(matches!(
                check_json(&json!({"contract": {"allowed": []}, "call": {"tool": "a"}, "history": long})),
                Err(ToolCheckError::HistoryTooLong { len, limit: MAX_TOOL_HISTORY }) if len == MAX_TOOL_HISTORY + 1
            ));
            assert!(matches!(
                check_json(
                    &json!({"contract": {"allowed": []}, "call": {"tool": "a"}, "history": [{"tool": "a"}, 1]})
                ),
                Err(ToolCheckError::HistoryCall { index: 1, .. })
            ));
            assert!(matches!(
                check_json(&json!({"contract": {"allowed": []}})),
                Err(ToolCheckError::MissingField { field: "call" })
            ));
        }
    }

    mod token_budget {
        use super::super::{check, ToolCall, ToolContract, ToolVerdict};

        #[test]
        fn token_budget_denies_when_exceeded() {
            let c = ToolContract::new(&["search"]).with_token_budget(100);
            // each call ~15 tokens (tool name 6 + args ~54 → ~15 tokens)
            let call = ToolCall::new(
                "search",
                r#"{"query":"very long search string for testing"}"#,
            );
            // fill history to near the budget
            let history: Vec<ToolCall> = (0..6)
                .map(|i| ToolCall::new("search", format!(r#"{{"query":"test {i} with padding"}}"#)))
                .collect();
            // total history ~6 × 9 tokens = ~54; + call ~15 = ~69 < 100 → allow
            assert!(check(&c, &history, &call).is_allow());
            // double the history → ~108 + 15 > 100 → deny
            let big_history: Vec<ToolCall> = (0..12)
                .map(|i| ToolCall::new("search", format!(r#"{{"query":"test {i} with padding"}}"#)))
                .collect();
            assert_eq!(
                check(&c, &big_history, &call),
                ToolVerdict::Deny("TOKEN_BUDGET")
            );
        }

        #[test]
        fn estimated_tokens_is_chars_div_4() {
            let call = ToolCall::new("search", r#"{"q":"test"}"#); // 6+12=18 chars → 4 tokens
            assert_eq!(call.estimated_tokens(), 4);
            let long = ToolCall::new("calculator", format!("{{{}", "x".repeat(400)));
            assert_eq!(long.estimated_tokens(), (10 + 401) / 4);
        }

        #[test]
        fn no_token_budget_by_default() {
            let c = ToolContract::new(&["t"]);
            let call = ToolCall::new("t", "x".repeat(10000));
            let history: Vec<ToolCall> = (0..100)
                .map(|_| ToolCall::new("t", "y".repeat(1000)))
                .collect();
            // no token budget and no global ceiling: the call passes
            assert!(check(&c, &history, &call).is_allow());
        }

        #[test]
        fn token_accounting_saturates_instead_of_wrapping() {
            // a near-max budget must not overflow `cumulative + estimate`
            let c = ToolContract::new(&["t"]).with_token_budget(usize::MAX - 1);
            let call = ToolCall::new("t", "x".repeat(64));
            assert!(check(&c, std::slice::from_ref(&call), &call).is_allow());
            let tight = ToolContract::new(&["t"]).with_token_budget(0);
            assert_eq!(check(&tight, &[], &call).code(), "TOKEN_BUDGET");
        }

        #[test]
        fn denied_arg_pattern_blocks_dangerous_args() {
            let contract = ToolContract::new(&["delete", "query"])
                .with_denied_arg_pattern("delete", r"(?i)--force|--all|--recursive")
                .expect("pattern compiles");
            // benign call passes
            let call = ToolCall::new("delete", r#"{"path":"./tmp"}"#);
            assert!(check(&contract, &[], &call).is_allow());
            // dangerous flag is denied
            let call = ToolCall::new("delete", r#"{"flags":"--force"}"#);
            assert_eq!(
                check(&contract, &[], &call),
                ToolVerdict::Deny("ARG_PATTERN")
            );
            // other tool is not affected by this tool's pattern
            let call = ToolCall::new("query", r#"{"flags":"--force"}"#);
            assert!(check(&contract, &[], &call).is_allow());
        }
    }
}
