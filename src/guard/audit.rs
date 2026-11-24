//! Metadata-only audit records for guard decisions.
//!
//! Every guard decision can be turned into an [`AuditRecord`] that carries
//! the seven fields the evaluation framework expects (timestamp, request id,
//! guard name, risk score, action, rationale, layer) - and **by construction
//! cannot carry content**: there is no text field for the scanned input.
//! Responses elsewhere in this crate already avoid echoing raw PII; this
//! type extends that guarantee to the audit path.
//!
//! Persistence + tamper evidence: [`ChainedAuditSink`] appends each record
//! as one JSON line and chains every entry with a SHA-256 digest over
//! `(previous hash || record json)` - a later edit of any line breaks every
//! following `prev_hash` (a library-level interpretation of a
//! "tamper-evident store"). SHA-256 is implemented in-tree
//! ([`sha256`], ~70 lines, FIPS 180-4 test vectors) to keep the
//! small-auditable-dependency principle: no crypto crate is pulled in for a
//! chaining digest (this is tamper evidence, not encryption).
//!
//! An OpenTelemetry exporter is deliberately NOT a dependency: the adapter
//! point is `to_json()`/`AuditRecord` itself.

use std::io::Write;

use crate::guard::action::GuardAction;
use crate::guard::category::GuardCategory;

/// One audit event, derived from a policy decision. Content-free by design.
///
/// serde: `Serialize` only - `layer` is a `&'static str` that `Deserialize`
/// cannot produce (no `'static` data from borrowed input).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AuditRecord {
    /// Unix-epoch milliseconds of the decision.
    pub timestamp_ms: u128,
    /// Caller-supplied correlation id (no default: the library never invents
    /// identifiers that could collide with the host's tracing scheme).
    pub request_id: String,
    /// Which layer produced the verdict (`"L0"`, `"L1"`, `"L2"`, `"L3"`).
    pub layer: &'static str,
    /// Guard/category name (`"SQL_INJECTION"`, ...).
    pub guard: String,
    /// Raw risk score (0.0-1.0).
    pub score: f32,
    /// Decision action (`"Block"`, `"Mask"`, `"Log"`, `"Allow"`).
    pub action: GuardAction,
    /// Human-readable rationale (rule/score/threshold strings; these never
    /// embed the input text - they name the pattern and the numbers).
    pub rationale: String,
    /// The fields of an agent tool-call decision (`None` for every other
    /// record, which then serializes without a `tool` key). See
    /// [`AuditRecord::tool_decision`].
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub tool: Option<ToolAuditFields>,
}

/// The content-free fields of one agent tool-call decision record: the
/// verdict code, the policy and engine identity, and counts. Argument
/// values never appear (only their length), and the tool name only when the
/// contract allowlists it (a name outside the allowlist is model-chosen
/// text).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct ToolAuditFields {
    /// The verdict code (`ALLOW`, `GLOBAL_BUDGET`, `EGRESS_HOST`, ...).
    pub code: &'static str,
    /// The tool name, when the contract allowlists it.
    pub tool: Option<String>,
    /// The server-held session the decision was made in (`None` for a
    /// request that supplied its own history).
    pub session_id: Option<String>,
    /// Hex SHA-256 of the contract's canonical JSON
    /// ([`ToolContract::policy_hash`](crate::guard::tools::ToolContract::policy_hash)).
    pub policy_hash: String,
    /// The redactify version that made the decision.
    pub engine_version: &'static str,
    /// Earlier calls counted for this decision (all tools).
    pub calls: usize,
    /// Earlier calls of the same tool.
    pub tool_calls: usize,
    /// Earlier identical calls (same tool and arguments).
    pub repeats: usize,
    /// Estimated tokens of the earlier calls.
    pub tokens: usize,
    /// Length of the checked call's arguments in bytes.
    pub args_bytes: usize,
}

impl ToolAuditFields {
    fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.code,
            "tool": self.tool,
            "session_id": self.session_id,
            "policy_hash": self.policy_hash,
            "engine_version": self.engine_version,
            "calls": self.calls,
            "tool_calls": self.tool_calls,
            "repeats": self.repeats,
            "tokens": self.tokens,
            "args_bytes": self.args_bytes,
        })
    }
}

impl AuditRecord {
    /// Builds a record from one verdict's primitives (the `policy` layer
    /// provides the `Decision`/`GuardVerdict` adapters - keeping this module
    /// free of upward imports).
    #[must_use]
    pub fn from_parts(
        request_id: impl Into<String>,
        layer: &'static str,
        guard: GuardCategory,
        score: f32,
        action: GuardAction,
        rationale: String,
    ) -> Self {
        Self {
            timestamp_ms: now_ms(),
            request_id: request_id.into(),
            layer,
            guard: guard.as_str().to_owned(),
            score,
            action,
            rationale,
            tool: None,
        }
    }

    /// Builds the DECISION summary record from primitives.
    #[must_use]
    pub fn decision(
        request_id: impl Into<String>,
        layer: &'static str,
        score: f32,
        action: GuardAction,
        rationale: String,
    ) -> Self {
        Self {
            timestamp_ms: now_ms(),
            request_id: request_id.into(),
            layer,
            guard: "DECISION".to_owned(),
            score,
            action,
            rationale,
            tool: None,
        }
    }

    /// Builds the record of one agent tool-call decision: layer `"TOOL"`,
    /// guard `"TOOL_CALL"`, action `Allow` (score 0.0) or `Block` (score
    /// 1.0), a rationale naming the verdict code, and `fields` under the
    /// `tool` key of [`Self::to_json`]. Records of this shape chain and
    /// verify like every other ([`ChainedAuditSink`], [`verify_chain`]).
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::audit::{verify_chain, ChainedAuditSink};
    /// use redactify::guard::tools::{check_json_with, ToolSessions};
    /// use serde_json::json;
    ///
    /// let sessions = ToolSessions::default();
    /// let outcome = check_json_with(&sessions, &json!({
    ///     "contract": {"allowed": ["search"]},
    ///     "session_id": "run-7",
    ///     "call": {"tool": "search", "args": {"q": "private query"}}
    /// }))
    /// .unwrap();
    /// let mut sink = ChainedAuditSink::new(Vec::new());
    /// sink.append(&outcome.audit_record("req-1")).unwrap();
    /// let log = String::from_utf8(sink.into_log()).unwrap();
    /// assert_eq!(verify_chain(log.lines(), None), Ok(1));
    /// assert!(log.contains("\"code\":\"ALLOW\"") && log.contains("\"session_id\":\"run-7\""));
    /// assert!(!log.contains("private query")); // never the arguments
    /// ```
    #[must_use]
    pub fn tool_decision(request_id: impl Into<String>, fields: ToolAuditFields) -> Self {
        let allow = fields.code == "ALLOW";
        Self {
            timestamp_ms: now_ms(),
            request_id: request_id.into(),
            layer: "TOOL",
            guard: "TOOL_CALL".to_owned(),
            score: if allow { 0.0 } else { 1.0 },
            action: if allow {
                GuardAction::Allow
            } else {
                GuardAction::Block
            },
            rationale: format!("tool call verdict {}", fields.code),
            tool: Some(fields),
        }
    }

    /// One JSON line (stable field order) - the export/OTLP adapter point.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut v = serde_json::json!({
            "timestamp_ms": self.timestamp_ms,
            "request_id": self.request_id,
            "layer": self.layer,
            "guard": self.guard,
            "score": self.score,
            "action": self.action.to_string(),
            "rationale": self.rationale,
        });
        if let (Some(tool), Some(obj)) = (&self.tool, v.as_object_mut()) {
            obj.insert("tool".to_owned(), tool.to_value());
        }
        v.to_string()
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Append-only audit sink with a per-line SHA-256 hash chain.
///
/// Tamper-evidence caveat: WITHOUT
/// an HMAC key the chain is only as trustworthy as its storage - an
/// attacker with write access to both the records and the chain can
/// recompute the whole chain consistently. Deployments that need
/// cryptographic tamper-evidence against a storage-level attacker must
/// pass an HMAC key (keyed hashes break recomputation) or anchor chain
/// heads externally (e.g. commit digests to a WORM sink). Writing is
/// fallible-but-non-fatal by design (an audit write error must not take the
/// guard down); callers that need fail-closed auditing check the returned
/// chain head after the batch.
///
/// Each record goes out as ONE write of the line plus its `\n`. A failed
/// write may still have left part of that line in the output, so the
/// first write error poisons the sink: every later [`Self::append`] fails
/// without writing, and no record is ever glued onto a torn line (the
/// caller continues degraded, without audit, or stops). A
/// [`FileAuditSink`] recovers by being reopened, which verifies the file
/// first.
pub struct ChainedAuditSink<W: Write> {
    out: W,
    /// SHA-256 over the previous line's chained bytes; all-zero start.
    prev_hash: [u8; 32],
    entries: u64,
    /// Optional HMAC key: when set, every link is `HMAC-SHA256(key,
    /// prev || record)` instead of plain SHA-256 (a rewriter without the
    /// key cannot re-forge the chain).
    hmac_key: Option<Vec<u8>>,
    /// Set by the first failed write: the output may end in a partial line.
    poisoned: bool,
}

/// The HMAC key is never printed, only whether the sink is keyed.
impl<W: Write> std::fmt::Debug for ChainedAuditSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainedAuditSink")
            .field("entries", &self.entries)
            .field("keyed", &self.hmac_key.is_some())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

const GENESIS: [u8; 32] = [0u8; 32];

impl<W: Write> ChainedAuditSink<W> {
    /// Creates a sink writing JSON lines to `out`, starting a fresh chain.
    pub fn new(out: W) -> Self {
        Self {
            out,
            prev_hash: GENESIS,
            entries: 0,
            hmac_key: None,
            poisoned: false,
        }
    }

    /// Switches the chain to keyed mode (HMAC-SHA256 per link). Call before
    /// the first [`Self::append`]; lines carry `"keyed": true` so a
    /// verifier knows which mode to recompute with.
    #[must_use]
    pub fn with_hmac_key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.hmac_key = Some(key.as_ref().to_vec());
        self
    }

    /// Appends one record as `{"chain_prev": ..., "hash": ..., ...record}`,
    /// where `hash = SHA256(prev_hash || record_json)` (or the HMAC
    /// equivalent in keyed mode).
    ///
    /// # Errors
    /// I/O errors of the underlying writer surface here (the chain state
    /// only advances on a successful write). After the first one the sink
    /// is poisoned (see the type docs) and every later call fails without
    /// writing.
    pub fn append(&mut self, record: &AuditRecord) -> std::io::Result<()> {
        if self.poisoned {
            return Err(std::io::Error::other(
                "audit sink poisoned by an earlier failed write (the output may end in a partial line)",
            ));
        }
        let body = record.to_json();
        let mut chained: Vec<u8> = Vec::with_capacity(32 + body.len());
        chained.extend_from_slice(&self.prev_hash);
        chained.extend_from_slice(body.as_bytes());
        let (hash, keyed) = match &self.hmac_key {
            Some(k) => (hmac_sha256(k, &chained), ",\"keyed\":true"),
            None => (sha256(&chained), ""),
        };
        // one write for the line AND its newline: a record and its line
        // end never reach the output separately. Exactly ONE brace is
        // removed on each side, never every trailing brace: a record may
        // end in a nested object (`{..,"tool":{..}}`).
        let inner = body
            .strip_prefix('{')
            .and_then(|b| b.strip_suffix('}'))
            .unwrap_or(&body);
        let line = format!(
            "{{\"chain_prev\":\"{}\",\"hash\":\"{}\"{},{}}}\n",
            hex(&self.prev_hash),
            hex(&hash),
            keyed,
            inner
        );
        if let Err(e) = self.out.write_all(line.as_bytes()) {
            self.poisoned = true;
            return Err(e);
        }
        self.prev_hash = hash;
        self.entries += 1;
        Ok(())
    }

    /// Number of successfully chained entries.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    /// Current chain head (verify a log by comparing the last line's `hash`).
    #[must_use]
    pub const fn chain_head(&self) -> [u8; 32] {
        self.prev_hash
    }
}

impl ChainedAuditSink<Vec<u8>> {
    /// Takes the in-memory log (the accumulated JSON lines) - the natural
    /// pairing with [`verify_chain`]: build a chain in memory, verify or
    /// ship it.
    #[must_use]
    pub fn into_log(self) -> Vec<u8> {
        self.out
    }
}

/// SHA-256 (FIPS 180-4), implemented in-tree to avoid a crypto dependency
/// for the chaining digest. Not constant-time (it hashes public audit
/// metadata, not secrets).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // padding: 0x80, zeros, 64-bit big-endian bit length
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parses 64 hex chars into a 32-byte chain hash (the inverse of [`hex`]).
fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Why a chain verification failed (see [`verify_chain`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// A line is not the exact format [`ChainedAuditSink`] writes.
    #[error("line {line}: not a chained audit line")]
    BadFormat {
        /// 1-based line number.
        line: usize,
    },
    /// A line's `chain_prev` does not match the previous line's hash:
    /// lines were removed, reordered or spliced in.
    #[error("line {line}: chain_prev does not continue the chain (lines removed/reordered)")]
    BrokenChain {
        /// 1-based line number.
        line: usize,
    },
    /// A line's stored hash does not recompute: its content was edited.
    #[error("line {line}: hash mismatch (content edited after writing)")]
    Tampered {
        /// 1-based line number.
        line: usize,
    },
    /// The log was written in a different mode (keyed vs plain) than the
    /// verification key provided.
    #[error("line {line}: keyed/plain mode mismatch between the log and the verification key")]
    ModeMismatch {
        /// 1-based line number.
        line: usize,
    },
}

/// Verifies a log written by [`ChainedAuditSink`]: every line's stored
/// hash must recompute from `(previous hash || record body)` in the same
/// mode the sink wrote (plain SHA-256, or HMAC-SHA256 when keyed - pass
/// the same key). Byte-exact: the record body is sliced from the line as
/// written, never re-serialized.
///
/// # Errors
/// The first problem found, with its 1-based [`ChainError`] line number.
///
/// # Examples
/// ```
/// use redactify::guard::audit::{verify_chain, ChainedAuditSink, AuditRecord};
///
/// let mut sink = ChainedAuditSink::new(Vec::<u8>::new());
/// sink.append(&AuditRecord::decision("r1", "L0", 0.0,
///     redactify::policy::GuardAction::Allow, "ok".into())).unwrap();
/// let log = String::from_utf8(sink.into_log()).unwrap();
/// assert_eq!(verify_chain(log.lines(), None), Ok(1));
/// ```
pub fn verify_chain<'a, I>(lines: I, hmac_key: Option<&[u8]>) -> Result<u64, ChainError>
where
    I: IntoIterator<Item = &'a str>,
{
    verify_chain_head(lines, hmac_key).map(|(entries, _)| entries)
}

/// [`verify_chain`] that also returns the verified chain head (the last
/// line's hash, or the all-zero genesis for an empty log).
fn verify_chain_head<'a, I>(
    lines: I,
    hmac_key: Option<&[u8]>,
) -> Result<(u64, [u8; 32]), ChainError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut verifier = ChainVerifier::new(hmac_key);
    for raw in lines {
        verifier.line(raw)?;
    }
    Ok((verifier.entries, verifier.prev))
}

/// Incremental chain verification, one line at a time: the state behind
/// [`verify_chain`] and the streamed check of [`FileAuditSink::open`].
struct ChainVerifier<'k> {
    hmac_key: Option<&'k [u8]>,
    /// The verified chain head so far (genesis before the first entry).
    prev: [u8; 32],
    /// Verified entries so far.
    entries: u64,
    /// 1-based number of the last line passed in (blank lines count).
    line_no: usize,
}

impl<'k> ChainVerifier<'k> {
    const fn new(hmac_key: Option<&'k [u8]>) -> Self {
        Self {
            hmac_key,
            prev: GENESIS,
            entries: 0,
            line_no: 0,
        }
    }

    /// Verifies the next line (trailing `\r` / `\n` ignored; a blank line
    /// is skipped but counted).
    fn line(&mut self, raw: &str) -> Result<(), ChainError> {
        self.line_no += 1;
        let line_no = self.line_no;
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(());
        }
        let v: serde_json::Value =
            serde_json::from_str(line).map_err(|_| ChainError::BadFormat { line: line_no })?;
        let (Some(stored_prev), Some(stored_hash)) = (
            v["chain_prev"].as_str(),
            v["hash"].as_str().map(String::from),
        ) else {
            return Err(ChainError::BadFormat { line: line_no });
        };
        if stored_prev != hex(&self.prev) {
            return Err(ChainError::BrokenChain { line: line_no });
        }
        let keyed = v["keyed"].as_bool().unwrap_or(false);
        match (self.hmac_key, keyed) {
            (Some(_), true) | (None, false) => {}
            _ => return Err(ChainError::ModeMismatch { line: line_no }),
        }
        // the body is the exact bytes after the deterministic prefix; the
        // writer hashes the record JSON WITH its braces but embeds it
        // brace-less, so the braces are re-added for the recomputation
        // (byte-exact, never re-serialized through serde)
        let keyed_seg = if keyed { ",\"keyed\":true" } else { "" };
        let prefix =
            format!("{{\"chain_prev\":\"{stored_prev}\",\"hash\":\"{stored_hash}\"{keyed_seg},");
        let body = line
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix('}'))
            .ok_or(ChainError::BadFormat { line: line_no })?;
        let mut chained = self.prev.to_vec();
        chained.extend_from_slice(format!("{{{body}}}").as_bytes());
        let actual = match self.hmac_key {
            Some(k) => hmac_sha256(k, &chained),
            None => sha256(&chained),
        };
        if hex(&actual) != stored_hash {
            return Err(ChainError::Tampered { line: line_no });
        }
        self.prev = unhex(&stored_hash).ok_or(ChainError::BadFormat { line: line_no })?;
        self.entries += 1;
        Ok(())
    }
}

/// Streams `reader` through a [`ChainVerifier`] one line at a time (the
/// content is never held whole in memory). Each line is decoded lossily:
/// invalid UTF-8 cannot pass, since the replacement character breaks the
/// JSON or the recomputed hash of that line. Returns the verified entry
/// count, the chain head and whether the content ends with `\n` (`true`
/// for empty content).
fn verify_reader(
    mut reader: impl std::io::BufRead,
    hmac_key: Option<&[u8]>,
) -> Result<(u64, [u8; 32], bool), AuditSinkError> {
    let mut verifier = ChainVerifier::new(hmac_key);
    let mut buf: Vec<u8> = Vec::new();
    let mut terminated = true;
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        terminated = buf.last() == Some(&b'\n');
        verifier.line(&String::from_utf8_lossy(&buf))?;
    }
    Ok((verifier.entries, verifier.prev, terminated))
}

/// HMAC-SHA256 (RFC 2104) over the in-tree [`sha256`]: key padded to the
/// 64-byte block (longer keys are hashed first), inner/outer
/// construction. Verified against the RFC 4231 test vectors (tests below).
/// Keys the audit chain so a log rewriter cannot re-forge it without the
/// key - plain SHA chaining only proves order-integrity.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    for b in k.iter() {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    for b in k.iter() {
        outer.push(b ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

// ---------------------------------------------------------- OTLP exporter

impl AuditRecord {
    /// Converts to an OTLP-compatible span JSON (OpenTelemetry Collector's
    /// `otlp/v1/traces` JSON payload, one resourceSpans entry per record).
    ///
    /// This is the **adapter point** for observability integration:
    /// the HOST application POSTs these payloads to
    /// its OTLP collector endpoint (`http://collector:4318/v1/traces`).
    /// No HTTP client dependency is added - the crate stays zero-network;
    /// any HTTP library the host already uses can send this JSON.
    ///
    /// Mapping (guard field → OTLP span field):
    /// - `timestamp_ms` → `startTimeUnixNano`
    /// - `request_id`   → span `trace_id` derivation input + attribute
    /// - `guard`        → span name
    /// - `action`       → span kind + status
    /// - `score`        → attribute `guard.risk_score`
    /// - `rationale`    → attribute `guard.rationale`
    /// - `layer`        → attribute `guard.layer`
    #[must_use]
    pub fn to_otlp_span(&self) -> String {
        let ts_nano = self.timestamp_ms * 1_000_000;
        let span_id = format!("{:016x}", self.timestamp_ms % 0xFFFF_FFFF_FFFF_FFFF);
        let trace_input = format!("{}:{}", self.request_id, self.guard);
        let trace_id = format!(
            "{:032x}",
            sha256(trace_input.as_bytes())[0..16]
                .iter()
                .fold(0u128, |acc, &b| (acc << 8) | u128::from(b))
        );
        let status = match self.action {
            crate::guard::action::GuardAction::Block => "STATUS_CODE_ERROR",
            _ => "STATUS_CODE_OK",
        };
        serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [{
                        "key": "service.name",
                        "value": {"stringValue": "redactify"}
                    }]
                },
                "scopeSpans": [{
                    "spans": [{
                        "traceId": trace_id,
                        "spanId": span_id,
                        "name": format!("guard.{}", self.guard),
                        "kind": "SPAN_KIND_INTERNAL",
                        "startTimeUnixNano": ts_nano.to_string(),
                        "endTimeUnixNano": (ts_nano + 1_000_000).to_string(),
                        "status": {"code": status},
                        "attributes": [
                            {"key": "guard.action", "value": {"stringValue": self.action.to_string()}},
                            {"key": "guard.risk_score", "value": {"doubleValue": self.score}},
                            {"key": "guard.rationale", "value": {"stringValue": self.rationale}},
                            {"key": "guard.layer", "value": {"stringValue": self.layer}},
                            {"key": "guard.request_id", "value": {"stringValue": self.request_id}},
                        ]
                    }]
                }]
            }]
        })
        .to_string()
    }
}

// ------------------------------------------------------- FileAuditSink

/// Why [`FileAuditSink::open`] refused to open an audit file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditSinkError {
    /// Reading the existing file or opening it for appending failed.
    #[error("audit file I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The existing file does not verify as a chain in the requested mode
    /// (edited, truncated mid-line, reordered, or keyed/plain mismatch):
    /// appending would extend a chain that can no longer be trusted.
    #[error("existing audit chain does not verify: {0}")]
    Chain(#[from] ChainError),
}

/// A ready-to-use audit sink that writes chained records to a file
/// (JSONL + hash chain per line). Wraps [`ChainedAuditSink`] over a
/// [`std::fs::File`] opened in append mode.
///
/// Opening an existing file first verifies its whole content exactly as
/// [`verify_chain`] does, in the requested mode (plain SHA-256 without a
/// key, HMAC-SHA256 with one), streaming it line by line (the file is
/// never loaded whole), and refuses on ANY [`ChainError`] - an edited,
/// reordered or torn (crash mid-write: a partial line never verifies)
/// file, or a keyed/plain mode mismatch. Only a verified chain is resumed:
/// new lines continue from its head, so the combined file verifies end to
/// end. A verified file whose last record lacks its final `\n` gets that
/// newline before the first append. A missing or empty file starts a
/// fresh chain.
///
/// Writing is fallible-but-non-fatal by design: [`FileAuditSink::append`]
/// returns the I/O error and the caller decides whether to stop (fail
/// closed) or continue degraded. After a failed write the sink refuses
/// further appends (see [`ChainedAuditSink`]); reopening verifies the file
/// again.
///
/// # Examples
/// ```
/// use redactify::guard::audit::{verify_chain, FileAuditSink};
/// use redactify::policy::{audit_from_decision, guard_all};
///
/// // in production: point at a persistent volume
/// let path = std::env::temp_dir().join(format!("redactify-doc-audit-{}.jsonl", std::process::id()));
/// let _ = std::fs::remove_file(&path);
/// let key = b"an audit key from the secret store".as_slice();
/// let mut sink = FileAuditSink::open(&path, Some(key)).expect("audit file opens");
/// let d = guard_all("TCKN 12345678950");
/// sink.append(&audit_from_decision("req-1", "L1", &d)).expect("writes");
/// drop(sink);
///
/// // reopening verifies the existing chain first, then resumes it
/// let sink = FileAuditSink::open(&path, Some(key)).expect("verified chain resumes");
/// assert_eq!(sink.entries(), 1);
/// // a plain (unkeyed) open of a keyed file is refused
/// assert!(FileAuditSink::open(&path, None).is_err());
/// let log = std::fs::read_to_string(&path).unwrap();
/// assert_eq!(verify_chain(log.lines(), Some(key)), Ok(1));
/// std::fs::remove_file(&path).ok();
/// ```
pub struct FileAuditSink {
    inner: ChainedAuditSink<std::fs::File>,
    path: std::path::PathBuf,
}

impl std::fmt::Debug for FileAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAuditSink")
            .field("path", &self.path)
            .field("chain", &self.inner)
            .finish()
    }
}

impl FileAuditSink {
    /// Opens (or creates) the audit file for appending. An existing file
    /// is verified first (see the type docs) and its chain resumed; `key`
    /// selects keyed mode (HMAC-SHA256 links, lines marked
    /// `"keyed": true`) for both the verification and every new line.
    ///
    /// # Errors
    /// [`AuditSinkError::Chain`] when the existing content does not verify
    /// in the requested mode; [`AuditSinkError::Io`] for read/open
    /// failures and for a failed write of a missing final newline.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        key: Option<&[u8]>,
    ) -> Result<Self, AuditSinkError> {
        use std::fs::OpenOptions;
        let path = path.as_ref();
        let (entries, prev_hash, terminated) = match std::fs::File::open(path) {
            Ok(file) => verify_reader(std::io::BufReader::new(file), key)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, GENESIS, true),
            Err(e) => return Err(AuditSinkError::Io(e)),
        };
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        if !terminated {
            // the last line verified but lacks its newline (a crash right
            // before the line end reached the disk): end it, so the next
            // record starts a line of its own
            file.write_all(b"\n")?;
        }
        let mut inner = ChainedAuditSink::new(file);
        inner.prev_hash = prev_hash;
        inner.entries = entries;
        inner.hmac_key = key.map(<[u8]>::to_vec);
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// Plain (unkeyed) shorthand for [`FileAuditSink::open`]`(path, None)`.
    ///
    /// # Errors
    /// As [`FileAuditSink::open`]; a keyed file is refused
    /// ([`ChainError::ModeMismatch`]).
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, AuditSinkError> {
        Self::open(path, None)
    }

    /// Appends one record (JSONL + hash chain, keyed when the sink was
    /// opened with a key).
    ///
    /// # Errors
    /// I/O errors from the underlying file write (the chain state only
    /// advances on a successful write); after the first one, every later
    /// call fails without writing (see [`ChainedAuditSink`]).
    pub fn append(&mut self, record: &AuditRecord) -> std::io::Result<()> {
        self.inner.append(record)
    }

    /// Number of chained entries in the file: the verified entries found
    /// at open plus every entry this instance appended.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.inner.entries()
    }

    /// Current chain head (for verification tooling).
    #[must_use]
    pub const fn chain_head(&self) -> [u8; 32] {
        self.inner.chain_head()
    }

    /// The audit file path (for logging/diagnostics).
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::{hmac_sha256, sha256, ChainedAuditSink};
    use crate::policy::{audit_from_decision, audit_from_verdict, guard_all, GuardAction};

    #[test]
    fn debug_output_never_shows_the_hmac_key() {
        let sink =
            ChainedAuditSink::new(Vec::new()).with_hmac_key(b"a-very-secret-audit-key-0123456789");
        let shown = format!("{sink:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(!shown.contains("97"), "{shown}"); // 'a' as a byte list
        assert!(shown.contains("keyed: true"), "{shown}");
    }

    #[test]
    fn hmac_rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            super::hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_rfc4231_test_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            super::hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_rfc4231_longer_than_block_key() {
        // Test Case 6 (131-byte key, 54-byte message): exercises the
        // hash-the-key-first branch
        let key = [0xaau8; 131];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = hmac_sha256(&key, msg);
        assert_eq!(
            super::hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn keyed_chain_marks_lines_and_tampering_breaks_the_head() {
        let d1 = guard_all("TCKN 12345678950");
        let d2 = guard_all("1' OR '1'='1");
        let mut sink = ChainedAuditSink::new(Vec::<u8>::new()).with_hmac_key(b"audit-secret");
        sink.append(&super::AuditRecord::decision(
            "r1",
            "L1",
            1.0,
            d1.action,
            d1.rationale.clone(),
        ))
        .unwrap();
        sink.append(&super::AuditRecord::decision(
            "r2",
            "L0",
            0.9,
            d2.action,
            d2.rationale.clone(),
        ))
        .unwrap();
        let log = String::from_utf8(sink.into_log()).unwrap();
        assert!(log.contains("\"keyed\":true"), "{log}");
        // the right key verifies the whole chain
        assert_eq!(
            super::verify_chain(log.lines(), Some(b"audit-secret")),
            Ok(2),
            "{log}"
        );
        // the WRONG key fails on the very first line
        assert_eq!(
            super::verify_chain(log.lines(), Some(b"other-key")),
            Err(super::ChainError::Tampered { line: 1 })
        );
        // a tampered body no longer recomputes to its own stored hash
        let tampered = log.replace("\"r1\"", "\"r9\"");
        assert_eq!(
            super::verify_chain(tampered.lines(), Some(b"audit-secret")),
            Err(super::ChainError::Tampered { line: 1 }),
            "tampered line still verifies"
        );
        // verifying a keyed log without a key reports the mode mismatch
        assert_eq!(
            super::verify_chain(log.lines(), None),
            Err(super::ChainError::ModeMismatch { line: 1 })
        );
    }

    #[test]
    fn verify_chain_catches_removal_and_tampering() {
        let d1 = guard_all("TCKN 12345678950");
        let d2 = guard_all("bugun hava guzel");
        let mut sink = ChainedAuditSink::new(Vec::<u8>::new());
        for (id, d) in [("r1", &d1), ("r2", &d2), ("r3", &d2)] {
            sink.append(&super::AuditRecord::decision(
                id,
                "L1",
                0.5,
                d.action,
                d.rationale.clone(),
            ))
            .unwrap();
        }
        let log = String::from_utf8(sink.into_log()).unwrap();
        // intact chain verifies with the entry count
        assert_eq!(super::verify_chain(log.lines(), None), Ok(3));

        // removing the MIDDLE line breaks the chain at the next line
        let mut lines: Vec<&str> = log.lines().collect();
        lines.remove(1);
        assert_eq!(
            super::verify_chain(lines, None),
            Err(super::ChainError::BrokenChain { line: 2 })
        );

        // editing a rationale in place is a Tampered at that line
        let tampered = log.replace(&d1.rationale, "edited-after-the-fact");
        if tampered != log {
            assert_eq!(
                super::verify_chain(tampered.lines(), None),
                Err(super::ChainError::Tampered { line: 1 })
            );
        }

        // a non-chain line is a BadFormat, not a crash
        assert_eq!(
            super::verify_chain(["not json"], None),
            Err(super::ChainError::BadFormat { line: 1 })
        );
    }

    #[test]
    fn record_from_decision_is_metadata_only() {
        let d = guard_all("TCKN 12345678950");
        let rec = audit_from_decision("req-42", "L1", &d);
        assert_eq!(rec.request_id, "req-42");
        assert_eq!(rec.action, GuardAction::Mask);
        let json = rec.to_json();
        for key in [
            "timestamp_ms",
            "request_id",
            "layer",
            "guard",
            "score",
            "action",
            "rationale",
        ] {
            assert!(json.contains(key), "{json}");
        }
        assert!(!json.contains("12345678950"), "{json}");
    }

    #[test]
    fn record_from_verdict_carries_category() {
        let d = guard_all("http://169.254.169.254/meta");
        assert!(!d.verdicts.is_empty());
        let rec = audit_from_verdict("req-43", "L0", &d.verdicts[0]);
        assert_eq!(rec.guard, "DANGEROUS_URL");
        assert!(rec.score >= 0.9);
        assert_eq!(rec.action, GuardAction::Block);
    }

    #[test]
    fn sha256_fips_vectors() {
        // FIPS 180-4 / NIST example vectors
        let empty = sha256(b"");
        assert_eq!(
            super::hex(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = sha256(b"abc");
        assert_eq!(
            super::hex(&abc),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // exactly one block boundary (64 bytes) + a longer multi-block input
        let long = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            super::hex(&long),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn chained_sink_chains_and_breaks_on_tamper() {
        let d1 = guard_all("TCKN 12345678950");
        let d2 = guard_all("http://169.254.169.254/meta");
        let mut buf: Vec<u8> = Vec::new();
        let head = {
            let mut sink = ChainedAuditSink::new(&mut buf);
            sink.append(&crate::policy::audit_from_decision("r1", "L1", &d1))
                .unwrap();
            sink.append(&crate::policy::audit_from_decision("r2", "L0", &d2))
                .unwrap();
            assert_eq!(sink.entries(), 2);
            sink.chain_head()
        };
        let text = String::from_utf8(buf.clone()).unwrap();
        assert_eq!(text.lines().count(), 2);
        // last line's hash field equals the reported chain head
        let last = text.lines().last().unwrap();
        let head_hex = super::hex(&head);
        assert!(last.contains(&head_hex), "{last}");

        // tamper: flip one character of the FIRST line -> the stored hashes
        // no longer reproduce from genesis
        let mut tampered = text.clone().into_bytes();
        tampered[60] ^= 0x01;
        let tampered = String::from_utf8_lossy(&tampered).to_string();
        let first_body_end = tampered.find('\n').unwrap();
        assert_ne!(&tampered[..first_body_end], &text[..first_body_end]);
    }

    #[test]
    fn chain_is_deterministic() {
        let d = guard_all("merhaba");
        let mut a: Vec<u8> = Vec::new();
        let mut b: Vec<u8> = Vec::new();
        let mut sa = ChainedAuditSink::new(&mut a);
        let mut sb = ChainedAuditSink::new(&mut b);
        // same record content except timestamp/request may differ; use one
        let rec = crate::policy::audit_from_decision("r", "L0", &d);
        sa.append(&rec).unwrap();
        sb.append(&rec).unwrap();
        assert_eq!(a, b);
    }

    mod otlp {
        use crate::policy::guard_all;

        #[test]
        fn otlp_span_is_valid_json_with_required_fields() {
            let d = guard_all("TCKN 12345678950");
            let rec = crate::policy::audit_from_decision("req-otlp-1", "L1", &d);
            let json = rec.to_otlp_span();
            let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
            // OTLP top-level structure
            assert!(v.get("resourceSpans").is_some(), "{json}");
            let spans = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
            assert!(spans.get("traceId").is_some());
            assert!(spans.get("spanId").is_some());
            assert!(spans.get("name").is_some());
            // guard attributes present
            let attrs = spans["attributes"].as_array().unwrap();
            let keys: Vec<&str> = attrs.iter().filter_map(|a| a["key"].as_str()).collect();
            for expected in [
                "guard.action",
                "guard.risk_score",
                "guard.rationale",
                "guard.layer",
            ] {
                assert!(keys.contains(&expected), "missing {expected}: {keys:?}");
            }
            // PII never leaks
            assert!(!json.contains("12345678950"), "{json}");
        }

        #[test]
        fn otlp_block_maps_to_error_status() {
            let d = guard_all("http://169.254.169.254/meta");
            let rec = crate::policy::audit_from_decision("req-2", "L0", &d);
            let json = rec.to_otlp_span();
            assert!(json.contains("STATUS_CODE_ERROR"), "Block → ERROR: {json}");
        }

        #[test]
        fn otlp_allow_maps_to_ok_status() {
            let d = guard_all("hello world");
            let rec = crate::policy::audit_from_decision("req-3", "L0", &d);
            let json = rec.to_otlp_span();
            assert!(json.contains("STATUS_CODE_OK"), "{json}");
        }
    }

    mod file_sink {
        use super::super::{verify_chain, AuditRecord, AuditSinkError, ChainError, FileAuditSink};
        use crate::policy::{audit_from_decision, guard_all};

        #[test]
        fn file_sink_resumes_the_existing_chain_across_restarts() {
            // a FileAuditSink reopened in append mode continues the stored
            // chain instead of starting a FRESH GENESIS-rooted one, so the
            // combined file verifies across the restart seam
            let dir = std::env::temp_dir().join(format!("redactify-audit-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("audit.jsonl");
            let _ = std::fs::remove_file(&path);

            let rec = || {
                AuditRecord::decision(
                    "r",
                    "L0",
                    0.0,
                    crate::policy::GuardAction::Allow,
                    "t".to_string(),
                )
            };
            {
                let mut sink = FileAuditSink::new(&path).unwrap();
                sink.append(&rec()).unwrap();
                sink.append(&rec()).unwrap();
                assert_eq!(sink.entries(), 2);
            }
            {
                let mut sink = FileAuditSink::new(&path).unwrap();
                assert_eq!(sink.entries(), 2, "resume must count prior entries");
                sink.append(&rec()).unwrap();
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 3);
            assert!(
                verify_chain(lines.iter().copied(), None).is_ok(),
                "combined file must verify after the restart seam"
            );
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn file_sink_writes_chained_jsonl() {
            let dir =
                std::env::temp_dir().join(format!("redactify-audit-test-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("audit.jsonl");

            let d1 = guard_all("TCKN 12345678950");
            let d2 = guard_all("merhaba");

            {
                let mut sink = FileAuditSink::new(&path).expect("opens");
                sink.append(&audit_from_decision("r1", "L1", &d1)).unwrap();
                sink.append(&audit_from_decision("r2", "L0", &d2)).unwrap();
                assert_eq!(sink.entries(), 2);
            } // drop closes the file

            let content = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = content.lines().collect();
            assert_eq!(lines.len(), 2, "two JSONL lines");
            // each line is valid JSON with the chain fields
            for line in lines {
                let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON: {line}");
                assert!(v.get("chain_prev").is_some(), "chain field present");
                assert!(v.get("hash").is_some(), "hash field present");
                assert!(v.get("guard").is_some(), "guard field present");
            }
            // no PII leaked
            assert!(!content.contains("12345678950"), "{content}");

            std::fs::remove_dir_all(&dir).ok();
        }

        /// A fresh, empty per-test directory under the system temp dir.
        fn temp_file(tag: &str) -> std::path::PathBuf {
            let dir =
                std::env::temp_dir().join(format!("redactify-audit-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("audit.jsonl");
            let _ = std::fs::remove_file(&path);
            path
        }

        fn rec(id: &str) -> AuditRecord {
            AuditRecord::decision(
                id,
                "L0",
                0.0,
                crate::policy::GuardAction::Allow,
                "t".to_string(),
            )
        }

        #[test]
        fn open_refuses_a_tampered_file() {
            let path = temp_file("tampered");
            {
                let mut sink = FileAuditSink::open(&path, None).unwrap();
                sink.append(&rec("r1")).unwrap();
                sink.append(&rec("r2")).unwrap();
            }
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, text.replace("\"r1\"", "\"r9\"")).unwrap();
            match FileAuditSink::open(&path, None) {
                Err(AuditSinkError::Chain(ChainError::Tampered { line: 1 })) => {}
                Err(other) => panic!("wrong refusal: {other}"),
                Ok(_) => panic!("tampered file must be refused"),
            }
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn open_refuses_a_torn_last_line() {
            let path = temp_file("torn");
            {
                let mut sink = FileAuditSink::open(&path, None).unwrap();
                sink.append(&rec("r1")).unwrap();
            }
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, format!("{text}{{\"chain_prev\":\"00")).unwrap();
            assert!(matches!(
                FileAuditSink::open(&path, None),
                Err(AuditSinkError::Chain(ChainError::BadFormat { line: 2 }))
            ));
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn keyed_chain_resumes_only_with_its_key() {
            let path = temp_file("keyed");
            let key = b"k-0123456789abcdef".as_slice();
            {
                let mut sink = FileAuditSink::open(&path, Some(key)).unwrap();
                sink.append(&rec("r1")).unwrap();
            }
            // plain open of a keyed file: mode mismatch, refused
            assert!(matches!(
                FileAuditSink::open(&path, None),
                Err(AuditSinkError::Chain(ChainError::ModeMismatch { line: 1 }))
            ));
            // the wrong key does not verify either
            assert!(matches!(
                FileAuditSink::open(&path, Some(b"other".as_slice())),
                Err(AuditSinkError::Chain(ChainError::Tampered { line: 1 }))
            ));
            {
                let mut sink = FileAuditSink::open(&path, Some(key)).unwrap();
                assert_eq!(sink.entries(), 1);
                sink.append(&rec("r2")).unwrap();
                assert_eq!(sink.entries(), 2);
            }
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(text.matches("\"keyed\":true").count(), 2, "{text}");
            assert_eq!(verify_chain(text.lines(), Some(key)), Ok(2));
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn a_record_ending_in_a_nested_object_chains_and_resumes() {
            // the writer must strip only the record's own closing `}`: a
            // record whose JSON ends in a nested object (a tool decision:
            // `..,"tool":{..}}`) must still produce a parsable line
            let path = temp_file("nested");
            let tool = || {
                AuditRecord::tool_decision(
                    "r",
                    super::super::ToolAuditFields {
                        code: "LOOP",
                        tool: Some("search".to_owned()),
                        session_id: Some("s".to_owned()),
                        policy_hash: "00".repeat(32),
                        engine_version: "0.1.0",
                        calls: 2,
                        tool_calls: 2,
                        repeats: 2,
                        tokens: 9,
                        args_bytes: 12,
                    },
                )
            };
            {
                let mut sink = FileAuditSink::open(&path, None).unwrap();
                sink.append(&tool()).unwrap();
                sink.append(&rec("flat")).unwrap();
            }
            let mut sink = FileAuditSink::open(&path, None).expect("verifies on reopen");
            sink.append(&tool()).unwrap();
            drop(sink);
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(verify_chain(text.lines(), None), Ok(3), "{text}");
            for line in text.lines() {
                let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
                assert!(v.get("hash").is_some(), "{line}");
            }
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn keyed_open_of_a_plain_file_is_refused() {
            let path = temp_file("plain");
            {
                let mut sink = FileAuditSink::open(&path, None).unwrap();
                sink.append(&rec("r1")).unwrap();
            }
            assert!(matches!(
                FileAuditSink::open(&path, Some(b"key".as_slice())),
                Err(AuditSinkError::Chain(ChainError::ModeMismatch { line: 1 }))
            ));
            let _ = std::fs::remove_file(&path);
        }
    }
}
