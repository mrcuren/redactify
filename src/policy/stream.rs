//! Incremental (streaming) guard.
//!
//! The batch APIs ([`crate::policy::sanitize`]) take whole texts. LLM
//! responses arrive as chunks; the industry answer is buffering the whole
//! stream (TTFT loss). Here, incremental guarding is exact instead:
//!
//! - **L1 is line-scoped**: entities never span lines, so a completed line's
//!   entities are final and masking it locally composes byte-identically
//!   with the batch redaction of the full text (relevance windows are
//!   line-scoped too, in batch and stream alike).
//! - **Every prefix is decided like batch**: after each completed line the
//!   stream decides exactly what the batch decision decides for the text
//!   so far, and the first prefix that blocks ends the stream. The
//!   decision is incremental: bounded windows per scan view plus
//!   constant-size state, derived rule family by rule family in
//!   `policy::stream::decider` (one feature, the backtick pairing of the command rule,
//!   keeps the text from the first backtick on). A blocking prefix stays
//!   blocking for every rule whose matches only accumulate, so the
//!   terminal state equals the batch decision of the whole text.
//!
//! Semantics (documented trade-off): emission is
//! **line-buffered** - a chunk stays held only until its line completes
//! (`\n` or `finish`). The metadata-derived intra-line HOLDBACK window
//! is the optimization for newline-free byte streams.
//!
//! Secrets are the one exception to line scoping: four secret rules may
//! span a line break (a credential assignment or a Bearer header whose
//! value sits on a later line, an AWS secret key on the line after its
//! cue, a PEM private-key block masked from its BEGIN line through its
//! END line). The stream scans every line's secrets together with the
//! earlier lines such a match could start on, holds the tail of a line
//! that may start a cross-line AWS key until the next line completes, and
//! holds an open PEM block (at most 16 KiB) until it closes, so the
//! output still equals the batch masking of the whole text.
//!
//! ML classifiers (L2) and NER recognizers are opt-in per stream
//! ([`StreamingGuard::with_ml`], [`StreamingGuard::with_ner`]); without
//! them the stream runs the deterministic chain, exactly like
//! [`Guard::decide`](crate::Guard::decide) without ML classifiers.
//!
//! # Examples
//! ```
//! use redactify::policy::{stream::StreamingGuard, GuardAction, GuardTarget};
//!
//! let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
//! // chunks split mid-identifier: the line is emitted only when complete,
//! // with its entities already masked
//! let ev1 = sg.push("TCKN 12345678");
//! assert!(ev1.is_empty()); // line still incomplete
//! let ev2 = sg.push("950 gecerli\n");
//! assert_eq!(ev2.len(), 1);
//! let out = sg.finish();
//! assert!(out.is_empty());
//! ```

mod decider;

use crate::guard::normalize::{align_for_scan, normalize_for_scan, normalize_for_scan_with_map};
use crate::guard::secrets::open_pem_block_start;
use crate::guard::{GuardSignal, SecretFinding};
use crate::pii::{CustomRule, Entity, NerRecognizer};
use crate::policy::{
    add_encoded_entities, effective_locales, effective_policy, encoded_pii_entities,
    encoded_tokens, ml_input, ner_degradation_signal, render_masked, secret_mask_spans, Detector,
    EntityAction, GuardTarget, MaskStyle, Policy, ScanReport,
};
// the batch guard the docs compare the stream with
#[cfg(doc)]
use crate::policy::Guard;
use fancy_regex::Regex;
use std::sync::{Arc, LazyLock};

/// One streaming-guard outcome.
///
/// serde (feature `serde`): `Serialize` only and log-safe - a segment's
/// `entities` serialize as `{kind, start, end, score}` WITHOUT the raw
/// matched text (the segment text next to them is already masked).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum GuardEvent {
    /// Text that is safe to forward: usually a completed line with its own
    /// PII entities and secrets masked (and HTML-encoded for
    /// `model_output` targets); an intra-line prefix, or a line whose tail
    /// is held for a cross-line secret, emits part of a line, and a held
    /// tail is emitted together with the next line. `entities` carries
    /// SEGMENT-relative offsets (into the text before HTML encoding).
    Segment {
        /// The masked (and possibly encoded) text, including the `\n` of
        /// every line it completes.
        text: String,
        /// PII masked in this segment (segment-relative byte offsets).
        #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_entity_spans"))]
        entities: Vec<Entity>,
    },
    /// The policy decided `Block` on the prefix seen so far: stop forwarding.
    /// No further segments are produced after this event.
    Block {
        /// Human-readable rationale (same strings as the batch decision).
        rationale: String,
    },
}

/// Serializes entities as spans only (`{kind, start, end, score}`): an
/// event must never carry the raw value its segment text masks.
#[cfg(feature = "serde")]
fn serialize_entity_spans<S: serde::Serializer>(
    entities: &[Entity],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;

    #[derive(serde::Serialize)]
    struct EntitySpan {
        kind: crate::pii::EntityType,
        start: usize,
        end: usize,
        score: f32,
    }

    let mut seq = serializer.serialize_seq(Some(entities.len()))?;
    for e in entities {
        seq.serialize_element(&EntitySpan {
            kind: e.kind,
            start: e.start,
            end: e.end,
            score: e.score,
        })?;
    }
    seq.end()
}

impl GuardEvent {
    /// Returns `(text, entities)` when this event is a segment.
    #[must_use]
    pub const fn as_segment(&self) -> Option<(&String, &Vec<Entity>)> {
        match self {
            Self::Segment { text, entities } => Some((text, entities)),
            Self::Block { .. } => None,
        }
    }
}

/// Line-buffered incremental guard over the deterministic chain (L0+L1+policy).
///
/// Feed chunks with [`StreamingGuard::push`]; complete lines are returned as
/// [`GuardEvent::Segment`] immediately (PII masked). When the accumulated
/// prefix makes the policy decide `Block`, a [`GuardEvent::Block`] is returned
/// and the guard stops emitting. [`StreamingGuard::finish`] flushes a
/// trailing partial line and finishes the stream.
///
/// Concatenated segment texts equal the batch output
/// `Guard::new(target).with_policy(..).with_locales(..).with_mask_style(..)
/// .sanitize(text).text` whenever the batch decision is not `Block`.
///
/// # Intra-line early emission
///
/// When a line stays open for a long time (newline-free streams), a safe
/// PREFIX of it is emitted before the line completes, under three conditions
/// that together guarantee the concatenated output stays byte-identical to
/// the batch `sanitize` result:
///
/// 1. **Bounded-rule holdback:** the held-back tail always holds at least
///    `L1_HOLDBACK` raw characters AND normalizes (NFKC + invisible
///    stripping, the view the detector also scans) to at least
///    `L1_HOLDBACK` characters that are not gap characters (whitespace,
///    `:`, `#`), and the cut never splits a normalization cluster - any
///    bounded-length match (IBAN <= 49 normalized chars, card, phone, TCKN,
///    the whitespace-collapsed IPv6 form and the US MRN whose gaps are
///    unbounded but whose other characters are not, the AWS secret key of
///    up to 101 raw chars, ...) that could still grow starts after the
///    emit point, however many raw bytes its fullwidth, zero-width
///    scattered or whitespace-padded form takes, and every visible match
///    intersecting the emitted region is already final (the +CUE_WINDOW
///    term also settles cue boosts).
/// 2. **Unbounded-rule hold:** the e-mail and URL regexes and every
///    unbounded secret value have NO length bound (and no whitespace), and
///    the NAME rule grows by whole words - so the trailing whitespace-free
///    run (a potential growing e-mail, URL or key) and any trailing run of
///    up to 4 capitalized words (a potential growing name) are always held
///    back.
/// 3. **Span adjustment:** if an already-detected entity or secret span
///    crosses the emit point, the emit point moves back to its start,
///    repeated until no span crosses it.
///
/// Early emission is disabled when NER recognizers are attached (see
/// [`with_ner`](Self::with_ner)), when custom rules are attached (see
/// [`with_custom_rules`](Self::with_custom_rules)), when the policy has relevance rules (a
/// downgrade depends on the whole line's context), and while the open
/// line has an incompletely scanned part.
///
/// # Cross-line secrets
///
/// A line's secret spans are found together with the earlier lines a
/// cross-line credential could start on (a line ending in a credential cue,
/// a `:`/`=` separator, `Authorization`/`Bearer`, a blank line, or an AWS
/// secret-key cue keeps the context open), exactly as the batch scan of
/// the whole text finds them. A line whose tail may be the cue of an AWS
/// secret key whose key sits on the NEXT line (the rule's separator may be
/// the line break, and the batch mask then spans both lines) emits only up
/// to that cue; the tail is emitted with the next line (or at `finish`).
/// Likewise a PEM private-key block that is still open (its last line
/// could be followed by more body or by the END line, see
/// `guard::secrets::open_pem_block_start`) emits only up to its BEGIN
/// header; the block is emitted, masked as one span, once a line closes
/// it (the END line, a non-body line, a third blank line, or the
/// 16 KiB block bound) or at `finish`. Held text therefore stays below
/// 16 KiB per block.
///
/// Within one newline-free line (a JSON string with escaped `\n`, or a
/// body collapsed to spaces) the PEM span grows token by token: whether a
/// token joins the block depends only on the token itself (a
/// whitespace-free run, held by condition 2 while it grows) and on the
/// next escaped line break and END marker after it (fewer than 60 non-gap
/// characters, inside the condition-1 holdback). So while the block can
/// still change, the partial line's block span crosses the emit point
/// and condition 3 moves the emit point before the header.
///
/// Documented caveats (text output unaffected unless stated): an
/// intra-line segment precedes the line's L0 decision, so a Block
/// triggered by the line's tail cannot retract the already-emitted prefix;
/// event `entities` scores near an emission boundary may miss a
/// pre-boundary cue boost (the mask text is identical either way); and a
/// regex runtime error that only appears once the line has grown masks
/// just the retained tail as `[SCAN_INCOMPLETE]` (the batch output masks
/// the whole line).
///
/// # Cost
///
/// Each completed line is decided over bounded windows of the scan views
/// (see the `policy::stream::decider` module docs for the derivation), so the work per line is bounded
/// by the window, not by the stream, and the guard keeps only those
/// windows, the secret context (the lines a cross-line secret could still
/// start on, an open PEM block up to 16 KiB) and the held lines. Kept
/// beyond the window, on purpose (exact evaluation needs it): each view's
/// text from its first backtick on (the command rule pairs backtick runs
/// over the whole text; re-checked only on lines that add a backtick),
/// and, only while `ENCODED_PII` can block or the ML lane reads its L0
/// trigger, the text since that became true (a later plain copy withdraws
/// an escape-view finding). Adversarial input can widen a window: a
/// template, subshell, `<img` or ERB opener that is never closed, or a
/// long run of lines that keep a credential context open, stays in it
/// until it closes.
///
/// Known difference: the secret rules with look-around run on a
/// backtracking engine whose step budget applies per search, and a search
/// that finds nothing runs to the end of the text it is given. A text of
/// many thousands of near-miss secret shapes can exhaust that budget in a
/// batch search over the whole text (a `SECRETS` signal `SCAN_ERROR`,
/// score 0.4) while no window of the stream does. The signal depends on
/// the text's length, not on its content, so it is not modeled; it blocks
/// only when `SECRETS` blocks at 0.4 or below.
///
/// # Reconfiguring a running stream
///
/// Every `with_*` call takes effect for every line completed after it:
/// that line is decided under the new configuration, over the same windows
/// and whole-text state (the target is fixed by [`new`](Self::new)). A
/// stream not reconfigured after its first push decides exactly like
/// batch, as described above. After a change, for every later line `k`:
///
/// - whatever lies in line `k`'s windows, and the whole-text state, which
///   is kept whatever the configuration (character splitting, backtick
///   pairing, PII inside a base64 layer), is decided under the new
///   configuration: if it blocks there, line `k` blocks;
/// - a Block at line `k` means the batch decision of the text up to `k`,
///   under the new configuration, blocks too, except in the two cases
///   below;
/// - what completed before the change and lies outside line `k`'s windows
///   (a pattern or secret match, an incompletely scanned line, NER health)
///   is not decided again: when only the new configuration makes it
///   blocking, the stream does not block on it while the batch decision of
///   the prefix does;
/// - escape-view PII (percent or character-reference encoded) that becomes
///   decisive only through the change is compared with the text received
///   since then, so a plain copy written earlier does not withdraw it, and
///   base64-layer PII found earlier was found with the locales, custom
///   rules and allowlist of its time: these two can block where batch
///   would not.
///
/// Cost grows linearly with the stream (release CLI `--stream`, 33-byte
/// lines): 2,000 lines take 0.13 s against 0.11 s for the batch decision
/// of the same text, 20,000 lines 1.05 s at a flat 13 MB peak memory. On
/// a mixed text with PII, secrets, a PEM block, code spans and escapes,
/// 18,000 lines take 7.4 s against 5.9 s for the batch decision (about
/// 1.2 s of it is the backtick re-check).
pub struct StreamingGuard {
    target: GuardTarget,
    /// The text not yet fully emitted, from a line start: the held
    /// complete lines (see `held`), then the FULL current line so far (no
    /// `\n` yet), including prefixes that were already emitted - the
    /// completion side re-detects on full lines so cue/lookbehind context
    /// is never lost
    line: String,
    /// byte offset into `line` up to which the text was already emitted
    emitted: usize,
    /// byte length of the complete (already decided) lines at the start of
    /// `line` whose tail is held for a cross-line secret (0 = none)
    held: usize,
    /// the masking-relevant PII of the held lines (relevance applied;
    /// `line` coordinates)
    held_entities: Vec<Entity>,
    /// the incompletely scanned spans of the held lines (`line` coordinates)
    held_errors: Vec<(usize, usize)>,
    /// The secret context: the completed lines since the last line that
    /// did not end open ([`ends_open`]) and was not part of an open PEM
    /// block. No secret match crosses the boundary before it, so scanning
    /// from here on finds every later line's secrets exactly as the batch
    /// scan of the whole text does. Ends with the held lines.
    ctx_text: String,
    /// The incremental prefix decision (see [`decider`]); it holds no
    /// configuration, every line is decided under the current one
    /// (created at the first completed line: `new` is a `const fn`).
    decider: Option<decider::PrefixDecider>,
    blocked: bool,
    finished: bool,
    /// Opt-in NER recognizers: when attached, each COMPLETED line is
    /// also scanned by the models (the NER-enabled [`Detector`]), masking free-prose
    /// NAME/ADDRESS in streams. Line-scoped semantics: equivalence is
    /// against the per-line batch masking, not whole-document NER (models
    /// never see beyond the line); intra-line early emission is disabled in
    /// this mode (a growing prefix would re-detect differently).
    ner: Vec<Arc<dyn NerRecognizer>>,
    /// Explicit locale set: when non-empty, every detection and decision
    /// in the stream runs these locale packs; when empty, the policy's
    /// default locales apply, else the default tr+en set. `L1_HOLDBACK`
    /// stays unchanged: the longest locale bounded pattern (German mobile,
    /// 12 digits + up to 8 separators = 20 chars) remains far below the
    /// IBAN bound (49 chars) that dominates the derivation; equivalence is
    /// additionally proven by the every-split differential tests.
    locales: Vec<String>,
    /// Opt-in budgeted ML security scan: an L2 classifier over the
    /// MASKED completed lines under [`MlStreamBudget`] pacing.
    ml: Option<(Arc<dyn crate::guard::ml::MlClassifier>, MlStreamBudget)>,
    /// Completed-line counter (drives the every-N pacing).
    line_count: usize,
    /// Caller-supplied policy (see [`Policy::for_target`] for how a
    /// target adapts it); `None` = the built-in per-target defaults.
    policy: Option<Policy>,
    /// How emitted segments render PII spans.
    mask: MaskStyle,
    /// Custom rules joining every detection and decision of the stream;
    /// intra-line early emission is disabled while any is attached (a
    /// custom pattern has no length bound the holdback could cover).
    custom: Vec<CustomRule>,
    /// Allowlisted values for every detection and decision of the stream.
    ignored: Vec<String>,
}

/// Content-free: the buffered stream text, held entities and allowlisted
/// values are user data, so only their sizes appear (the same rule as the
/// audit records); the configuration is shown as presence and counts.
impl std::fmt::Debug for StreamingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingGuard")
            .field("target", &self.target)
            .field("lines", &self.line_count)
            .field("buffered_bytes", &self.line.len())
            .field("blocked", &self.blocked)
            .field("finished", &self.finished)
            .field("locales", &self.locales)
            .field("policy", &self.policy.is_some())
            .field("ner", &self.ner.len())
            .field("ml", &self.ml.is_some())
            .field("custom_rules", &self.custom.len())
            .field("ignored", &self.ignored.len())
            .finish_non_exhaustive()
    }
}

/// Pacing for the opt-in ML-in-stream scan ([`StreamingGuard::with_ml`]).
///
/// The L2 classifier never runs per line by default (about 30 ms p95 per
/// call would dominate line latency). This budget schedules it:
/// the first line, every Nth line, and/or any line whose L0 chain already
/// produced an obfuscation/encoded-payload signal (the classic ML bait).
/// The classifier sees the MASKED line text (the same privacy rule as the
/// batch pipeline: models never receive raw identifiers).
///
/// Calibration: tune N and the block effect with your model on a labelled
/// set of your own data before relying on this in production; the tests
/// cover the pacing and escalation logic only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct MlStreamBudget {
    /// Scan the first completed line.
    pub first_line: bool,
    /// Scan every Nth completed line (0 = never).
    pub every_n_lines: usize,
    /// Scan any line whose L0 chain flagged obfuscation or an encoded
    /// payload.
    pub on_l0_trigger: bool,
}

impl Default for MlStreamBudget {
    /// Conservative default: first line + L0-triggered, no periodic scan.
    fn default() -> Self {
        Self {
            first_line: true,
            every_n_lines: 0,
            on_l0_trigger: true,
        }
    }
}

/// Longest bounded PII match in normalized non-gap characters: the
/// international IBAN pattern (`[A-Z]{2}\d{2}(?: ?[A-Z0-9]{1,4}){3,9}` ->
/// <= 4 + 9x5 = 49 chars) dominates every bounded locale pattern, the
/// whitespace-collapsed IPv6 form (8 groups of <= 4 hex digits = 32
/// non-gap chars) and the US MRN (cue <= 19 non-gap chars + <= 14 value
/// chars). The cryptocurrency address rules are longer (a segwit address
/// reaches 74 characters) but match whitespace-free tokens only, so a
/// growing address is always the trailing whitespace-free run that
/// condition 2 holds back, like an e-mail or URL (locked by
/// `tests/stream_differential.rs`).
const PII_SPAN_MAX: usize = 49;

/// The context-cue window after a value (`pii::detect::CUE_WINDOW`): a cue
/// arriving within it can still create or boost a finding.
const CUE_WINDOW_CHARS: usize = 18;

/// Longest bounded secret span in raw characters: the AWS secret-key rule
/// of `guard::secrets` masks its whole match, cue included (`aws`,
/// `[^\n]{0,30}?`, `secret`, `[^\n]{0,20}?`, `[=:\s]`, `["']?` and 40 key
/// chars: 3 + 30 + 6 + 20 + 1 + 1 + 40 = 101). Every other bounded secret
/// span is shorter or whitespace-free (the trailing-run condition holds
/// those whatever their length).
const SECRET_SPAN_MAX: usize = 101;

/// Safety margin on top of the derived bounds.
const HOLDBACK_MARGIN: usize = 31;

/// Derivation (from the ACTUAL rule patterns): a match that
/// can still grow or appear must start inside the held-back tail, so the
/// tail must exceed every bounded match, counted where the match is
/// bounded:
/// - PII ([`PII_SPAN_MAX`] + [`CUE_WINDOW_CHARS`]) in NORMALIZED characters
///   (the detector also scans the normalized view, where a fullwidth or
///   zero-width-scattered value is as long as its ASCII form) that are not
///   gap characters ([`is_gap`]: the collapsed IPv6 helper and the US MRN
///   gap `[\s:#]*` repeat those without bound);
/// - secrets ([`SECRET_SPAN_MAX`]) in RAW characters (the AWS rule's gaps
///   accept any character, and a compatibility character there can
///   normalize to up to 18 characters; the raw count also covers the
///   raw-pass cue windows);
/// - plus [`HOLDBACK_MARGIN`].
const L1_HOLDBACK: usize = {
    let pii = PII_SPAN_MAX + CUE_WINDOW_CHARS;
    (if pii > SECRET_SPAN_MAX {
        pii
    } else {
        SECRET_SPAN_MAX
    }) + HOLDBACK_MARGIN
};

// the holdback covers every derived bound (checked at compile time)
const _: () =
    assert!(PII_SPAN_MAX + CUE_WINDOW_CHARS < L1_HOLDBACK && SECRET_SPAN_MAX < L1_HOLDBACK);

/// An unemitted remainder shorter than this never triggers intra-line
/// emission (avoids dribble; complete-line events handle short lines).
const INTRA_LINE_MIN_PENDING: usize = 192;

/// Do not emit intra-line prefixes smaller than this many bytes.
const INTRA_LINE_MIN_EMIT: usize = 48;

/// Gap characters: the characters bounded-shape rules repeat without
/// bound between their bounded parts (whitespace in the collapsed IPv6
/// helper and the MRN gap, plus the MRN gap's `:` and `#`).
fn is_gap(c: char) -> bool {
    c.is_whitespace() || c == ':' || c == '#'
}

/// Whether `tail` holds back enough (condition 1): at least
/// [`L1_HOLDBACK`] raw characters and, normalized on its own, at least
/// [`L1_HOLDBACK`] non-gap characters.
fn holds_enough(tail: &str) -> bool {
    tail.chars().count() >= L1_HOLDBACK
        && normalize_for_scan(tail)
            .chars()
            .filter(|&c| !is_gap(c))
            .count()
            >= L1_HOLDBACK
}

/// Condition 1 of the intra-line emit point: the largest raw cut whose
/// held-back tail holds enough ([`holds_enough`]). The cut is an offset of
/// the normalization map, so it never splits a normalization cluster (a
/// base char and its combining marks, a fullwidth char, a char and the
/// invisible characters stripped after it stay on one side).
fn holdback_cut(pending: &str) -> usize {
    if pending.is_ascii() {
        // ASCII is its own normalized form: one byte per char
        let bytes = pending.as_bytes();
        let mut non_gap = 0usize;
        for i in (1..bytes.len()).rev() {
            if !is_gap(char::from(bytes[i])) {
                non_gap += 1;
            }
            if non_gap >= L1_HOLDBACK && bytes.len() - i >= L1_HOLDBACK {
                return i;
            }
        }
        return 0;
    }
    let Some((norm, map)) = normalize_for_scan_with_map(pending) else {
        return 0; // alignment failed (defensive): emit nothing early
    };
    // candidates: the raw starts of the normalized chars, from the end,
    // with both counts kept incrementally; a candidate is confirmed on the
    // tail normalized on its own (a cut inside a multi-char expansion maps
    // to the cluster end, so that tail holds fewer chars)
    let mut non_gap = 0usize;
    let mut raw_chars = 0usize;
    let mut prev_cut = pending.len();
    for (i, c) in norm.char_indices().rev() {
        if !is_gap(c) {
            non_gap += 1;
        }
        let cut = map[i];
        if cut == 0 {
            break;
        }
        raw_chars += pending[cut..prev_cut].chars().count();
        prev_cut = cut;
        if non_gap >= L1_HOLDBACK && raw_chars >= L1_HOLDBACK && holds_enough(&pending[cut..]) {
            return cut;
        }
    }
    0
}

/// Moves the emit point `e` back to the start of every span that crosses
/// it, repeated until nothing moves (terminates: `e` strictly decreases on
/// every move). A crossing key or value would otherwise leak its head into
/// the emitted text.
fn settle(mut e: usize, spans: &[(usize, usize)]) -> usize {
    loop {
        let before = e;
        for &(start, end) in spans {
            if start < e && end > e {
                e = start;
            }
        }
        if e == before {
            return e;
        }
    }
}

/// The head of an AWS secret key whose key may sit on the NEXT line: the
/// `AWS_SECRET_KEY` rule of `guard::secrets`
/// (`aws[^\n]{0,30}?(?:secret|sk)[^\n]{0,20}?[=:\s]["']?<40 key chars>`)
/// accepts the line break as its separator and masks its whole match, so a
/// line ending like this may still start a mask that spans the break.
static AWS_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)aws[^\n]{0,30}?(?:secret|sk)[^\n]{0,20}?\z").expect("valid inline pattern")
});

/// A line ending this way may continue a credential assignment or a Bearer
/// header on a later line (`guard::secrets` `CREDENTIAL_ASSIGNMENT` and
/// `BEARER_TOKEN`: the `\s*` around the separator may span line breaks).
/// Every key of `CREDENTIAL_ASSIGNMENT` ends in one of these words
/// (`password`, `passwd`, `pwd`, `secret`, `key`, `token`: `api_key`,
/// `APP_KEY`, `GITHUB_TOKEN`, `client_secret`, ...), may be followed by a
/// quote (`"password"`) and then only by whitespace and the `=`/`:`
/// separator before the value; `BEARER_TOKEN` breaks after
/// `authorization` or `bearer`. No `\b` is required, so the cue may sit at
/// the end of a longer word: an over-approximation is safe, it only widens
/// the scanned context.
static OPEN_TAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:password|passwd|pwd|secret|key|token|authorization|bearer)["']?[\s=:]*\z"#)
        .expect("valid inline pattern")
});

/// The earliest byte offset of `line` (one line, its `\n` optional) where
/// a cross-line AWS secret key could start ([`AWS_HEAD`] on the raw line
/// and on its normalized view, whose secrets are masked too), or `None`.
/// A normalized head maps to its cluster's raw START; a regex runtime
/// error or a line that cannot be aligned holds the whole line (fail safe:
/// holding only delays emission).
fn cross_line_head(line: &str) -> Option<usize> {
    let body = line.strip_suffix('\n').unwrap_or(line);
    let mut head = match AWS_HEAD.find(body) {
        Ok(m) => m.map(|m| m.start()),
        Err(_) => return Some(0),
    };
    if !body.is_ascii() {
        let norm = normalize_for_scan(body);
        if norm != body {
            match AWS_HEAD.find(&norm) {
                Ok(Some(m)) => {
                    let aligned = align_for_scan(body);
                    let start = if aligned.unaligned.is_empty() && aligned.normalized == norm {
                        aligned.start[m.start()]
                    } else {
                        0
                    };
                    head = Some(head.map_or(start, |h| h.min(start)));
                }
                Ok(None) => {}
                Err(_) => return Some(0),
            }
        }
    }
    head
}

/// Whether a secret match may continue from `line` (one line, its `\n`
/// optional) onto a later line: [`OPEN_TAIL`] or [`AWS_HEAD`] on the raw
/// line or its normalized view (a regex runtime error counts as open), or
/// a line of whitespace and `=`/`:` only inside an open context
/// (`ctx_open`: the line before ended open), which may sit inside the gap
/// between a key and its value. Such a line after a closed context cannot
/// hold the start of any secret match (none starts with whitespace, `=`
/// or `:`), so it closes the context instead of keeping it open forever.
pub(super) fn ends_open(line: &str, ctx_open: bool) -> bool {
    let body = line.strip_suffix('\n').unwrap_or(line);
    let open = |s: &str| {
        OPEN_TAIL.is_match(s).unwrap_or(true)
            || (ctx_open && s.chars().all(|c| c.is_whitespace() || c == '=' || c == ':'))
    };
    open(body)
        || (!body.is_ascii() && open(&normalize_for_scan(body)))
        || cross_line_head(line).is_some()
}

/// The start (in `unit` coordinates) of a PEM private-key block that is
/// still open at the end of `ctx` + `unit`
/// ([`open_pem_block_start`](crate::guard::secrets::open_pem_block_start)),
/// or `None`. A block open in the context lines is held from the unit
/// start (defensive: the hold keeps an open block's lines in the unit).
fn open_pem_head(ctx: &str, unit: &str) -> Option<usize> {
    let start = if ctx.is_empty() {
        open_pem_block_start(unit)?
    } else {
        let mut text = String::with_capacity(ctx.len() + unit.len());
        text.push_str(ctx);
        text.push_str(unit);
        open_pem_block_start(&text)?
    };
    Some(start.saturating_sub(ctx.len()))
}

/// The secret spans of `unit` (in `unit` coordinates), scanned together
/// with the context lines `ctx` that precede it in the stream (see
/// [`spans_from`]).
fn unit_secret_spans(ctx: &str, unit: &str) -> Vec<SecretFinding> {
    if ctx.is_empty() {
        return secret_mask_spans(unit);
    }
    let mut text = String::with_capacity(ctx.len() + unit.len());
    text.push_str(ctx);
    text.push_str(unit);
    spans_from(&secret_mask_spans(&text), ctx.len())
}

/// The spans of `spans` from byte `off` on, shifted to start at `off`: a
/// span crossing `off` is clipped to it, a span ending at or before it is
/// dropped, and a zero-length `SCAN_ERROR` health marker is kept at
/// `0..0` (it masks nothing anywhere; kept so the span list carries the
/// same health facts as the batch list).
fn spans_from(spans: &[SecretFinding], off: usize) -> Vec<SecretFinding> {
    spans
        .iter()
        .filter(|s| s.end > off || s.start == s.end)
        .map(|s| {
            let (start, end) = if s.start == s.end {
                (0, 0)
            } else {
                (s.start.max(off) - off, s.end - off)
            };
            SecretFinding {
                start,
                end,
                ..s.clone()
            }
        })
        .collect()
}

/// The entities of `text` that the slice `[from, to)` masks, in slice
/// coordinates: a secret span wins over an overlapping entity (batch
/// precedence), and an entity crossing a slice edge is CLIPPED to the
/// slice (never dropped: when its head was already emitted, its tail must
/// still be masked).
fn slice_entities(
    text: &str,
    entities: &[Entity],
    secrets: &[SecretFinding],
    from: usize,
    to: usize,
) -> Vec<Entity> {
    entities
        .iter()
        .filter(|x| {
            x.end > from
                && x.start < to
                && !secrets.iter().any(|s| x.start < s.end && s.start < x.end)
        })
        .map(|x| {
            let (start, end) = (x.start.max(from), x.end.min(to));
            Entity {
                start: start - from,
                end: end - from,
                text: text[start..end].to_owned(),
                ..x.clone()
            }
        })
        .collect()
}

/// Computes the safe intra-line emit point for `pending` given its visible
/// entities and secret spans: a byte offset on a UTF-8 character boundary
/// (`0` when nothing may be emitted yet).
fn intra_line_emit_point(pending: &str, ents: &[Entity], secrets: &[SecretFinding]) -> usize {
    // condition 1: bounded-rule holdback, in normalized characters
    let mut e = holdback_cut(pending);
    // condition 2a: hold the trailing whitespace-free run (growing e-mail)
    let mut w = pending.len();
    while w > 0 {
        let prev = prev_char_start(pending, w);
        if pending[..w]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace)
        {
            break;
        }
        w = prev;
    }
    e = e.min(w);
    // condition 2b: hold a trailing run of up to 4 capitalized words
    // (a growing NAME candidate; names cannot cross a non-capitalized word)
    let mut token_end = w;
    for _ in 0..4 {
        if token_end == 0 {
            break;
        }
        // skip the whitespace before the previous token
        let mut s = token_end;
        while s > 0
            && pending[..s]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace)
        {
            s = prev_char_start(pending, s);
        }
        if s == 0 {
            break;
        }
        // walk back over the token's non-whitespace characters
        let mut t = s;
        while t > 0
            && !pending[..t]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace)
        {
            t = prev_char_start(pending, t);
        }
        let token = &pending[t..s];
        let first = token.chars().next();
        if first.is_some_and(char::is_uppercase) {
            e = e.min(t); // could be the first word of a growing name
            token_end = t;
        } else {
            break; // names never extend across a non-capitalized word
        }
    }
    // condition 3: no entity or secret span may cross the emit point.
    // Moving back past one span can make another one cross: `settle`
    // repeats until nothing moves.
    let spans: Vec<(usize, usize)> = ents
        .iter()
        .map(|x| (x.start, x.end))
        .chain(secrets.iter().map(|s| (s.start, s.end)))
        .collect();
    settle(e, &spans)
}

/// Byte index of the previous character start (assumes `at` is a boundary).
fn prev_char_start(s: &str, at: usize) -> usize {
    let mut i = at - 1;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

impl StreamingGuard {
    /// Creates a guard for one stream and one target.
    #[must_use]
    pub const fn new(target: GuardTarget) -> Self {
        Self {
            target,
            line: String::new(),
            emitted: 0,
            held: 0,
            held_entities: Vec::new(),
            held_errors: Vec::new(),
            ctx_text: String::new(),
            decider: None,
            blocked: false,
            finished: false,
            ner: Vec::new(),
            locales: Vec::new(),
            ml: None,
            line_count: 0,
            policy: None,
            mask: MaskStyle::Label,
            custom: Vec::new(),
            ignored: Vec::new(),
        }
    }

    /// Uses a caller-supplied policy for every line decision, the ML
    /// escalation lines and (when no explicit locales are set) its
    /// default locales. A `ToolResponse` stream decides under the built-in
    /// tool lines (see [`Policy::for_target`]). Set on a running stream, it
    /// applies to every line completed after the call (see the type docs,
    /// "Reconfiguring a running stream").
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Attaches a budgeted ML security classifier (opt-in): the L2
    /// classifier scans MASKED completed lines per [`MlStreamBudget`]; a
    /// signal at or above its category's effective block line escalates
    /// the stream to a terminal `Block` event (categories the policy
    /// disables are ignored, except on `ToolResponse`).
    #[must_use]
    pub fn with_ml(
        mut self,
        classifier: Arc<dyn crate::guard::ml::MlClassifier>,
        budget: MlStreamBudget,
    ) -> Self {
        self.ml = Some((classifier, budget));
        self
    }

    /// Attaches NER recognizers (opt-in): completed lines are then
    /// scanned with the recognizers ([`Detector::with_ner`]), so free-prose
    /// NAME/ADDRESS are masked in streams too. A recognizer reporting
    /// degraded health after a line's call adds a `NER_DEGRADED` signal to
    /// that line's decision (blockable via a category override, like the
    /// batch guard).
    ///
    /// Semantics (documented trade-off): **line-scoped** NER - each line is
    /// masked exactly like the batch masking of that line alone; models do
    /// not see surrounding lines. Intra-line early emission is disabled in
    /// this mode (a growing prefix would re-detect differently and NER is
    /// too expensive per push). Expect ~one NER call per line (~27-68 ms
    /// measured on CPU depending on the model).
    #[must_use]
    pub fn with_ner(mut self, ner: Vec<Arc<dyn NerRecognizer>>) -> Self {
        self.ner = ner;
        self
    }

    /// Opts the stream into the locale packs (opt-in rules:
    /// EU/national identifiers, national phone formats). An empty slice
    /// selects the policy's default locales when a policy is attached,
    /// else the default tr+en set.
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{GuardTarget, StreamingGuard};
    ///
    /// let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_locales(&["uk"]);
    /// let ev = sg.push("nhs 9434765870\n");
    /// assert!(ev[0].as_segment().unwrap().0.contains("[UK_NHS]"));
    /// ```
    #[must_use]
    pub fn with_locales(mut self, locales: &[&str]) -> Self {
        self.locales = locales.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Selects how emitted segments render PII spans (default
    /// [`MaskStyle::Label`]; secrets always render as `[SECRET:VENDOR]`),
    /// matching [`Guard::with_mask_style`] in batch.
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{GuardTarget, StreamingGuard};
    /// use redactify::MaskStyle;
    ///
    /// let mut sg = StreamingGuard::new(GuardTarget::UserPrompt)
    ///     .with_mask_style(MaskStyle::Template("<{type}>".into()));
    /// let ev = sg.push("TCKN 12345678950\n");
    /// assert_eq!(ev[0].as_segment().unwrap().0, "TCKN <TCKN>\n");
    /// ```
    #[must_use]
    pub fn with_mask_style(mut self, style: MaskStyle) -> Self {
        self.mask = style;
        self
    }

    /// Custom rules for every detection and decision of the stream, as
    /// [`Guard::with_custom_rules`] applies them in batch. Intra-line early
    /// emission is disabled while custom rules are attached: a custom
    /// pattern can match a span of any length (spaces included), which no
    /// fixed holdback covers, so a line is emitted once it completes.
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{GuardTarget, StreamingGuard};
    /// use redactify::{CustomRule, EntityType};
    ///
    /// let staff = EntityType::custom("STAFF_ID").unwrap();
    /// let rule = CustomRule::new(staff, r"\bE\d{6}\b").unwrap();
    /// let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_custom_rules(vec![rule]);
    /// assert_eq!(sg.push("personel E123456\n")[0].as_segment().unwrap().0, "personel [STAFF_ID]\n");
    /// ```
    #[must_use]
    pub fn with_custom_rules(mut self, rules: Vec<CustomRule>) -> Self {
        self.custom = rules;
        self
    }

    /// Allowlisted values for every detection and decision of the stream,
    /// as [`Guard::with_ignored`] applies them in batch.
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{GuardTarget, StreamingGuard};
    ///
    /// let mut sg = StreamingGuard::new(GuardTarget::UserPrompt)
    ///     .with_ignored(vec!["0532 123 45 67".to_owned()]);
    /// let ev = sg.push("Destek 0532 123 45 67, TCKN 12345678950\n");
    /// assert_eq!(ev[0].as_segment().unwrap().0, "Destek 0532 123 45 67, TCKN [TCKN]\n");
    /// ```
    #[must_use]
    pub fn with_ignored(mut self, values: Vec<String>) -> Self {
        self.ignored = values;
        self
    }

    /// The custom rules the stream's own detector runs: the stream's
    /// rules, then the policy's (a [`Guard`] built with the policy adds the
    /// policy's rules itself).
    fn detector_rules(&self) -> Vec<&CustomRule> {
        let policy_rules = self
            .policy
            .as_ref()
            .map_or(&[][..], |p| p.custom_rules.rules());
        self.custom.iter().chain(policy_rules).collect()
    }

    /// The allowlisted values as the slice the detector and guard borrow.
    fn ignored_refs(&self) -> Vec<&str> {
        self.ignored.iter().map(String::as_str).collect()
    }

    /// The effective locale list (explicit, else the policy's default
    /// locales, else empty = the default tr+en set).
    fn locale_refs(&self) -> Vec<&str> {
        let explicit: Vec<&str> = self.locales.iter().map(String::as_str).collect();
        effective_locales(&explicit, self.policy.as_ref())
    }

    /// The policy every line decides under (caller policy or built-in
    /// default, adapted to the target).
    fn effective_policy(&self) -> Policy {
        effective_policy(self.policy.as_ref(), self.target)
    }

    /// Whether intra-line early emission may run at all (see the type
    /// docs): not with NER recognizers, custom rules, relevance rules or
    /// entity actions (they decide a line only once it is complete).
    fn intra_line_enabled(&self) -> bool {
        self.ner.is_empty()
            && self.detector_rules().is_empty()
            && !self
                .policy
                .as_ref()
                .is_some_and(|p| !p.relevance.is_empty() || !p.entity_actions.is_empty())
    }

    /// Feeds one chunk; returns the events produced by the lines it completes.
    /// After a `Block` (or after `finish`) further pushes are ignored.
    pub fn push(&mut self, chunk: &str) -> Vec<GuardEvent> {
        if self.blocked || self.finished || chunk.is_empty() {
            return Vec::new();
        }
        self.line.push_str(chunk);
        let mut events = Vec::new();
        // the open line starts after the held lines and has no `\n` before
        // the emitted offset
        while let Some(rel) = self.line[self.held.max(self.emitted)..].find('\n') {
            let end = self.held.max(self.emitted) + rel + 1;
            if let Some(ev) = self.complete_line(end, false) {
                let is_block = matches!(ev, GuardEvent::Block { .. });
                events.push(ev);
                if is_block {
                    self.blocked = true;
                    return events;
                }
            }
        }
        // intra-line early emission: a long still-open line emits its
        // safe prefix; the FULL line is kept so the completion side can
        // re-detect with intact cue/lookbehind context.
        if self.intra_line_enabled() && self.line.len() - self.emitted >= INTRA_LINE_MIN_PENDING {
            if let Some(ev) = self.intra_line_segment() {
                events.push(ev);
            }
        }
        events
    }

    /// The secret context of `self.line`: the context lines up to the held
    /// lines (which are part of `self.line`).
    fn secret_context(&self) -> &str {
        &self.ctx_text[..self.ctx_text.len() - self.held]
    }

    /// The safe prefix segment of the open line, if one may be emitted
    /// now. Detection is normalization-aware (the completion path and the
    /// batch transform see fullwidth/zero-width values too); an open line
    /// with an incompletely scanned part is held until it completes.
    fn intra_line_segment(&mut self) -> Option<GuardEvent> {
        let locales = self.locale_refs();
        let rules = self.detector_rules();
        let ignored = self.ignored_refs();
        let detector = Detector::new()
            .with_locales(&locales)
            .with_custom_rules(&rules)
            .with_ignored(&ignored)
            .with_normalization(true);
        let mut report = detector.scan(&self.line);
        if !report.error_spans.is_empty() {
            return None;
        }
        let mut ents = std::mem::take(&mut report.entities);
        // a base64 token that hides PII is one entity (a token that hides a
        // credential is among the secret spans); the emit point never cuts
        // either, and a token still being received is held as the trailing
        // whitespace-free run
        add_encoded_entities(
            &mut ents,
            encoded_pii_entities(&self.line, &encoded_tokens(&self.line), &detector),
        );
        let secrets = unit_secret_spans(self.secret_context(), &self.line);
        let e = intra_line_emit_point(&self.line, &ents, &secrets);
        if e < self.emitted + INTRA_LINE_MIN_EMIT {
            return None;
        }
        let seg_ents = slice_entities(&self.line, &ents, &secrets, self.emitted, e);
        report.entities = seg_ents.clone();
        let text = self.render(&self.line, self.emitted, e, &secrets, report);
        self.emitted = e;
        Some(GuardEvent::Segment {
            text,
            entities: seg_ents,
        })
    }

    /// Ends the stream: flushes a trailing partial line as a final segment
    /// (or a Block). Idempotent - a second call returns nothing.
    pub fn finish(&mut self) -> Vec<GuardEvent> {
        if self.blocked || self.finished {
            return Vec::new();
        }
        self.finished = true;
        if self.line.is_empty() {
            return Vec::new();
        }
        let end = self.line.len();
        match self.complete_line(end, true) {
            // a fully-emitted trailing line still needs its L0 decision: a
            // Block must surface; an empty retained segment is dropped
            Some(ev @ GuardEvent::Block { .. }) => {
                self.blocked = true;
                vec![ev]
            }
            Some(GuardEvent::Segment { text, .. }) if text.is_empty() => Vec::new(),
            other => other.into_iter().collect(),
        }
    }

    /// Whether a Block was emitted (terminal state).
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Processes the unit `self.line[..end]`: the held lines (already
    /// decided) followed by one newly completed line (including its `\n`;
    /// at `finish` (`last`) the trailing text, possibly empty). Extends the
    /// decision prefix with the new line, re-decides, and emits the
    /// RETAINED part (from the emitted offset) masked with entities
    /// detected on FULL lines - so a cue or lookbehind that lives in the
    /// already-emitted prefix still contributes (this is what keeps
    /// intra-line emission equivalent to the batch result) -
    /// and with the unit's secret spans found together with their context
    /// lines. Unless `last`, a new line whose tail may start a cross-line
    /// AWS secret key emits only up to that tail, which stays held.
    fn complete_line(&mut self, end: usize, last: bool) -> Option<GuardEvent> {
        let rest = self.line.split_off(end);
        let unit = std::mem::replace(&mut self.line, rest);
        let held = std::mem::take(&mut self.held);
        let emitted = std::mem::take(&mut self.emitted);
        let mut entities = std::mem::take(&mut self.held_entities);
        let mut error_spans = std::mem::take(&mut self.held_errors);
        let new_line = &unit[held..];
        // the line before ended open (the context holds lines)
        let ctx_open = !self.ctx_text.is_empty();
        if !new_line.is_empty() {
            self.ctx_text.push_str(new_line);
        }
        // the unit is the tail of the context; its context lines precede it
        let ctx_end = self.ctx_text.len() - unit.len();
        let ctx = &self.ctx_text[..ctx_end];
        let secrets = unit_secret_spans(ctx, &unit);
        // a PEM block still open at the end of the unit may grow over the
        // next lines: it is held from its header on (unless `last`)
        let pem_head = if last {
            None
        } else {
            open_pem_head(ctx, &unit)
        };
        if !new_line.is_empty() {
            let line_secrets = spans_from(&secrets, held);
            let report = match self.decide_line(new_line, &line_secrets) {
                Ok(report) => report,
                Err(block) => return Some(block),
            };
            entities.extend(report.entities.into_iter().map(|e| Entity {
                start: e.start + held,
                end: e.end + held,
                ..e
            }));
            error_spans.extend(
                report
                    .error_spans
                    .into_iter()
                    .map(|(s, e)| (s + held, e + held)),
            );
            if pem_head.is_none() && !ends_open(new_line, ctx_open) {
                // no secret match continues past this line: later lines
                // need no earlier context
                self.ctx_text.clear();
            }
        }

        // Cross-line hold: a new line ending like the cue of an AWS secret
        // key emits only up to that cue, and an open PEM block only up to
        // its header (moved back past every span crossing it); the rest
        // waits for the next line.
        let mut upto = unit.len();
        if !last {
            let aws_head = cross_line_head(new_line).map(|h| held + h);
            let head = match (aws_head, pem_head) {
                (Some(a), Some(p)) => Some(a.min(p)),
                (a, p) => a.or(p),
            };
            if let Some(head) = head {
                let spans: Vec<(usize, usize)> = entities
                    .iter()
                    .map(|x| (x.start, x.end))
                    .chain(secrets.iter().map(|s| (s.start, s.end)))
                    .chain(error_spans.iter().copied())
                    .collect();
                upto = settle(head, &spans).max(emitted);
            }
        }

        // Emission: mask the RETAINED slice with the unit's entities and
        // secret spans (same one pass as batch sanitize: a secret span wins
        // over an overlapping entity). Allow implies no PII anywhere;
        // Mask/Log with PII mask too - same rule the batch transform uses.
        // An incompletely scanned line is replaced by `[SCAN_INCOMPLETE]`
        // like in batch.
        let seg_ents = slice_entities(&unit, &entities, &secrets, emitted, upto);
        let report = ScanReport {
            entities: seg_ents.clone(),
            engine_errors: 0,
            error_spans: error_spans
                .iter()
                .filter(|&&(s, e)| e > emitted && s < upto)
                .map(|&(s, e)| (s.max(emitted) - emitted, e.min(upto) - emitted))
                .collect(),
        };
        let text = self.render(&unit, emitted, upto, &secrets, report);
        if upto < unit.len() {
            // keep the lines from the one holding `upto` (already decided)
            let keep_from = unit[..upto].rfind('\n').map_or(0, |i| i + 1);
            self.line.insert_str(0, &unit[keep_from..]);
            self.held = unit.len() - keep_from;
            self.emitted = upto - keep_from;
            self.held_entities = entities
                .into_iter()
                .filter(|x| x.start >= keep_from)
                .map(|x| Entity {
                    start: x.start - keep_from,
                    end: x.end - keep_from,
                    ..x
                })
                .collect();
            self.held_errors = error_spans
                .into_iter()
                .filter(|&(s, _)| s >= keep_from)
                .map(|(s, e)| (s - keep_from, e - keep_from))
                .collect();
        }
        (!text.is_empty()).then_some(GuardEvent::Segment {
            text,
            entities: seg_ents,
        })
    }

    /// The decision side of one newly completed `line` (the stream
    /// prefix already extended with it): scans the FULL line, decides the
    /// prefix, runs the scheduled ML scan, and returns the line's
    /// masking-relevant PII (relevance applied) in line coordinates - or
    /// the terminal `Block` event. `line_secrets` are the line's secret
    /// spans (cross-line context included) for the ML input.
    fn decide_line(
        &mut self,
        line: &str,
        line_secrets: &[SecretFinding],
    ) -> Result<ScanReport, GuardEvent> {
        let locales = self.locale_refs();
        let refs: Vec<&dyn NerRecognizer> = self.ner.iter().map(Arc::as_ref).collect();
        let rules = self.detector_rules();
        let ignored = self.ignored_refs();
        let line_policy = self.effective_policy();
        let actions = &line_policy.entity_actions;
        let ignored_types = actions.ignored_types();

        // Scan of the FULL line (cue context intact even when the cue sits
        // in the already-emitted prefix), normalization-aware: entities only
        // the normalizer can see (fullwidth/zero-width values) come back in
        // raw line coordinates. NER mode: the attached recognizers scan the
        // line too (line-scoped semantics).
        let detector = Detector::new()
            .with_locales(&locales)
            .with_ner(&refs)
            .with_custom_rules(&rules)
            .with_ignored(&ignored)
            .with_ignored_types(&ignored_types)
            .with_normalization(true);
        let mut report = detector.scan(line);
        // base64 tokens of the line that hide PII (batch parity: the batch
        // transform adds the same entities after relevance; models see them
        // masked too)
        let encoded = encoded_pii_entities(line, &encoded_tokens(line), &detector);

        // Prefix decision: the batch decision of the stream so far, decided
        // incrementally (see `decider`). The recognizers' health is read
        // AFTER this line's call: a failure on this line degrades this
        // line's decision.
        let ner_health: Vec<GuardSignal> = ner_degradation_signal(&refs).into_iter().collect();
        let verdict = self.prefix_verdict(line, ner_health);
        if let Some(rationale) = verdict.block {
            return Err(GuardEvent::Block { rationale });
        }
        // entity actions (batch parity: a BLOCK type blocks the decision,
        // unless a relevance rule downgraded the entity; the rationale
        // names type labels, never values)
        if !actions.is_empty() {
            let kept: Vec<&Entity> = if line_policy.relevance.is_empty() {
                report.entities.iter().collect()
            } else {
                line_policy.relevance.partition(line, &report.entities).0
            };
            let mut blocked: Vec<&str> = Vec::new();
            for e in kept.into_iter().chain(&encoded) {
                let label = e.kind.as_str();
                if actions.action_for(e.kind) == EntityAction::Block && !blocked.contains(&label) {
                    blocked.push(label);
                }
            }
            if !blocked.is_empty() {
                return Err(GuardEvent::Block {
                    rationale: format!("entity type(s) configured BLOCK: {}", blocked.join(", ")),
                });
            }
        }

        // Budgeted ML scan (opt-in): schedule per the pacing, classify
        // the MASKED full line (privacy rule: models never see raw
        // identifiers or credentials; the batch ML input helper, secrets
        // first), escalate block-level signals to a terminal Block event.
        // Log-level ML signals are ignored here (the stream contract emits
        // Segment/Block only).
        if let Some((clf, budget)) = &self.ml {
            self.line_count += 1;
            let l0_trigger = budget.on_l0_trigger && verdict.l0_trigger;
            let scheduled = (budget.first_line && self.line_count == 1)
                || (budget.every_n_lines > 0 && self.line_count % budget.every_n_lines == 0)
                || l0_trigger;
            if scheduled {
                let mut entities = report.entities.clone();
                add_encoded_entities(&mut entities, encoded.clone());
                let ml_input = ml_input(line, line_secrets, entities);
                // each category blocks at ITS effective line (override or
                // global), and disabled categories stay silent - the same
                // verdict rule as the batch decision
                let effective = self.effective_policy();
                // chunked like the batch path: a single very long line must
                // not lose its tail to the 512-token truncation here either
                let clf = clf.as_ref();
                for (cat, score) in crate::guard::ml::classify_chunked(clf, &ml_input) {
                    if !effective.is_enabled(cat) {
                        continue;
                    }
                    let block_line = effective.block_line_for(cat);
                    if score >= block_line {
                        return Err(GuardEvent::Block {
                            rationale: format!(
                                "ml stream signal {cat:?} score {score:.2} >= block threshold {block_line:.2}"
                            ),
                        });
                    }
                }
            }
        }

        // Relevance (opt-in): entities downgraded by a matching rule stay
        // in the emitted text - partitioned on the FULL raw line (the
        // coordinates the batch decision and transform use) so a cue in the
        // already-emitted prefix still counts; the ML input above keeps the
        // UNFILTERED entities on purpose (models always see the masked
        // text, conservative like the batch path).
        let effective = self.effective_policy();
        if !effective.relevance.is_empty() {
            let (keep, _) = effective.relevance.partition(line, &report.entities);
            report.entities = keep.into_iter().cloned().collect();
        }
        add_encoded_entities(&mut report.entities, encoded);
        // entity actions: LOG types are reported, not masked
        if actions.has_log() {
            report
                .entities
                .retain(|e| actions.action_for(e.kind) != EntityAction::Log);
        }
        Ok(report)
    }

    /// The decision of the stream so far, extended with the completed
    /// `line` (see [`decider`]), under the current configuration; `extra`
    /// are the line's own signals (NER health).
    fn prefix_verdict(&mut self, line: &str, extra: Vec<GuardSignal>) -> decider::Verdict {
        let mut decider = self.decider.take().unwrap_or_default();
        let policy = self.effective_policy();
        let ml_trigger = self.ml.as_ref().is_some_and(|(_, b)| b.on_l0_trigger);
        let verdict = {
            let locales = self.locale_refs();
            let rules = self.detector_rules();
            let ignored = self.ignored_refs();
            let ignored_types = policy.entity_actions.ignored_types();
            // the decision's PII detector: the batch `Guard::detector()`
            // without recognizers and without a normalization pass (the
            // decision scans the normalized view on its own)
            let detector = Detector::new()
                .with_locales(&locales)
                .with_custom_rules(&rules)
                .with_ignored(&ignored)
                .with_ignored_types(&ignored_types);
            decider.push_line(line, &detector, extra, &policy, ml_trigger)
        };
        self.decider = Some(decider);
        verdict
    }

    /// Renders `text[from..to]` the way the batch transform renders that
    /// part of the text (the one masking pass, `policy::render_masked`):
    /// the secret spans (found with their full context) become
    /// `[SECRET:VENDOR]` and win over overlapping entities, `report`
    /// (entities and incompletely scanned lines, in slice coordinates) is
    /// masked with the stream's mask style, then `ModelOutput` is
    /// HTML-entity encoded.
    fn render(
        &self,
        text: &str,
        from: usize,
        to: usize,
        secrets: &[SecretFinding],
        report: ScanReport,
    ) -> String {
        let spans: Vec<SecretFinding> = secrets
            .iter()
            .filter_map(|s| {
                let (start, end) = (s.start.max(from), s.end.min(to));
                (start < end).then(|| SecretFinding {
                    start: start - from,
                    end: end - from,
                    ..s.clone()
                })
            })
            .collect();
        let masked = render_masked(&text[from..to], &spans, report, &self.mask);
        match self.target {
            GuardTarget::ModelOutput => crate::guard::encode_html(&masked),
            _ => masked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GuardEvent, MlStreamBudget, StreamingGuard};
    use crate::guard::category::GuardCategory;
    use crate::guard::ml::MlClassifier;
    use crate::policy::GuardTarget;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn debug_output_carries_no_stream_content() {
        let mut g = StreamingGuard::new(GuardTarget::UserPrompt);
        // an incomplete line stays buffered inside the guard
        let _ = g.push("my e-mail is jane.doe@example.com and the TC");
        let shown = format!("{g:?}");
        assert!(!shown.contains("jane"), "{shown}");
        assert!(!shown.contains("example.com"), "{shown}");
        assert!(shown.contains("buffered_bytes"), "{shown}");
    }

    /// Counting mock: records every classify() call and can force a
    /// block-level signal on demand (and asserts the privacy rule: the
    /// input it receives must already be masked).
    struct CountingMock {
        calls: AtomicUsize,
        block_after: usize,
    }

    impl MlClassifier for CountingMock {
        fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(
                !text.contains("12345678950"),
                "privacy rule violated: classifier saw a raw TCKN in {text:?}"
            );
            if n >= self.block_after {
                vec![(GuardCategory::PromptInjection, 0.9)]
            } else {
                Vec::new()
            }
        }
        fn name(&self) -> &'static str {
            "counting-mock"
        }
    }

    #[test]
    fn ml_budget_paces_calls_and_escalates_on_block_signal() {
        let mock = Arc::new(CountingMock {
            calls: AtomicUsize::new(0),
            block_after: 3,
        });
        let budget = MlStreamBudget {
            first_line: true,
            every_n_lines: 2,
            on_l0_trigger: false,
        };
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt)
            .with_ml(Arc::clone(&mock) as Arc<dyn MlClassifier>, budget);
        // five lines: scheduled scans at lines 1, 2, 4 (first + every 2nd);
        // the third scan (line 4) returns a block-level signal -> Block
        for i in 0..3 {
            sg.push(&format!("line {i} TCKN 12345678950 tamam\n"));
        }
        let events = sg.push("line 3 done\n");
        assert!(matches!(events[0], GuardEvent::Block { .. }), "{events:?}");
        assert!(sg.is_blocked());
        assert_eq!(mock.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn ml_budget_l0_trigger_scans_unscheduled_lines() {
        let mock = Arc::new(CountingMock {
            calls: AtomicUsize::new(0),
            block_after: usize::MAX,
        });
        let budget = MlStreamBudget {
            first_line: false,
            every_n_lines: 0,
            on_l0_trigger: true,
        };
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt)
            .with_ml(Arc::clone(&mock) as Arc<dyn MlClassifier>, budget);
        // an ordinary line is NOT scanned (nothing scheduled)
        sg.push("ordinary line\n");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
        // a letter-splitting SQL word pair (obfuscation) triggers the scan
        sg.push("kural: d r o p t a b l e kullanicilar\n");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ml_budget_disabled_never_scans() {
        let mock = Arc::new(CountingMock {
            calls: AtomicUsize::new(0),
            block_after: usize::MAX,
        });
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
        // no with_ml: the default stream never calls a classifier
        sg.push("line one\nline two\nline three\n");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn line_held_until_complete_then_masked() {
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
        assert!(sg.push("TCKN 12345678").is_empty());
        let ev = sg.push("950 gecerli\n");
        assert_eq!(ev.len(), 1);
        match &ev[0] {
            GuardEvent::Segment { text, entities } => {
                assert_eq!(text, "TCKN [TCKN] gecerli\n");
                assert_eq!(entities.len(), 1);
            }
            other => panic!("expected segment, got {other:?}"),
        }
        assert!(sg.finish().is_empty());
    }

    #[test]
    fn multiple_lines_in_one_chunk() {
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
        let ev = sg.push("a@b.com yaz\nikinci satir\nucuncu\n");
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].as_segment().unwrap().0, "[EMAIL] yaz\n");
        assert!(sg.finish().is_empty());
    }

    #[test]
    fn block_stops_emission() {
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
        let ev1 = sg.push("ilk satir\n");
        assert_eq!(ev1.len(), 1);
        let ev2 = sg.push("bkz http://169.254.169.254/meta\n");
        assert_eq!(ev2.len(), 1, "block line replaces its segment");
        assert!(matches!(ev2[0], GuardEvent::Block { .. }));
        assert!(sg.is_blocked());
        assert!(sg.push("sonra bunlar\nyok\n").is_empty());
        assert!(sg.finish().is_empty());
    }

    #[test]
    fn finish_flushes_partial_tail() {
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
        assert!(sg.push("kuyruk TCKN 12345678950").is_empty());
        let ev = sg.finish();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].as_segment().unwrap().0, "kuyruk TCKN [TCKN]");
        // idempotent
        assert!(sg.finish().is_empty());
    }

    #[test]
    fn model_output_encodes_per_line() {
        let mut sg = StreamingGuard::new(GuardTarget::ModelOutput);
        let ev = sg.push("a < b\n");
        assert_eq!(ev[0].as_segment().unwrap().0, "a &lt; b\n");
    }

    #[test]
    fn log_level_danger_with_pii_still_masks() {
        // 0.4-level quote+OR signal (Log, not Block) + PII in the same line:
        // the segment is emitted MASKED (the batch transform applies the
        // same rule)
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt);
        let ev = sg.push("a' or 'b diye sordu, TCKN 12345678950\n");
        let (seg, _) = ev[0]
            .as_segment()
            .expect("segment, not block (Log-level signal)");
        assert!(seg.contains("[TCKN]"), "{seg}");
        assert!(!seg.contains("12345678950"));
    }

    #[test]
    fn with_ner_masks_names_line_scoped() {
        use std::sync::Arc;
        let ner = Arc::new(crate::MockNameRecognizer::new());
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_ner(vec![ner]);
        let ev = sg.push("toplanda Ahmet Yılmaz ve TCKN 12345678950 konustu\n");
        assert_eq!(ev.len(), 1);
        let (seg, ents) = ev[0].as_segment().unwrap();
        assert!(seg.contains("[NAME]"), "{seg}");
        assert!(seg.contains("[TCKN]"), "{seg}");
        assert!(ents.iter().any(|e| e.kind == crate::EntityType::Name));
        assert!(sg.finish().is_empty());
    }

    /// Differential proof (NER mode): at EVERY character split, the stream's
    /// concatenated output equals the per-line batch masking
    /// (NER-enabled detection + label mask, line by line) - the documented
    /// line-scoped semantics.
    #[test]
    fn with_ner_stream_equals_per_line_batch_at_every_split() {
        use std::sync::Arc;
        let texts = [
            "Bugun Ahmet Yilmaz geldi\nTCKN 12345678950 gecerli\nson satir\n",
            "Ahmet Yılmaz konustu ve Ahmet Yılmaz yazdi\nikinci Ahmet Yılmaz satiri\n",
            "satir basi\nAhmet Yılmaz ortada\nsatir sonu",
        ];
        let batch = |full: &str| -> String {
            let ner = crate::MockNameRecognizer::new();
            let rec = [&ner as &dyn crate::NerRecognizer];
            let detector = crate::Detector::new().with_ner(&rec);
            let mut out = String::new();
            for line in full.split_inclusive('\n') {
                let ents = detector.detect(line);
                out.push_str(&crate::MaskStyle::Label.redact(line, &ents));
            }
            out
        };
        for text in texts {
            let expected = batch(text);
            for split in 0..=text.len() {
                if !text.is_char_boundary(split) {
                    continue;
                }
                let ner = Arc::new(crate::MockNameRecognizer::new());
                let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_ner(vec![ner]);
                let mut got = String::new();
                for chunk in [&text[..split], &text[split..]] {
                    for ev in sg.push(chunk) {
                        if let Some((seg, _)) = ev.as_segment() {
                            got.push_str(seg);
                        }
                    }
                }
                for ev in sg.finish() {
                    if let Some((seg, _)) = ev.as_segment() {
                        got.push_str(seg);
                    }
                }
                assert_eq!(got, expected, "split {split} of {text:?}");
            }
        }
    }

    #[test]
    fn crossing_spans_move_the_emit_point_until_none_crosses() {
        use crate::guard::SecretFinding;
        use crate::pii::{Entity, EntityType};
        // 300 ASCII bytes ending in whitespace, 4 non-gap chars per 5: the
        // holdback alone keeps the last 33 words (132 non-gap chars) and
        // cuts at 300 - 165 = 135
        let pending = "aaaa ".repeat(60);
        assert_eq!(super::L1_HOLDBACK, 132);
        assert_eq!(super::intra_line_emit_point(&pending, &[], &[]), 135);
        // the secret crosses 135 -> back to 130; the entity then crosses
        // 130 -> back to 120 (one pass over entities-then-secrets stopped
        // at 130 and split the entity)
        let secret = SecretFinding {
            start: 130,
            end: 150,
            vendor: "TEST",
            score: 0.9,
        };
        let entity = Entity {
            kind: EntityType::Phone,
            start: 120,
            end: 135,
            text: pending[120..135].to_owned(),
            score: 0.9,
        };
        assert_eq!(
            super::intra_line_emit_point(&pending, &[entity], &[secret]),
            120
        );
    }

    #[test]
    fn holdback_covers_the_longest_bounded_pii_and_secret_spans() {
        // pinned derivation: the AWS secret-key span measured on the real
        // rule is the derived SECRET_SPAN_MAX (the compile-time assertion
        // next to L1_HOLDBACK keeps it, and IBAN + cue window, inside the
        // holdback)
        let key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let gap30 = " ab".repeat(10);
        let gap20 = " cd".repeat(6) + "xy";
        let text = format!("x aws{gap30}secret{gap20}=\"{key}\" y");
        let spans = crate::guard::find_secret_spans(&text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0].vendor, "AWS_SECRET_KEY");
        assert_eq!(spans[0].end - spans[0].start, super::SECRET_SPAN_MAX);
        // one more char in either gap and the rule no longer matches
        for (g30, g20) in [
            (gap30.clone() + "z", gap20.clone()),
            (gap30.clone(), gap20.clone() + "z"),
        ] {
            let longer = format!("x aws{g30}secret{g20}=\"{key}\" y");
            assert!(
                crate::guard::find_secret_spans(&longer)
                    .iter()
                    .all(|s| s.vendor != "AWS_SECRET_KEY"),
                "{longer}"
            );
        }
    }

    #[test]
    fn holdback_counts_raw_and_non_gap_normalized_characters() {
        // whitespace, `:` and `#` do not count as held-back characters
        let gappy = format!("{}{}", "x".repeat(300), " :#".repeat(100));
        let cut = super::holdback_cut(&gappy);
        assert_eq!(cut, 300 - super::L1_HOLDBACK);
        // a compatibility char that NFKC expands (U+FDFA -> 18 chars) does
        // not shrink the raw tail below the bound
        let expanding = format!("{}{}", "x".repeat(300), "\u{FDFA}".repeat(100));
        let cut = super::holdback_cut(&expanding);
        assert!(expanding.is_char_boundary(cut));
        assert_eq!(expanding[cut..].chars().count(), super::L1_HOLDBACK);
    }

    #[test]
    fn holdback_counts_normalized_characters() {
        use crate::guard::normalize::normalize_for_scan;
        // ASCII: bytes == normalized chars
        let ascii = "x".repeat(300);
        assert_eq!(super::holdback_cut(&ascii), 300 - super::L1_HOLDBACK);
        // fullwidth (3 bytes per char) and zero-width scatter (4 bytes per
        // visible char): the tail still normalizes to L1_HOLDBACK chars
        let fullwidth: String = "\u{FF11}".repeat(300);
        let scattered: String = "1\u{200B}".repeat(300);
        for text in [&fullwidth, &scattered] {
            let cut = super::holdback_cut(text);
            assert!(text.is_char_boundary(cut));
            assert_eq!(
                normalize_for_scan(&text[cut..]).chars().count(),
                super::L1_HOLDBACK,
                "{cut}"
            );
        }
        // a zero-width char stays with the char it follows (no cut between
        // a char and the invisible run the normalizer folds into it)
        let cut = super::holdback_cut(&scattered);
        assert!(scattered[cut..].starts_with('1'), "{cut}");
        // too short to emit anything
        assert_eq!(super::holdback_cut(&"\u{FF11}".repeat(50)), 0);
    }

    /// Always reports one category at a fixed score.
    struct FixedScore {
        category: GuardCategory,
        score: f32,
    }

    impl MlClassifier for FixedScore {
        fn classify(&self, _text: &str) -> Vec<(GuardCategory, f32)> {
            vec![(self.category, self.score)]
        }
        fn name(&self) -> &'static str {
            "fixed-score"
        }
    }

    fn blocks_first_line(target: GuardTarget, policy: crate::policy::Policy, score: f32) -> bool {
        let clf = Arc::new(FixedScore {
            category: GuardCategory::PromptInjection,
            score,
        });
        let mut sg = StreamingGuard::new(target)
            .with_policy(policy)
            .with_ml(clf, MlStreamBudget::default());
        sg.push("ordinary line\n")
            .iter()
            .any(|e| matches!(e, GuardEvent::Block { .. }))
    }

    #[test]
    fn ml_stream_escalation_uses_the_category_line_and_disabled_list() {
        use crate::policy::{Policy, Threshold};
        let default = Policy::default();
        // 0.5 stays under the global 0.6 line...
        assert!(!blocks_first_line(
            GuardTarget::UserPrompt,
            default.clone(),
            0.5
        ));
        // ...but blocks under a Low override for its category
        let strict = default
            .clone()
            .with_category(GuardCategory::PromptInjection, Threshold::Low);
        assert!(blocks_first_line(GuardTarget::UserPrompt, strict, 0.5));
        // a High override raises the bar above a 0.7 score
        let lax = default
            .clone()
            .with_category(GuardCategory::PromptInjection, Threshold::High);
        assert!(!blocks_first_line(GuardTarget::UserPrompt, lax, 0.7));
        // a disabled category never escalates...
        let disabled = Policy {
            disabled: vec![GuardCategory::PromptInjection],
            ..Policy::default()
        };
        assert!(!blocks_first_line(
            GuardTarget::UserPrompt,
            disabled.clone(),
            0.99
        ));
        // ...except on ToolResponse, which ignores the disabled list
        assert!(blocks_first_line(GuardTarget::ToolResponse, disabled, 0.99));
    }

    #[test]
    fn mask_style_applies_to_every_emitted_segment() {
        use crate::policy::{Guard, MaskStyle};
        let style = MaskStyle::Template("<{type}>".into());
        let text = format!(
            "TCKN 12345678950 satiri\n{}mail ali@ornek.com son",
            "uzun aciklama metni ".repeat(12)
        );
        let batch = Guard::new(GuardTarget::UserPrompt)
            .with_mask_style(style.clone())
            .sanitize(&text);
        let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_mask_style(style);
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(9) {
            for ev in sg.push(std::str::from_utf8(chunk).unwrap()) {
                out.push_str(ev.as_segment().unwrap().0);
            }
        }
        for ev in sg.finish() {
            out.push_str(ev.as_segment().unwrap().0);
        }
        assert_eq!(out, batch.text);
        assert!(out.contains("<TCKN>") && out.contains("<EMAIL>"), "{out}");
    }

    #[test]
    fn secret_spans_are_masked_and_report_spans_follow_the_rewrite() {
        use crate::pii::{Entity, EntityType};
        use crate::policy::Detector;
        let text = "ab KEY1 cd TCKN 12345678950 ef KEY2";
        let k1 = text.find("KEY1").unwrap();
        let k2 = text.find("KEY2").unwrap();
        let mut report = Detector::new().scan(text);
        report.entities.push(Entity {
            kind: EntityType::Email,
            start: 0,
            end: 2,
            text: "ab".into(),
            score: 0.9,
        });
        // an incomplete-line span starting inside the first secret
        report.error_spans = vec![(k1 + 1, text.len())];
        let spans = [(k1, k1 + 4, "A"), (k2, k2 + 4, "BB"), (5, 5, "EMPTY")];
        let out = crate::policy::mask_secret_spans(text, &spans, &mut report);
        assert_eq!(out, "ab [SECRET:A] cd TCKN 12345678950 ef [SECRET:BB]");
        let tckn = report
            .entities
            .iter()
            .find(|e| e.kind == EntityType::Tckn)
            .unwrap();
        assert_eq!(&out[tckn.start..tckn.end], "12345678950");
        let email = report
            .entities
            .iter()
            .find(|e| e.kind == EntityType::Email)
            .unwrap();
        assert_eq!((email.start, email.end), (0, 2));
        // a span edge inside a secret moves to the placeholder edge
        assert_eq!(report.error_spans, vec![(3, out.len())]);
    }
}
