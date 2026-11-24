//! Incremental prefix decision of the streaming guard.
//!
//! The streaming guard must decide, after every completed line `k`,
//! exactly what the batch decision
//! ([`Guard::decide`](crate::policy::Guard::decide)) decides for the
//! prefix `P_k` (lines `1..=k`). Re-deciding the whole prefix costs
//! O(lines x bytes); this module computes the same verdict from bounded
//! windows plus constant-size state. The argument below is derived from
//! the code of the decision pipeline (`Guard::decide_views`,
//! `policy::collect_guard_signals`, `policy::rule_battery`, the rules of
//! `guard::rules` and `guard::secrets`, `guard::normalize::ScanViews`)
//! and is locked by `tests/stream_window_bounds.rs`, the every-split
//! differential tests and the property tests.
//!
//! # What a stream decision needs
//!
//! The stream emits a `Block` event or nothing, so it needs one bit per
//! line: is `decide(P_k).action == Block`. `policy::decide` blocks when
//! ANY signal's score reaches its category's block line, so the bit is an
//! OR over signals. PII entities, relevance rules and the mask summary
//! only choose between Allow, Log and Mask and never matter here.
//! The stream stops at its first Block, so when line `k` is decided,
//! `P_{k-1}` did not block: only a blocking signal that `P_{k-1}` did not
//! have can make `P_k` block (for the rule families whose signals can
//! only grow; the three whole-text features below are handled exactly on
//! their own).
//!
//! # Views are append-only line transforms
//!
//! The decision scans the raw text and every scan view of
//! `ScanViews::compute`. Each view of `P_k` is the view of `P_{k-1}`
//! with line `k`'s contribution appended, which is why every view can be
//! decided incrementally:
//!
//! - normalized: NFKC, invisible stripping and the confusable fold never
//!   cross a `\n` (the fold works per whitespace-delimited token), so the
//!   view is the concatenation of the normalized lines;
//! - base64 layers: a candidate is a run of base64 bytes, and `\n` is not
//!   one, so layer 1 is the decoded candidates of each normalized line,
//!   joined with `\n`, and layer `j + 1` the candidates of layer `j`'s
//!   tokens; a line adds `\n` plus its tokens;
//! - percent and character-reference views: an escape never contains a
//!   `\n`, so the decoded view is the per-line decoding (a line without
//!   an escape contributes its normalized text). The view exists once any
//!   line decodes; before that its text equals the normalized view, so
//!   scanning it anyway only repeats normalized-view results.
//!
//! The batch skips a view equal to the raw text and runs only the
//! non-markup rules on the character-reference view; both only remove
//! results the raw or normalized scan already has, so deciding every
//! view's window gives the same OR.
//!
//! # Rule families
//!
//! Every rule of `rule_battery`, plus `script_scheme_risk` on the
//! character-reference view, falls in one of these families (the regex
//! patterns were read one by one; `tests/stream_window_bounds.rs` pins
//! each bound on the real rules):
//!
//! 1. **Pattern rules** (`sql_risk`, `xss_risk`, `script_scheme_risk`,
//!    `path_traversal_risk`, the regex tiers of `command_injection_risk`,
//!    `template_injection_risk`, `nosql_injection_risk`, `xxe_risk`,
//!    `crlf_injection_risk`, `xpath_injection_risk`,
//!    `authority_impersonation_risk`, `tool_injection_risk`): the signal
//!    is the highest tier with ANY match, so blocking means "some pattern
//!    of a blocking tier matches somewhere". These patterns have no
//!    look-around and no `^`/`$` anchors (they run on the regex crate,
//!    which never fails at run time), and `\b` sees the same thing at a
//!    line start as after a `\n`. Hence a match ending in the old text is
//!    a match of `P_{k-1}` (it would have blocked already), a match in a
//!    window that starts at a line start is a match of `P_k`, and only a
//!    match ending in the new line's contribution matters. Such a match
//!    can start in the old text only through a part that crosses `\n`:
//!    - `\s` gaps (and `[\t\r\n]` in the script schemes): the old part
//!      then holds at most 12 whitespace-delimited tokens (the longest,
//!      the task-resume trailer of `tool_injection_risk`, has 13 tokens
//!      and its last one is in the new line); covered by
//!      [`REACH_TOKENS`] (one more token covers an old part that starts in
//!      whitespace, as the CRLF rules do);
//!    - bounded spans (`[\s\S]{0,80}`, `[^.]{0,40}`, `[^\n]{0,80}` after
//!      `\s`-separated words, `[^}]{1,50}`): the old part holds at most
//!      109 non-whitespace characters after its first token (the
//!      "important message ... to you" framing: 27 + 80 + 2); covered by
//!      [`REACH_NWS`] (the window is rounded down to a line start, so an
//!      unbounded first token such as `TUB\w+TAK` is inside it);
//!    - unbounded negated classes: `'\s*or\s*'[^']*'\s*=\s*'` and the
//!      XPath tautology hold at most three quotes in the old part and
//!      their first quote's line starts the match (window from the line of
//!      the third-last quote); `<\s*img\b[^>]*...` holds no `>` (window
//!      from the earliest `<\s*img\b` after the last `>`); `\$\([^)]+\)`
//!      no `)` (earliest `$(` after the last `)`); the `{{`, `${` and
//!      `#{` template patterns no `}` (earliest opener after the last
//!      `}`); the ERB patterns exactly the opener's `%` (the `<` before
//!      the last `%`). Each opener is tracked per view.
//!    - nothing else crosses a line: `.*` and `[^\n]` stop at it, and the
//!      URL and the whitespace-free patterns cannot hold one.
//! 2. **Secret rules** (`secrets_risk`): blocking means a candidate of a
//!    blocking score exists (overlap resolution always keeps the
//!    highest-score candidate). Three rules cross a line
//!    (`CREDENTIAL_ASSIGNMENT` and `BEARER_TOKEN` through `\s*` gaps, the
//!    AWS secret key through its `[=:\s]` separator; a PEM block only
//!    extends a single-line header's mask, never its existence or score).
//!    The first two filter their matches (placeholder values, code
//!    expressions), so the window must also start where the batch
//!    `find_iter` is in step: the secret window starts after the last line
//!    that does not end open ([`super::ends_open`]: no match of these
//!    rules contains a `\n` that follows such a line), which is the
//!    context the masking side already scans with.
//! 3. **Whole-text features**, decided exactly with their own state:
//!    - `obfuscation_risk` counts words over the whole collapsed text. It
//!      fires exactly when a word of its tables is revealed by a run of
//!      four or more single-character tokens (pairs: both words present
//!      in a multi-character token or such a run, one of them revealed);
//!      a revealed word guarantees the collapsed text is shorter, so its
//!      length gate never decides. Those facts only grow, and a run can
//!      span lines, so [`ObfTracker`] keeps the facts plus the run's last
//!      characters: constant memory.
//!    - the backtick check of `command_injection_risk` pairs backtick runs
//!      over the whole text (fences close at any later run, and the
//!      parity of the run count switches between sequential and adjacent
//!      pairing), so one stray backtick can make a span between two runs
//!      written a thousand lines earlier count. No window bounds that:
//!      exact evaluation needs state that grows with the number of
//!      backtick runs. This feature keeps text instead of a window: each
//!      view keeps its text from its first backtick on and re-runs the check on the
//!      lines that add a backtick (a line without one cannot change any
//!      run, pair or span).
//!    - `ENCODED_PII` signals of the escape views are suppressed when the
//!      value appears verbatim anywhere in the raw or normalized text, so
//!      a later line can remove one: exact evaluation needs the whole
//!      text. It only matters when `ENCODED_PII` can block (its signals
//!      score 0.35) or when the ML lane's L0 trigger reads it; only while
//!      that holds the whole text is kept for that feature.
//! 4. **Per-line signals**: PII engine errors (`SCAN_INCOMPLETE`) and
//!    base64-layer PII (`ENCODED_PII`) come from line-scoped scans of the
//!    line's view contributions, the URL rule is line-local, and the
//!    NER health signal is the line's own. The scans of the plain line
//!    only run while `SCAN_INCOMPLETE` can block; the decoded
//!    contributions (rare) are always scanned, and an earlier base64
//!    finding is carried as a signal of every later prefix.
//!
//! The state holds no configuration: the policy, its block lines and the
//! ML trigger are read at every line. The windows and the whole-text state
//! (character-splitting facts, backtick verdict, base64 finding) are kept
//! whatever the policy, so a reconfigured stream decides every later line
//! under the new configuration (`StreamingGuard` documents the equality
//! that holds then). The window is the minimum of the reaches above;
//! every reach only moves forward, so the retained text is the window.
//!
//! The Block event's rationale is built by the same `decide` over the
//! line's signals plus the strongest earlier signal of each kind: the
//! Block itself is exact, but when several categories block on one line,
//! or an earlier non-blocking signal outscores the blocking one, the
//! wording can name another signal than the whole-prefix decision (its
//! order and duplicate removal span the whole text, which a bounded
//! state does not keep).

use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::guard::normalize::{
    base64_candidates, decode_html_refs, normalize_for_scan, percent_decode_once, ViewKind,
    DECODE_DEPTH,
};
use crate::guard::rules::{
    backtick_shell_span, backtick_signal, encoded_pii_signals, is_collapse_separator,
    OBFUSCATION_PAIRS, OBFUSCATION_WORDS,
};
use crate::guard::{GuardSignal, SignalKind};
use crate::policy::{
    decide, retain_enabled, rule_battery_with, scan_incomplete_signal, signal_kind_to_category,
    Battery, Detector, PiiViews, Policy,
};

/// Whitespace-delimited tokens the window reaches back over (rule family
/// 1, `\s` gaps): the longest token-bounded pattern holds 13 tokens, so at
/// most 12 lie before the new line, plus one for an old part that starts
/// in whitespace, plus margin.
pub(super) const REACH_TOKENS: usize = 16;

/// Non-whitespace characters the window reaches back over (rule family 1,
/// bounded spans): at most 109 after the old part's first token, plus one,
/// plus margin.
pub(super) const REACH_NWS: usize = 128;

const _: () = assert!(13 < REACH_TOKENS && 109 < REACH_NWS);

/// The opener of `<\s*img\b[^>]*\bon\w+\s*=` (`xss_risk`).
static IMG_OPENER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<\s*img\b").expect("valid inline pattern"));

/// Number of views: raw, normalized, the base64 layers, percent,
/// character references.
const VIEWS: usize = 4 + DECODE_DEPTH;
const RAW: usize = 0;
const NORM: usize = 1;
const PCT: usize = 2 + DECODE_DEPTH;
const HTML: usize = 3 + DECODE_DEPTH;

/// The view a view equals until its first differing contribution
/// (normalized: the raw text; escape views: the normalized view).
const fn reference(view: usize) -> Option<usize> {
    match view {
        NORM => Some(RAW),
        PCT | HTML => Some(NORM),
        _ => None,
    }
}

/// Whether the markup rules run on `view` (all but the character-reference
/// view, as `ViewKind::runs_markup_rules`).
const fn markup(view: usize) -> bool {
    view != HTML
}

/// One completed line split into its view contributions.
struct LineViews {
    norm: String,
    /// Decoded, normalized base64 tokens per layer.
    layers: Vec<Vec<String>>,
    /// The re-normalized percent-decoded line, when an escape decoded.
    percent: Option<String>,
    /// The re-normalized character-reference-decoded line, when one decoded.
    html: Option<String>,
}

impl LineViews {
    fn new(line: &str) -> Self {
        let norm = normalize_for_scan(line);
        let mut layers: Vec<Vec<String>> = Vec::with_capacity(DECODE_DEPTH);
        let mut prev: Vec<String> = vec![norm.clone()];
        for _ in 0..DECODE_DEPTH {
            let layer: Vec<String> = prev
                .iter()
                .flat_map(|t| base64_candidates(t))
                .map(|c| normalize_for_scan(&c))
                .collect();
            prev.clone_from(&layer);
            layers.push(layer);
        }
        let percent = percent_decode_once(&norm).map(|d| normalize_for_scan(&d));
        let html = decode_html_refs(&norm).map(|d| normalize_for_scan(&d));
        Self {
            norm,
            layers,
            percent,
            html,
        }
    }

    /// The text `line` appends to `view` (`tokens` = tokens already in a
    /// base64 view); `None` when the view gains nothing.
    fn chunk(&self, line: &str, view: usize, tokens: usize) -> Option<String> {
        match view {
            RAW => Some(line.to_owned()),
            NORM => Some(self.norm.clone()),
            PCT => Some(self.percent.clone().unwrap_or_else(|| self.norm.clone())),
            HTML => Some(self.html.clone().unwrap_or_else(|| self.norm.clone())),
            layer => {
                let toks = &self.layers[layer - 2];
                if toks.is_empty() {
                    return None;
                }
                let mut out = String::new();
                for (i, t) in toks.iter().enumerate() {
                    if tokens + i > 0 {
                        out.push('\n');
                    }
                    out.push_str(t);
                }
                Some(out)
            }
        }
    }

    /// Whether the line's contribution to `view` differs from its
    /// reference view's contribution.
    fn differs(&self, line: &str, view: usize) -> bool {
        match view {
            NORM => self.norm != line,
            PCT => self.percent.as_ref().is_some_and(|p| *p != self.norm),
            HTML => self.html.as_ref().is_some_and(|h| *h != self.norm),
            _ => true,
        }
    }
}

/// The incremental form of `obfuscation_risk` over one view (see the
/// module docs, family 3): the word facts plus the open token and the
/// tail of the current single-character run.
#[derive(Debug, Clone, Default)]
pub(super) struct ObfTracker {
    /// Characters of the token being read (no separator yet).
    token: String,
    /// Lowercased tail of the current run of single-character tokens.
    run: String,
    /// Words present in the collapsed view (bit per [`obf_words`] entry).
    present: u32,
    /// Words revealed by a run of single-character tokens.
    revealed: u32,
}

/// Characters of a run kept: enough for the longest word (11 chars) plus
/// lowercase expansions.
const RUN_TAIL: usize = 16;

/// The distinct words of the obfuscation tables, in table order.
fn obf_words() -> &'static [&'static str] {
    static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        let mut words: Vec<&'static str> = Vec::new();
        for (a, b) in OBFUSCATION_PAIRS {
            for w in [*a, *b] {
                if !words.contains(&w) {
                    words.push(w);
                }
            }
        }
        for w in OBFUSCATION_WORDS {
            if !words.contains(w) {
                words.push(w);
            }
        }
        words
    });
    &WORDS
}

/// Bit of word `w` in the tracker's fact masks.
fn obf_bit(w: &str) -> u32 {
    obf_words()
        .iter()
        .position(|x| *x == w)
        .map_or(0, |i| 1u32 << i)
}

/// The fact mask of the words `s` contains.
fn obf_mask(s: &str) -> u32 {
    obf_words()
        .iter()
        .enumerate()
        .filter(|(_, w)| s.contains(**w))
        .fold(0, |m, (i, _)| m | (1u32 << i))
}

impl ObfTracker {
    /// Feeds the next text of the view.
    pub(super) fn feed(&mut self, text: &str) {
        for c in text.chars() {
            if is_collapse_separator(c) {
                let token = std::mem::take(&mut self.token);
                self.close(&token);
            } else {
                self.token.push(c);
            }
        }
    }

    /// Ends one token (`char_collapse`'s split item).
    fn close(&mut self, token: &str) {
        let mut chars = token.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => {
                self.run.extend(c.to_lowercase());
                let keep = self.run.chars().count().saturating_sub(RUN_TAIL);
                if keep > 0 {
                    let cut = self.run.char_indices().nth(keep).map_or(0, |(i, _)| i);
                    self.run.drain(..cut);
                }
                let m = obf_mask(&self.run);
                self.present |= m;
                self.revealed |= m;
            }
            _ => {
                // a multi-character (or empty) token ends the run
                self.run.clear();
                if !token.is_empty() {
                    self.present |= obf_mask(&token.to_lowercase());
                }
            }
        }
    }

    /// Whether `obfuscation_risk` fires on the view text fed so far (the
    /// open token read as the last one).
    pub(super) fn fires(&self) -> bool {
        let (present, revealed) = if self.token.is_empty() {
            (self.present, self.revealed)
        } else {
            let mut end = self.clone();
            let token = std::mem::take(&mut end.token);
            end.close(&token);
            (end.present, end.revealed)
        };
        let has = |m: u32, w: &str| m & obf_bit(w) != 0;
        OBFUSCATION_PAIRS.iter().any(|(a, b)| {
            has(present, a) && has(present, b) && (has(revealed, a) || has(revealed, b))
        }) || OBFUSCATION_WORDS.iter().any(|w| has(revealed, w))
    }
}

/// The window state of one view.
#[derive(Debug, Clone, Default)]
struct ViewState {
    /// The retained text: the view from absolute offset `base` on.
    buf: String,
    base: usize,
    /// Base64 views: tokens appended so far (the `\n` join).
    tokens: usize,
    /// Absolute offsets of the last three `'`.
    quotes: Vec<usize>,
    last_gt: Option<usize>,
    last_rparen: Option<usize>,
    last_rbrace: Option<usize>,
    last_pct: Option<usize>,
    /// Absolute start of the open secret context (valid while `ctx_open`).
    ctx: usize,
    ctx_open: bool,
    obf: ObfTracker,
    /// The view from its first backtick on (kept text, see module docs).
    backticks: Option<String>,
    /// The backtick verdict on that text (re-checked when a backtick
    /// arrives).
    backtick_hit: Option<GuardSignal>,
}

/// The two windows of one line in one view (offsets into `buf`).
struct Windows {
    rules: usize,
    secrets: usize,
    /// The chunk starts with the `\n` that joins it to a base64 view's
    /// previous token.
    joined: bool,
}

impl ViewState {
    fn end(&self) -> usize {
        self.base + self.buf.len()
    }

    /// The start of the line of `buf` holding relative offset `at`.
    fn line_start(&self, at: usize) -> usize {
        self.buf[..at].rfind('\n').map_or(0, |p| p + 1)
    }

    /// Relative offset of the absolute `at`, clamped into the buffer.
    fn rel(&self, at: usize) -> usize {
        at.saturating_sub(self.base).min(self.buf.len())
    }

    /// Appends `chunk` and returns the windows of the new contribution
    /// (module docs, families 1 and 2).
    fn push(&mut self, chunk: &str, tokens_added: usize, joined: bool) -> Windows {
        let old = self.buf.len();
        let mut start = reach_tokens(&self.buf, REACH_TOKENS).min(reach_nws(&self.buf, REACH_NWS));
        if let Some(&q) = self.quotes.first() {
            start = start.min(self.line_start(self.rel(q)));
        }
        let after = |x: Option<usize>| x.map_or(0, |x| x + 1);
        let from = self.rel(after(self.last_rparen));
        if let Some(p) = self.buf[from..old].find("$(") {
            start = start.min(self.line_start(from + p));
        }
        let from = self.rel(after(self.last_rbrace));
        if let Some(p) = ["{{", "${", "#{"]
            .iter()
            .filter_map(|o| self.buf[from..old].find(o))
            .min()
        {
            start = start.min(self.line_start(from + p));
        }
        if let Some(p) = self.last_pct {
            let p = self.rel(p);
            if p > 0 && self.buf.as_bytes()[p - 1] == b'<' {
                start = start.min(self.line_start(p - 1));
            }
        }
        let img_from = self.rel(after(self.last_gt));
        let secrets = if self.ctx_open {
            self.rel(self.ctx)
        } else {
            old
        };

        let at = self.end();
        self.buf.push_str(chunk);
        self.tokens += tokens_added;
        for (i, b) in chunk.bytes().enumerate() {
            let p = at + i;
            match b {
                b'\'' => {
                    if self.quotes.len() == 3 {
                        self.quotes.remove(0);
                    }
                    self.quotes.push(p);
                }
                b'>' => self.last_gt = Some(p),
                b')' => self.last_rparen = Some(p),
                b'}' => self.last_rbrace = Some(p),
                b'%' => self.last_pct = Some(p),
                _ => {}
            }
        }
        // an `<img` opener may start in the old text and end in the chunk
        if self.buf[img_from..old].contains('<') {
            if let Ok(Some(m)) = IMG_OPENER.find(&self.buf[img_from..]) {
                if img_from + m.start() < old {
                    start = start.min(self.line_start(img_from + m.start()));
                }
            }
        }
        Windows {
            rules: start,
            secrets,
            joined,
        }
    }

    /// After the line's scans: advances the secret context over the
    /// chunk's lines and drops text no later window can reach.
    fn settle(&mut self, chunk: &str, windows: &Windows) {
        let mut at = self.end() - chunk.len();
        let mut pieces: Vec<&str> = chunk.split('\n').collect();
        if chunk.ends_with('\n') {
            pieces.pop();
        }
        if windows.joined && !pieces.is_empty() {
            // the `\n` that ends the previous (already judged) token line
            pieces.remove(0);
            at += 1;
        }
        for piece in pieces {
            if super::ends_open(piece, self.ctx_open) {
                if !self.ctx_open {
                    self.ctx = at;
                    self.ctx_open = true;
                }
            } else {
                self.ctx_open = false;
            }
            at += piece.len() + 1;
        }
        let keep = windows.rules.min(windows.secrets).min(if self.ctx_open {
            self.rel(self.ctx)
        } else {
            self.buf.len()
        });
        // amortized: drop the dead prefix once it dominates the buffer
        if keep > 0 && keep * 2 >= self.buf.len() {
            self.buf.drain(..keep);
            self.base += keep;
        }
    }
}

/// Start of the line holding the `n`-th last whitespace-delimited token
/// of `text` (0 when `text` has fewer tokens).
fn reach_tokens(text: &str, n: usize) -> usize {
    let mut count = 0;
    let mut token_start: Option<usize> = None;
    for (i, c) in text.char_indices().rev() {
        if c.is_whitespace() {
            if let Some(start) = token_start.take() {
                count += 1;
                if count == n {
                    return text[..start].rfind('\n').map_or(0, |p| p + 1);
                }
            }
        } else {
            token_start = Some(i);
        }
    }
    0
}

/// Start of the line holding the `n`-th last non-whitespace character of
/// `text` (0 when `text` has fewer).
fn reach_nws(text: &str, n: usize) -> usize {
    let mut count = 0;
    for (i, c) in text.char_indices().rev() {
        if !c.is_whitespace() {
            count += 1;
            if count == n {
                return text[..i].rfind('\n').map_or(0, |p| p + 1);
            }
        }
    }
    0
}

/// Whether the signal `kind`, at most `top`, can block under `policy`.
fn can_block(policy: &Policy, kind: SignalKind, top: f32) -> bool {
    let category = signal_kind_to_category(kind);
    policy.is_enabled(category) && top >= policy.block_line_for(category)
}

/// The incremental decision state of one stream. It holds no
/// configuration: the policy and the ML trigger are read at every line, so
/// a reconfigured guard decides every later line under its new
/// configuration (see `StreamingGuard`'s docs for the equality that holds
/// then).
#[derive(Debug)]
pub(super) struct PrefixDecider {
    /// `None` while the view equals its reference view.
    views: Vec<Option<ViewState>>,
    /// The raw and normalized text since escape-view PII became decisive
    /// (`ENCODED_PII` can block, or the ML lane reads the L0 trigger);
    /// `None` while it is not.
    history: Option<(String, String)>,
    /// Escape-view PII values not (yet) visible in the plain text.
    hidden: Vec<String>,
    /// A base64 layer held PII (an `ENCODED_PII` signal stays forever).
    encoded_base64: bool,
    /// The strongest signal of each kind seen so far (rationale only).
    best: Vec<GuardSignal>,
}

/// The verdict on one line.
pub(super) struct Verdict {
    /// The Block rationale, when the prefix blocks.
    pub(super) block: Option<String>,
    /// Whether the prefix decision holds an obfuscation or encoded-PII
    /// signal (the ML lane's L0 trigger).
    pub(super) l0_trigger: bool,
}

impl Default for PrefixDecider {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixDecider {
    /// A decider for a new stream.
    pub(super) fn new() -> Self {
        let mut views: Vec<Option<ViewState>> = vec![None; VIEWS];
        for (i, v) in views.iter_mut().enumerate() {
            if reference(i).is_none() {
                *v = Some(ViewState::default());
            }
        }
        Self {
            views,
            history: None,
            hidden: Vec::new(),
            encoded_base64: false,
            best: Vec::new(),
        }
    }

    /// The view whose state `view` currently equals (itself, or the
    /// nearest reference with a state of its own).
    fn materialized(&self, view: usize) -> usize {
        match (&self.views[view], reference(view)) {
            (None, Some(r)) => self.materialized(r),
            _ => view,
        }
    }

    /// The state `view` currently equals (its own, or its reference's).
    fn state(&self, view: usize) -> &ViewState {
        match (&self.views[view], reference(view)) {
            (Some(s), _) => s,
            (None, Some(r)) => self.state(r),
            (None, None) => unreachable!("a view without a reference always has its own state"),
        }
    }

    /// Decides the prefix extended with `line` (one completed line, its
    /// `\n` included, or the stream's last text). `detector` is the
    /// decision's PII detector (no normalization pass); `extra` are the
    /// line's own signals (NER health); `policy` is the stream's current
    /// policy (adapted to the target) and `ml_trigger` whether the ML lane
    /// currently reads the L0 trigger.
    pub(super) fn push_line(
        &mut self,
        line: &str,
        detector: &Detector<'_>,
        extra: Vec<GuardSignal>,
        policy: &Policy,
        ml_trigger: bool,
    ) -> Verdict {
        let lv = LineViews::new(line);
        // a view that starts to differ from its reference takes over the
        // reference's state as of the end of the previous line
        for view in 0..VIEWS {
            if self.views[view].is_none() && lv.differs(line, view) {
                let own = self.state(view).clone();
                self.views[view] = Some(own);
            }
        }
        let mut signals: Vec<GuardSignal> = Vec::new();
        let mut windows: Vec<Option<(usize, Windows, String)>> = Vec::with_capacity(VIEWS);
        for view in 0..VIEWS {
            let Some(state) = self.views[view].as_mut() else {
                windows.push(None);
                continue;
            };
            let Some(chunk) = lv.chunk(line, view, state.tokens) else {
                windows.push(None);
                continue;
            };
            let added = if (2..PCT).contains(&view) {
                lv.layers[view - 2].len()
            } else {
                0
            };
            let joined = added > 0 && state.tokens > 0;
            let w = state.push(&chunk, added, joined);
            windows.push(Some((view, w, chunk)));
        }
        for entry in &windows {
            let Some((view, w, _)) = entry else {
                continue;
            };
            let state = self.views[*view].as_ref().expect("pushed view has a state");
            let rules = &state.buf[w.rules..];
            let secrets = &state.buf[w.secrets..];
            // a window equal to its reference view's window repeats its
            // results (the character-reference view runs a subset)
            let same = reference(*view).is_some_and(|r| {
                let r = self.materialized(r);
                windows
                    .iter()
                    .flatten()
                    .find(|(v, _, _)| *v == r)
                    .is_some_and(|(_, rw, _)| {
                        let rs = self.state(r);
                        rs.buf[rw.rules..] == *rules && rs.buf[rw.secrets..] == *secrets
                    })
            });
            if !same {
                signals.extend(rule_battery_with(
                    rules,
                    markup(*view),
                    Vec::new(),
                    Battery::WINDOW,
                ));
                if !markup(*view) {
                    signals.extend(crate::guard::script_scheme_risk(rules));
                }
                signals.extend(crate::guard::secrets_risk(secrets));
            }
        }
        self.whole_text_features(&windows, &mut signals);
        self.line_pii(&lv, line, detector, policy, ml_trigger, &mut signals);
        signals.extend(extra);
        retain_enabled(&mut signals, policy);

        let blocks = signals
            .iter()
            .any(|s| s.score >= policy.block_line_for(signal_kind_to_category(s.kind)));
        let block = blocks.then(|| {
            let mut all = self.best.clone();
            retain_enabled(&mut all, policy);
            all.extend(signals.iter().cloned());
            decide(&all, &[], policy).rationale
        });
        let enabled = |kind: SignalKind| policy.is_enabled(signal_kind_to_category(kind));
        let l0_trigger = signals.iter().any(|s| s.kind == SignalKind::Obfuscation)
            || (enabled(SignalKind::EncodedPii)
                && (self.encoded_base64 || !self.hidden.is_empty()));
        for s in signals {
            match self.best.iter_mut().find(|b| b.kind == s.kind) {
                Some(b) if s.score >= b.score => *b = s,
                Some(_) => {}
                None => self.best.push(s),
            }
        }
        for entry in windows.into_iter().flatten() {
            let (view, w, chunk) = entry;
            if let Some(state) = self.views[view].as_mut() {
                state.settle(&chunk, &w);
            }
        }
        Verdict { block, l0_trigger }
    }

    /// The obfuscation and backtick signals of the prefix (module docs,
    /// family 3).
    fn whole_text_features(
        &mut self,
        windows: &[Option<(usize, Windows, String)>],
        signals: &mut Vec<GuardSignal>,
    ) {
        for (view, _, chunk) in windows.iter().flatten() {
            let Some(state) = self.views[*view].as_mut() else {
                continue;
            };
            // always tracked, whatever the policy: their state spans the
            // whole stream, so a later configuration may need it
            state.obf.feed(chunk);
            if state.obf.fires() {
                signals.push(GuardSignal {
                    kind: SignalKind::Obfuscation,
                    score: 0.5,
                    evidence: String::new(),
                    rationale: "character-split trick (whole stream)".to_owned(),
                });
            }
            match state.backticks.as_mut() {
                Some(text) => text.push_str(chunk),
                None => {
                    if let Some(p) = chunk.find('`') {
                        state.backticks = Some(chunk[p..].to_owned());
                    }
                }
            }
            // a line without a backtick changes no run, pair or span: the
            // last verdict stands
            if chunk.contains('`') {
                state.backtick_hit = state
                    .backticks
                    .as_deref()
                    .and_then(backtick_shell_span)
                    .map(backtick_signal);
            }
            signals.extend(state.backtick_hit.clone());
        }
    }

    /// The line's PII-derived signals: engine errors of its view scans and
    /// PII inside its decoded contributions (module docs, families 3, 4).
    fn line_pii(
        &mut self,
        lv: &LineViews,
        line: &str,
        detector: &Detector<'_>,
        policy: &Policy,
        ml_trigger: bool,
        signals: &mut Vec<GuardSignal>,
    ) {
        let scan_errors = can_block(policy, SignalKind::ScanIncomplete, 0.4);
        let escapes = can_block(policy, SignalKind::EncodedPii, 0.35)
            || (ml_trigger && policy.is_enabled(signal_kind_to_category(SignalKind::EncodedPii)));
        if !escapes {
            self.history = None;
            self.hidden.clear();
        } else if self.history.is_none() {
            self.history = Some((String::new(), String::new()));
        }
        let mut pii = PiiViews {
            raw: Vec::new(),
            normalized: Vec::new(),
            decoded: Vec::new(),
            engine_errors: 0,
            first_incomplete_line: None,
        };
        // the plain line's scans only matter for their engine errors
        if scan_errors {
            let report = detector.scan(line);
            pii.record_health(line, &report);
            if lv.norm != line {
                let report = detector.scan(&lv.norm);
                pii.record_health(&lv.norm, &report);
            }
        }
        for (j, layer) in lv.layers.iter().enumerate() {
            for token in layer {
                let report = detector.scan(token);
                pii.record_health(token, &report);
                let depth = u8::try_from(j + 1).unwrap_or(u8::MAX);
                pii.decoded
                    .push((ViewKind::Base64 { depth }, report.entities));
            }
        }
        for (kind, view) in [(ViewKind::Percent, &lv.percent), (ViewKind::Html, &lv.html)] {
            if let Some(text) = view.as_deref().filter(|t| *t != lv.norm) {
                let report = detector.scan(text);
                pii.record_health(text, &report);
                pii.decoded.push((kind, report.entities));
            }
        }
        if scan_errors {
            signals.extend(scan_incomplete_signal(&pii));
        }
        // base64-layer PII always counts (no plain-text check), so it is
        // tracked whatever the policy; decoded tokens are rare, the scan
        // costs nothing on plain lines
        for (kind, ents) in &pii.decoded {
            if matches!(kind, ViewKind::Base64 { .. }) {
                self.encoded_base64 |= !ents.is_empty();
            }
        }
        let base64 = pii
            .decoded
            .iter()
            .filter(|(k, _)| matches!(k, ViewKind::Base64 { .. }))
            .map(|(k, e)| (*k, e.as_slice()));
        signals.extend(encoded_pii_signals("", "", base64));
        if self.encoded_base64 {
            // an earlier base64 finding stays in every later prefix
            signals.push(GuardSignal {
                kind: SignalKind::EncodedPii,
                score: 0.35,
                evidence: String::new(),
                rationale: "PII finding inside a base64 layer (earlier in the stream)".to_owned(),
            });
        }
        // escape-view PII is suppressed by a plain copy anywhere in the
        // text: decided against the history kept while it is decisive
        if let Some((raw, norm)) = self.history.as_mut() {
            raw.push_str(line);
            norm.push_str(&lv.norm);
            self.hidden
                .retain(|v| !line.contains(v.as_str()) && !lv.norm.contains(v.as_str()));
            let escape: Vec<(ViewKind, &[crate::pii::Entity])> = pii
                .decoded
                .iter()
                .filter(|(k, _)| !matches!(k, ViewKind::Base64 { .. }))
                .map(|(k, e)| (*k, e.as_slice()))
                .collect();
            for (_, ents) in &escape {
                for e in ents.iter() {
                    if !raw.contains(e.text.as_str()) && !norm.contains(e.text.as_str()) {
                        self.hidden.push(e.text.clone());
                    }
                }
            }
            signals.extend(encoded_pii_signals(raw, norm, escape));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{reach_nws, reach_tokens, ObfTracker};
    use crate::guard::obfuscation_risk;

    /// Deterministic pseudo-random texts over the obfuscation alphabet.
    fn texts() -> Vec<String> {
        const PARTS: &[&str] = &[
            "d",
            "r",
            "o",
            "p",
            "t",
            "a",
            "b",
            "l",
            "e",
            "drop",
            "table",
            "union",
            "select",
            "x",
            "D",
            "R",
            "O",
            "P",
            "\u{130}",
            "j",
            "v",
            "s",
            "c",
            "i",
            ":",
            "<",
            "n",
            "javascript:",
            "onerror",
            "from",
            "delete",
            "insert",
            "into",
            "f",
            "m",
            "_",
            "xp_cmdshell",
            "word",
            "d r o p",
            "t a b l e",
            "o n e r r o r",
            "j a v a s c r i p t :",
            "D.R.O.P",
            "u-n-i-o-n",
            "s e l e c t",
            "i n t o",
            "x p _ c m d s h e l l",
            "< s c r i p t",
            "d\nr\no\np",
        ];
        const SEPS: &[&str] = &[" ", "\n", ".", "-", "  ", "\n\n", "", " - ", "\t"];
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % n as u64).unwrap_or(0)
        };
        (0..4000)
            .map(|_| {
                let len = 1 + next(40);
                let mut s = String::new();
                for _ in 0..len {
                    s.push_str(PARTS[next(PARTS.len())]);
                    s.push_str(SEPS[next(SEPS.len())]);
                }
                s
            })
            .collect()
    }

    #[test]
    fn obfuscation_tracker_equals_the_whole_text_rule_at_every_chunking() {
        let mut fired = 0;
        for text in texts() {
            let expected = obfuscation_risk(&text).is_some();
            fired += usize::from(expected);
            // whole text, line by line, and char by char
            let mut whole = ObfTracker::default();
            whole.feed(&text);
            assert_eq!(whole.fires(), expected, "{text:?}");
            let mut by_line = ObfTracker::default();
            for line in text.split_inclusive('\n') {
                by_line.feed(line);
            }
            assert_eq!(by_line.fires(), expected, "{text:?}");
            let mut by_char = ObfTracker::default();
            let mut prefix = String::new();
            for c in text.chars() {
                by_char.feed(c.encode_utf8(&mut [0; 4]));
                prefix.push(c);
                assert_eq!(
                    by_char.fires(),
                    obfuscation_risk(&prefix).is_some(),
                    "{prefix:?}"
                );
            }
        }
        assert!(fired > 100, "the generator must exercise the rule: {fired}");
    }

    #[test]
    fn reaches_count_tokens_and_characters_from_the_end() {
        let text = "a b\nc d e\n\n f\n";
        assert_eq!(reach_tokens(text, 1), 11);
        assert_eq!(reach_tokens(text, 2), 4);
        assert_eq!(reach_tokens(text, 4), 4);
        assert_eq!(reach_tokens(text, 5), 0);
        assert_eq!(reach_tokens(text, 9), 0);
        assert_eq!(reach_nws(text, 1), 11);
        assert_eq!(reach_nws(text, 3), 4);
        assert_eq!(reach_nws(text, 6), 0);
    }
}
