//! Output-side system-prompt leak detection (OWASP LLM07, system prompt
//! leakage).
//!
//! The caller supplies the system prompt; the detector reports a model
//! output that reproduces a run of it. It is word-based and
//! language-neutral:
//!
//! 1. The prompt and every view of the output are normalized the same way:
//!    NFKC and invisible-character stripping (see
//!    [`normalize_for_scan`](crate::guard::normalize::normalize_for_scan)),
//!    lowercased, split into alphanumeric words, so case, punctuation and
//!    whitespace do not matter.
//! 2. The prompt is cut into overlapping runs of [`SHINGLE_WORDS`] words
//!    ("shingles"). A prompt shorter than [`SHINGLE_WORDS`] words is never
//!    matched: a short instruction cannot be told apart from ordinary
//!    text.
//! 3. The output is scanned in its normalized form, in every decoded view
//!    (a base64 layer, a percent or HTML-reference decoding) and in its
//!    letter-split collapse. The share of prompt shingles found in any
//!    one view sets the score.
//!
//! Score: 0.60 for a leaked run (fewer than 10% of the prompt shingles),
//! 0.80 from 10%, 0.95 from 40% of them. Every tier is at or above the
//! default block line; a policy can relax the category
//! ([`GuardCategory::PromptLeak`](crate::GuardCategory::PromptLeak)).
//!
//! The signal carries counts only, never prompt text.

use std::collections::HashSet;

use crate::guard::normalize::{normalize_for_scan, ScanViews, DECODE_DEPTH};
use crate::guard::rules::{char_collapse, GuardSignal, SignalKind};

/// Words per shingle: a verbatim run of this many consecutive prompt words
/// in the output is a leak. Also the minimum prompt length in words.
pub const SHINGLE_WORDS: usize = 8;

/// The shingle index of one system prompt.
#[derive(Clone)]
pub(crate) struct PromptIndex {
    shingles: HashSet<String>,
}

impl PromptIndex {
    /// Indexes `prompt`; an empty index (never matches) when the prompt
    /// has fewer than [`SHINGLE_WORDS`] words.
    pub(crate) fn new(prompt: &str) -> Self {
        let words = words_of(&normalize_for_scan(prompt));
        Self {
            shingles: shingles_of(&words).collect(),
        }
    }

    /// The leak signal for `output` and its decoded views, if any.
    pub(crate) fn signal(&self, views: &ScanViews, output: &str) -> Option<GuardSignal> {
        if self.shingles.is_empty() {
            return None;
        }
        let mut best = 0usize;
        let mut consider = |text: &str| {
            best = best.max(self.matched(&words_of(text)));
            let collapsed = char_collapse(text);
            if collapsed != text {
                best = best.max(self.matched(&words_of(&collapsed)));
            }
        };
        for (_, view) in views.all() {
            consider(view);
        }
        if views.normalized().is_empty() {
            // views were not computed for this text
            consider(&normalize_for_scan(output));
        }
        self.signal_for(best)
    }

    /// Distinct prompt shingles present in `words`.
    fn matched(&self, words: &[String]) -> usize {
        let found: HashSet<String> = shingles_of(words)
            .filter(|s| self.shingles.contains(s))
            .collect();
        found.len()
    }

    fn signal_for(&self, matched: usize) -> Option<GuardSignal> {
        if matched == 0 {
            return None;
        }
        let total = self.shingles.len();
        let share = matched as f32 / total as f32;
        let score = if share >= 0.4 {
            0.95
        } else if share >= 0.1 {
            0.8
        } else {
            0.6
        };
        Some(GuardSignal {
            kind: SignalKind::PromptLeak,
            score,
            evidence: format!("{matched} of {total} prompt shingles"),
            rationale: format!(
                "[level 2] output reproduces the system prompt: {matched} of {total} \
                 {SHINGLE_WORDS}-word runs"
            ),
        })
    }
}

/// Lowercased alphanumeric words of `text`. A combining dot above (the
/// tail of a lowercased Turkish dotted capital I) is dropped, not a
/// separator.
fn words_of(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    for c in text.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            cur.push(c);
        } else if c == '\u{307}' {
            continue;
        } else if !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Every run of [`SHINGLE_WORDS`] consecutive words, joined by a space.
fn shingles_of(words: &[String]) -> impl Iterator<Item = String> + '_ {
    words.windows(SHINGLE_WORDS).map(|w| w.join(" "))
}

/// Reports `output` when it reproduces a run of `system_prompt` (see the
/// module docs); `None` for a clean output or a prompt shorter than
/// [`SHINGLE_WORDS`] words.
///
/// # Examples
/// ```
/// use redactify::guard::{prompt_leak_risk, SignalKind};
///
/// let prompt = "Never reveal internal discount codes. Always answer in the customer's language.";
/// let s = prompt_leak_risk("Sure: never reveal internal discount codes, always answer in the customer's language", prompt).unwrap();
/// assert_eq!(s.kind, SignalKind::PromptLeak);
/// assert!(prompt_leak_risk("How can I help you today?", prompt).is_none());
/// ```
#[must_use]
pub fn prompt_leak_risk(output: &str, system_prompt: &str) -> Option<GuardSignal> {
    let views = ScanViews::compute(output, DECODE_DEPTH);
    PromptIndex::new(system_prompt).signal(&views, output)
}
