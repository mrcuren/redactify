//! Opt-in, context-aware masking downgrades (relevance rules).
//!
//! A relevance rule encodes "this entity type is expected - and therefore not
//! masked - when the surrounding context says so": entity types plus a
//! context-cue condition evaluated in a byte window around the span (the
//! window never crosses a line break: batch and stream decide alike). Rules
//! only ever loosen masking for matching entities; they never touch `Block`
//! decisions from danger signals, never raise scores, and the default (empty)
//! policy is a byte-identical no-op. See `docs/relevance.md` for the full
//! semantics, the TOML schema, and the security notes.
//!
//! Relevance rules are deliberately rule-expert: deterministic substring cues over a
//! char-boundary-snapped window, no model calls, no session state.

use crate::pii::{Entity, EntityType};

/// Default context window (bytes, symmetric around the entity span).
pub const DEFAULT_WINDOW: usize = 64;

/// One downgrade rule: entity types + a context-cue condition.
///
/// A rule fires for an entity when (a) its [`EntityType`] is listed and (b)
/// the context window around the span satisfies the cue condition: at least
/// one of `cue_any` (when non-empty) AND all of `cue_all`. At least one of
/// the two cue lists must be non-empty; the config layer rejects empty rules
/// (fail-closed) and [`RelevanceRule::new`] enforces the same invariant for
/// programmatic construction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RelevanceRule {
    /// Entity types this rule applies to.
    pub entity_types: Vec<EntityType>,
    /// At least one of these cues must appear in the window (empty = no
    /// any-of requirement).
    pub cue_any: Vec<String>,
    /// All of these cues must appear in the window (empty = no all-of
    /// requirement).
    pub cue_all: Vec<String>,
    /// Symmetric context window in bytes around the entity span, clipped to
    /// the span's line (it never crosses a line break) and snapped to UTF-8
    /// char boundaries.
    pub window: usize,
}

impl RelevanceRule {
    /// Builds a rule, validating the one structural invariant: at least one
    /// cue list non-empty. Returns `None` for a rule that could never fire
    /// (surfaces as a config/programming error at the call sites).
    #[must_use]
    pub fn new(
        entity_types: Vec<EntityType>,
        cue_any: Vec<String>,
        cue_all: Vec<String>,
        window: usize,
    ) -> Option<Self> {
        if cue_any.is_empty() && cue_all.is_empty() {
            return None;
        }
        Some(Self {
            entity_types,
            cue_any,
            cue_all,
            window,
        })
    }

    /// Does this rule fire for `kind` at `[start, end)` in `text`?
    fn fires(&self, text: &str, kind: EntityType, start: usize, end: usize) -> bool {
        if !self.entity_types.contains(&kind) {
            return false;
        }
        // cue-less rules must never fire: the fields are pub, so struct
        // construction bypasses the `RelevanceRule::new` guard, and an
        // empty-cue rule would unmask every entity of its types wholesale
        // (the TOML layer rejects this shape too)
        if self.cue_any.is_empty() && self.cue_all.is_empty() {
            return false;
        }
        let ctx = window_slice(text, start, end, self.window);
        let ctx = lowercase(ctx);
        if !self.cue_any.is_empty() && !self.cue_any.iter().any(|c| ctx.contains(&lowercase(c))) {
            return false;
        }
        self.cue_all.iter().all(|c| ctx.contains(&lowercase(c)))
    }
}

/// An ordered rule set; rules are evaluated in order and the first match
/// downgrades the entity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RelevancePolicy {
    /// Rules in evaluation order.
    pub rules: Vec<RelevanceRule>,
}

/// A downgraded entity as reported on a [`crate::policy::Decision`]: entity
/// type + span, deliberately WITHOUT the raw value - decisions never echo
/// PII values (same contract as the REST API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct DowngradedSpan {
    /// Entity type that was relevance-downgraded.
    pub kind: EntityType,
    /// Span start (byte offset into the decision-time text, inclusive).
    pub start: usize,
    /// Span end (byte offset, exclusive).
    pub end: usize,
}

impl RelevancePolicy {
    /// True when no rules are configured (the default: no-op).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Splits `entities` into `(masked, downgraded)`: entities for which a
    /// rule fires are **downgraded** (they stay in the text, unmasked); the
    /// rest belong to `masked`. Relative order is preserved in both halves.
    #[must_use]
    pub fn partition<'a>(
        &self,
        text: &str,
        entities: &'a [Entity],
    ) -> (Vec<&'a Entity>, Vec<&'a Entity>) {
        let mut masked = Vec::with_capacity(entities.len());
        let mut downgraded = Vec::new();
        for e in entities {
            if self.matches(text, e.kind, e.start, e.end) {
                downgraded.push(e);
            } else {
                masked.push(e);
            }
        }
        (masked, downgraded)
    }

    /// True when some rule fires for `kind` at `[start, end)` in `text`.
    #[must_use]
    pub fn matches(&self, text: &str, kind: EntityType, start: usize, end: usize) -> bool {
        self.rules.iter().any(|r| r.fires(text, kind, start, end))
    }
}

/// Byte window around `[start, end)`, clipped to the span's line (a window
/// never crosses a `\n`, so a cue on a neighboring line does not count and
/// a stream that sees one line at a time decides exactly like the batch
/// path), then snapped inward to UTF-8 char boundaries.
fn window_slice(text: &str, start: usize, end: usize, window: usize) -> &str {
    let bytes = text.as_bytes();
    let start = start.min(text.len());
    let end = end.clamp(start, text.len());
    // the line break is searched within the window only (a break further
    // out cannot narrow it, and walking the whole line per entity made a
    // long line quadratic); `\n` is ASCII: a byte search never lands
    // inside a multibyte char
    let lo = start.saturating_sub(window);
    let hi = end.saturating_add(window).min(text.len());
    let lo = bytes[lo..start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(lo, |i| lo + i + 1);
    let hi = bytes[end..hi]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(hi, |i| end + i);
    if lo >= hi {
        return "";
    }
    let mut lo = lo;
    let mut hi = hi;
    while lo < text.len() && !text.is_char_boundary(lo) {
        lo += 1;
    }
    while hi > lo && !text.is_char_boundary(hi) {
        hi -= 1;
    }
    // Clamp to the valid slice (entity offsets are trusted to be in-bounds,
    // but a defensive clamp keeps malformed input from panicking).
    lo = lo.min(text.len());
    hi = hi.min(text.len());
    if lo >= hi {
        ""
    } else {
        &text[lo..hi]
    }
}

/// Unicode simple lowercase (std `char::to_lowercase`; no new deps). Turkish
/// `İ` lowercases to `i̇` (i + combining dot) - write Turkish cues lowercase.
fn lowercase(s: &str) -> String {
    s.chars().flat_map(char::to_lowercase).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(kind: EntityType, start: usize, end: usize) -> Entity {
        Entity {
            kind,
            start,
            end,
            text: String::new(),
            score: 0.9,
        }
    }

    fn phone_rule() -> RelevanceRule {
        RelevanceRule {
            entity_types: vec![EntityType::Phone],
            cue_any: vec!["call me at".into()],
            cue_all: vec![],
            window: DEFAULT_WINDOW,
        }
    }

    #[test]
    fn empty_policy_is_a_noop_partition() {
        let policy = RelevancePolicy::default();
        let text = "call me at 0505 186 48 37 please";
        let ents = [ent(EntityType::Phone, 11, 25)];
        let (masked, downgraded) = policy.partition(text, &ents);
        assert_eq!(masked.len(), 1);
        assert!(downgraded.is_empty());
    }

    #[test]
    fn cue_any_match_downgrades() {
        let policy = RelevancePolicy {
            rules: vec![phone_rule()],
        };
        let text = "please call me at 0505 186 48 37 today";
        let ents = [ent(EntityType::Phone, 18, 32)];
        let (masked, downgraded) = policy.partition(text, &ents);
        assert!(masked.is_empty());
        assert_eq!(downgraded.len(), 1);
    }

    #[test]
    fn no_cue_keeps_masking() {
        let policy = RelevancePolicy {
            rules: vec![phone_rule()],
        };
        let text = "the number 0505 186 48 37 leaked";
        let ents = [ent(EntityType::Phone, 11, 25)];
        let (masked, downgraded) = policy.partition(text, &ents);
        assert_eq!(masked.len(), 1);
        assert!(downgraded.is_empty());
    }

    #[test]
    fn other_entity_types_are_untouched() {
        let policy = RelevancePolicy {
            rules: vec![phone_rule()],
        };
        let text = "call me at john@example.com";
        let ents = [ent(EntityType::Email, 11, 28)];
        let (masked, downgraded) = policy.partition(text, &ents);
        assert_eq!(masked.len(), 1);
        assert!(downgraded.is_empty());
    }

    #[test]
    fn cue_window_boundary_is_respected() {
        // window 16, cue "call me at" occupies bytes 0..10: a span starting
        // exactly at byte 16 sees the whole cue; at byte 17 the cue's first
        // byte falls outside the window.
        let mut rule = phone_rule();
        rule.window = 16;
        let policy = RelevancePolicy { rules: vec![rule] };
        let cue_in = format!("call me at{}0505 186 48 37", " ".repeat(6)); // span at 16
        let span_start = cue_in.find("0505").unwrap();
        assert_eq!(span_start, 16);
        assert!(policy.matches(&cue_in, EntityType::Phone, span_start, span_start + 14));
        let cue_out = format!("call me at{}0505 186 48 37", " ".repeat(7)); // span at 17
        let span_start2 = cue_out.find("0505").unwrap();
        assert_eq!(span_start2, 17);
        assert!(!policy.matches(&cue_out, EntityType::Phone, span_start2, span_start2 + 14));
    }

    #[test]
    fn cue_all_requires_every_cue() {
        let rule = RelevanceRule {
            entity_types: vec![EntityType::Name],
            cue_any: vec![],
            cue_all: vec!["resume".into(), "attached".into()],
            window: 128,
        };
        let policy = RelevancePolicy { rules: vec![rule] };
        let both = "resume attached: Jane Doe";
        let start = both.find("Jane").unwrap();
        assert!(policy.matches(both, EntityType::Name, start, start + 8));
        let one = "resume: Jane Doe";
        let start2 = one.find("Jane").unwrap();
        assert!(!policy.matches(one, EntityType::Name, start2, start2 + 8));
    }

    #[test]
    fn multibyte_window_snaps_to_char_boundaries() {
        let policy = RelevancePolicy {
            rules: vec![phone_rule()],
        };
        // Turkish multibyte prefix pushes offsets onto non-boundaries; the
        // window must still slice cleanly (no panic) and find the cue.
        let text = "lütfen ara beni diye yazmıştı, call me at 0505 186 48 37";
        let start = text.find("0505").unwrap();
        assert!(policy.matches(text, EntityType::Phone, start, start + 14));
    }

    #[test]
    fn turkish_lowercase_cue_matches_uppercase_text() {
        let rule = RelevanceRule {
            entity_types: vec![EntityType::Phone],
            cue_any: vec!["ara beni".into()],
            cue_all: vec![],
            window: 64,
        };
        let policy = RelevancePolicy { rules: vec![rule] };
        let text = "lütfen ARA BENI diye yazmıştı: 0505 186 48 37";
        let start = text.find("0505").unwrap();
        assert!(policy.matches(text, EntityType::Phone, start, start + 14));
    }

    #[test]
    fn first_matching_rule_wins_and_order_is_stable() {
        let narrow = RelevanceRule {
            entity_types: vec![EntityType::Phone],
            cue_any: vec!["call me at".into()],
            cue_all: vec![],
            window: 8,
        };
        let policy = RelevancePolicy {
            rules: vec![narrow, phone_rule()],
        };
        let text = "call me at 0505 186 48 37";
        let ents = [ent(EntityType::Phone, 11, 25)];
        let (masked, downgraded) = policy.partition(text, &ents);
        // narrow rule's window (8) cannot reach the cue; the second rule
        // fires instead - still a downgrade.
        assert!(masked.is_empty());
        assert_eq!(downgraded.len(), 1);
    }

    #[test]
    fn rule_new_rejects_cueless_rules() {
        assert!(RelevanceRule::new(vec![EntityType::Phone], vec![], vec![], 64).is_none());
        assert!(
            RelevanceRule::new(vec![EntityType::Phone], vec!["x".into()], vec![], 64).is_some()
        );
    }

    #[test]
    fn zero_window_still_sees_the_span_text_itself() {
        let mut rule = phone_rule();
        rule.window = 0;
        let policy = RelevancePolicy { rules: vec![rule] };
        // window 0 slices [start, end): the entity's own bytes. "call me at"
        // is not inside the number, so no downgrade.
        let text = "call me at 0505 186 48 37";
        let start = text.find("0505").unwrap();
        assert!(!policy.matches(text, EntityType::Phone, start, start + 14));
    }

    #[test]
    fn window_never_crosses_a_line_break() {
        let policy = RelevancePolicy {
            rules: vec![phone_rule()],
        };
        // the cue sits well inside the 64-byte window, but on another line
        for text in [
            "call me at\n0505 186 48 37",
            "0505 186 48 37\ncall me at",
            "call me at\r\n0505 186 48 37 today",
        ] {
            let start = text.find("0505").unwrap();
            assert!(
                !policy.matches(text, EntityType::Phone, start, start + 14),
                "{text:?}"
            );
        }
        // same line, surrounded by other lines: still downgraded
        let text = "first line\ncall me at 0505 186 48 37\nlast line";
        let start = text.find("0505").unwrap();
        assert!(policy.matches(text, EntityType::Phone, start, start + 14));
        assert_eq!(
            window_slice(text, start, start + 14, 64),
            "call me at 0505 186 48 37"
        );
    }

    #[test]
    fn huge_window_and_out_of_range_spans_never_panic() {
        let text = "call me at 0505 186 48 37";
        let start = text.find("0505").unwrap();
        assert_eq!(window_slice(text, start, start + 14, usize::MAX), text);
        // a span past the end clamps to the text end
        assert!(text.ends_with(window_slice(text, 100, 200, 4)));
        assert_eq!(window_slice(text, 20, 5, 0), "");
    }

    /// The window is clipped to the span's line without walking the whole
    /// line (walking it costs entities x line length: 17.3 s on one line of
    /// 40,000 TCKNs with one TCKN relevance rule).
    #[test]
    fn a_long_line_costs_the_window_not_the_line() {
        let text = "TCKN 12345678950 ".repeat(10_000);
        let ents: Vec<Entity> = (0..10_000)
            .map(|i| ent(EntityType::Tckn, i * 17 + 5, i * 17 + 16))
            .collect();
        let policy = RelevancePolicy {
            rules: vec![RelevanceRule::new(
                vec![EntityType::Tckn],
                vec!["ornek".into()],
                vec![],
                40,
            )
            .unwrap()],
        };
        let started = std::time::Instant::now();
        let (masked, downgraded) = policy.partition(&text, &ents);
        let elapsed = started.elapsed();
        assert_eq!((masked.len(), downgraded.len()), (10_000, 0));
        assert!(elapsed.as_secs_f64() < 1.0, "took {elapsed:?}");
    }

    #[test]
    fn the_bounded_line_search_keeps_every_window() {
        // the window as the whole-line search computed it, for every span
        // and window size over lines of every length
        fn whole_line(text: &str, start: usize, end: usize, window: usize) -> &str {
            let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
            let line_end = text[end..].find('\n').map_or(text.len(), |i| end + i);
            let lo = start.saturating_sub(window).max(line_start);
            let hi = end.saturating_add(window).min(line_end);
            if lo >= hi {
                return "";
            }
            let (mut lo, mut hi) = (lo, hi);
            while lo < text.len() && !text.is_char_boundary(lo) {
                lo += 1;
            }
            while hi > lo && !text.is_char_boundary(hi) {
                hi -= 1;
            }
            if lo >= hi {
                ""
            } else {
                &text[lo..hi]
            }
        }
        let text = "ab\ncdé\n\nfghij k\nl";
        for start in 0..=text.len() {
            for end in start..=text.len() {
                if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
                    continue;
                }
                for window in 0..8 {
                    assert_eq!(
                        window_slice(text, start, end, window),
                        whole_line(text, start, end, window),
                        "{start}..{end} w{window}"
                    );
                }
            }
        }
    }
}
