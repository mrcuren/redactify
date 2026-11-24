//! Detection rule model shared by every locale.
//!
//! A rule bundles everything needed to claim a PII span: the regex that produces
//! candidates, an optional checksum/structure validator, the context-cue policy
//! and the base confidence score. Locales (`locales/tr`, `locales/en`, ...)
//! define rules; the engine (`detect.rs`) runs every active rule through the
//! same generic pipeline, so adding a locale never duplicates engine code.
//!
//! Backtrack budget: every detection regex (built-in and custom) is
//! compiled with an explicit [`BACKTRACK_LIMIT`]. The value equals the
//! default of the regex engine (`RegexBuilder::backtrack_limit`, "Default
//! is `1_000_000`" - fancy-regex 0.20.0 API documentation,
//! <https://docs.rs/fancy-regex/0.20.0/fancy_regex/struct.RegexBuilder.html#method.backtrack_limit>,
//! retrieved 2026-10-29), so setting it explicitly changes no result; it
//! only makes the budget visible. When a match attempt exceeds it the
//! engine returns a runtime error instead of a match, which the detection
//! engine counts as an incomplete scan of that line.

use crate::pii::entity::EntityType;
use fancy_regex::Regex;
use std::sync::LazyLock;

/// Backtracking step budget of every detection regex (see the module
/// docs: equal to the regex engine's own default).
pub(crate) const BACKTRACK_LIMIT: usize = 1_000_000;

/// Module-path prefix stripped from rule ids (`redactify::pii::locales::tr::tckn`
/// becomes `tr::tckn`).
const RULE_ID_PREFIX: &str = "redactify::pii::locales::";

/// The public rule id derived from a rule's `module_path!()`: the path
/// below the locale registry (e.g. `"tr::tckn"`).
pub(crate) fn rule_id(module_path: &'static str) -> &'static str {
    module_path
        .strip_prefix(RULE_ID_PREFIX)
        .unwrap_or(module_path)
}

/// How nearby context words interact with a candidate.
#[derive(Clone, Debug)]
pub(crate) enum ContextPolicy {
    /// No context handling.
    None,
    /// The candidate is only claimable when a cue appears nearby (used when the
    /// identifier has no checksum, e.g. VKN, passports).
    RequiredCue(&'static [&'static str]),
    /// The candidate stands alone at `Rule::score`; a nearby cue raises it to
    /// the policy's boosted value (plate-style confidence boosting).
    Boost(&'static [&'static str], f32),
}

/// A single detection rule.
pub(crate) struct Rule {
    /// Stable rule id reported by explanations (`"tr::tckn"`,
    /// `"generic::email"`; see [`rule_id`]).
    pub id: &'static str,
    /// Entity type produced by this rule.
    pub kind: EntityType,
    /// Candidate-producing pattern.
    pub regex: &'static LazyLock<Regex>,
    /// `None` -> every candidate passes (no checksum available).
    pub validator: Option<fn(&str) -> bool>,
    /// Context-cue policy for this rule.
    pub context: ContextPolicy,
    /// Base confidence score (see [`crate::Entity::score`] rationale).
    pub score: f32,
}

#[cfg(test)]
mod tests {
    use super::rule_id;

    #[test]
    fn rule_id_strips_the_registry_prefix() {
        assert_eq!(rule_id("redactify::pii::locales::tr::tckn"), "tr::tckn");
        assert_eq!(rule_id("redactify::pii::locales::iban"), "iban");
        // anything outside the registry keeps its full path
        assert_eq!(rule_id("other::path"), "other::path");
    }
}
