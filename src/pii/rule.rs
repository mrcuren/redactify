//! Detection rule model shared by every locale.
//!
//! A rule bundles everything needed to claim a PII span: the regex that produces
//! candidates, an optional checksum/structure validator, the context-cue policy
//! and the base confidence score. Locales (`locales/tr`, `locales/en`, ...)
//! define rules; the engine (`detect.rs`) runs every active rule through the
//! same generic pipeline, so adding a locale never duplicates engine code.

use crate::pii::entity::EntityType;
use fancy_regex::Regex;
use std::sync::LazyLock;

/// How nearby context words interact with a candidate.
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
