//! French postal code (code postal): format + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. La Poste: code postal = 5 digits (01000-99999 metropolitan;
//!    97xxx-98xxx overseas).
//! 2. Wikipedia "Postal codes in France": same 5-digit scheme.
//!
//! No checksum; cue required (DE PLZ precedent).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a code postal candidate claimable.
pub(super) const CUES: &[&str] = &["code postal", "postal", "cp", "adresse"];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::FrPostal,
        r"(?<!\d)0[1-9]\d{3}(?!\d)|(?<!\d)[1-8]\d{4}(?!\d)|(?<!\d)9[0-8]\d{3}(?!\d)",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod postal_tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn fr_postal_with_cue() {
        let ents = engine_detect("code postal 75001", &["fr"]);
        assert!(
            ents.iter().any(|e| e.kind == EntityType::FrPostal),
            "{ents:?}"
        );
        let ents = engine_detect("ref 75001", &["fr"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::FrPostal),
            "{ents:?}"
        );
    }
}
