//! US ZIP code: format + rule (5-digit, PLZ precedent).
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. USPS "ZIP Code Lookup" / addressing guide: 5-digit ZIP, range
//!    00001-99950 (00000 unassigned).
//! 2. Wikipedia "ZIP Code": same 5-digit format.
//!
//! No checksum; cue required (a bare 5-digit number is order-id noise).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a ZIP candidate claimable. "zip" is delimited
/// (`zip:`, `zip ` ...): bare, it is a substring of "zipped", "zipper" and
/// "zipping" (residual: "unzip " ends in a delimited form).
pub(super) const CUES: &[&str] = &[
    "zip:", "zip ", "zip#", "zip-", "zip/", "zip+", "(zip)", "postal", "zipcode", "postcode",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UsZip,
        r"(?<!\d)[0-9]{5}(?!\d)",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod zip_tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn zip_with_cue() {
        let ents = engine_detect("ZIP 90210", &["en"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::UsZip), "{ents:?}");
        let ents = engine_detect("ref 90210", &["en"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::UsZip),
            "{ents:?}"
        );
    }
}
