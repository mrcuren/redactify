//! UK UTR (Unique Taxpayer Reference): format + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. HMRC design pattern: "10 digit number" (format only).
//! 2. OECD UK TIN sheet: UTR = 10 numerals, no check digit algorithm
//!    published.
//!
//! The checksum algorithm is NOT publicly documented (HMRC FOI refused;
//! an independent public implementation is single-source and NOT trusted).
//! Format + RequiredCue only (NINO precedent).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a UTR candidate claimable. "utr" is delimited
/// (`utr:`, `utr ` ...): bare, it is a substring of "nutrition",
/// "neutral" and the French "autre".
pub(super) const CUES: &[&str] = &[
    "utr:",
    "utr ",
    "utr#",
    "utr-",
    "(utr)",
    "tax reference",
    "self assessment",
    "hmrc",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UkUtr,
        r"(?<!\d)K?\d{10}(?!\d)",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod utr_tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn utr_detected_with_cue() {
        let ents = engine_detect("UTR 1234567890 on file", &["uk"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::UkUtr), "{ents:?}");
        // without cue: not claimed
        let ents = engine_detect("ref 1234567890", &["uk"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::UkUtr),
            "{ents:?}"
        );
    }
}
