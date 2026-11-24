//! German passport number (Reisepass 2010+): format + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. Wikipedia "German passport": 9 chars; position 1 from
//!    {C,F,G,H,J,K}; positions 2-9 from digits/letters in the ICAO
//!    subset (no I,O,Q; zero excluded in the strict form to avoid O/0
//!    confusion). Example: C3JJ4789L.
//! 2. A commercial DLP vendor's published sensitive-information-type
//!    definition "German Passport Number": 9-11 chars
//!    (9 printed + optional MRZ check digit + 'D'); checksum only in
//!    the MRZ (not on the printed number).
//!
//! Wikipedia-strict charset (position 2-9: [1-9A-HJ-NPR-Z], no 0)
//! used; cue required.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a DE passport candidate claimable. "Pass" is
/// delimited (`pass:`, `pass-`, `pass.` ...) or written as its compounds:
/// bare, "pass" is a substring of "Passwort" / "password", "passiert",
/// "passed" and the Italian "passaporto" (residual: words that end in
/// "pass" before a delimiter, e.g. "Kompass ", "bypass ").
pub(super) const CUES: &[&str] = &[
    "pass:",
    "pass ",
    "pass-",
    "pass.",
    "passnummer",
    "passnr",
    "reisepass",
    "passport",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DePassport,
        r"(?<![A-Z0-9])[CFGHJK][1-9A-HJ-NPR-Z]{8}(?![A-Z0-9])",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod passport_tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn de_passport_with_cue() {
        let ents = engine_detect("Reisepass C3JJ4789L", &["de"]);
        assert!(
            ents.iter().any(|e| e.kind == EntityType::DePassport),
            "{ents:?}"
        );
        // no cue, not claimed
        let ents = engine_detect("code C3JJ4789L", &["de"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::DePassport),
            "{ents:?}"
        );
    }
}
