//! UK passport number: format + rule.
//!
//! Official source: HM Passport Office, "Basic passport checks" (GOV.UK
//! publication, last updated 28 January 2026,
//! <https://www.gov.uk/government/publications/basic-passport-checks>;
//! PDF `2025_BasicPassportChecks_1.1.pdf`,
//! <https://assets.publishing.service.gov.uk/media/6979d8b4128d9c1d09a98c73/2025_BasicPassportChecks_1.1.pdf>,
//! retrieved 2026-10-30, re-read 2026-10-31), section "Numbering" of each
//! design: "9 digits, printed on page 1" (the 1988 to 2015 designs), "9
//! numerical digits are: Printed on the inner front cover page" (2020,
//! series C) and "9 numerical digits printed on the inner front cover"
//! (2025, series D). The document publishes no check digit, so the rule
//! is nine digits next to a REQUIRED cue (score 0.9).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a UK passport candidate claimable.
pub(super) const CUES: &[&str] = &["passport", "pasaport", "travel document"];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UkPassport,
        r"(?<!\d)\d{9}(?!\d)",
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
    fn uk_passport_with_cue() {
        let ents = engine_detect("passport 123456789 valid", &["uk"]);
        assert!(
            ents.iter().any(|e| e.kind == EntityType::UkPassport),
            "{ents:?}"
        );
        let ents = engine_detect("ref 123456789", &["uk"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::UkPassport),
            "{ents:?}"
        );
    }
}
