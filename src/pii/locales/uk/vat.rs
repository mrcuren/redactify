//! UK VAT registration number: validator + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. Wikipedia "VAT identification number" (UK section): standard
//!    format GB + 9 digits, last 2 are check digits (range 00-96,
//!    weighted mod-97); alternative series uses check-55 and check-42.
//! 2. An independent public implementation (code reference): weights
//!    (8,7,6,5,4,3,2,10,1), sum mod 97, accepted residues 0/42/55.
//!
//! Cue REQUIRED: a random 9-digit number passes the mod-97 ~1/97 of
//! the time.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a UK VAT candidate claimable. "vat" and "gb" are
/// delimited (`vat:`, `gb ` ...): bare, "vat" is a substring of "private",
/// "motivation" and "innovative", "gb" of "LGBTQ" and the currency code
/// "GBP". "tax" stays bare: delimiting it would drop "taxes" and
/// "taxpayer" (residual: "syntax", "taxi").
pub(super) const CUES: &[&str] = &[
    "vat:",
    "vat ",
    "vat#",
    "vat-",
    "vat/",
    "(vat)",
    "gb:",
    "gb ",
    "gb-",
    "tax",
    "registration",
];

/// Returns `true` if `vat` is a checksum-valid UK VAT number (9 digits,
/// weighted mod-97 check digit at positions 8-9, with the 42/55
/// alternative series).
///
/// # Examples
/// ```
/// use redactify::valid_uk_vat;
/// assert!(valid_uk_vat("999999973")); // Wikipedia example
/// assert!(!valid_uk_vat("999999972")); // wrong check digit
/// assert!(!valid_uk_vat("123456789")); // wrong check digits
/// ```
#[must_use]
pub fn valid_uk_vat(vat: &str) -> bool {
    let cleaned: String = vat.chars().filter(|c| c.is_ascii_digit()).collect();
    let b = cleaned.as_bytes();
    if b.len() != 9 {
        return false;
    }
    // independent implementation's formulation: dot(weights, digits) mod 97 ∈ {0, 42, 55}
    const WEIGHTS: [u32; 9] = [8, 7, 6, 5, 4, 3, 2, 10, 1];
    let sum: u32 = b
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    matches!(sum % 97, 0 | 42 | 55)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UkVat,
        r"(?<!\d)GB[ ]?\d{3}[ ]?\d{4}[ ]?\d{2}(?!\d)|(?<!\d)\d{3}[ ]?\d{4}[ ]?\d{2}(?!\d)",
        Some(valid_uk_vat),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod vat_tests {
    use super::valid_uk_vat;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn vat_valid() {
        assert!(valid_uk_vat("999999973")); // Wikipedia
        assert!(valid_uk_vat("980780684")); // Wikipedia
        assert!(!valid_uk_vat("999999972"));
        assert!(!valid_uk_vat("123456789"));
    }

    #[test]
    fn vat_detected_with_cue() {
        let ents = engine_detect("VAT GB999 9999 73 registered", &["uk"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::UkVat), "{ents:?}");
        let ents2 = engine_detect("VAT 999 9999 73 here", &["uk"]);
        assert!(
            ents2.iter().any(|e| e.kind == EntityType::UkVat),
            "{ents2:?}"
        );
    }

    #[test]
    fn vat_without_cue_not_claimed() {
        let ents = engine_detect("ref 999 9999 73", &["uk"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::UkVat),
            "{ents:?}"
        );
    }
}
