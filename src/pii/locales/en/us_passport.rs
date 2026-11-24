//! US passport number: detection rule (Next Generation format).
//!
//! Official source: U.S. Department of State, "Design and Security of our
//! Documents", section "Next Generation Passport"
//! (<https://travel.state.gov/en/passports/apply/help/security-design.html>,
//! retrieved 2026-10-30; the page answered 403 on a re-check on
//! 2026-10-31): "Another important feature is a
//! perforated alphanumeric passport number on every page, which is a letter
//! followed by 8 numbers".
//!
//! The rule takes exactly that shape (`[A-Z]` + 8 digits). No checksum
//! exists, so - like the Turkish passport rule - a nearby cue is
//! MANDATORY: a bare letter + 8 digits token is never claimed on its own.
//! The older all-numeric 9-digit form is not covered: no official source
//! for it was found, and a bare 9-digit run would collide
//! with order ids and other cue-gated identifiers.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Returns `true` if `s` matches the US passport Next Generation format
/// (one uppercase letter followed by exactly 8 digits).
#[must_use]
pub fn valid_us_passport(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 9 && b[0].is_ascii_uppercase() && b[1..].iter().all(u8::is_ascii_digit)
}

/// Cue words required to claim a candidate. Not `us` (a common English
/// pronoun); " states" carries a leading space because "states" is a
/// substring of "estates" (the label usage "United States" keeps the
/// space; "united" covers a line that starts with the country name).
pub(super) const CUES: &[&str] = &[
    "united",
    " states",
    "passport",
    "passport no",
    "passport number",
    "travel",
    "document",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UsPassport,
        r"(?<![A-Za-z0-9])[A-Z]\d{8}(?![A-Za-z0-9])",
        Some(valid_us_passport),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_us_passport;
    use crate::{detect, EntityType};

    #[test]
    fn format_vectors() {
        assert!(valid_us_passport("A12345678"));
        assert!(!valid_us_passport("a12345678")); // lowercase
        assert!(!valid_us_passport("A1234567")); // 7 digits
        assert!(!valid_us_passport("A123456789")); // 9 digits
        assert!(!valid_us_passport(""));
    }

    #[test]
    fn cue_required() {
        assert!(detect("US passport: A12345678")
            .iter()
            .any(|e| e.kind == EntityType::UsPassport));
        assert!(!detect("code A12345678 x")
            .iter()
            .any(|e| e.kind == EntityType::UsPassport));
    }
}
