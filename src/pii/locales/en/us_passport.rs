//! US passport number: detection rule (Next Generation format).
//!
//! Source of the pattern: the open-source industry PII analyzer (US passport
//! recognizer). Two patterns exist there: a bare 9-digit form (scored "very
//! weak") and the Next Generation `[A-Z][0-9]{8}` form (weak). Only the Next
//! Generation form is ported here, and - like the Turkish passport rule - a
//! nearby cue is MANDATORY: with no checksum, a bare letter+8-digits token must
//! not be claimed on its own. The 9-digit-only form is deliberately not ported
//! (it would collide with order IDs and card fragments).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Returns `true` if `s` matches the US passport Next Generation format
/// (one uppercase letter followed by exactly 8 digits).
#[must_use]
pub fn valid_us_passport(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 9 && b[0].is_ascii_uppercase() && b[1..].iter().all(u8::is_ascii_digit)
}

/// Cue words required to claim a candidate (industry context list, minus the
/// two-letter word `us` which is a common English pronoun and would fire on
/// ordinary text).
pub(super) const CUES: &[&str] = &[
    "united",
    "states",
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
