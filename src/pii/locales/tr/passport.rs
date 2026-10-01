//! Turkish passport number: validator + detection rule (format + mandatory cue).

/// Returns `true` if `s` is a valid biometric Turkish passport number.
///
/// Format: the letter `U` (either case) followed by exactly 8 digits - the
/// format used by biometric passports issued since 2010 (Turkish passport
/// reference lists; ICAO Doc 9303 MRZ standard).
///
/// **No checksum exists** -> within [`crate::detect`] a bare candidate is only
/// accepted when a `pasaport`/`passport` cue appears nearby (same context
/// model as the VKN rule).
///
/// # Examples
/// ```
/// use redactify::valid_passport;
/// assert!(valid_passport("U12345678"));
/// assert!(valid_passport("u12345678")); // lowercase accepted
/// assert!(!valid_passport("U1234567"));  // 7 digits
/// assert!(!valid_passport("X12345678")); // letter other than U
/// assert!(!valid_passport("U123456789")); // 9 digits
/// ```
#[must_use]
pub fn valid_passport(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 9 && (b[0] == b'U' || b[0] == b'u') && b[1..].iter().all(u8::is_ascii_digit)
}

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words required to claim a `U` + 8-digit candidate (no checksum exists).
pub(super) const CUES: &[&str] = &[
    "pasaport",
    "pasaport no",
    "pasaport numarasi",
    "passport",
    "passport no",
    "passport number",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Passport,
        r"(?i)(?<![a-z0-9])u\d{8}(?![a-z0-9])",
        Some(valid_passport),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_passport;

    #[test]
    fn golden_vectors() {
        assert!(valid_passport("U12345678"));
        assert!(valid_passport("u12345678"));
        assert!(!valid_passport("U1234567"));
        assert!(!valid_passport("U123456789"));
        assert!(!valid_passport("X12345678"));
        assert!(!valid_passport("12345678"));
        assert!(!valid_passport(""));
        assert!(!valid_passport("U1234567a"));
    }
}
