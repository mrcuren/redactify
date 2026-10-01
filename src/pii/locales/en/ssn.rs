//! US Social Security Number (SSN): validator + detection rule.
//!
//! Source of the pattern and the invalidation logic: the open-source industry
//! PII analyzer (US SSN recognizer, medium-strength pattern
//! `[0-9]{3}[-. ][0-9]{2}[-. ][0-9]{4}` + `invalidate_result`), translated
//! verbatim into `valid_ssn`. Only the separator-bearing pattern is used here;
//! the "very weak" bare 9-digit variants are deliberately not ported (false
//! positive surface).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Returns `true` if `s` is a structurally valid SSN (checksums do not exist).
///
/// Rules (industry-standard invalidation set):
/// - both separators must be the same character,
/// - digits must not all be identical,
/// - group digits `[3..5]` may not be `00`, group `[5..]` may not be `0000`,
/// - area (first group) `000` and `666` are never issued,
/// - canonical sample SSNs (`123456789`, `987654320`, `078051120`) are rejected
///   by their digit sequence, regardless of separators.
///
/// # Examples
/// ```
/// use redactify::valid_ssn;
/// assert!(valid_ssn("536-90-6292"));
/// assert!(valid_ssn("536 90 6292"));  // space is a valid separator
/// assert!(!valid_ssn("536-90.6292")); // mismatched separators
/// assert!(!valid_ssn("666-45-6789")); // area 666 is never issued
/// assert!(!valid_ssn("123-45-6789")); // canonical sample (digits 123456789)
/// ```
#[must_use]
pub fn valid_ssn(s: &str) -> bool {
    let mut seps: Vec<char> = s
        .chars()
        .filter(|c| *c == '.' || *c == '-' || *c == ' ')
        .collect();
    seps.dedup();
    if seps.len() > 1 {
        return false; // mismatched separators
    }
    let d: Vec<char> = s.chars().filter(char::is_ascii_digit).collect();
    if d.len() != 9 || d.iter().all(|&c| c == d[0]) {
        return false;
    }
    let g2: String = d[3..5].iter().collect();
    let g3: String = d[5..].iter().collect();
    let area: String = d[..3].iter().collect();
    if g2 == "00" || g3 == "0000" || area == "000" || area == "666" {
        return false;
    }
    // canonical sample SSNs are rejected on their DIGITS (separators stripped),
    // mirroring the source invalidation logic exactly.
    !matches!(
        d.iter().collect::<String>().as_str(),
        "123456789" | "987654320" | "078051120"
    )
}

/// Cue words that raise SSN confidence from 0.75 to 0.95 (industry context list).
pub(super) const CUES: &[&str] = &["social", "security", "ssn", "ssns", "ssid"];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Ssn,
        r"(?<!\d)\d{3}[-. ]\d{2}[-. ]\d{4}(?!\d)",
        Some(valid_ssn),
        ContextPolicy::Boost(CUES, 0.95),
        0.75
    )
}

#[cfg(test)]
mod tests {
    use super::valid_ssn;

    #[test]
    fn golden_vectors() {
        assert!(valid_ssn("536-90-6292"));
        assert!(valid_ssn("536.90.6292"));
        assert!(valid_ssn("536 90 6292"));
        assert!(!valid_ssn("536-90.6292")); // mismatched separators
        assert!(!valid_ssn("111-11-1111")); // all identical digits
        assert!(!valid_ssn("123-00-6789")); // group 2 all zeros
        assert!(!valid_ssn("123-45-0000")); // group 3 all zeros
        assert!(!valid_ssn("000-45-6789")); // area 000 never issued
        assert!(!valid_ssn("666-45-6789")); // area 666 never issued
        assert!(!valid_ssn("123456789")); // canonical sample (bare)
        assert!(!valid_ssn("123-45-6789")); // canonical sample WITH separators
        assert!(!valid_ssn("987-65-4320")); // canonical sample with separators
        assert!(!valid_ssn("078-05-1120")); // canonical sample with separators
        assert!(!valid_ssn(""));
    }
}
