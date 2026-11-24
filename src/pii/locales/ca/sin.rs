//! Canadian SIN (Social Insurance Number): validator + rule.
//! Evidence (two independent implementations, retrieved
//! 2026-10-08):
//! An independent public implementation: 9 digits, first digit never 0 or 8,
//! Luhn check.
//! An independent public rule set: separator-bearing medium pattern
//! `\b[1-79]\d{2}([- ])\d{3}\1\d{3}\b` (the SAME separator character in
//! both positions), Luhn via `invalidate_result`; docstring: "SINs
//! beginning with 0 or 8 are reserved and not currently issued";
//! context "sin", "social insurance number" (+ French "nas",
//! "numéro d'assurance sociale").
//!
//! Only the separator-bearing form is claimed (US-SSN precedent: a bare
//! 9-digit run is never a SIN).
//!
//! A cue is REQUIRED: Luhn admits ~10% of random 9-digit shapes.

use crate::pii::entity::EntityType;

use crate::pii::locales::{luhn_valid, rule, ContextPolicy, Rule};

/// Cue words that make a SIN candidate claimable (English + French).
/// The bare "sin" from the public rule set's context list is deliberately
/// omitted: as a substring it also matches business/using/sing, which
/// would let ordinary prose unlock the shape (documented deviation);
/// label forms cover the realistic usages.
pub(super) const CUES: &[&str] = &[
    "sin:",
    "sin number",
    "sin no",
    "social insurance",
    "nas:",
    "assurance sociale",
];

/// Returns `true` if `sin` is a valid Canadian SIN (9 digits; dashes and
/// spaces stripped; first digit 1-7 or 9; Luhn check).
///
/// # Examples
/// ```
/// use redactify::valid_ca_sin;
/// assert!(valid_ca_sin("123-456-782")); // independently verified vector
/// assert!(valid_ca_sin("123 456 782"));
/// assert!(!valid_ca_sin("123-456-783")); // Luhn fails
/// assert!(!valid_ca_sin("023456786"));   // unissued 0 prefix
/// ```
#[must_use]
pub fn valid_ca_sin(sin: &str) -> bool {
    let s: String = sin
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let b = s.as_bytes();
    if b.len() != 9 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if b[0] == b'0' || b[0] == b'8' {
        return false;
    }
    // Luhn over the 9 digits (the shared helper has no length gate; the
    // public card check `valid_luhn` requires >= 13 digits)
    luhn_valid(b)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::CaSin,
        r"(?<!\d)[1-79]\d{2}([- ])\d{3}\1\d{3}(?!\d)",
        Some(valid_ca_sin),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_ca_sin;

    #[test]
    fn checksum_math() {
        // vectors confirmed against an independent public implementation
        for v in ["123456782", "304167281", "756451233", "613555127"] {
            assert!(valid_ca_sin(v), "{v}");
        }
        assert!(valid_ca_sin("123-456-782"));
        assert!(valid_ca_sin("123 456 782"));
        // Luhn break
        assert!(!valid_ca_sin("123456783"));
        // unissued prefixes
        assert!(!valid_ca_sin("023456786"));
        assert!(!valid_ca_sin("823456787"));
        assert!(!valid_ca_sin("12345678"));
        // independent recomputation of 123456782: double every second
        // digit from the right -> 1 4 3 8 5 3 7 7 2, sum 40
        let v = [1u32, 2, 3, 4, 5, 6, 7, 8, 2];
        let mut sum = 0;
        for (i, d) in v.iter().enumerate() {
            let mut x = *d;
            if i % 2 == 1 {
                x *= 2;
                if x > 9 {
                    x -= 9;
                }
            }
            sum += x;
        }
        assert_eq!(sum % 10, 0);
    }
}
