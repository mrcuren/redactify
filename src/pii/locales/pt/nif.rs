//! Portuguese NIF (número de identificação fiscal): validator + rule.
//! Evidence (retrieved 2026-10-08):
//! An independent public implementation: 9 digits, first digit non-zero, check
//! digit = ((11 - sum(weights 9,8,...,2 over the first eight)) % 11)
//! % 10.
//! A commercial DLP vendor's published sensitive-information-type
//! definition "Portugal tax identification number": Format
//! "nine digits with optional spaces" (3-3-3), Checksum: Yes, keywords
//! "nif", "numero fiscal", "número de identificação fisca".
//!
//! A cue is REQUIRED: a single check digit admits ~9% of random
//! 9-digit shapes (BSN precedent). The bare DLP keyword "nif" is
//! deliberately replaced by label forms: as a substring it also matches
//! unify/magnify, which would let ordinary prose unlock the shape
//! (documented deviation; caught by the FPR canary). This also closes
//! the lang_gate gap: "pt" was a Latin-script routing candidate with no
//! rules.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make an NIF candidate claimable (DLP keyword list,
/// accented and unaccented forms).
pub(super) const CUES: &[&str] = &[
    "nif:",
    "contribuinte",
    "numero fiscal",
    "número fiscal",
    "identificação fisca",
    "identificacao fisca",
];

/// Returns `true` if `nif` is a valid Portuguese NIF (9 digits; spaces
/// and dashes stripped; first digit non-zero; weighted mod-11 check
/// digit).
///
/// # Examples
/// ```
/// use redactify::valid_pt_nif;
/// assert!(valid_pt_nif("123456789")); // independently verified vector
/// assert!(valid_pt_nif("123 456 789"));
/// assert!(!valid_pt_nif("123456780")); // check digit off
/// assert!(!valid_pt_nif("023456789")); // leading zero
/// ```
#[must_use]
pub fn valid_pt_nif(nif: &str) -> bool {
    let s: String = nif
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let b = s.as_bytes();
    if b.len() != 9 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if b[0] == b'0' {
        return false;
    }
    // weights 9,8,7,6,5,4,3,2 over the first eight digits (independent
    // implementation's formulation, verbatim structure)
    let sum: u32 = b[..8]
        .iter()
        .zip((2..=9u32).rev())
        .map(|(&c, weight)| u32::from(c - b'0') * weight)
        .sum();
    ((11 - sum % 11) % 11) % 10 == u32::from(b[8] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::PtNif,
        r"(?<!\d)\d{3}(?: ?\d{3})(?: ?\d{3})(?!\d)",
        Some(valid_pt_nif),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_pt_nif;

    #[test]
    fn checksum_math() {
        // vectors confirmed against an independent public implementation
        for v in ["123456789", "299266753", "501963871"] {
            assert!(valid_pt_nif(v), "{v}");
        }
        assert!(valid_pt_nif("123 456 789"));
        // single check-digit substitution caught
        assert!(!valid_pt_nif("123456780"));
        assert!(!valid_pt_nif("023456789"));
        // independent recomputation of 123456789:
        // 1*9 + 2*8 + 3*7 + 4*6 + 5*5 + 6*4 + 7*3 + 8*2 = 156;
        // 156 % 11 = 2 -> (11 - 2) % 11 = 9 -> check digit 9
        let s = 9 + 2 * 8 + 3 * 7 + 4 * 6 + 5 * 5 + 6 * 4 + 7 * 3 + 8 * 2;
        assert_eq!(s, 156);
        assert_eq!(((11 - s % 11) % 11) % 10, 9);
    }
}
