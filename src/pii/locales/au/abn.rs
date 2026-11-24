//! Australian Business Number (ABN): validator + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. Australian Business Register "Format of the ABN" (official):
//!    11 digits; subtract 1 from the first digit; weights
//!    (10,1,3,5,7,9,11,13,15,17,19); sum mod 89 == 0.
//!    Worked example: 51 824 753 556 → sum 534 = 89 × 6.
//! 2. Wikipedia "Australian Business Number": same algorithm.
//!
//! Cue REQUIRED: ~1/89 of random 11-digit shapes pass the check.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make an ABN candidate claimable. "ABN" and "ACN" (ASIC:
/// a company may show its ABN in place of its ACN) are delimited
/// (`abn:`, `acn ` ...): bare, "abn" is a substring of "abnormal", "acn"
/// of "acne".
pub(super) const CUES: &[&str] = &[
    "abn:",
    "abn#",
    "abn ",
    "(abn)",
    "acn:",
    "acn#",
    "acn ",
    "(acn)",
    "business number",
    "australian business",
];

/// Returns `true` if `abn` is a checksum-valid Australian Business
/// Number (11 digits, mod-89 check with first-digit-minus-1).
///
/// # Examples
/// ```
/// use redactify::valid_au_abn;
/// assert!(valid_au_abn("51824753556")); // ABR worked example
/// assert!(valid_au_abn("33100200300"));
/// assert!(!valid_au_abn("52824753557")); // wrong digits
/// assert!(!valid_au_abn("12345678901")); // fails mod 89
/// ```
#[must_use]
pub fn valid_au_abn(abn: &str) -> bool {
    let digits: String = abn.chars().filter(|c| c.is_ascii_digit()).collect();
    let b = digits.as_bytes();
    if b.len() != 11 {
        return false;
    }
    const WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let sum: u32 = b
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| {
            let d = u32::from(c - b'0');
            d * w
        })
        .sum();
    // subtract 1 from the first digit's contribution. A leading zero
    // cannot satisfy the check BY DEFINITION (0 - 1 would underflow) - the
    // regex admits leading zeros, so reject them before the arithmetic
    // instead of panicking.
    if b[0] == b'0' {
        return false;
    }
    let first_contribution = u32::from(b[0] - b'0') * 10;
    let adjusted = sum - first_contribution + (u32::from(b[0] - b'0') - 1) * 10;
    adjusted % 89 == 0
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::AuAbn,
        r"(?<!\d)\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}(?!\d)",
        Some(valid_au_abn),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod abn_tests {
    use super::valid_au_abn;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn abn_valid() {
        assert!(valid_au_abn("51824753556")); // ABR worked example
        assert!(valid_au_abn("33100200300")); // sum 89
        assert!(!valid_au_abn("52824753557")); // altered
        assert!(!valid_au_abn("41824753556")); // first digit altered
        assert!(!valid_au_abn("12345678901")); // fails
    }

    #[test]
    fn abn_leading_zero_never_panics() {
        // the regex admits leading zeros; the first-digit-minus-1 arithmetic
        // must reject them, not underflow-panic (debug abort / release
        // wrap)
        assert!(!valid_au_abn("01824753556"));
        assert!(!valid_au_abn("00000000000"));
        assert!(!valid_au_abn("00 000 000 000"));
        // and the detection path stays panic-free with a cued all-zero shape
        let ents = engine_detect("abn 00 000 000 000", &["au"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::AuAbn),
            "{ents:?}"
        );
    }

    #[test]
    fn abn_detected_with_cue() {
        let ents = engine_detect("abn 51 824 753 556 registered", &["au"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::AuAbn), "{ents:?}");
        // without cue: not claimed
        let ents = engine_detect("ref 51824753556", &["au"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::AuAbn),
            "{ents:?}"
        );
    }
}
