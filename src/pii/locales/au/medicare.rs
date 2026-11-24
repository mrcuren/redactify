//! Australian Medicare card number: validator + rule.
//! Evidence (three independent sources, retrieved 2026-10-08):
//! 1. A published validation article "Australian Medicare Number
//!    Validation": 8 identifier digits (first digit 2-6), 1 check digit
//!    and 1 issue number; weights (1, 3, 7, 9, 1, 3, 7, 9); check digit ==
//!    weighted sum mod 10.
//! 2. A published health-identifier reference "Australian Health
//!    Identifiers": the same structure and weights with the worked example
//!    31899770 -> check digit 2.
//! 3. An independent public rule set: patterns
//!    `\b[2-6]\d{3}\s\d{5}\s\d\b` (4-5-1 spaced) and `\b[2-6]\d{9}\b`;
//!    `validate_result` computes the same weighted sum with check = 9th
//!    digit; context "medicare".
//!
//! The 11th IRN position (individual reference number) is deliberately
//! excluded: the rule set does not cover it and its formatting is not
//! standardized across sources.
//!
//! A cue is REQUIRED: a single check digit admits ~10% of random
//! 10-digit shapes (TFN precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a Medicare candidate claimable.
pub(super) const CUES: &[&str] = &["medicare"];

/// Returns `true` if `num` is a valid Australian Medicare card number:
/// 10 digits (spaces stripped), first digit 2-6, 9th digit equal to the
/// weighted (1,3,7,9,1,3,7,9) digit sum mod 10. The 10th (issue) digit
/// is not constrained by any source.
///
/// # Examples
/// ```
/// use redactify::valid_au_medicare;
/// assert!(valid_au_medicare("3189 97702 1")); // reference worked example
/// assert!(valid_au_medicare("3189977021"));
/// assert!(!valid_au_medicare("3189977031")); // 9th (check) digit off
/// assert!(!valid_au_medicare("1189977021")); // first digit 1
/// ```
#[must_use]
pub fn valid_au_medicare(num: &str) -> bool {
    let s: String = num.chars().filter(|c| !c.is_whitespace()).collect();
    let b = s.as_bytes();
    if b.len() != 10 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !(b'2'..=b'6').contains(&b[0]) {
        return false;
    }
    const WEIGHTS: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = b[..8]
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    sum % 10 == u32::from(b[8] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::AuMedicare,
        r"(?<!\d)[2-6]\d{3}(?: ?\d{5}) ?\d(?!\d)",
        Some(valid_au_medicare),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_au_medicare;

    #[test]
    fn checksum_math() {
        // reference worked example: 31899770 -> (3+3+56+81+9+21+49+0)=222,
        // 222 % 10 = 2 -> check digit 2; issue number 1
        assert!(valid_au_medicare("3189977021"));
        assert!(valid_au_medicare("3189 97702 1"));
        // generated + cross-verified vectors
        for v in ["4073241381", "4361970681", "4334703171", "6467770011"] {
            assert!(valid_au_medicare(v), "{v}");
        }
        // single-digit substitution caught
        assert!(!valid_au_medicare("3189977031")); // 9th (check) digit off
        assert!(!valid_au_medicare("4073241391")); // check digit substituted
                                                   // first digit range 2-6
        assert!(!valid_au_medicare("1189977021"));
        assert!(!valid_au_medicare("318997702"));
        // independent recomputation of 3189977021:
        // 3*1+1*3+8*7+9*9+9*1+7*3+7*7+0*9 = 222 -> 222 % 10 = 2
        assert_eq!(3 + 3 + 8 * 7 + 9 * 9 + 9 + 7 * 3 + 7 * 7, 222);
        assert_eq!(222 % 10, 2);
    }
}
