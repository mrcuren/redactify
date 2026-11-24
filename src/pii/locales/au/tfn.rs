//! Australian TFN (tax file number): validator + rule.
//! Evidence (two independent implementations, retrieved 2026-10-08):
//! An independent public implementation: 8 or 9 digits, weighted sum with
//! weights (1, 4, 3, 7, 5, 8, 6, 9, 10) divisible by 11.
//! An independent public rule set: the same weights and mod-11 rule;
//! patterns for the spaced 3-3-3 form and the bare 9-digit form;
//! context "tax file number", "tfn".
//!
//! Scope: only the 9-digit form is claimed.
//! The rule set also matches only 9 digits; the implementation accepts
//! 8-digit TFNs, but a bare 8-digit run is a common order-reference
//! shape, and the second source does not cover it.
//!
//! A cue is REQUIRED: mod-11 admits ~9% of random 9-digit shapes.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a TFN candidate claimable.
pub(super) const CUES: &[&str] = &["tfn", "tax file number"];

/// Returns `true` if `tfn` is a valid Australian TFN (9 digits; spaces
/// and dashes stripped; weighted sum divisible by 11).
///
/// # Examples
/// ```
/// use redactify::valid_au_tfn;
/// assert!(valid_au_tfn("100010747")); // independently verified vector
/// assert!(valid_au_tfn("100 010 747"));
/// assert!(!valid_au_tfn("100010748")); // checksum off
/// assert!(!valid_au_tfn("10001074"));  // 8 digits (out of scope, module doc)
/// ```
#[must_use]
pub fn valid_au_tfn(tfn: &str) -> bool {
    let s: String = tfn
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let b = s.as_bytes();
    if b.len() != 9 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    const WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = b
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    sum % 11 == 0
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::AuTfn,
        r"(?<!\d)\d{3}(?: ?\d{3})(?: ?\d{3})(?!\d)",
        Some(valid_au_tfn),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_au_tfn;

    #[test]
    fn checksum_math() {
        // vectors confirmed against an independent public implementation
        for v in ["100010747", "100013678", "100029310"] {
            assert!(valid_au_tfn(v), "{v}");
        }
        assert!(valid_au_tfn("100 010 747"));
        // single-digit substitution caught
        assert!(!valid_au_tfn("100010748"));
        assert!(!valid_au_tfn("200010747"));
        assert!(!valid_au_tfn("10001074"));
        // independent recomputation of 100010747:
        // 1*1 + 0*4 + 0*3 + 0*7 + 1*5 + 0*8 + 7*6 + 4*9 + 7*10 = 154 = 14*11
        assert_eq!(1 + 5 + 7 * 6 + 4 * 9 + 7 * 10, 154);
        assert_eq!(154 % 11, 0);
    }
}
