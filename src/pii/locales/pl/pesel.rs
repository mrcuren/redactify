//! Polish PESEL: validator + rule. Evidence (two
//! independent implementations, retrieved 2026-10-08):
//! An independent public implementation: 11 digits; check digit over the first
//! ten with weights (1, 3, 7, 9, 1, 3, 7, 9, 1, 3), check = (10 - sum
//! % 10) % 10; the month field encodes the century (month // 20 selects
//! 1800..2200, month % 20 is the calendar month) and it validates a
//! real calendar date.
//! An independent public rule set: the same weights and mod-10 check;
//! regex encodes the century-month classes (tens digit even with unit
//! 1-9, or odd with unit 0-2) and day 01-31; context "PESEL".
//!
//! Limit: full calendar validation (Feb 30
//! etc.) is NOT replicated - rule-set parity is kept (shape classes +
//! checksum only).
//!
//! A cue is REQUIRED: a single check digit admits ~10% of random
//! 11-digit shapes (Steuer-IdNr precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a PESEL candidate claimable.
pub(super) const CUES: &[&str] = &["pesel"];

/// Returns `true` if `pesel` is a checksum-valid Polish PESEL (11
/// digits; the date encoding is enforced by the rule pattern).
///
/// # Examples
/// ```
/// use redactify::valid_pesel;
/// assert!(valid_pesel("80010123450")); // independently verified vector
/// assert!(valid_pesel("05211501236")); // 2000s century (month 21)
/// assert!(!valid_pesel("80010123451")); // check digit off
/// assert!(!valid_pesel("8001012345"));  // 10 digits
/// ```
#[must_use]
pub fn valid_pesel(pesel: &str) -> bool {
    let b = pesel.as_bytes();
    if b.len() != 11 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = b
        .iter()
        .take(10)
        .zip(WEIGHTS)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    (10 - sum % 10) % 10 == u32::from(b[10] - b'0')
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Pesel,
        r"(?<!\d)\d{2}(?:[02468][1-9]|[13579][012])(?:0[1-9]|[12]\d|3[01])\d{5}(?!\d)",
        Some(valid_pesel),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_pesel;

    #[test]
    fn checksum_math() {
        // vectors confirmed against an independent public implementation (see
        // module docs), covering the 1900s / 2000s / 2100s century encodings
        for v in ["80010123450", "99123199993", "05211501236", "30412907770"] {
            assert!(valid_pesel(v), "{v}");
        }
        // single check-digit substitution caught
        assert!(!valid_pesel("80010123451"));
        assert!(!valid_pesel("99123199990"));
        assert!(!valid_pesel("8001012345"));
        // independent recomputation of one vector with inline weights:
        // digits 8,0,0,1,0,1,2,3,4,5 -> 8*1+0*3+0*7+1*9+0*1+1*3+2*7+3*9+4*1+5*3
        let s = 8 + 9 + 3 + 14 + 27 + 4 + 15;
        assert_eq!((10 - s % 10) % 10, 0);
        assert_eq!("80010123450".as_bytes()[10], b'0');
    }
}
