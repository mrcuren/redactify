//! Indian PAN (Permanent Account Number): validator + rule.
//!
//! Official source: Income Tax Department, "India - Information on Tax
//! Identification Numbers" (country sheet published on the OECD AEOI
//! portal, PDF of 2016-09-29,
//! <https://www.oecd.org/content/dam/oecd/en/topics/policy-issue-focus/aeoi/india-tin.pdf>,
//! Section II, retrieved 2026-10-30): "A typical PAN is AFZPK7190K. First
//! three characters ... are alphabetic series running from AAA to ZZZ.
//! Fourth character of PAN represents the status of PAN holder ... "P"
//! stands for Individual, "F" stands for Firm, "C" stands for Company, "H"
//! stands for HUF, "A" stands for AOP, "T" stands for TRUST, "B" stands for
//! Body of Individuals, "L" stands for Local Authority, "J" stands for
//! Artificial Juridical Person, "G" stands for Government. Fifth character
//! ... represents first character of the PAN holder's last name/surname.
//! Next four characters ... are sequential number running from 0001 to
//! 9999. Last character ... is an alphabetic check digit."
//!
//! The validator applies exactly that: three letters, a holder-type letter
//! (`A B C F G H J L P T`), a letter, a sequence number 0001-9999 (so
//! `0000` is rejected) and a final letter. The check letter is not
//! verified: its algorithm is not published.
//!
//! A cue is REQUIRED (no checksum exists - passport precedent). The
//! bare rule-set cue "pan" is deliberately replaced by label forms:
//! as a substring it also matches company/japan/expand, which would
//! unlock the shape from ordinary prose (documented deviation).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase substring matching) that make a PAN candidate
/// claimable.
pub(super) const CUES: &[&str] = &[
    "pan:",
    "pan no.",
    "pan number",
    "pan card",
    "permanent account",
];

/// Returns `true` if `pan` is a structurally valid Indian PAN: three
/// letters, a holder-type letter (`A`/`B`/`C`/`F`/`G`/`H`/`J`/`L`/`P`/
/// `T`), a letter, four digits (not all zero), and a final letter.
///
/// # Examples
/// ```
/// use redactify::valid_in_pan;
/// assert!(valid_in_pan("AFZPK7190K"));  // the Income Tax Department example
/// assert!(valid_in_pan("AAAPL1234C"));
/// assert!(!valid_in_pan("ABCDE1234F")); // D is not a holder-type letter
/// assert!(!valid_in_pan("AAAPL0000C")); // all-zero digit block
/// assert!(!valid_in_pan("aaapl1234c")); // lower case
/// ```
#[must_use]
pub fn valid_in_pan(pan: &str) -> bool {
    let b = pan.as_bytes();
    if b.len() != 10 {
        return false;
    }
    if !matches!(
        b[3],
        b'A' | b'B' | b'C' | b'F' | b'G' | b'H' | b'J' | b'L' | b'P' | b'T'
    ) {
        return false;
    }
    if !b[0..3].iter().all(u8::is_ascii_uppercase) || !b[4].is_ascii_uppercase() {
        return false;
    }
    if !b[5..9].iter().all(u8::is_ascii_digit) {
        return false;
    }
    if &b[5..9] == b"0000" {
        return false;
    }
    b[9].is_ascii_uppercase()
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::InPan,
        r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Z0-9])",
        Some(valid_in_pan),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_in_pan;

    #[test]
    fn structural_rules() {
        // vectors confirmed against an independent public implementation
        for v in ["AAAPL1234C", "BQQBP5731K"] {
            assert!(valid_in_pan(v), "{v}");
        }
        // holder-type letter restriction
        assert!(!valid_in_pan("ABCDE1234F"));
        assert!(!valid_in_pan("AAADI1234F"));
        // all-zero digit block rejected (independent implementation raises InvalidComponent)
        assert!(!valid_in_pan("AAAPL0000C"));
        assert!(!valid_in_pan("aaapl1234c"));
        assert!(!valid_in_pan("AAAPL1234"));
    }
}
