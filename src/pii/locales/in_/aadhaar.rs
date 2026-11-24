//! Indian Aadhaar number: validator + rule.
//!
//! Official sources:
//!
//! 1. Unique Identification Authority of India (UIDAI), Circular No. 1 of
//!    2018, F.No. K-11020/217/2018-UIDAI (Auth-I), 10 January 2018,
//!    "Enhancing Privacy of Aadhaar holders: Implementation of Virtual ID,
//!    UID Token and Limited KYC",
//!    <https://uidai.gov.in/images/46Circular_for_Implementation_of_Virtual_ID_UID_Token_and_Limited_KYC_0001_compressed.pdf>,
//!    "Features of VID", item b (retrieved 2026-10-30): "Last digit of the
//!    VID is the checksum using Verhoeff algorithm as in Aadhaar number."
//! 2. UIDAI working paper "A UID Numbering Scheme" (H. Kanakia,
//!    S. Nadhamuni, S. Sarma, May 2010; archived copy of
//!    `uidai.gov.in/UID_PDF/Working_Papers/A_UID_Numbering_Scheme.pdf`),
//!    <https://web.archive.org/web/20140611025606/http://uidai.gov.in/UID_PDF/Working_Papers/A_UID_Numbering_Scheme.pdf>,
//!    sections "Number Design: 12 Digits" and "The Checksum" (retrieved
//!    2026-10-30): "we suggest the use of 12 digits (11 + 1 check sum) ...
//!    0- numbers (a1 = 0) could be used as an "escape" for future
//!    extensions ... 1- numbers (a1 = 1) could be reserved for entities
//!    rather than individuals ... We could use 2-9 numbers (a1 = 2,3...9)
//!    right away to assign UIDs. ... We recommend the Verhoeff scheme."
//!
//! The validator checks exactly what the two sources state: 12 digits,
//! first digit 2-9 (individuals), Verhoeff check digit. Palindromes are
//! not rejected: neither source states that palindromic numbers are never
//! issued (80,153 of the 800,000 twelve-digit palindromes with a first
//! digit 2-9 pass Verhoeff and are accepted).
//!
//! A cue is REQUIRED: Verhoeff admits ~10% of random 12-digit shapes.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make an Aadhaar candidate claimable.
pub(super) const CUES: &[&str] = &["aadhaar", "uidai"];

/// Verhoeff dihedral group table `d`.
const D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// Verhoeff permutation table `p` (8 cycles).
const P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff inverse table.
const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/// Returns `true` if `aadhaar` is a valid Aadhaar number: 12 digits
/// (whitespace, `-` and `:` separators stripped), first digit 2-9 and a
/// valid Verhoeff check digit.
///
/// # Examples
/// ```
/// use redactify::valid_in_aadhaar;
/// assert!(valid_in_aadhaar("607324134360"));
/// assert!(valid_in_aadhaar("6073 2413 4360"));
/// assert!(valid_in_aadhaar("200009900002")); // a palindrome passing Verhoeff
/// assert!(!valid_in_aadhaar("607324134361")); // Verhoeff fails
/// assert!(!valid_in_aadhaar("107324134360")); // leading 1
/// ```
#[must_use]
pub fn valid_in_aadhaar(aadhaar: &str) -> bool {
    let s: String = aadhaar
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != ':')
        .collect();
    let b = s.as_bytes();
    if b.len() != 12 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    // working paper: 0 and 1 are reserved, individuals get 2-9
    if b[0] < b'2' {
        return false;
    }
    // Verhoeff: walk the digits right-to-left through the permutation
    let mut c: u8 = 0;
    for (i, &digit) in b.iter().rev().enumerate() {
        let d = digit - b'0';
        c = D[usize::from(c)][usize::from(P[i % 8][usize::from(d)])];
    }
    INV[usize::from(c)] == 0
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::InAadhaar,
        r"(?<!\d)\d{4}(?:[- ]?\d{4}){2}(?!\d)",
        Some(valid_in_aadhaar),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_in_aadhaar;

    #[test]
    fn verhoeff_math() {
        for v in ["607324134360", "397065334700", "518467770056"] {
            assert!(valid_in_aadhaar(v), "{v}");
        }
        assert!(valid_in_aadhaar("6073 2413 4360"));
        // single-digit substitution caught by Verhoeff
        assert!(!valid_in_aadhaar("607324134361"));
        assert!(!valid_in_aadhaar("507324134360"));
        // leading digit 0/1 rejected (reserved in the UIDAI scheme)
        assert!(!valid_in_aadhaar("107324134360"));
        assert!(!valid_in_aadhaar("007324134360"));
        // wrong length
        assert!(!valid_in_aadhaar("60732413436"));
    }

    #[test]
    fn palindromes_follow_verhoeff_only() {
        // no source rejects palindromes, so a
        // palindrome is valid exactly when Verhoeff passes
        assert!(valid_in_aadhaar("200009900002"));
        assert!(valid_in_aadhaar("333333333333"));
        assert!(!valid_in_aadhaar("222222222222")); // Verhoeff fails
    }
}
