//! UK NHS number: validator + rule.
//!
//! Official source: NHS England, "NHS Data Model and Dictionary",
//! attribute NHS NUMBER, section "Description" (the live page answers 403
//! to scripted clients; Internet Archive copy of 2025-09-14,
//! <http://web.archive.org/web/20250914053312/https://www.datadictionary.nhs.uk/attributes/nhs_number.html>,
//! retrieved 2026-10-30): "The NHS NUMBER is 10 numeric digits in length.
//! The tenth digit is a check digit used to confirm its validity. The
//! check digit is validated using the Modulus 11 algorithm [...] Step 1
//! Multiply each of the first nine digits by a weighting factor [10, 9, 8,
//! 7, 6, 5, 4, 3, 2] Step 2 Add the results of each multiplication
//! together. Step 3 Divide the total by 11 and establish the remainder.
//! Step 4 Subtract the remainder from 11 to give the check digit. If the
//! result is 11 then a check digit of 0 is used. If the result is 10 then
//! the NHS NUMBER is invalid and not used. Step 5 Check the remainder
//! matches the check digit."
//!
//! The validator uses the equivalent sum form (weights 10 to 1 over all
//! ten digits, total divisible by 11): no single digit can satisfy a
//! required contribution of 10, so the numbers Step 4 declares invalid
//! fail here too. Spaces or dashes between the 3-3-4 groups are accepted
//! (presentation format; the dictionary defines the ten digits only).
//!
//! A cue is REQUIRED: a single check digit admits ~9% of random 10-digit
//! shapes (BSN/Steuer-IdNr precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make an NHS candidate claimable. A leading cue counts
/// when its END lies within the 18-character cue window before the value
/// (`pii::context`), so the full name "national health service" is a cue;
/// "health service" (also inside "health services authority") and
/// "health authority" cover the shorter labels and a trailing mention (a
/// trailing cue must lie entirely inside the window).
pub(super) const CUES: &[&str] = &[
    "nhs",
    "national health service",
    "health service",
    "health authority",
];

/// Returns `true` if `nhs` is a valid UK NHS number (10 digits, optional
/// single spaces or dashes between the 3-3-4 groups, weighted digit sum
/// divisible by 11).
///
/// # Examples
/// ```
/// use redactify::valid_uk_nhs;
/// assert!(valid_uk_nhs("943-476-5870"));  // independently verified vector
/// assert!(valid_uk_nhs("943 476 5870"));
/// assert!(valid_uk_nhs("9434765870"));
/// assert!(!valid_uk_nhs("9434765871"));   // check digit off by one
/// assert!(!valid_uk_nhs("943476587"));    // 9 digits
/// ```
#[must_use]
pub fn valid_uk_nhs(nhs: &str) -> bool {
    let s: String = nhs
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let b = s.as_bytes();
    if b.len() != 10 || !b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    // weights 10..1 left-to-right over the ten digits (the independent
    // implementation enumerates 1..=10 right-to-left; identical sums)
    let total: u32 = b
        .iter()
        .zip((1..=10u32).rev())
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    total % 11 == 0
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UkNhs,
        r"(?<!\d)\d{3}[- ]?\d{3}[- ]?\d{4}(?!\d)",
        Some(valid_uk_nhs),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_uk_nhs;

    #[test]
    fn checksum_math() {
        // independently verified vector: 943-476-5870 passes, off-by-one fails
        assert!(valid_uk_nhs("943-476-5870"));
        assert!(!valid_uk_nhs("9434765871"));
        // generated + cross-verified vectors: for a 9-digit base with
        // weighted sum S (weights 10..2), the check digit is
        // (11 - S % 11) % 11; recomputed here independently of the
        // validator (single-digit d10 satisfies S + d10 = 0 mod 11)
        for base in ["400123456", "987654321", "100000000", "100000001"] {
            let s9: u32 = base
                .bytes()
                .zip((2..=10u32).rev())
                .map(|(c, w)| u32::from(c - b'0') * w)
                .sum();
            let rem = s9 % 11;
            if rem == 1 {
                // required check digit would be 10 -> unrepresentable,
                // officially invalid; the validator must reject every d10
                for d10 in 0..10u8 {
                    assert!(!valid_uk_nhs(&format!("{base}{d10}")));
                }
                continue;
            }
            let d10 = ((11 - rem) % 11).to_string();
            let full = format!("{base}{d10}");
            assert!(valid_uk_nhs(&full), "{full}");
            // every other check digit breaks the checksum
            for wrong in 0..10u8 {
                let cand = format!("{base}{wrong}");
                assert_eq!(valid_uk_nhs(&cand), cand == full, "{cand}");
            }
        }
        // the remainder-10-invalid case is real: weighted sum of base
        // 100000001 (10 + 2) = 12, remainder 1 -> required check digit 10
        assert_eq!(
            "100000001"
                .bytes()
                .zip((2..=10u32).rev())
                .map(|(c, w)| u32::from(c - b'0') * w)
                .sum::<u32>()
                % 11,
            1
        );
        // separators / shape
        assert!(valid_uk_nhs("943 476 5870"));
        assert!(valid_uk_nhs("9434765870"));
        assert!(!valid_uk_nhs("943-476-587"));
        assert!(!valid_uk_nhs("0943476587A")); // non-digit
    }
}
