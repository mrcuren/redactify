//! US National Provider Identifier (NPI): validator + detection rule.
//!
//! Official source (retrieved 2026-10-30): CMS, "Requirements for National
//! Provider Identifier (NPI) and NPI Check Digit" (January 23, 2004),
//! sections "Requirements for NPI" (items 2 and 4), "Requirements for NPI
//! Check Digit" and "Example of Check Digit Calculation for NPI used
//! without Prefix"
//! (<https://www.cms.gov/Regulations-and-Guidance/Administrative-Simplification/NationalProvIdentStand/Downloads/NPIcheckdigit.pdf>):
//! "The NPI will consist of 9 numeric digits followed by one numeric check
//! digit. [...] NPIs will initially be issued with the first digit = 1 or
//! 2. [...] The National Provider Identifier check digit is calculated
//! using the Luhn formula for computing the modulus 10 "double-add-double"
//! check digit. [...] it is preceded by the prefix 80840 [...] the check
//! digit will always be calculated as if the prefix is present." Worked
//! example: "NPI with check digit = 1234567893".
//!
//! The validator runs the shared Luhn helper over `80840` + the ten NPI
//! digits (the card-issuer form the source describes); the source's
//! "add the constant 24" shortcut is the same computation. No other
//! rejection is applied (no official source states one). Only the bare
//! ten-digit form is claimed: the source defines no separator grouping.
//!
//! Cue REQUIRED (score 1.0, checksum verified): a single Luhn digit admits
//! about 10% of random runs with a leading 1 or 2. A bare "npi" is not a
//! cue (substring of "unpin", "unpick"); the delimited label forms are.

use crate::pii::entity::EntityType;
use crate::pii::locales::{code_chars, luhn_valid, rule, ContextPolicy, Rule};

/// Cue words that make an NPI candidate claimable.
pub(super) const CUES: &[&str] = &[
    "npi:",
    "npi#",
    "npi ",
    " npi",
    "(npi)",
    "national provider",
    "provider id",
];

/// Returns `true` if `s` is a valid US National Provider Identifier: ten
/// ASCII digits, first digit 1 or 2, and the CMS check digit (Luhn over
/// the number preceded by the `80840` prefix).
///
/// # Examples
/// ```
/// use redactify::valid_us_npi;
/// assert!(valid_us_npi("1234567893")); // CMS worked example
/// assert!(!valid_us_npi("1234567890")); // check digit off
/// assert!(!valid_us_npi("3234567893")); // first digit must be 1 or 2
/// ```
#[must_use]
pub fn valid_us_npi(s: &str) -> bool {
    let Some(d) = code_chars::<10>(s, u8::is_ascii_digit, b"") else {
        return false;
    };
    if !matches!(d[0], b'1' | b'2') {
        return false;
    }
    let mut full = [0u8; 15];
    full[..5].copy_from_slice(b"80840");
    full[5..].copy_from_slice(&d);
    luhn_valid(&full)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UsNpi,
        r"(?<!\d)[12]\d{9}(?!\d)",
        Some(valid_us_npi),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_us_npi;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn official_vector_and_edges() {
        assert!(valid_us_npi("1234567893")); // CMS worked example
        assert!(!valid_us_npi("1234567890"));
        assert!(!valid_us_npi("1234567894"));
        assert!(!valid_us_npi("3234567893")); // first digit 3
        assert!(!valid_us_npi("123456789")); // 9 digits
        assert!(!valid_us_npi("808401234567893")); // the prefixed card form is not an NPI
        assert!(!valid_us_npi("1234-567-893")); // no separator grouping is defined
        assert!(!valid_us_npi(""));
        // CMS "constant 24" formulation of the same check: double every
        // second body digit from the right, add 24, complement to 10
        let body = [1u32, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut sum = 24;
        for (i, d) in body.iter().rev().enumerate() {
            let x = if i % 2 == 0 { d * 2 } else { *d };
            sum += if x > 9 { x - 9 } else { x };
        }
        assert_eq!((10 - sum % 10) % 10, 3);
    }

    #[test]
    fn cue_required() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["en"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        assert_eq!(kinds("NPI 1234567893"), vec![EntityType::UsNpi]);
        assert_eq!(kinds("provider NPI: 1234567893"), vec![EntityType::UsNpi]);
        assert_eq!(kinds("Provider ID: 1234567893"), vec![EntityType::UsNpi]);
        assert!(kinds("batch 1234567893 shipped").is_empty());
        assert!(kinds("unpin 1234567893").is_empty());
    }
}
